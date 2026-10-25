//! Native FastCGI responder for PHP-FPM and compatible backends.
//!
//! Supports the common Apache `mod_proxy_fcgi` forms:
//!
//! ```text
//! ProxyPassMatch ^/(.*\.php(/.*)?)$ unix:/run/php/php-fpm.sock|fcgi://localhost/var/www/html/
//! SetHandler "proxy:unix:/run/php/php-fpm.sock|fcgi://localhost"
//! SetHandler "proxy:fcgi://127.0.0.1:9000"
//! ```
//!
//! The implementation is deliberately buffered: a FastCGI response is parsed
//! through the same validated CGI header path as local CGI.  That keeps header
//! splitting, status handling and compression consistent across both paths.

use crate::cgi::{self, CgiContext};
use crate::config::{Config, Scope, VHost};
use crate::http::{Body, Request, Response};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

const FCGI_VERSION: u8 = 1;
const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
const FCGI_STDERR: u8 = 7;
const FCGI_RESPONDER: u16 = 1;
const MAX_FASTCGI_OUTPUT: u64 = 1024 * 1024 * 1024;
const FASTCGI_SPOOL_THRESHOLD: usize = 1024 * 1024;

#[derive(Clone, Debug)]
enum Transport {
    Unix(PathBuf),
    Tcp(String, u16),
}

#[derive(Clone, Debug)]
pub struct Backend {
    transport: Transport,
    prefix: String,
}

pub struct Target {
    backend: Backend,
    pub script_filename: PathBuf,
    pub script_name: String,
    pub path_info: String,
}

impl Target {
    /// Exact FastCGI transport/script identity used for resource binding.
    pub(crate) fn binding_key(&self) -> String {
        let transport = match &self.backend.transport {
            Transport::Unix(path) => format!("unix:{}", path.display()),
            Transport::Tcp(host, port) => format!("tcp:{host}:{port}"),
        };
        format!(
            "{transport}|{}|{}|{}",
            self.script_filename.display(),
            self.script_name,
            self.path_info
        )
    }
}

fn parse_backend(value: &str) -> Option<Backend> {
    let value = value.trim();
    let value = value.strip_prefix("proxy:").unwrap_or(value);
    if let Some(rest) = value.strip_prefix("unix:") {
        let (sock, url) = match rest.split_once('|') {
            Some((sock, url)) => (sock, url),
            None => (rest, ""),
        };
        if sock.is_empty() {
            return None;
        }
        let prefix = if url.is_empty() {
            String::new()
        } else {
            let url = url.strip_prefix("fcgi://")?;
            let (_, _, path) = split_host_path(url)?;
            path
        };
        return Some(Backend {
            transport: Transport::Unix(PathBuf::from(sock)),
            prefix,
        });
    }
    let rest = value.strip_prefix("fcgi://")?;
    let (host, port, path) = split_host_path(rest)?;
    Some(Backend {
        transport: Transport::Tcp(host, port),
        prefix: path,
    })
}

fn split_host_path(rest: &str) -> Option<(String, u16, String)> {
    let (hostport, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest, String::new()),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (hostport.to_string(), 9000),
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path))
}

fn script_from_prefix(backend: &Backend, root: &Path, rel: &Path) -> PathBuf {
    let rel_text = rel.to_string_lossy().trim_start_matches('/').to_string();
    if backend.prefix.contains("$1") {
        PathBuf::from(backend.prefix.replace("$1", &rel_text))
    } else if !backend.prefix.is_empty() && backend.prefix != "/" {
        PathBuf::from(format!(
            "{}/{}",
            backend.prefix.trim_end_matches('/'),
            rel_text
        ))
    } else {
        root.join(rel)
    }
}

fn prefix_suffix<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    if path == prefix {
        Some("")
    } else if let Some(rest) = path.strip_prefix(prefix) {
        if rest.starts_with('/') {
            Some(rest.trim_start_matches('/'))
        } else {
            None
        }
    } else {
        None
    }
}

/// Match a `ProxyPassMatch` (or a prefix `ProxyPass` with a FastCGI backend)
/// against the final URL path.
pub fn match_proxy(scope: &Scope, url_path: &str, root: &Path) -> Option<Target> {
    for rule in &scope.proxy_policy.proxy_passes {
        let Some(suffix) = prefix_suffix(&rule.prefix, url_path) else {
            continue;
        };
        let Some(backend) = parse_backend(&rule.backend) else {
            continue;
        };
        let rel = PathBuf::from(suffix);
        let script_filename = script_from_prefix(&backend, root, &rel);
        return Some(Target {
            backend,
            script_filename,
            script_name: url_path.to_string(),
            path_info: String::new(),
        });
    }
    for rule in &scope.proxy_policy.proxy_rules {
        let caps = match rule.pattern.captures(url_path) {
            Some(c) => c,
            None => continue,
        };
        let backend = match parse_backend(&rule.backend) {
            Some(b) => b,
            None => continue,
        };
        let rel_text = caps
            .get(1)
            .or_else(|| caps.get(0))
            .map(|m| m.as_str())
            .unwrap_or(url_path)
            .trim_start_matches('/');
        let rel_capture = PathBuf::from(rel_text);
        let script_filename = script_from_prefix(&backend, root, &rel_capture);
        return Some(Target {
            backend,
            script_filename,
            script_name: url_path.to_string(),
            path_info: String::new(),
        });
    }
    None
}

/// Match a `SetHandler "proxy:fcgi://..."` handler for an existing file.
pub fn handler_target(scope: &Scope, root: &Path, rel: &Path, url_path: &str) -> Option<Target> {
    let name = rel.file_name().map(|n| n.as_encoded_bytes()).unwrap_or(b"");
    let handler = crate::config::effective_handler(scope, name)?;
    if !handler.starts_with("proxy:") {
        return None;
    }
    let backend = parse_backend(handler)?;
    let script_filename = script_from_prefix(&backend, root, rel);
    Some(Target {
        backend,
        script_filename,
        script_name: url_path.to_string(),
        path_info: String::new(),
    })
}

fn connect(backend: &Backend, timeout: Duration) -> io::Result<Box<dyn ReadWrite>> {
    match &backend.transport {
        Transport::Unix(path) => {
            let s = UnixStream::connect(path)?;
            s.set_read_timeout(Some(timeout))?;
            s.set_write_timeout(Some(timeout))?;
            Ok(Box::new(s))
        }
        Transport::Tcp(host, port) => {
            let mut last = None;
            for addr in (host.as_str(), *port).to_socket_addrs()? {
                match TcpStream::connect_timeout(&addr, timeout) {
                    Ok(s) => {
                        s.set_read_timeout(Some(timeout))?;
                        s.set_write_timeout(Some(timeout))?;
                        return Ok(Box::new(s));
                    }
                    Err(e) => last = Some(e),
                }
            }
            Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address")))
        }
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn put_len(out: &mut Vec<u8>, n: usize) {
    if n < 128 {
        out.push(n as u8);
    } else {
        out.extend_from_slice(&((n as u32) | 0x8000_0000).to_be_bytes());
    }
}

fn put_param(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    put_len(out, name.len());
    put_len(out, value.len());
    out.extend_from_slice(name);
    out.extend_from_slice(value);
}

fn record(out: &mut Vec<u8>, ty: u8, id: u16, content: &[u8]) {
    let pad = (8 - content.len() % 8) % 8;
    out.push(FCGI_VERSION);
    out.push(ty);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.push(pad as u8);
    out.push(0);
    out.extend_from_slice(content);
    out.extend(std::iter::repeat(0).take(pad));
}

fn env_from_base(base: &CgiContext) -> Vec<(OsString, OsString)> {
    cgi::build_env(base)
}

fn build_params(env: &[(OsString, OsString)]) -> Vec<u8> {
    let mut params = Vec::new();
    for (k, v) in env {
        put_param(
            &mut params,
            k.as_os_str().as_bytes(),
            v.as_os_str().as_bytes(),
        );
    }
    params
}

fn send_request(stream: &mut dyn ReadWrite, params: &[u8], body: &mut dyn Read) -> io::Result<()> {
    let mut out = Vec::new();
    let mut begin = vec![0u8; 8];
    begin[0..2].copy_from_slice(&FCGI_RESPONDER.to_be_bytes());
    record(&mut out, FCGI_BEGIN_REQUEST, 1, &begin);
    for chunk in params.chunks(60_000) {
        record(&mut out, FCGI_PARAMS, 1, chunk);
    }
    record(&mut out, FCGI_PARAMS, 1, &[]);
    stream.write_all(&out)?;
    let mut chunk = vec![0u8; 60_000];
    loop {
        let n = body.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        let mut record_bytes = Vec::new();
        record(&mut record_bytes, FCGI_STDIN, 1, &chunk[..n]);
        stream.write_all(&record_bytes)?;
    }
    let mut end = Vec::new();
    record(&mut end, FCGI_STDIN, 1, &[]);
    stream.write_all(&end)
}

enum Spool {
    Memory(Vec<u8>),
    File { file: File, len: u64 },
}

impl Spool {
    fn len(&self) -> u64 {
        match self {
            Spool::Memory(v) => v.len() as u64,
            Spool::File { len, .. } => *len,
        }
    }

    fn push(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Spool::Memory(v) => {
                if v.len().saturating_add(data.len()) > FASTCGI_SPOOL_THRESHOLD {
                    let mut file = temp_file()?;
                    file.write_all(v)?;
                    file.write_all(data)?;
                    let len = v.len() as u64 + data.len() as u64;
                    *self = Spool::File { file, len };
                } else {
                    v.extend_from_slice(data);
                }
            }
            Spool::File { file, len } => {
                file.write_all(data)?;
                *len = len.saturating_add(data.len() as u64);
            }
        }
        Ok(())
    }
}

fn temp_file() -> io::Result<File> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("vapache-fastcgi-{}-{}.body", std::process::id(), n));
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&path)?;
    let _ = std::fs::remove_file(&path);
    Ok(file)
}

fn response_from_spool(spool: Spool, version: crate::http::Version) -> io::Result<Response> {
    match spool {
        Spool::Memory(data) => cgi::parse_cgi_response(&data, version)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid FastCGI response")),
        Spool::File { mut file, len } => {
            file.seek(SeekFrom::Start(0))?;
            let prefix_len = len.min(128 * 1024) as usize;
            let mut prefix = vec![0u8; prefix_len];
            file.read_exact(&mut prefix)?;
            let head_end = prefix
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|p| p + 4)
                .or_else(|| prefix.windows(2).position(|w| w == b"\n\n").map(|p| p + 2))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "FastCGI headers too large")
                })?;
            let mut head = prefix[..head_end].to_vec();
            if !head.ends_with(b"\r\n\r\n") {
                head.extend_from_slice(b"\r\n\r\n");
            }
            let mut response = cgi::parse_cgi_response(&head, version).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid FastCGI response")
            })?;
            let body_len = len.saturating_sub(head_end as u64);
            if response.status == 204 || response.status == 304 || body_len == 0 {
                response.body = Body::Empty;
            } else {
                response.body = Body::File {
                    file,
                    offset: head_end as u64,
                    len: body_len,
                };
            }
            Ok(response)
        }
    }
}

fn read_response(stream: &mut dyn ReadWrite) -> io::Result<(Spool, Vec<u8>)> {
    let mut spool = Spool::Memory(Vec::new());
    let mut stderr = Vec::new();
    loop {
        let mut header = [0u8; 8];
        stream.read_exact(&mut header)?;
        if header[0] != FCGI_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad FastCGI version",
            ));
        }
        let ty = header[1];
        let len = u16::from_be_bytes([header[4], header[5]]) as usize;
        let pad = header[6] as usize;
        let mut content = vec![0u8; len + pad];
        stream.read_exact(&mut content)?;
        content.truncate(len);
        match ty {
            FCGI_STDOUT => {
                spool.push(&content)?;
                if spool.len() > MAX_FASTCGI_OUTPUT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "FastCGI output too large",
                    ));
                }
            }
            FCGI_STDERR => {
                if stderr.len() + content.len() <= 64 * 1024 {
                    stderr.extend_from_slice(&content);
                }
            }
            FCGI_END_REQUEST => return Ok((spool, stderr)),
            _ => {}
        }
    }
}

/// Execute a FastCGI request.  `base` supplies the request and connection
/// metadata; `target` supplies the backend and SCRIPT_FILENAME.
pub fn execute(base: &CgiContext, scope: &Scope, target: &Target) -> Response {
    let mut env = env_from_base(base);
    env.retain(|(k, _)| k != "SCRIPT_FILENAME" && k != "SCRIPT_NAME");
    env.push((
        OsString::from("SCRIPT_FILENAME"),
        OsString::from(target.script_filename.to_string_lossy().into_owned()),
    ));
    env.push((
        OsString::from("SCRIPT_NAME"),
        OsString::from(target.script_name.clone()),
    ));
    if !target.path_info.is_empty() {
        env.push((
            OsString::from("PATH_INFO"),
            OsString::from(target.path_info.clone()),
        ));
    }
    let result = (|| -> io::Result<Response> {
        let timeout = base.cfg.timeout.max(Duration::from_secs(5));
        let mut stream = connect(&target.backend, timeout)?;
        let params = build_params(&env);
        if let Some(reader) = base.req.body_reader() {
            let mut reader = reader?;
            send_request(&mut stream, &params, &mut reader)?;
        } else {
            let mut reader = Cursor::new(base.req.body.as_slice());
            send_request(&mut stream, &params, &mut reader)?;
        }
        let (spool, stderr) = read_response(&mut stream)?;
        if !stderr.is_empty() {
            eprintln!(
                "vapache FastCGI stderr: {}",
                String::from_utf8_lossy(&stderr).trim()
            );
        }
        response_from_spool(spool, base.req.version)
    })();

    match result {
        Ok(mut r) => {
            crate::compression::finalize(scope, base.req, &mut r, target.script_name.as_bytes());
            r
        }
        Err(e) => {
            eprintln!("vapache FastCGI error: {e}");
            crate::files::error_response(
                base.cfg,
                base.vhost,
                scope,
                502,
                base.req,
                &target.script_name,
                base.local_port,
                base.host,
                base.remote_ip
                    .parse()
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                base.local_ip,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::sync::{Arc, Mutex};

    fn config(root: &Path) -> Config {
        let path = root.join("httpd.conf");
        fs::write(&path, "Listen 127.0.0.1:0\n").unwrap();
        Config::load(&path, root, &HashMap::new(), &HashMap::new(), false).unwrap()
    }

    fn request(path: &str) -> Request {
        Request {
            method: "GET".into(),
            target: path.as_bytes().to_vec(),
            raw_path: path.as_bytes().to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    fn mock_fastcgi(
        listener: UnixListener,
        seen: Arc<Mutex<Vec<u8>>>,
        payload: Option<Vec<u8>>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            loop {
                let mut header = [0u8; 8];
                if stream.read_exact(&mut header).is_err() {
                    break;
                }
                let ty = header[1];
                let len = u16::from_be_bytes([header[4], header[5]]) as usize;
                let pad = header[6] as usize;
                let mut content = vec![0u8; len + pad];
                stream.read_exact(&mut content).unwrap();
                content.truncate(len);
                if ty == FCGI_PARAMS {
                    seen.lock().unwrap().extend_from_slice(&content);
                }
                if ty == FCGI_STDIN && len == 0 {
                    break;
                }
            }
            let mut out = Vec::new();
            record(
                &mut out,
                FCGI_STDOUT,
                1,
                b"Content-Type: text/plain\r\n\r\n",
            );
            if let Some(payload) = payload {
                for chunk in payload.chunks(60_000) {
                    record(&mut out, FCGI_STDOUT, 1, chunk);
                }
            } else {
                record(&mut out, FCGI_STDOUT, 1, b"fastcgi ok\n");
            }
            record(&mut out, FCGI_STDOUT, 1, &[]);
            record(&mut out, FCGI_END_REQUEST, 1, &[0u8; 8]);
            stream.write_all(&out).unwrap();
        })
    }

    #[test]
    fn parses_and_executes_unix_fastcgi() {
        let dir = std::env::temp_dir().join(format!("vapache-fcgi-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("fcgi.sock");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let listener = UnixListener::bind(&sock).unwrap();
        let handle = mock_fastcgi(listener, seen.clone(), None);
        let cfg = config(&dir);
        let req = request("/index.php");
        let backend = parse_backend(&format!(
            "unix:{}|fcgi://localhost/var/www/html/",
            sock.display()
        ))
        .unwrap();
        let target = Target {
            backend,
            script_filename: PathBuf::from("/var/www/html/index.php"),
            script_name: "/index.php".into(),
            path_info: String::new(),
        };
        let ctx = CgiContext {
            cfg: &cfg,
            vhost: None,
            req: &req,
            root: &dir,
            script_rel: Path::new(""),
            script_name: "/index.php",
            path_info: "",
            docroot: &dir,
            remote_ip: "127.0.0.1",
            remote_port: 12345,
            local_ip: "127.0.0.1",
            local_port: 8080,
            server_name: "localhost",
            host: "localhost",
            follow_symlinks: false,
            env: &[],
            script_file: None,
        };
        let resp = execute(&ctx, &cfg.global, &target);
        assert_eq!(resp.status, 200);
        match resp.body {
            Body::Bytes(b) => assert_eq!(b, b"fastcgi ok\n"),
            _ => panic!("expected bytes"),
        }
        let params = String::from_utf8_lossy(&seen.lock().unwrap()).into_owned();
        assert!(params.contains("SCRIPT_FILENAME"));
        assert!(params.contains("/var/www/html/index.php"));
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn large_fastcgi_output_uses_a_file_backed_body() {
        let dir = std::env::temp_dir().join(format!("vapache-fcgi-large-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("fcgi.sock");
        let payload = vec![b'q'; 2 * 1024 * 1024];
        let expected = payload.len();
        let listener = UnixListener::bind(&sock).unwrap();
        let handle = mock_fastcgi(listener, Arc::new(Mutex::new(Vec::new())), Some(payload));
        let cfg = config(&dir);
        let req = request("/index.php");
        let backend = parse_backend(&format!(
            "unix:{}|fcgi://localhost/var/www/html/",
            sock.display()
        ))
        .unwrap();
        let target = Target {
            backend,
            script_filename: PathBuf::from("/var/www/html/index.php"),
            script_name: "/index.php".into(),
            path_info: String::new(),
        };
        let ctx = CgiContext {
            cfg: &cfg,
            vhost: None,
            req: &req,
            root: &dir,
            script_rel: Path::new(""),
            script_name: "/index.php",
            path_info: "",
            docroot: &dir,
            remote_ip: "127.0.0.1",
            remote_port: 12345,
            local_ip: "127.0.0.1",
            local_port: 8080,
            server_name: "localhost",
            host: "localhost",
            follow_symlinks: false,
            env: &[],
            script_file: None,
        };
        let resp = execute(&ctx, &cfg.global, &target);
        assert_eq!(resp.status, 200);
        match resp.body {
            Body::File { len, .. } => assert_eq!(len as usize, expected),
            _ => panic!("expected file-backed body"),
        }
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn backend_forms_are_parsed() {
        assert!(parse_backend("proxy:fcgi://127.0.0.1:9000/var/www").is_some());
        assert!(parse_backend("unix:/run/php.sock|fcgi://localhost").is_some());
        assert!(parse_backend("http://example.com").is_none());
    }
}
