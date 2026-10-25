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
    pub route_order: usize,
    pub logical_url: Option<String>,
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

fn clean_script_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        use std::path::Component::*;
        match component {
            Prefix(_) | RootDir => out.push(component.as_os_str()),
            CurDir => {}
            ParentDir => {
                out.pop();
            }
            Normal(name) => out.push(name),
        }
    }
    out
}

/// Component-aware containment consumed by FastCGI script construction and
/// the `PATH_INFO` ancestor walk.  This is the verified kernel shared with
/// alias/rewrite mapping; `/srv/www2/x.php` is not below `/srv/www`.
fn script_under_base(script: &Path, base: &Path) -> bool {
    vapache_verified::path_under_base(
        script.as_os_str().as_encoded_bytes(),
        base.as_os_str().as_encoded_bytes(),
    )
}

/// Stable directory that bounds a FastCGI script target.  A configured
/// `fcgi://.../prefix/` names the base; a `$1` template is bounded by the
/// literal prefix before the first capture.  With no prefix the request's
/// document/alias root is the base.
fn fastcgi_script_base(backend: &Backend, root: &Path) -> PathBuf {
    let raw = if let Some(cut) = backend.prefix.find("$1") {
        backend.prefix[..cut].trim_end_matches('/')
    } else if !backend.prefix.is_empty() && backend.prefix != "/" {
        backend.prefix.trim_end_matches('/')
    } else {
        return clean_script_path(root);
    };
    if raw.is_empty() {
        return clean_script_path(root);
    }
    let raw = PathBuf::from(raw);
    let base = if raw.is_absolute() {
        raw
    } else {
        root.join(raw)
    };
    clean_script_path(&base)
}

fn script_from_prefix(backend: &Backend, root: &Path, rel: &Path) -> Option<(PathBuf, PathBuf)> {
    let rel_text = rel.to_string_lossy().trim_start_matches('/').to_string();
    let raw = if backend.prefix.contains("$1") {
        PathBuf::from(backend.prefix.replace("$1", &rel_text))
    } else if !backend.prefix.is_empty() && backend.prefix != "/" {
        PathBuf::from(format!(
            "{}/{}",
            backend.prefix.trim_end_matches('/'),
            rel_text
        ))
    } else {
        root.join(rel)
    };
    let raw = if raw.is_absolute() {
        raw
    } else {
        root.join(raw)
    };
    let base = fastcgi_script_base(backend, root);
    let script = clean_script_path(&raw);
    // A capture, suffix or template must never turn the script filename into
    // an absolute path outside the configured FastCGI/docroot base.
    if !script_under_base(&script, &base) {
        return None;
    }
    Some((script, base))
}

fn contained_after_resolving_symlinks(candidate: &Path, base: &Path) -> bool {
    let Ok(base) = std::fs::canonicalize(base) else {
        return false;
    };
    let Ok(candidate) = std::fs::canonicalize(candidate) else {
        return false;
    };
    script_under_base(&candidate, &base)
}

/// Split `PATH_INFO` from a FastCGI script target by finding the longest
/// existing file prefix, matching PHP-FPM's `ProxyPassMatch` convention.  This
/// also makes the authorization target the real script rather than the
/// synthesized `/index.php/extra` path.  The ancestor walk is bounded by the
/// configured script base and every selected file is resolved to reject
/// symlinks that leave that base while preserving the requested script path
/// for policy evaluation.
fn split_path_info(
    script_filename: PathBuf,
    url_path: &str,
    base: &Path,
) -> Option<(PathBuf, String, String)> {
    let script_filename = clean_script_path(&script_filename);
    if !script_under_base(&script_filename, base) {
        return None;
    }
    if script_filename.is_file() {
        if !contained_after_resolving_symlinks(&script_filename, base) {
            return None;
        }
        return Some((script_filename, url_path.to_string(), String::new()));
    }
    let original = script_filename.clone();
    let mut candidate = script_filename;
    let mut suffix = Vec::new();
    while let Some(parent) = candidate.parent() {
        // Never walk above the configured base, even when an ancestor happens
        // to be a regular file (for example /bin/sh).
        if !script_under_base(parent, base) {
            break;
        }
        if let Some(name) = candidate.file_name() {
            suffix.push(name.to_string_lossy().into_owned());
        }
        candidate = parent.to_path_buf();
        if candidate.is_file() {
            if !contained_after_resolving_symlinks(&candidate, base) {
                return None;
            }
            suffix.reverse();
            let info = format!("/{}", suffix.join("/"));
            let name = url_path.strip_suffix(&info).unwrap_or(url_path).to_string();
            return Some((candidate, name, info));
        }
        if candidate.parent().is_none() {
            break;
        }
    }
    script_under_base(&original, base).then_some((original, url_path.to_string(), String::new()))
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
    let mut best: Option<Target> = None;
    for rule in &scope.proxy_policy.proxy_passes {
        let Some(suffix) = prefix_suffix(&rule.prefix, url_path) else {
            continue;
        };
        let Some(backend) = parse_backend(&rule.backend) else {
            continue;
        };
        let rel = PathBuf::from(suffix);
        let Some((script_filename, base)) = script_from_prefix(&backend, root, &rel) else {
            continue;
        };
        let Some((script_filename, script_name, path_info)) =
            split_path_info(script_filename, url_path, &base)
        else {
            continue;
        };
        let candidate = Target {
            backend,
            script_filename,
            script_name,
            path_info,
            route_order: rule.route_order,
            logical_url: Some(format!(
                "{}/{}",
                rule.backend.trim_end_matches('/'),
                suffix.trim_start_matches('/')
            )),
        };
        if best
            .as_ref()
            .map(|b| candidate.route_order < b.route_order)
            .unwrap_or(true)
        {
            best = Some(candidate);
        }
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
        let Some((script_filename, base)) = script_from_prefix(&backend, root, &rel_capture) else {
            continue;
        };
        let Some((script_filename, script_name, path_info)) =
            split_path_info(script_filename, url_path, &base)
        else {
            continue;
        };
        let logical_url = rule.backend.replace(
            "$1",
            caps.get(1)
                .or_else(|| caps.get(0))
                .map(|m| m.as_str())
                .unwrap_or(url_path),
        );
        let candidate = Target {
            backend,
            script_filename,
            script_name,
            path_info,
            route_order: rule.route_order,
            logical_url: Some(logical_url),
        };
        if best
            .as_ref()
            .map(|b| candidate.route_order < b.route_order)
            .unwrap_or(true)
        {
            best = Some(candidate);
        }
    }
    best
}

/// Match a `SetHandler "proxy:fcgi://..."` handler for an existing file.
pub fn handler_target(scope: &Scope, root: &Path, rel: &Path, url_path: &str) -> Option<Target> {
    let name = rel.file_name().map(|n| n.as_encoded_bytes()).unwrap_or(b"");
    let handler = crate::config::effective_handler(scope, name)?;
    if !handler.starts_with("proxy:") {
        return None;
    }
    let backend = parse_backend(handler)?;
    let (script_filename, base) = script_from_prefix(&backend, root, rel)?;
    if script_filename.is_file() && !contained_after_resolving_symlinks(&script_filename, &base) {
        return None;
    }
    Some(Target {
        backend,
        script_filename,
        script_name: url_path.to_string(),
        path_info: String::new(),
        route_order: usize::MAX,
        logical_url: Some(handler.to_string()),
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

fn read_response_with_limit(
    stream: &mut dyn ReadWrite,
    max_output: u64,
) -> io::Result<(Spool, Vec<u8>)> {
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
                if spool.len() > max_output {
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

fn read_response(stream: &mut dyn ReadWrite) -> io::Result<(Spool, Vec<u8>)> {
    read_response_with_limit(stream, MAX_FASTCGI_OUTPUT)
}

/// Execute a FastCGI request.  `base` supplies the request and connection
/// metadata; `target` supplies the backend and SCRIPT_FILENAME.
pub fn execute(base: &CgiContext, scope: &Scope, target: &Target) -> Response {
    let mut env = env_from_base(base);
    // The FastCGI target, not the base request mapping, is authoritative for
    // the script and PATH_INFO.  Remove all four derived values before adding
    // the exact target values so a stale mapping cannot be sent twice or win
    // in a backend that takes the first duplicate parameter.
    env.retain(|(k, _)| {
        !matches!(
            k.to_str(),
            Some("SCRIPT_FILENAME" | "SCRIPT_NAME" | "PATH_INFO" | "PATH_TRANSLATED")
        )
    });
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
        env.push((
            OsString::from("PATH_TRANSLATED"),
            OsString::from(
                base.docroot
                    .join(target.path_info.trim_start_matches('/'))
                    .to_string_lossy()
                    .into_owned(),
            ),
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
            route_order: 0,
            logical_url: None,
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
            https: false,
            server_name: "localhost",
            host: "localhost",
            follow_symlinks: false,
            env: &[],
            remote_user: Some("alice"),
            auth_type: Some("Basic"),
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
        assert!(params.contains("REMOTE_USER"));
        assert!(params.contains("alice"));
        assert!(params.contains("AUTH_TYPE"));
        assert!(params.contains("Basic"));
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fastcgi_response_limits_and_protocol_errors() {
        let mut input = Vec::new();
        for _ in 0..16 {
            record(&mut input, FCGI_STDERR, 1, &vec![b'x'; 16 * 1024]);
        }
        record(&mut input, FCGI_END_REQUEST, 1, &[0u8; 8]);
        let mut cursor = Cursor::new(input);
        let (_spool, stderr) = read_response(&mut cursor).expect("bounded stderr");
        assert!(
            stderr.len() <= 64 * 1024,
            "FastCGI stderr must be capped, got {} bytes",
            stderr.len()
        );

        let mut bad_version = Cursor::new(vec![0u8; 8]);
        assert!(read_response(&mut bad_version).is_err());
    }

    #[test]
    fn fastcgi_target_overrides_script_and_path_info_exactly_once() {
        let dir = std::env::temp_dir().join(format!("vapache-fcgi-env-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("fcgi.sock");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let listener = UnixListener::bind(&sock).unwrap();
        let handle = mock_fastcgi(listener, seen.clone(), None);
        let cfg = config(&dir);
        let req = request("/index.php/info");
        let backend = parse_backend(&format!(
            "unix:{}|fcgi://localhost/var/www/html/",
            sock.display()
        ))
        .unwrap();
        let target = Target {
            backend,
            script_filename: PathBuf::from("/var/www/html/index.php"),
            script_name: "/index.php".into(),
            path_info: "/info".into(),
            route_order: 0,
            logical_url: None,
        };
        let ctx = CgiContext {
            cfg: &cfg,
            vhost: None,
            req: &req,
            root: &dir,
            script_rel: Path::new(""),
            script_name: "/index.php/info",
            path_info: "/info",
            docroot: &dir,
            remote_ip: "127.0.0.1",
            remote_port: 12345,
            local_ip: "127.0.0.1",
            local_port: 8080,
            https: false,
            server_name: "localhost",
            host: "localhost",
            follow_symlinks: false,
            env: &[],
            remote_user: None,
            auth_type: None,
            script_file: None,
        };
        let resp = execute(&ctx, &cfg.global, &target);
        assert_eq!(resp.status, 200);
        let params = seen.lock().unwrap();
        let count = |needle: &[u8]| {
            params
                .windows(needle.len())
                .filter(|w| *w == needle)
                .count()
        };
        assert_eq!(count(b"SCRIPT_FILENAME"), 1);
        assert_eq!(count(b"SCRIPT_NAME"), 1);
        assert_eq!(count(b"PATH_INFO"), 1);
        assert_eq!(count(b"PATH_TRANSLATED"), 1);
        assert!(String::from_utf8_lossy(&params).contains("/var/www/html/index.php"));
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
            route_order: 0,
            logical_url: None,
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
            https: false,
            server_name: "localhost",
            host: "localhost",
            follow_symlinks: false,
            env: &[],
            remote_user: None,
            auth_type: None,
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

    #[test]
    fn backend_parser_and_binding_edges() {
        let unix = parse_backend("unix:/tmp/php.sock").unwrap();
        assert!(matches!(&unix.transport, Transport::Unix(p) if p == Path::new("/tmp/php.sock")));
        assert!(unix.prefix.is_empty());

        let unix_url = parse_backend("unix:/tmp/php.sock|fcgi://localhost/var/www").unwrap();
        assert_eq!(unix_url.prefix, "/var/www");
        assert!(parse_backend("unix:|fcgi://localhost/").is_none());
        assert!(parse_backend("unix:/tmp/php.sock|http://localhost/").is_none());

        let tcp = parse_backend("fcgi://localhost").unwrap();
        assert!(matches!(&tcp.transport, Transport::Tcp(host, 9000) if host == "localhost"));
        assert!(tcp.prefix.is_empty());
        let tcp_path = parse_backend("fcgi://localhost:9001/var/www").unwrap();
        assert_eq!(tcp_path.prefix, "/var/www");
        assert!(matches!(&tcp_path.transport, Transport::Tcp(_, 9001)));
        assert!(parse_backend("fcgi://:9000/").is_none());
        assert!(parse_backend("fcgi://localhost:notaport/").is_none());
        assert!(parse_backend("http://example.com").is_none());

        let unix_target = Target {
            backend: unix,
            script_filename: PathBuf::from("/srv/index.php"),
            script_name: "/index.php".into(),
            path_info: String::new(),
            route_order: 0,
            logical_url: None,
        };
        assert!(unix_target.binding_key().starts_with("unix:/tmp/php.sock|"));
        let tcp_target = Target {
            backend: tcp_path,
            script_filename: PathBuf::from("/srv/index.php"),
            script_name: "/index.php".into(),
            path_info: "/info".into(),
            route_order: 0,
            logical_url: None,
        };
        assert!(tcp_target.binding_key().starts_with("tcp:localhost:9001|"));
    }

    #[test]
    fn script_base_and_prefix_edges() {
        let root = Path::new("/srv/www");
        let backend = |prefix: &str| Backend {
            transport: Transport::Unix(PathBuf::from("/tmp/php.sock")),
            prefix: prefix.into(),
        };
        assert_eq!(
            fastcgi_script_base(&backend("$1"), root),
            Path::new("/srv/www")
        );
        assert_eq!(
            fastcgi_script_base(&backend("www/$1"), root),
            Path::new("/srv/www/www")
        );
        assert_eq!(
            fastcgi_script_base(&backend("/"), root),
            Path::new("/srv/www")
        );
        assert_eq!(
            fastcgi_script_base(&backend("/abs/$1"), root),
            Path::new("/abs")
        );

        let (script, base) =
            script_from_prefix(&backend("www"), root, Path::new("index.php")).unwrap();
        assert_eq!(script, Path::new("/srv/www/www/index.php"));
        assert_eq!(base, Path::new("/srv/www/www"));
        let (script, base) =
            script_from_prefix(&backend("$1"), root, Path::new("index.php")).unwrap();
        assert_eq!(script, Path::new("/srv/www/index.php"));
        assert_eq!(base, root);
        let (script, _) = script_from_prefix(&backend("/"), root, Path::new("index.php")).unwrap();
        assert_eq!(script, Path::new("/srv/www/index.php"));

        assert_eq!(
            clean_script_path(Path::new("a/./b/../c")),
            PathBuf::from("a/c")
        );
        assert_eq!(clean_script_path(Path::new("./a")), PathBuf::from("a"));
    }

    #[test]
    fn containment_and_path_info_edges() {
        let dir = std::env::temp_dir().join(format!("vapache-fcgi-path-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let base = dir.join("www");
        fs::create_dir_all(base.join("dir")).unwrap();
        fs::write(base.join("index.php"), "<?php\n").unwrap();
        fs::write(base.join("dir").join("script.php"), "<?php\n").unwrap();

        assert!(!contained_after_resolving_symlinks(
            &base.join("missing"),
            &base
        ));
        assert!(!contained_after_resolving_symlinks(
            &base,
            &base.join("missing")
        ));

        let (script, name, info) =
            split_path_info(base.join("index.php"), "/index.php", &base).unwrap();
        assert_eq!(script, base.join("index.php"));
        assert_eq!(name, "/index.php");
        assert!(info.is_empty());

        let (script, name, info) = split_path_info(
            base.join("dir/script.php/info"),
            "/dir/script.php/info",
            &base,
        )
        .unwrap();
        assert_eq!(script, base.join("dir/script.php"));
        assert_eq!(name, "/dir/script.php");
        assert_eq!(info, "/info");

        // An ancestor selected by the PATH_INFO walk must also resolve inside
        // the base.
        fs::write(dir.join("outside.php"), "<?php\n").unwrap();
        std::os::unix::fs::symlink(dir.join("outside.php"), base.join("dir").join("link.php"))
            .unwrap();
        assert!(
            split_path_info(base.join("dir/link.php/info"), "/dir/link.php/info", &base).is_none()
        );

        // The base directory itself is not a file; the walk stops before its
        // parent and falls back to the contained lexical target.
        assert!(split_path_info(base.clone(), "/", &base).is_some());
        // Root base exercises the "candidate has no parent" walk terminator.
        assert!(
            split_path_info(PathBuf::from("/definitely-missing"), "/x", Path::new("/")).is_some()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn match_proxy_and_handler_target_edges() {
        let dir = std::env::temp_dir().join(format!("vapache-fcgi-match-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let root = dir.join("www");
        let outside = dir.join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("index.php"), "<?php\n").unwrap();
        fs::write(outside.join("secret.php"), "<?php\n").unwrap();
        std::os::unix::fs::symlink(outside.join("secret.php"), root.join("link.php")).unwrap();

        let valid = format!("unix:/tmp/php.sock|fcgi://localhost{}/", root.display());
        let mut scope = Scope::default();
        let mut pass = |prefix: &str, backend: &str, order: usize| {
            scope
                .proxy_policy
                .proxy_passes
                .push(crate::config::ProxyPassRule {
                    prefix: prefix.into(),
                    backend: backend.into(),
                    sticky_cookie: None,
                    fail_on_status: Vec::new(),
                    route_order: order,
                });
        };
        pass("/bad", "http://example.test/", 0);
        pass("/escape", &valid, 0);
        pass("/link", "unix:/tmp/php.sock|fcgi://localhost", 0);
        pass("/ok", "unix:/tmp/php.sock|fcgi://localhost", 1);
        pass("/ok", &valid, 0);
        let target = match_proxy(&scope, "/ok/index.php", &root).unwrap();
        assert_eq!(target.route_order, 0);
        assert_eq!(target.script_filename, root.join("index.php"));
        assert!(target.logical_url.as_deref().unwrap().starts_with("unix:"));
        assert!(match_proxy(&scope, "/escape/../outside/secret.php", &root).is_none());
        assert!(match_proxy(&scope, "/link/link.php", &root).is_none());

        let mut regex_scope = Scope::default();
        let mut rule = |pattern: &str, backend: &str, order: usize| {
            regex_scope
                .proxy_policy
                .proxy_rules
                .push(crate::config::ProxyRule {
                    pattern: std::sync::Arc::new(regex::Regex::new(pattern).unwrap()),
                    backend: backend.into(),
                    route_order: order,
                });
        };
        rule("^/nomatch$", "unix:/tmp/php.sock|fcgi://localhost", 0);
        rule("^/badregex$", "http://example.test/", 0);
        rule("^/escape/(.*)$", &valid, 0);
        rule("^/nogroup$", "unix:/tmp/php.sock|fcgi://localhost", 0);
        rule("^/link/(.*)$", "unix:/tmp/php.sock|fcgi://localhost", 0);
        rule("^/ok/(.*)$", "unix:/tmp/php.sock|fcgi://localhost", 1);
        rule("^/ok/(.*)$", &format!("{valid}$1"), 0);
        let regex_target = match_proxy(&regex_scope, "/ok/index.php", &root).unwrap();
        assert_eq!(regex_target.route_order, 0);
        assert_eq!(regex_target.script_filename, root.join("index.php"));
        assert!(match_proxy(&regex_scope, "/badregex", &root).is_none());
        assert!(match_proxy(&regex_scope, "/escape/../outside/secret.php", &root).is_none());
        assert!(match_proxy(&regex_scope, "/nogroup", &root).is_some());
        assert!(match_proxy(&regex_scope, "/link/link.php", &root).is_none());

        assert_eq!(prefix_suffix("/x", "/x"), Some(""));
        assert_eq!(prefix_suffix("/x", "/x/y"), Some("y"));
        assert_eq!(prefix_suffix("/x", "/xy"), None);
        assert_eq!(prefix_suffix("/x", "/other"), None);

        let handler_scope = |handler: &str| {
            let mut scope = Scope::default();
            scope
                .mapping_policy
                .handlers
                .push(crate::config::Handler::add("php".into(), handler.into()));
            scope
        };
        assert!(handler_target(
            &Scope::default(),
            &root,
            Path::new("index.php"),
            "/index.php"
        )
        .is_none());
        assert!(handler_target(
            &handler_scope("default-handler"),
            &root,
            Path::new("index.php"),
            "/index.php"
        )
        .is_none());
        assert!(handler_target(
            &handler_scope("proxy:http://example.test/"),
            &root,
            Path::new("index.php"),
            "/index.php"
        )
        .is_none());
        let proxy_handler = format!("proxy:{valid}");
        assert!(handler_target(
            &handler_scope(&proxy_handler),
            &root,
            Path::new("link.php"),
            "/link.php"
        )
        .is_none());
        let handler = handler_target(
            &handler_scope(&proxy_handler),
            &root,
            Path::new("index.php"),
            "/index.php",
        )
        .unwrap();
        assert_eq!(handler.script_filename, root.join("index.php"));
        assert_eq!(handler.logical_url.as_deref(), Some(proxy_handler.as_str()));
        let _ = fs::remove_dir_all(&dir);
    }

    struct Sink(Vec<u8>);

    impl Read for Sink {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn tcp_transport_connect_success_and_failure() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let _ = listener.accept();
        });
        let backend = Backend {
            transport: Transport::Tcp("127.0.0.1".into(), port),
            prefix: String::new(),
        };
        assert!(connect(&backend, Duration::from_secs(2)).is_ok());
        handle.join().unwrap();

        let dead = Backend {
            transport: Transport::Tcp("127.0.0.1".into(), 1),
            prefix: String::new(),
        };
        assert!(connect(&dead, Duration::from_millis(100)).is_err());
    }

    #[test]
    fn record_encoding_and_streamed_body_edges() {
        let mut len = Vec::new();
        put_len(&mut len, 127);
        assert_eq!(len.len(), 1);
        put_len(&mut len, 128);
        assert_eq!(len.len(), 5);

        let mut params = Vec::new();
        put_param(&mut params, b"K", b"V");
        assert!(!params.is_empty());
        let long_params = build_params(&[(
            OsString::from("k".repeat(200)),
            OsString::from("v".repeat(200)),
        )]);
        assert!(long_params.len() > 400);

        let mut sink = Sink(Vec::new());
        let body = vec![b'b'; 130_000];
        send_request(
            &mut sink,
            &vec![b'p'; 130_000],
            &mut Cursor::new(body.clone()),
        )
        .unwrap();
        assert!(sink.0.len() > body.len());
        assert_eq!(sink.0[0], FCGI_VERSION);
        assert!(sink.0.windows(2).any(|w| w == [FCGI_VERSION, FCGI_PARAMS]));
    }

    fn spool_from_bytes(data: &[u8]) -> Spool {
        let mut file = temp_file().unwrap();
        file.write_all(data).unwrap();
        Spool::File {
            file,
            len: data.len() as u64,
        }
    }

    #[test]
    fn spool_and_response_conversion_edges() {
        let mut spool = Spool::Memory(Vec::new());
        assert_eq!(spool.len(), 0);
        spool.push(b"abc").unwrap();
        assert_eq!(spool.len(), 3);
        let large = vec![b'x'; FASTCGI_SPOOL_THRESHOLD + 1];
        spool.push(&large).unwrap();
        assert!(matches!(spool, Spool::File { .. }));
        spool.push(b"z").unwrap();
        assert_eq!(spool.len(), 3 + large.len() as u64 + 1);

        let memory = response_from_spool(
            Spool::Memory(b"Content-Type: text/plain\r\n\r\nhello".to_vec()),
            crate::http::Version::Http11,
        )
        .unwrap();
        assert_eq!(memory.body_len(), 5);
        assert!(response_from_spool(
            Spool::Memory(b"not-a-response".to_vec()),
            crate::http::Version::Http11
        )
        .is_err());

        let file = response_from_spool(
            spool_from_bytes(b"Content-Type: text/plain\r\n\r\nhello"),
            crate::http::Version::Http11,
        )
        .unwrap();
        assert!(matches!(file.body, Body::File { len: 5, .. }));

        let lf_only = response_from_spool(
            spool_from_bytes(b"Content-Type: text/plain\n\nhello"),
            crate::http::Version::Http11,
        )
        .unwrap();
        assert!(matches!(lf_only.body, Body::File { len: 5, .. }));

        let no_header = response_from_spool(
            spool_from_bytes(b"no header separator"),
            crate::http::Version::Http11,
        );
        assert!(no_header.is_err());

        let empty = response_from_spool(
            spool_from_bytes(b"Status: 204 No Content\r\n\r\n"),
            crate::http::Version::Http11,
        )
        .unwrap();
        assert!(matches!(empty.body, Body::Empty));

        assert!(response_from_spool(
            spool_from_bytes(b"Content-Type\r\n\r\n"),
            crate::http::Version::Http11
        )
        .is_err());
    }

    #[test]
    fn response_reader_unknown_records_and_output_limit() {
        let mut input = Vec::new();
        record(&mut input, 99, 1, b"ignored");
        record(&mut input, FCGI_END_REQUEST, 1, &[0u8; 8]);
        let mut cursor = Cursor::new(input);
        let (spool, stderr) = read_response(&mut cursor).unwrap();
        assert_eq!(spool.len(), 0);
        assert!(stderr.is_empty());

        let mut input = Vec::new();
        record(&mut input, FCGI_STDOUT, 1, b"12345678");
        record(&mut input, FCGI_END_REQUEST, 1, &[0u8; 8]);
        let mut cursor = Cursor::new(input);
        assert!(read_response_with_limit(&mut cursor, 4).is_err());

        let mut input = Vec::new();
        for _ in 0..8 {
            record(&mut input, FCGI_STDERR, 1, &vec![b'e'; 16 * 1024]);
        }
        record(&mut input, FCGI_END_REQUEST, 1, &[0u8; 8]);
        let mut cursor = Cursor::new(input);
        let (_, stderr) = read_response(&mut cursor).unwrap();
        assert!(stderr.len() <= 64 * 1024);
    }

    fn mock_fastcgi_with_stderr(listener: UnixListener) -> std::thread::JoinHandle<()> {
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
                if ty == FCGI_STDIN && len == 0 {
                    break;
                }
            }
            let mut out = Vec::new();
            record(&mut out, FCGI_STDERR, 1, b"backend diagnostic\n");
            record(
                &mut out,
                FCGI_STDOUT,
                1,
                b"Content-Type: text/plain\r\n\r\nok\n",
            );
            record(&mut out, FCGI_STDOUT, 1, &[]);
            record(&mut out, FCGI_END_REQUEST, 1, &[0u8; 8]);
            stream.write_all(&out).unwrap();
        })
    }

    #[test]
    fn execute_error_stderr_and_spooled_body_paths() {
        let dir = std::env::temp_dir().join(format!("vapache-fcgi-exec-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = config(&dir);
        let req = request("/index.php");

        let missing = Target {
            backend: parse_backend("unix:/definitely/missing.sock|fcgi://localhost").unwrap(),
            script_filename: dir.join("index.php"),
            script_name: "/index.php".into(),
            path_info: String::new(),
            route_order: 0,
            logical_url: None,
        };
        let mut ctx = CgiContext {
            cfg: &cfg,
            vhost: None,
            req: &req,
            root: &dir,
            script_rel: Path::new(""),
            script_name: "/index.php",
            path_info: "",
            docroot: &dir,
            remote_ip: "not-an-ip",
            remote_port: 12345,
            local_ip: "127.0.0.1",
            local_port: 8080,
            https: false,
            server_name: "localhost",
            host: "localhost",
            follow_symlinks: false,
            env: &[],
            remote_user: None,
            auth_type: None,
            script_file: None,
        };
        assert_eq!(execute(&ctx, &cfg.global, &missing).status, 502);

        let sock = dir.join("fcgi.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let handle = mock_fastcgi_with_stderr(listener);
        let target = Target {
            backend: parse_backend(&format!("unix:{}|fcgi://localhost", sock.display())).unwrap(),
            script_filename: dir.join("index.php"),
            script_name: "/index.php".into(),
            path_info: String::new(),
            route_order: 0,
            logical_url: None,
        };
        assert_eq!(execute(&ctx, &cfg.global, &target).status, 200);
        handle.join().unwrap();
        let _ = fs::remove_file(&sock);

        // Exercise the spooled request-body path through the same worker.
        let listener = UnixListener::bind(&sock).unwrap();
        let handle = mock_fastcgi(listener, Arc::new(Mutex::new(Vec::new())), None);
        let body = vec![b'b'; 1_500_000];
        let mut wire = format!(
            "POST /index.php HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        wire.extend_from_slice(&body);
        let mut cursor = Cursor::new(wire);
        let mut buf = Vec::new();
        let spooled = crate::http::read_request(
            &mut cursor,
            &mut buf,
            &crate::http::Limits::default(),
            |_| {},
        )
        .unwrap()
        .unwrap();
        assert!(spooled.body_spool.is_some());
        ctx.req = &spooled;
        assert_eq!(execute(&ctx, &cfg.global, &target).status, 200);
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fastcgi_script_targets_cannot_escape_the_configured_base() {
        let dir = std::env::temp_dir().join(format!("vapache-fcgi-base-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let root = dir.join("www");
        let outside = dir.join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("index.php"), "<?php\n").unwrap();
        fs::write(outside.join("secret.php"), "<?php\n").unwrap();
        let sibling = dir.join("www2");
        fs::create_dir_all(&sibling).unwrap();
        fs::write(sibling.join("secret.php"), "<?php\n").unwrap();

        let prefix = parse_backend(&format!(
            "unix:/run/php.sock|fcgi://localhost{}/",
            root.display()
        ))
        .unwrap();
        let (script, base) = script_from_prefix(&prefix, &root, Path::new("index.php")).unwrap();
        assert_eq!(script, root.join("index.php"));
        assert!(script.starts_with(&base));
        assert!(
            script_from_prefix(&prefix, &root, Path::new("../../outside/secret.php")).is_none()
        );
        // `/…/www2` shares a byte prefix with `/…/www` but is not a child.
        assert!(split_path_info(sibling.join("secret.php"), "/x", &base).is_none());

        let template = parse_backend(&format!(
            "unix:/run/php.sock|fcgi://localhost{}/$1",
            root.display()
        ))
        .unwrap();
        assert!(script_from_prefix(&template, &root, Path::new("../outside/secret.php")).is_none());

        let no_prefix = parse_backend("unix:/run/php.sock|fcgi://localhost").unwrap();
        let (script, base) = script_from_prefix(&no_prefix, &root, Path::new("index.php")).unwrap();
        assert_eq!(script, root.join("index.php"));
        assert!(split_path_info(script.clone(), "/index.php/info", &base).is_some());
        // Even a caller-supplied target outside the base is rejected, and the
        // PATH_INFO ancestor walk cannot select an ancestor file such as
        // /bin/sh above the document root.
        assert!(split_path_info(outside.join("secret.php"), "/x", &base).is_none());
        assert!(split_path_info(root.join("../outside/secret.php/info"), "/x", &base).is_none());
        std::os::unix::fs::symlink(outside.join("secret.php"), root.join("link.php")).unwrap();
        assert!(split_path_info(root.join("link.php"), "/link.php", &base).is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
