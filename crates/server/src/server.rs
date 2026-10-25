//! Listener management and request dispatch.

use crate::access::{self, Access};
use crate::cgi::{self, CgiContext};
use crate::config::{Config, EncodedSlashes, Options, Scope, VHost};
use crate::fastcgi;
use crate::files::{
    directory_index_name, error_response, mime_type, resolve_target, serve_directory, serve_file,
    simple_html, Target,
};
use crate::http::{
    read_request, write_response, Body, Limits, ParseError, ReadError, Request, Response,
    ResponseOptions, ResponseWrite, Version,
};
use crate::log::{AccessEntry, Logger};
use crate::proxy;
use crate::util::is_canonical_path;
use crate::verified::{normalize_uri_path, percent_decode_path};
use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Bound {
    pub listener: TcpListener,
    pub port: u16,
    pub addr: String,
    pub tls: Option<Arc<rustls::ServerConfig>>,
}

/// Bind all configured listeners.  Called while still privileged so ports
/// below 1024 work, before dropping to the configured user.
pub fn bind(cfg: &Config) -> io::Result<Vec<Bound>> {
    crate::cache::prepare(cfg);
    crate::cache::prepare_dir(cfg, &cfg.server_root.join("logs").join("ocsp-cache"));
    crate::proxy::start_health_checks(cfg);
    let mut out = Vec::new();
    for l in &cfg.listeners {
        let addr_str = if l.addr == "*" { "0.0.0.0" } else { &l.addr };
        let sock_addr = if let Ok(ip) = addr_str.parse::<IpAddr>() {
            SocketAddr::new(ip, l.port)
        } else {
            use std::net::ToSocketAddrs;
            let mut addrs = (addr_str, l.port).to_socket_addrs()?;
            addrs
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no address"))?
        };
        let tls = crate::tls::server_config(cfg, l.port)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let listener = bind_reuse(sock_addr, cfg.listen_backlog)?;
        out.push(Bound {
            listener,
            port: l.port,
            addr: l.addr.clone(),
            tls,
        });
    }
    Ok(out)
}

/// Rebuild per-generation listener handles against an existing bound set.
/// The original listeners stay open across reloads, which keeps privileged
/// ports usable after the daemon has dropped root.
pub fn rebind(cfg: &Config, previous: &[Bound]) -> io::Result<Vec<Bound>> {
    if cfg.listeners.len() != previous.len() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "changing Listen directives requires a full restart",
        ));
    }
    let mut out = Vec::with_capacity(previous.len());
    for (l, old) in cfg.listeners.iter().zip(previous) {
        if l.port != old.port || l.addr != old.addr {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "changing Listen directives requires a full restart",
            ));
        }
        let listener = old.listener.try_clone()?;
        let tls = crate::tls::server_config(cfg, l.port)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        out.push(Bound {
            listener,
            port: l.port,
            addr: l.addr.clone(),
            tls,
        });
    }
    crate::cache::prepare(cfg);
    crate::cache::prepare_dir(cfg, &cfg.server_root.join("logs").join("ocsp-cache"));
    crate::proxy::start_health_checks(cfg);
    Ok(out)
}

fn bind_reuse(addr: SocketAddr, backlog: i32) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of_val(&one) as libc::socklen_t,
        );
    }
    let storage = sockaddr_storage(addr);
    let rc = unsafe {
        libc::bind(
            fd,
            &storage.0 as *const _ as *const libc::sockaddr,
            storage.1,
        )
    };
    if rc != 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    if unsafe { libc::listen(fd, backlog.max(1)) } != 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    use std::os::unix::io::FromRawFd;
    Ok(unsafe { TcpListener::from_raw_fd(fd) })
}

fn sockaddr_storage(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let s = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &s as *const _ as *const u8,
                    &mut storage as *mut _ as *mut u8,
                    std::mem::size_of_val(&s),
                );
            }
            (storage, std::mem::size_of_val(&s) as libc::socklen_t)
        }
        SocketAddr::V6(v6) => {
            let s = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &s as *const _ as *const u8,
                    &mut storage as *mut _ as *mut u8,
                    std::mem::size_of_val(&s),
                );
            }
            (storage, std::mem::size_of_val(&s) as libc::socklen_t)
        }
    }
}

static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

pub fn active_connections() -> usize {
    ACTIVE_CONNECTIONS.load(Ordering::Relaxed)
}

pub struct Server {
    cfg: Arc<Config>,
    logger: Arc<Logger>,
    stop: Arc<AtomicBool>,
}

impl Server {
    pub fn new(cfg: Arc<Config>, logger: Arc<Logger>) -> Self {
        Server {
            cfg,
            logger,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }

    pub fn run(&self, bound: &[Bound]) -> io::Result<()> {
        for b in bound {
            b.listener.set_nonblocking(true)?;
        }
        let mut pollfds: Vec<libc::pollfd> = bound
            .iter()
            .map(|b| libc::pollfd {
                fd: b.listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        while !self.stop.load(Ordering::Relaxed) {
            let rc = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, 100) };
            if rc < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            for (i, b) in bound.iter().enumerate() {
                if pollfds[i].revents & libc::POLLIN == 0 {
                    continue;
                }
                loop {
                    match b.listener.accept() {
                        Ok((stream, peer)) => {
                            let local = stream.local_addr().ok();
                            let cfg = self.cfg.clone();
                            let logger = self.logger.clone();
                            let worker_limit = cfg.max_request_workers.max(1);
                            if !vapache_verified::connection_admit(
                                ACTIVE_CONNECTIONS.load(Ordering::Relaxed) as u64,
                                worker_limit as u64,
                            ) {
                                if b.tls.is_some() {
                                    drop(stream);
                                    continue;
                                }
                                let mut s = stream;
                                let _ = write_response(
                                    &mut s,
                                    &mut simple_html(503, "Server busy", None),
                                    &ResponseOptions {
                                        server_header: &self.cfg.server_header(),
                                        keep_alive: false,
                                        head_only: false,
                                        protocol: Version::Http11,
                                        request_keep_alive: false,
                                    },
                                );
                                continue;
                            }
                            ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
                            let port = local.map(|l| l.port()).unwrap_or(b.port);
                            let local_ip = local
                                .map(|l| l.ip().to_string())
                                .unwrap_or_else(|| "127.0.0.1".into());
                            let tls = b.tls.clone();
                            std::thread::Builder::new()
                                .name("conn".into())
                                .spawn(move || {
                                    let _guard = ActiveGuard;
                                    if let Some(tls_cfg) = tls {
                                        let _ = handle_tls_connection(
                                            cfg, logger, stream, peer, local_ip, port, tls_cfg,
                                        );
                                    } else {
                                        stream.set_nodelay(true).ok();
                                        stream.set_read_timeout(Some(Duration::from_secs(20))).ok();
                                        stream.set_write_timeout(Some(cfg.timeout)).ok();
                                        let mut stream = stream;
                                        let _ = handle_connection(
                                            &cfg,
                                            &logger,
                                            &mut stream,
                                            peer,
                                            &local_ip,
                                            port,
                                        );
                                    }
                                })
                                .ok();
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            }
        }
        Ok(())
    }
}

struct ActiveGuard;
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
    }
}

trait Conn: Read + Write {
    fn set_read_timeout(&mut self, _timeout: Option<Duration>) {}
    fn try_clone_tcp(&self) -> Option<TcpStream> {
        None
    }
    fn take_tls_stream(
        &mut self,
    ) -> Option<(
        tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        tokio::runtime::Handle,
    )> {
        None
    }
}

impl Conn for TcpStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        let _ = TcpStream::set_read_timeout(self, timeout);
    }

    fn try_clone_tcp(&self) -> Option<TcpStream> {
        self.try_clone().ok()
    }
}

fn write_ws_error<C: ResponseWrite>(
    stream: &mut C,
    cfg: &Config,
    status: u16,
    message: &[u8],
) -> io::Result<()> {
    let mut r = Response::bytes(status, "text/html; charset=iso-8859-1", message.to_vec());
    r.headers.push(("Connection".into(), b"close".to_vec()));
    write_response(
        stream,
        &mut r,
        &ResponseOptions {
            server_header: &cfg.server_header(),
            keep_alive: false,
            head_only: false,
            protocol: Version::Http11,
            request_keep_alive: false,
        },
    )?;
    Ok(())
}

fn write_ws_response<C: ResponseWrite>(
    stream: &mut C,
    cfg: &Config,
    response: &mut Response,
) -> io::Result<()> {
    write_response(
        stream,
        response,
        &ResponseOptions {
            server_header: &cfg.server_header(),
            keep_alive: false,
            head_only: false,
            protocol: Version::Http11,
            request_keep_alive: false,
        },
    )
    .map(|_| ())
}

fn handle_connection<C: Conn + ResponseWrite>(
    cfg: &Config,
    logger: &Logger,
    stream: &mut C,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
) -> io::Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let limits = Limits {
        request_line: cfg.limit_request_line,
        fields: cfg.limit_request_fields,
        field_size: cfg.limit_request_field_size,
        body: cfg.limit_request_body,
        header_timeout: cfg.request_header_timeout.max(Duration::from_secs(1)),
        body_timeout: cfg.request_body_timeout.max(Duration::from_secs(1)),
        header_min_rate: cfg.request_header_min_rate,
        body_min_rate: cfg.request_body_min_rate,
    };
    // `Time out` applies to the first request; idle keep-alive connections use
    // `KeepAliveTimeout`.  Set the socket option once per connection instead of
    // paying a `setsockopt` on every request.
    stream.set_read_timeout(Some(cfg.request_header_timeout.max(Duration::from_secs(1))));
    let mut served = 0usize;
    loop {
        if served == 0 {
            stream.set_read_timeout(Some(cfg.request_header_timeout.max(Duration::from_secs(1))));
        }
        let started = Instant::now();
        let req = match read_request(stream, &mut buf, &limits, |stream| {
            stream.set_read_timeout(Some(cfg.request_body_timeout.max(Duration::from_secs(1))));
        }) {
            Ok(Some(r)) => r,
            Ok(None) => return Ok(()),
            Err(ReadError::Io(e)) => return Err(e),
            Err(ReadError::Parse(e)) => {
                let status = e.status();
                let body = error_body(&e);
                let mut r =
                    Response::bytes(status, "text/html; charset=iso-8859-1", body.into_bytes());
                r.headers.push(("Connection".into(), b"close".to_vec()));
                let _ = write_response(
                    stream,
                    &mut r,
                    &ResponseOptions {
                        server_header: &cfg.server_header(),
                        keep_alive: false,
                        head_only: false,
                        protocol: Version::Http11,
                        request_keep_alive: false,
                    },
                );
                return Ok(());
            }
        };
        let peer = cfg.client_addr(peer, &req);
        let remote_ip = peer.ip().to_string();
        let bytes_in = req.target.len() as u64 + req.body_len();

        // WebSocket upgrades need the raw connection after the 101 response;
        // the normal Response pipeline only supports buffered bodies.
        if proxy::is_websocket(&req) {
            let host = host_header(&req).unwrap_or("");
            let vhost =
                cfg.select_vhost(local_port, if host.is_empty() { None } else { Some(host) });
            // The upgrade path must use the same canonical path as ordinary
            // dispatch.  Raw paths containing dot segments or encoded
            // separators would otherwise let the proxy/ACL see a different
            // resource from the one the upstream eventually resolves.
            let allow_encoded = cfg.encoded_slashes == EncodedSlashes::On;
            let decoded = match percent_decode_path(&req.raw_path, allow_encoded) {
                Some(d) => d,
                None => {
                    let _ = write_ws_error(stream, &cfg, 400, b"bad request path");
                    return Ok(());
                }
            };
            let norm = match normalize_uri_path(&decoded) {
                Some(n) if is_canonical_path(&n) => n,
                _ => {
                    let _ = write_ws_error(stream, &cfg, 400, b"bad request path");
                    return Ok(());
                }
            };
            let trailing_slash = decoded.len() > 1 && decoded.ends_with(b"/");
            let mut url_path = String::from_utf8_lossy(&norm).into_owned();
            if trailing_slash && url_path != "/" {
                url_path.push('/');
            }
            let (root, rel, _script_alias) = map_path(&cfg, vhost, &norm);
            let fs_path = root.join(&rel);
            let (mut scope, config_conditionals, htaccess_conditionals) =
                match evaluate_scope_for_path(&cfg, vhost, &fs_path, &url_path, &req, peer.ip()) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("vapached: .htaccess error: {e}");
                        let _ = write_ws_error(stream, &cfg, 500, b"access-file error");
                        return Ok(());
                    }
                };
            apply_scope_conditionals(
                &cfg,
                vhost,
                &mut scope,
                &config_conditionals,
                &htaccess_conditionals,
                &fs_path,
                &url_path,
                &req,
                peer.ip(),
            );

            // Apply rewrite rules before selecting the upstream.  A rule that
            // forbids, redirects or internally rewrites the upgrade must not be
            // skipped.  Only an unchanged request or an explicit proxy rewrite
            // is allowed to continue here; other outcomes fail closed.
            let rewrite_ctx = crate::rewrite::Context {
                url_path: &url_path,
                fs_path: &fs_path,
                docroot: &root,
                server_root: &cfg.server_root,
                query: &req.query,
                peer: peer.ip(),
                port: local_port,
                https: local_port == 443 || vhost.map(|v| v.ssl.engine).unwrap_or(cfg.ssl.engine),
                server_name: &server_name_for_public(&cfg, &req, local_port),
            };
            let mut rewritten_target = None;
            match crate::rewrite::process(&scope, &req, &rewrite_ctx) {
                crate::rewrite::Outcome::None => {}
                crate::rewrite::Outcome::Forbidden => {
                    let _ = write_ws_error(stream, &cfg, 403, b"forbidden");
                    return Ok(());
                }
                crate::rewrite::Outcome::Gone => {
                    let _ = write_ws_error(stream, &cfg, 410, b"gone");
                    return Ok(());
                }
                crate::rewrite::Outcome::Error(e) => {
                    eprintln!("vapached: websocket rewrite error: {e}");
                    let _ = write_ws_error(stream, &cfg, 500, b"rewrite error");
                    return Ok(());
                }
                crate::rewrite::Outcome::Redirect { .. } => {
                    let _ = write_ws_error(stream, &cfg, 403, b"upgrade redirect unsupported");
                    return Ok(());
                }
                crate::rewrite::Outcome::Internal { .. } => {
                    let _ = write_ws_error(stream, &cfg, 403, b"upgrade rewrite unsupported");
                    return Ok(());
                }
                crate::rewrite::Outcome::Proxy { url, effects } => {
                    apply_rewrite_effects(&mut scope, &effects);
                    match proxy::target_from_url(&cfg, &scope, &url, &req) {
                        Some(target) => rewritten_target = Some(target),
                        None => {
                            let _ = write_ws_error(stream, &cfg, 502, b"bad proxy target");
                            return Ok(());
                        }
                    }
                }
            }

            let ws_target = rewritten_target
                .or_else(|| proxy::match_target_req(&cfg, &scope, &url_path, Some(&req)));
            if let Some(target) = ws_target {
                cfg.apply_proxy_access(vhost, &mut scope, &target.proxy_url, &req, peer.ip());
                if let Some(mut resp) = helper_method_not_allowed(
                    &cfg,
                    vhost,
                    &scope,
                    &req,
                    &url_path,
                    local_port,
                    &server_name_for_public(&cfg, &req, local_port),
                    peer.ip(),
                    &local_ip,
                ) {
                    let _ = write_ws_response(stream, &cfg, &mut resp);
                    return Ok(());
                }
                let mut resource = access::ResourceKey::request(
                    vhost,
                    &req,
                    &url_path,
                    Some(&fs_path),
                    Some(target.proxy_url.as_str()),
                );
                let _grant = match helper_access_response(
                    &cfg,
                    vhost,
                    &scope,
                    &req,
                    &url_path,
                    local_port,
                    &server_name_for_public(&cfg, &req, local_port),
                    peer.ip(),
                    &local_ip,
                    &mut resource,
                ) {
                    Ok(grant) => grant,
                    Err(mut resp) => {
                        let _ = write_ws_response(stream, &cfg, &mut resp);
                        return Ok(());
                    }
                };
                if let Some((tls, handle)) = stream.take_tls_stream() {
                    let result = handle.block_on(proxy::websocket_async(
                        &cfg, &scope, &req, &target, &_grant, &resource, tls, peer, true, host,
                        &buf,
                    ));
                    if result.is_err() {
                        // The TLS stream has been consumed by the tunnel;
                        // there is no safe way to inject a response here.
                        return Ok(());
                    }
                    return Ok(());
                }
                if let Some(mut client) = stream.try_clone_tcp() {
                    client.set_nonblocking(true)?;
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_io()
                        .enable_time()
                        .build()?;
                    let cfg_ref = cfg;
                    let scope_ref = &scope;
                    let req_ref = &req;
                    let target_ref = &target;
                    let buf_ref = &buf;
                    let result = rt.block_on(async move {
                        let tcp = tokio::net::TcpStream::from_std(client)?;
                        proxy::websocket_async(
                            cfg_ref, scope_ref, req_ref, target_ref, &_grant, &resource, tcp, peer,
                            false, host, buf_ref,
                        )
                        .await
                    });
                    if let Err(_) = result {
                        let _ = write_ws_error(stream, &cfg, 502, b"WebSocket upstream failed");
                    }
                    return Ok(());
                }
                let _ = write_ws_error(stream, &cfg, 501, b"WebSocket transport is not supported");
                return Ok(());
            }
        }

        let mut resp = dispatch(&cfg, &req, peer, &local_ip, local_port);
        let keep_alive = cfg.keep_alive
            && req.keep_alive
            && (cfg.max_keep_alive_requests == 0 || served + 1 < cfg.max_keep_alive_requests);
        let mut opts = ResponseOptions {
            server_header: &cfg.server_header(),
            keep_alive,
            head_only: req.is_head(),
            protocol: req.version,
            request_keep_alive: req.keep_alive,
        };
        if !keep_alive {
            opts.keep_alive = false;
        }
        let body_sent = write_response(stream, &mut resp, &opts).unwrap_or(0);
        crate::status::hit(body_sent);
        if logger.wants_access_log() {
            let host = host_header(&req).unwrap_or("");
            let server_name = server_name_for(&cfg, &req, local_port);
            let vhost_idx = cfg
                .select_vhost(local_port, if host.is_empty() { None } else { Some(host) })
                .and_then(|v| cfg.vhosts.iter().position(|x| std::ptr::eq(x, v)));
            let uri = String::from_utf8_lossy(&req.target);
            logger.access(&AccessEntry {
                remote_ip: &remote_ip,
                remote_port: peer.port(),
                local_ip,
                local_port,
                server_name: &server_name,
                method: &req.method,
                uri: &uri,
                protocol: req.version.as_str(),
                status: resp.status,
                bytes_sent: body_sent,
                bytes_in,
                referer: req.header_str("referer").unwrap_or(""),
                user_agent: req.header_str("user-agent").unwrap_or(""),
                host,
                vhost_index: vhost_idx,
                started,
            });
        }
        served += 1;
        if !keep_alive {
            return Ok(());
        }
        if served == 1 {
            stream.set_read_timeout(Some(cfg.keep_alive_timeout));
        }
    }
}

/// Blocking adapter for an async TLS stream.  Every read/write is bounded by
/// a timeout so an idle TLS client cannot pin one of the server's connection
/// threads forever.  The adapter runs on a `spawn_blocking` thread, so a
/// nested `Handle::block_on` is safe and is the same mechanism `SyncIoBridge`
/// uses internally.
struct TlsH1 {
    stream: Option<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>,
    handle: tokio::runtime::Handle,
    read_timeout: Duration,
}

impl TlsH1 {
    fn new(
        stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            stream: Some(stream),
            handle,
            read_timeout: Duration::from_secs(20),
        }
    }
}

impl Read for TlsH1 {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let handle = self.handle.clone();
        let timeout = self.read_timeout;
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "TLS stream closed"))?;
        handle.block_on(async move {
            match tokio::time::timeout(timeout, stream.read(buf)).await {
                Ok(r) => r,
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "TLS read timeout")),
            }
        })
    }
}

impl Write for TlsH1 {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let handle = self.handle.clone();
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "TLS stream closed"))?;
        handle.block_on(async move {
            match tokio::time::timeout(Duration::from_secs(30), stream.write(buf)).await {
                Ok(r) => r,
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "TLS write timeout")),
            }
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        let handle = self.handle.clone();
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "TLS stream closed"))?;
        handle.block_on(async move {
            match tokio::time::timeout(Duration::from_secs(30), stream.flush()).await {
                Ok(r) => r,
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "TLS flush timeout")),
            }
        })
    }
}

impl Conn for TlsH1 {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        if let Some(timeout) = timeout {
            self.read_timeout = timeout;
        }
    }

    fn take_tls_stream(
        &mut self,
    ) -> Option<(
        tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        tokio::runtime::Handle,
    )> {
        self.stream.take().map(|s| (s, self.handle.clone()))
    }
}
impl ResponseWrite for TlsH1 {}

fn handle_tls_connection(
    cfg: Arc<Config>,
    logger: Arc<Logger>,
    stream: TcpStream,
    peer: SocketAddr,
    local_ip: String,
    local_port: u16,
    tls_config: Arc<rustls::ServerConfig>,
) -> io::Result<()> {
    stream.set_nodelay(true).ok();
    stream.set_nonblocking(true)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    rt.block_on(async move {
        let tcp = tokio::net::TcpStream::from_std(stream)?;
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
        let tls = tokio::time::timeout(Duration::from_secs(20), acceptor.accept(tcp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;
        let alpn = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
        if alpn.as_deref() == Some(b"h2") {
            return crate::h2::serve(cfg, logger, tls, peer, local_ip, local_port).await;
        }
        let bridge = TlsH1::new(tls, tokio::runtime::Handle::current());
        tokio::task::spawn_blocking(move || {
            let mut bridge = bridge;
            handle_connection(&cfg, &logger, &mut bridge, peer, &local_ip, local_port)
        })
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
    })
}

fn error_body(e: &ParseError) -> String {
    let status = e.status();
    format!(
        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>{status} {}</title>\n</head><body>\n<h1>{}</h1>\n<p>{}</p>\n</body></html>\n",
        crate::http::reason_phrase(status),
        crate::http::reason_phrase(status),
        crate::util::html_escape(e.message().as_bytes())
    )
}

fn host_header(req: &Request) -> Option<&str> {
    req.header_str("host").and_then(|h| {
        let t = h.trim();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    })
}

fn allowed_methods(cfg: &Config) -> Vec<&'static str> {
    let mut methods = vec!["GET", "HEAD", "POST", "OPTIONS"];
    if cfg.trace_enable {
        methods.push("TRACE");
    }
    methods
}

fn allow_header(cfg: &Config) -> String {
    allowed_methods(cfg).join(", ")
}

fn options_response(cfg: &Config, mime: Option<String>) -> Response {
    let mut r = Response::new(200);
    r.headers
        .push(("Allow".into(), allow_header(cfg).into_bytes()));
    r.headers.push(("Content-Length".into(), b"0".to_vec()));
    if let Some(mime) = mime {
        r.headers.push(("Content-Type".into(), mime.into_bytes()));
    }
    r
}

fn helper_method_not_allowed(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    req: &Request,
    url_path: &str,
    local_port: u16,
    server_name: &str,
    peer: std::net::IpAddr,
    local_ip: &str,
) -> Option<Response> {
    if scope.method_allowed(&req.method) {
        return None;
    }
    let mut r = error_response(
        cfg,
        vhost,
        scope,
        405,
        req,
        url_path,
        local_port,
        server_name,
        peer,
        local_ip,
    );
    if let Some(allow) = scope.allow_methods_header() {
        r.headers.push(("Allow".into(), allow.into_bytes()));
    }
    Some(r)
}

fn helper_access_response(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    req: &Request,
    url_path: &str,
    local_port: u16,
    server_name: &str,
    peer: std::net::IpAddr,
    local_ip: &str,
    resource: &mut access::ResourceKey,
) -> Result<access::AccessGrant, Response> {
    let mut access = access::check(scope, req, peer, None);
    if access == Access::AuthRequired {
        if let Some(identity) = crate::auth::authenticate(scope, req) {
            resource.identity = Some(identity.user.clone());
            access = access::check(scope, req, peer, Some(&identity));
            if access == Access::AuthRequired {
                access = Access::Denied;
            }
        }
    }
    match access {
        Access::Allowed => {
            Ok(access::grant_if_allowed(access, resource.clone()).expect("allowed grant"))
        }
        Access::Denied => Err(error_response(
            cfg,
            vhost,
            scope,
            403,
            req,
            url_path,
            local_port,
            server_name,
            peer,
            local_ip,
        )),
        Access::AuthRequired => {
            let mut r = error_response(
                cfg,
                vhost,
                scope,
                401,
                req,
                url_path,
                local_port,
                server_name,
                peer,
                local_ip,
            );
            let realm: String = scope
                .authorization
                .auth_name
                .as_deref()
                .unwrap_or("Restricted")
                .chars()
                .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
                .collect();
            r.headers.push((
                "WWW-Authenticate".into(),
                format!("Basic realm=\"{realm}\"").into_bytes(),
            ));
            Err(r)
        }
    }
}

fn absolute_url_scheme(
    req: &Request,
    path: &str,
    server_name: &str,
    port: u16,
    https: bool,
) -> String {
    let authority = req
        .header_str("host")
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            if (!https && port == 80) || (https && port == 443) {
                server_name.to_string()
            } else {
                format!("{server_name}:{port}")
            }
        });
    format!(
        "{}://{authority}{path}",
        if https { "https" } else { "http" }
    )
}

fn canonicalize_rewrite_path(path: &str) -> Option<String> {
    let trailing = path.len() > 1 && path.ends_with('/');
    let norm = normalize_uri_path(path.as_bytes())?;
    if !is_canonical_path(&norm) {
        return None;
    }
    let mut out = String::from_utf8_lossy(&norm).into_owned();
    if trailing && out != "/" {
        out.push('/');
    }
    Some(out)
}

fn strip_port(h: &str) -> &str {
    if let Some(rest) = h.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    if h.matches(':').count() == 1 {
        h.split(':').next().unwrap_or(h)
    } else {
        h
    }
}

fn server_name_for(cfg: &Config, req: &Request, port: u16) -> String {
    if let Some(v) = cfg.select_vhost(port, host_header(req)) {
        if let Some(n) = &v.server_name {
            return strip_port(n).to_string();
        }
    }
    if let Some(h) = host_header(req) {
        return strip_port(h).to_string();
    }
    cfg.server_name
        .clone()
        .unwrap_or_else(|| "localhost".to_string())
}

pub(crate) fn server_name_for_public(cfg: &Config, req: &Request, port: u16) -> String {
    server_name_for(cfg, req, port)
}

pub fn dispatch(
    cfg: &Config,
    req: &Request,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
) -> Response {
    let host = host_header(req).unwrap_or("");
    let path = String::from_utf8_lossy(&req.raw_path).into_owned();
    let vhost = cfg.select_vhost(local_port, if host.is_empty() { None } else { Some(host) });
    let https_for_cache =
        local_port == 443 || vhost.map(|v| v.ssl.engine).unwrap_or(cfg.ssl.engine);
    let server_name_for_cache = server_name_for(cfg, req, local_port);
    let cache_scope = crate::cache::request_scope(
        cfg,
        vhost,
        req,
        peer.ip(),
        &path,
        local_port,
        https_for_cache,
        &server_name_for_cache,
        host,
    );
    if let Some((scope, grant)) = &cache_scope {
        if let Some(resp) =
            crate::cache::lookup(cfg, vhost, req, host, &path, scope, peer.ip(), grant)
        {
            return resp;
        }
    }
    let mut resp = dispatch_inner(
        cfg,
        req,
        peer,
        local_ip,
        local_port,
        vhost,
        &server_name_for_cache,
    );
    if let Some((scope, grant)) = cache_scope {
        crate::cache::store(
            cfg,
            vhost,
            req,
            host,
            &path,
            &scope,
            peer.ip(),
            &mut resp,
            &grant,
        );
    }
    if !matches!(req.method.as_str(), "GET" | "HEAD" | "OPTIONS" | "TRACE") {
        crate::cache::invalidate(cfg, host, &path);
    }
    resp
}

/// Perform an internal subrequest (DirectoryIndex or a local ErrorDocument)
/// through the normal dispatcher so handlers, access rules and `.htaccess`
/// overrides are applied exactly as for a client request.
pub(crate) fn internal_dispatch(
    cfg: &Config,
    req: &Request,
    url: &str,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
) -> Response {
    let mut internal = req.clone();
    let mut target = url.to_string();
    if !internal.query.is_empty() {
        target.push('?');
        target.push_str(&String::from_utf8_lossy(&internal.query));
    }
    internal.target = target.into_bytes();
    internal.raw_path = url.as_bytes().to_vec();
    internal.body.clear();
    internal.body_spool = None;
    internal.framing = crate::verified::BodyFraming::None;
    internal.expect_continue = false;
    internal.headers.remove("content-length");
    internal.headers.remove("transfer-encoding");
    internal.headers.remove("expect");
    let host = host_header(&internal).unwrap_or("");
    let vhost = cfg.select_vhost(local_port, if host.is_empty() { None } else { Some(host) });
    let server_name = server_name_for(cfg, &internal, local_port);
    dispatch_inner(
        cfg,
        &internal,
        peer,
        local_ip,
        local_port,
        vhost,
        &server_name,
    )
}

/// Evaluate the full configuration/access-file scope for one filesystem and
/// URL path.  Used by the upgrade path and after a rewrite selects a different
/// filesystem target, so both see the same policy as ordinary dispatch.
fn evaluate_scope_for_path(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    url_path: &str,
    req: &Request,
    peer: IpAddr,
) -> Result<
    (
        Scope,
        Vec<crate::config::ScopeRule>,
        Vec<crate::config::ScopeRule>,
    ),
    String,
> {
    if cfg.htaccess_may_apply(fs_path) {
        let layers = crate::htaccess::collect_layers(cfg, vhost, fs_path, url_path)?;
        Ok(crate::policy_ref::effective_scope_with_layers(
            cfg, vhost, fs_path, url_path, req, peer, &layers,
        ))
    } else {
        let (scope, conditionals) =
            cfg.effective_scope_req_cached(vhost, fs_path, url_path, req, peer);
        Ok((scope, conditionals.as_ref().clone(), Vec::new()))
    }
}

/// Re-authorize a resolved file/directory target and bind the grant to the
/// opened inode.  If the descriptor resolves to a different path (symlink),
/// re-evaluate Directory/Files/.htaccess policy for that path before binding.
#[allow(clippy::too_many_arguments)]
fn bind_target_grant(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    grant: &access::AccessGrant,
    fs_path: &Path,
    actual_path: &Path,
    meta: &std::fs::Metadata,
    url_path: &str,
    req: &Request,
    peer: IpAddr,
    local_port: u16,
    server_name: &str,
    local_ip: &str,
    rewrite_effects: &crate::rewrite::Effects,
) -> Result<(access::AccessGrant, access::ResourceKey, Scope), Response> {
    if actual_path == fs_path {
        let mut key = access::ResourceKey::request(vhost, req, url_path, Some(actual_path), None);
        key.identity = grant.key().identity.clone();
        return match grant.bind_file(&key, meta) {
            Some(bound) => {
                let key = bound.key().clone();
                Ok((bound, key, scope.clone()))
            }
            None => Err(error_response(
                cfg,
                vhost,
                scope,
                500,
                req,
                url_path,
                local_port,
                server_name,
                peer,
                local_ip,
            )),
        };
    }

    let (mut target_scope, config_conditionals, htaccess_conditionals) =
        match evaluate_scope_for_path(cfg, vhost, actual_path, url_path, req, peer) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("vapached: target scope error: {e}");
                return Err(error_response(
                    cfg,
                    vhost,
                    scope,
                    500,
                    req,
                    url_path,
                    local_port,
                    server_name,
                    peer,
                    local_ip,
                ));
            }
        };
    apply_rewrite_effects(&mut target_scope, rewrite_effects);
    apply_scope_conditionals(
        cfg,
        vhost,
        &mut target_scope,
        &config_conditionals,
        &htaccess_conditionals,
        actual_path,
        url_path,
        req,
        peer,
    );
    let mut key = access::ResourceKey::request(vhost, req, url_path, Some(actual_path), None);
    let target_grant = match helper_access_response(
        cfg,
        vhost,
        &target_scope,
        req,
        url_path,
        local_port,
        server_name,
        peer,
        local_ip,
        &mut key,
    ) {
        Ok(g) => g,
        Err(r) => return Err(r),
    };
    match target_grant.bind_file(&key, meta) {
        Some(bound) => {
            let key = bound.key().clone();
            Ok((bound, key, target_scope))
        }
        None => Err(error_response(
            cfg,
            vhost,
            scope,
            500,
            req,
            url_path,
            local_port,
            server_name,
            peer,
            local_ip,
        )),
    }
}

fn apply_scope_conditionals(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &mut Scope,
    config_conditionals: &[crate::config::ScopeRule],
    htaccess_conditionals: &[crate::config::ScopeRule],
    fs_path: &Path,
    url_path: &str,
    req: &Request,
    peer: IpAddr,
) {
    let fname = fs_path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();
    let docroot = cfg.documentation_root_for(vhost);
    let mut state = std::collections::HashMap::new();
    crate::config::apply_deferred_req(
        scope,
        config_conditionals,
        req,
        peer,
        &docroot,
        fs_path,
        url_path,
        &fname,
        &mut state,
    );
    let mut state = std::collections::HashMap::new();
    crate::config::apply_deferred_req(
        scope,
        htaccess_conditionals,
        req,
        peer,
        &docroot,
        fs_path,
        url_path,
        &fname,
        &mut state,
    );
}

fn dispatch_inner(
    cfg: &Config,
    req: &Request,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
    vhost: Option<&VHost>,
    server_name: &str,
) -> Response {
    // Methods we do not implement at all are 501, matching Apache.  Known
    // methods that are invalid for a particular resource (for example POST
    // to a static file) are handled below with 405.
    const KNOWN_METHODS: &[&str] = &[
        "GET", "HEAD", "POST", "OPTIONS", "TRACE", "PUT", "DELETE", "CONNECT", "PATCH",
    ];
    if !KNOWN_METHODS.contains(&req.method.as_str()) {
        let mut r = error_response(
            cfg,
            vhost,
            &vhost.map(|v| &v.scope).unwrap_or(&cfg.global),
            501,
            req,
            &String::from_utf8_lossy(&req.raw_path),
            local_port,
            &server_name,
            peer.ip(),
            local_ip,
        );
        r.headers
            .push(("Allow".into(), allow_header(cfg).into_bytes()));
        return r;
    }

    if req.method == "TRACE" {
        if !cfg.trace_enable {
            let mut r = error_response(
                cfg,
                vhost,
                &vhost.map(|v| &v.scope).unwrap_or(&cfg.global),
                405,
                req,
                &String::from_utf8_lossy(&req.raw_path),
                local_port,
                &server_name,
                peer.ip(),
                local_ip,
            );
            r.headers
                .push(("Allow".into(), allow_header(cfg).into_bytes()));
            return r;
        }
        let mut body = format!("TRACE / {} HTTP/1.1\r\n", req.method);
        for (n, v) in req.headers.iter() {
            body.push_str(&format!("{}: {}\r\n", n, String::from_utf8_lossy(v)));
        }
        body.push_str("\r\n");
        return Response::bytes(200, "message/http", body.into_bytes());
    }

    let base_scope = vhost.map(|v| &v.scope).unwrap_or(&cfg.global);

    // `OPTIONS *` is server-wide and does not resolve a path.  Resource
    // OPTIONS requests continue through access control and path mapping so
    // they cannot bypass a Require rule or report the wrong media type.
    if req.method == "OPTIONS" && req.raw_path == b"*" {
        return options_response(cfg, None);
    }

    // Decode and canonicalize the path.  Borrow the request bytes for the
    // common case instead of cloning the raw path on every request.
    let raw_path: &[u8] = if req.raw_path == b"*" {
        b"/"
    } else {
        &req.raw_path
    };
    let allow_encoded = cfg.encoded_slashes == EncodedSlashes::On;
    let decoded = match percent_decode_path(raw_path, allow_encoded) {
        Some(d) => d,
        None => {
            return error_response(
                cfg,
                vhost,
                base_scope,
                404,
                req,
                &String::from_utf8_lossy(raw_path),
                local_port,
                &server_name,
                peer.ip(),
                local_ip,
            )
        }
    };
    let trailing_slash = decoded.len() > 1 && decoded.ends_with(b"/");
    let norm = match normalize_uri_path(&decoded) {
        Some(n) if is_canonical_path(&n) => n,
        _ => {
            return error_response(
                cfg,
                vhost,
                base_scope,
                400,
                req,
                &String::from_utf8_lossy(raw_path),
                local_port,
                &server_name,
                peer.ip(),
                local_ip,
            )
        }
    };
    let mut url_path = String::from_utf8_lossy(&norm).into_owned();
    if trailing_slash && url_path != "/" {
        url_path.push('/');
    }

    // Rewrites may change the URL, so resolve the target and its override
    // scope first, then restart resolution with the rewritten path.  A hard
    // limit prevents pathological rewrite loops from consuming a worker.
    let mut owned_req: Option<Request> = None;
    let mut norm = norm;
    let mut rewrite_rounds = 0usize;
    let mut stop_rewriting = false;
    let mut rewrite_effects = crate::rewrite::Effects::default();
    let mut rewrite_filesystem: Option<PathBuf> = None;
    let https = local_port == 443 || vhost.map(|v| v.ssl.engine).unwrap_or(cfg.ssl.engine);
    let (mut root, mut rel, mut script_alias);
    let mut fs_path;
    let mut scope;
    loop {
        (root, rel, script_alias) = map_path(cfg, vhost, &norm);
        fs_path = root.join(&rel);
        let mut config_files = Vec::new();
        let mut config_locations = Vec::new();
        let mut config_conditionals = Vec::new();
        let mut cached_conditionals = None;
        let mut htaccess_files = Vec::new();
        let mut htaccess_conditionals = Vec::new();
        if cfg.htaccess_may_apply(&fs_path) {
            let layers = match crate::htaccess::collect_layers(cfg, vhost, &fs_path, &url_path) {
                Ok(layers) => layers,
                Err(e) => {
                    eprintln!("vapached: .htaccess error: {e}");
                    return error_response(
                        cfg,
                        vhost,
                        &vhost.map(|v| &v.scope).unwrap_or(&cfg.global),
                        500,
                        owned_req.as_ref().unwrap_or(req),
                        &url_path,
                        local_port,
                        &server_name,
                        peer.ip(),
                        local_ip,
                    );
                }
            };
            let (evaluated, conditionals, access_conditionals) =
                crate::policy_ref::effective_scope_with_layers(
                    cfg,
                    vhost,
                    &fs_path,
                    &url_path,
                    req,
                    peer.ip(),
                    &layers,
                );
            scope = evaluated;
            config_conditionals = conditionals;
            htaccess_conditionals = access_conditionals;
        } else {
            let (cached_scope, conditionals) =
                cfg.effective_scope_req_cached(vhost, &fs_path, &url_path, req, peer.ip());
            scope = cached_scope;
            cached_conditionals = Some(conditionals);
        }
        apply_rewrite_effects(&mut scope, &rewrite_effects);
        let cond_fname = fs_path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        let cond_docroot = cfg.documentation_root_for(vhost);
        crate::config::apply_normal_rule_list(
            &config_files,
            &mut scope,
            req,
            peer.ip(),
            &cond_docroot,
            &fs_path,
            &url_path,
            &cond_fname,
            &mut config_conditionals,
        );
        crate::config::apply_normal_rule_list(
            &htaccess_files,
            &mut scope,
            req,
            peer.ip(),
            &cond_docroot,
            &fs_path,
            &url_path,
            &cond_fname,
            &mut htaccess_conditionals,
        );
        crate::config::apply_normal_rule_list(
            &config_locations,
            &mut scope,
            req,
            peer.ip(),
            &cond_docroot,
            &fs_path,
            &url_path,
            &cond_fname,
            &mut config_conditionals,
        );
        config_conditionals.sort_by_key(|rule| rule.order);
        let config_conditionals: &[crate::config::ScopeRule] = match &cached_conditionals {
            Some(conditionals) => conditionals.as_slice(),
            None => config_conditionals.as_slice(),
        };
        let mut cond_state = std::collections::HashMap::new();
        crate::config::apply_deferred_req(
            &mut scope,
            config_conditionals,
            req,
            peer.ip(),
            &cond_docroot,
            &fs_path,
            &url_path,
            &cond_fname,
            &mut cond_state,
        );
        let mut htaccess_state = std::collections::HashMap::new();
        crate::config::apply_deferred_req(
            &mut scope,
            &htaccess_conditionals,
            req,
            peer.ip(),
            &cond_docroot,
            &fs_path,
            &url_path,
            &cond_fname,
            &mut htaccess_state,
        );
        if stop_rewriting {
            break;
        }
        let current_req = owned_req.as_ref().unwrap_or(req);
        let rewrite_ctx = crate::rewrite::Context {
            url_path: &url_path,
            fs_path: &fs_path,
            docroot: &root,
            server_root: &cfg.server_root,
            query: &current_req.query,
            peer: peer.ip(),
            port: local_port,
            https,
            server_name: &server_name,
        };
        match crate::rewrite::process(&scope, current_req, &rewrite_ctx) {
            crate::rewrite::Outcome::None => break,
            crate::rewrite::Outcome::Forbidden => {
                return error_response(
                    cfg,
                    vhost,
                    &scope,
                    403,
                    current_req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                )
            }
            crate::rewrite::Outcome::Gone => {
                return error_response(
                    cfg,
                    vhost,
                    &scope,
                    410,
                    current_req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                )
            }
            crate::rewrite::Outcome::Error(e) => {
                eprintln!("vapached: rewrite error: {e}");
                return error_response(
                    cfg,
                    vhost,
                    &scope,
                    500,
                    current_req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                );
            }
            crate::rewrite::Outcome::Proxy { url, effects } => {
                apply_rewrite_effects(&mut scope, &effects);
                let (url_path_part, query) = match url.split_once('?') {
                    Some((path, query)) => (path, query),
                    None => (url.as_str(), ""),
                };
                let Some(target) = proxy::target_from_url(cfg, &scope, url_path_part, current_req)
                else {
                    return error_response(
                        cfg,
                        vhost,
                        &scope,
                        502,
                        current_req,
                        &url_path,
                        local_port,
                        &server_name,
                        peer.ip(),
                        local_ip,
                    );
                };
                cfg.apply_proxy_access(
                    vhost,
                    &mut scope,
                    &target.proxy_url,
                    current_req,
                    peer.ip(),
                );
                if let Some(r) = helper_method_not_allowed(
                    cfg,
                    vhost,
                    &scope,
                    current_req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                ) {
                    return r;
                }
                let mut resource = access::ResourceKey::request(
                    vhost,
                    current_req,
                    &url_path,
                    None,
                    Some(target.proxy_url.as_str()),
                );
                let _grant = match helper_access_response(
                    cfg,
                    vhost,
                    &scope,
                    current_req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                    &mut resource,
                ) {
                    Ok(grant) => grant,
                    Err(r) => return r,
                };
                let mut proxy_req = current_req.clone();
                proxy_req.query = query.as_bytes().to_vec();
                return proxy::execute(
                    cfg,
                    vhost,
                    &scope,
                    &proxy_req,
                    url_path_part,
                    &target,
                    peer,
                    local_port,
                    https,
                    &server_name,
                    local_ip,
                    &_grant,
                    &resource,
                );
            }
            crate::rewrite::Outcome::Redirect {
                status,
                location,
                effects,
            } => {
                rewrite_effects.merge(effects);
                apply_rewrite_effects(&mut scope, &rewrite_effects);
                let location = if location.starts_with("//") {
                    format!("{}:{}", if https { "https" } else { "http" }, location)
                } else if location.starts_with('/') {
                    absolute_url_scheme(current_req, &location, &server_name, local_port, https)
                } else {
                    location
                };
                let mut r = simple_html(
                    status,
                    &format!("The document has moved to {location}"),
                    Some(&location),
                );
                if current_req.method == "HEAD" {
                    r.body = Body::Empty;
                }
                crate::compression::finalize(&scope, current_req, &mut r, url_path.as_bytes());
                return r;
            }
            crate::rewrite::Outcome::Internal {
                path,
                query,
                final_pass,
                effects,
                filesystem,
            } => {
                if filesystem.is_some() {
                    rewrite_filesystem = filesystem;
                }
                rewrite_effects.merge(effects);
                rewrite_rounds += 1;
                if rewrite_rounds > 10 {
                    return error_response(
                        cfg,
                        vhost,
                        &scope,
                        500,
                        current_req,
                        &url_path,
                        local_port,
                        &server_name,
                        peer.ip(),
                        local_ip,
                    );
                }
                let Some(canonical) = canonicalize_rewrite_path(&path) else {
                    return error_response(
                        cfg,
                        vhost,
                        &scope,
                        400,
                        current_req,
                        &url_path,
                        local_port,
                        &server_name,
                        peer.ip(),
                        local_ip,
                    );
                };
                if canonical == url_path && query == current_req.query {
                    break;
                }
                if query != current_req.query {
                    let mut r = current_req.clone();
                    r.query = query;
                    owned_req = Some(r);
                }
                url_path = canonical;
                norm = url_path.as_bytes().to_vec();
                stop_rewriting = final_pass;
            }
        }
    }
    let req: &Request = owned_req.as_ref().unwrap_or(req);
    apply_rewrite_effects(&mut scope, &rewrite_effects);
    if let Some(filesystem) = rewrite_filesystem {
        root = filesystem
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/"));
        rel = PathBuf::from(
            filesystem
                .file_name()
                .map(|n| n.to_os_string())
                .unwrap_or_default(),
        );
        fs_path = root.join(&rel);
        // The rewrite changed the filesystem target after the scope was
        // evaluated for the URL mapping.  Re-evaluate against the target so
        // <Directory>, <Files> and target .htaccess policy cannot be skipped.
        match evaluate_scope_for_path(cfg, vhost, &fs_path, &url_path, req, peer.ip()) {
            Ok((mut target_scope, config_conditionals, htaccess_conditionals)) => {
                apply_rewrite_effects(&mut target_scope, &rewrite_effects);
                apply_scope_conditionals(
                    cfg,
                    vhost,
                    &mut target_scope,
                    &config_conditionals,
                    &htaccess_conditionals,
                    &fs_path,
                    &url_path,
                    req,
                    peer.ip(),
                );
                scope = target_scope;
            }
            Err(e) => {
                eprintln!("vapached: target scope error after rewrite: {e}");
                return error_response(
                    cfg,
                    vhost,
                    &scope,
                    500,
                    req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                );
            }
        }
    }

    // Redirects are evaluated after rewrites but before access control and
    // filesystem mapping, matching Apache's URL translation order.
    if let Some(red) = match_redirect(&scope, &url_path) {
        let suffix = if red.from.ends_with('/') {
            &url_path[red.from.len()..]
        } else if url_path.len() > red.from.len() {
            &url_path[red.from.len()..]
        } else {
            ""
        };
        let loc = format!("{}{}", red.to, suffix);
        let loc = if loc.starts_with('/') {
            absolute_url_scheme(req, &loc, &server_name, local_port, https)
        } else {
            loc
        };
        let mut r = simple_html(
            red.status,
            &format!("The document has moved to {loc}"),
            Some(&loc),
        );
        if req.method == "HEAD" {
            r.body = Body::Empty;
        }
        crate::compression::finalize(&scope, req, &mut r, url_path.as_bytes());
        return r;
    }

    let proxy_target = proxy::match_target_req(cfg, &scope, &url_path, Some(req));
    if let Some(target) = &proxy_target {
        cfg.apply_proxy_access(vhost, &mut scope, &target.proxy_url, req, peer.ip());
    }

    if let Some(r) = helper_method_not_allowed(
        cfg,
        vhost,
        &scope,
        req,
        &url_path,
        local_port,
        &server_name,
        peer.ip(),
        local_ip,
    ) {
        return r;
    }
    let mut resource = access::ResourceKey::request(
        vhost,
        req,
        &url_path,
        Some(&fs_path),
        proxy_target.as_ref().map(|t| t.proxy_url.as_str()),
    );
    let grant = match helper_access_response(
        cfg,
        vhost,
        &scope,
        req,
        &url_path,
        local_port,
        &server_name,
        peer.ip(),
        local_ip,
        &mut resource,
    ) {
        Ok(grant) => grant,
        Err(r) => return r,
    };

    if scope
        .mapping_policy
        .handlers
        .iter()
        .any(|h| h.handler.eq_ignore_ascii_case("server-status"))
    {
        let auto = req.query.eq_ignore_ascii_case(b"auto");
        return crate::status::response(auto);
    }

    if let Some(target) = fastcgi::match_proxy(&scope, &url_path, &root) {
        return run_fastcgi(
            cfg,
            vhost,
            req,
            &url_path,
            &server_name,
            peer,
            local_ip,
            local_port,
            &scope,
            &target,
            &grant,
            &resource,
        );
    }

    if let Some(target) = proxy_target {
        return proxy::execute(
            cfg,
            vhost,
            &scope,
            req,
            &url_path,
            &target,
            peer,
            local_port,
            https,
            &server_name,
            local_ip,
            &grant,
            &resource,
        );
    }
    if proxy::balancer_unavailable(cfg, &scope, &url_path) {
        return error_response(
            cfg,
            vhost,
            &scope,
            503,
            req,
            &url_path,
            local_port,
            &server_name,
            peer.ip(),
            local_ip,
        );
    }

    let follow = scope.effective_options().contains(Options::FOLLOW_SYMLINKS)
        || scope
            .effective_options()
            .contains(Options::SYMLINKS_IF_OWNER_MATCH);

    match resolve_target(&root, &rel, follow) {
        Target::File { file, meta } => {
            let name = rel.file_name().map(|n| n.as_encoded_bytes()).unwrap_or(b"");
            if req.method == "OPTIONS" {
                return options_response(cfg, mime_type(cfg, &scope, name));
            }
            if !scope.mapping_policy.unsupported_filters.is_empty() {
                eprintln!(
                    "vapached: unsupported output filter(s) {:?} for {}",
                    scope.mapping_policy.unsupported_filters, url_path
                );
                return error_response(
                    cfg,
                    vhost,
                    &scope,
                    500,
                    req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                );
            }
            if let Some(target) = fastcgi::handler_target(&scope, &root, &rel, &url_path) {
                return run_fastcgi(
                    cfg,
                    vhost,
                    req,
                    &url_path,
                    &server_name,
                    peer,
                    local_ip,
                    local_port,
                    &scope,
                    &target,
                    &grant,
                    &resource,
                );
            }
            if cgi::is_cgi(cfg, &scope, name, script_alias) {
                return run_cgi(
                    cfg,
                    vhost,
                    req,
                    &root,
                    &rel,
                    &url_path,
                    "",
                    &url_path,
                    &server_name,
                    peer,
                    local_ip,
                    local_port,
                    &scope,
                    &grant,
                    &resource,
                    Some(&file),
                    Some(&meta),
                );
            }
            if let Some(handler) = crate::config::effective_handler(&scope, name) {
                let handler = handler.trim();
                if !handler.is_empty()
                    && !handler.eq_ignore_ascii_case("default-handler")
                    && !handler.eq_ignore_ascii_case("none")
                {
                    eprintln!(
                        "vapached: unsupported handler '{}' for {}",
                        handler, url_path
                    );
                    return error_response(
                        cfg,
                        vhost,
                        &scope,
                        500,
                        req,
                        &url_path,
                        local_port,
                        &server_name,
                        peer.ip(),
                        local_ip,
                    );
                }
            }
            if !matches!(req.method.as_str(), "GET" | "HEAD") {
                let mut r = error_response(
                    cfg,
                    vhost,
                    &scope,
                    405,
                    req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                );
                r.headers
                    .push(("Allow".into(), b"GET, HEAD, OPTIONS".to_vec()));
                return r;
            }
            let actual_path = crate::files::fd_path(&file).unwrap_or_else(|| fs_path.clone());
            let (target_grant, target_resource, target_scope) = match bind_target_grant(
                cfg,
                vhost,
                &scope,
                &grant,
                &fs_path,
                &actual_path,
                &meta,
                &url_path,
                req,
                peer.ip(),
                local_port,
                &server_name,
                local_ip,
                &rewrite_effects,
            ) {
                Ok(v) => v,
                Err(r) => return r,
            };
            serve_file(
                cfg,
                &target_scope,
                req,
                file,
                &meta,
                &actual_path,
                name,
                peer.ip(),
                local_ip,
                &target_grant,
                &target_resource,
            )
        }
        Target::Directory { file, meta } => {
            if req.method == "OPTIONS" {
                return options_response(cfg, None);
            }
            if req.method != "GET" && req.method != "HEAD" {
                let mut r = error_response(
                    cfg,
                    vhost,
                    &scope,
                    405,
                    req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                );
                r.headers
                    .push(("Allow".into(), b"GET, HEAD, OPTIONS".to_vec()));
                return r;
            }
            if let Some(name) =
                directory_index_name(cfg, &scope, req, &file, &url_path, &req.raw_path)
            {
                let index_url = format!(
                    "{}/{}",
                    url_path.trim_end_matches('/'),
                    String::from_utf8_lossy(&name)
                );
                return internal_dispatch(cfg, req, &index_url, peer, local_ip, local_port);
            }
            let actual_path = crate::files::fd_path(&file).unwrap_or_else(|| fs_path.clone());
            let (target_grant, target_resource, target_scope) = match bind_target_grant(
                cfg,
                vhost,
                &scope,
                &grant,
                &fs_path,
                &actual_path,
                &meta,
                &url_path,
                req,
                peer.ip(),
                local_port,
                &server_name,
                local_ip,
                &rewrite_effects,
            ) {
                Ok(v) => v,
                Err(r) => return r,
            };
            serve_directory(
                cfg,
                vhost,
                &target_scope,
                req,
                file,
                &meta,
                &actual_path,
                &url_path,
                &req.raw_path,
                &server_name,
                local_port,
                peer.ip(),
                local_ip,
                &target_grant,
                &target_resource,
            )
        }
        Target::Forbidden => error_response(
            cfg,
            vhost,
            &scope,
            403,
            req,
            &url_path,
            local_port,
            &server_name,
            peer.ip(),
            local_ip,
        ),
        Target::NotFound => {
            if req.method == "OPTIONS" {
                return options_response(cfg, None);
            }
            // CGI PATH_INFO: try progressively shorter script names.
            let maybe_cgi = script_alias || cgi::is_cgi(cfg, &scope, norm.as_slice(), false);
            if maybe_cgi {
                if let Some(st) = cgi::find_script(&root, &rel, follow) {
                    let script_name = if st.path_info.is_empty() {
                        url_path.clone()
                    } else {
                        url_path
                            .strip_suffix(&st.path_info)
                            .unwrap_or(&url_path)
                            .to_string()
                    };
                    return run_cgi(
                        cfg,
                        vhost,
                        req,
                        &root,
                        &st.rel_script,
                        &url_path,
                        &st.path_info,
                        &script_name,
                        &server_name,
                        peer,
                        local_ip,
                        local_port,
                        &scope,
                        &grant,
                        &resource,
                        Some(&st.file),
                        Some(&st.meta),
                    );
                }
            }
            error_response(
                cfg,
                vhost,
                &scope,
                404,
                req,
                &url_path,
                local_port,
                &server_name,
                peer.ip(),
                local_ip,
            )
        }
    }
}

fn map_path(cfg: &Config, vhost: Option<&VHost>, norm: &[u8]) -> (PathBuf, PathBuf, bool) {
    let url = String::from_utf8_lossy(norm);
    let base_scope = vhost.map(|v| &v.scope).unwrap_or(&cfg.global);
    let mut best: Option<(&crate::config::Alias, usize)> = None;
    for a in &base_scope.mapping_policy.aliases {
        if let Some(rest) = alias_remainder(&a.virtual_path, &url) {
            if best.map(|(_, l)| a.virtual_path.len() > l).unwrap_or(true) {
                best = Some((a, a.virtual_path.len()));
            }
            let _ = rest;
        }
    }
    if let Some((a, _)) = best {
        let rest = alias_remainder(&a.virtual_path, &url).unwrap_or_default();
        let rel = PathBuf::from(rest.trim_start_matches('/'));
        return (a.fs_path.clone(), rel, a.script);
    }
    let root = cfg.documentation_root_for(vhost);
    let rel = PathBuf::from(OsStr::from_bytes(&norm[1..]));
    (root, rel, false)
}

fn alias_remainder(alias: &str, url: &str) -> Option<String> {
    if alias.ends_with('/') {
        if url.starts_with(alias) {
            return Some(url[alias.len()..].to_string());
        }
        // Apache also matches the alias directory without the trailing slash
        // so it can issue a redirect.
        let trimmed = alias.trim_end_matches('/');
        if url == trimmed {
            return Some(String::new());
        }
        return None;
    }
    if url == alias {
        Some(String::new())
    } else if let Some(rest) = url.strip_prefix(alias) {
        if rest.starts_with('/') {
            Some(rest.to_string())
        } else {
            None
        }
    } else {
        None
    }
}

fn match_redirect<'a>(scope: &'a Scope, url: &str) -> Option<&'a crate::config::Redirect> {
    let mut best: Option<&crate::config::Redirect> = None;
    for r in &scope.mapping_policy.redirects {
        let m = if r.from.ends_with('/') {
            url.starts_with(&r.from)
        } else {
            url == r.from || url.starts_with(&format!("{}/", r.from))
        };
        if m && best.map(|b| r.from.len() > b.from.len()).unwrap_or(true) {
            best = Some(r);
        }
    }
    best
}

#[allow(clippy::too_many_arguments)]
fn run_fastcgi(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    url_path: &str,
    server_name: &str,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
    scope: &Scope,
    target: &fastcgi::Target,
    grant: &crate::access::AccessGrant,
    resource: &crate::access::ResourceKey,
) -> Response {
    let binding = target.binding_key();
    let Some(bound) = grant.bind_backend(resource, binding.clone()) else {
        return error_response(
            cfg,
            vhost,
            scope,
            500,
            req,
            url_path,
            local_port,
            server_name,
            peer.ip(),
            local_ip,
        );
    };
    let mut expected = resource.clone();
    expected.backend_target = Some(binding);
    if !bound.require(&expected)
        || resource.fs_path.as_deref() != Some(target.script_filename.as_path())
    {
        return error_response(
            cfg,
            vhost,
            scope,
            500,
            req,
            url_path,
            local_port,
            server_name,
            peer.ip(),
            local_ip,
        );
    }
    let docroot = cfg.documentation_root_for(vhost);
    let ctx = CgiContext {
        cfg,
        vhost,
        req,
        root: &docroot,
        script_rel: Path::new(""),
        script_name: url_path,
        path_info: &target.path_info,
        docroot: &docroot,
        remote_ip: &peer.ip().to_string(),
        remote_port: peer.port(),
        local_ip,
        local_port,
        server_name,
        host: server_name,
        follow_symlinks: true,
        env: &scope.request_env(req),
        script_file: None,
    };
    fastcgi::execute(&ctx, scope, target)
}

#[allow(clippy::too_many_arguments)]
fn run_cgi(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    root: &Path,
    script_rel: &Path,
    _url_path: &str,
    path_info: &str,
    script_name: &str,
    server_name: &str,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
    scope: &Scope,
    grant: &crate::access::AccessGrant,
    resource: &crate::access::ResourceKey,
    script_file: Option<&std::fs::File>,
    script_meta: Option<&std::fs::Metadata>,
) -> Response {
    if !grant.require(resource) {
        return error_response(
            cfg,
            vhost,
            scope,
            500,
            req,
            script_name,
            local_port,
            server_name,
            peer.ip(),
            local_ip,
        );
    }
    if let (Some(_), Some(meta)) = (script_file, script_meta) {
        if grant.bind_file(resource, meta).is_none() {
            let _ = std::fs::write(
                "/tmp/vapache-cgi-debug",
                format!("bind fail resource={resource:?} grant={:?}\n", grant.key()),
            );
            return error_response(
                cfg,
                vhost,
                scope,
                500,
                req,
                script_name,
                local_port,
                server_name,
                peer.ip(),
                local_ip,
            );
        }
    }
    let follow = scope.effective_options().contains(Options::FOLLOW_SYMLINKS)
        || scope
            .effective_options()
            .contains(Options::SYMLINKS_IF_OWNER_MATCH);
    let docroot = cfg.documentation_root_for(vhost);
    let ctx = CgiContext {
        cfg,
        vhost,
        req,
        root,
        script_rel,
        script_name,
        path_info,
        docroot: &docroot,
        remote_ip: &peer.ip().to_string(),
        remote_port: peer.port(),
        local_ip,
        local_port,
        server_name,
        host: server_name,
        follow_symlinks: follow,
        env: &scope.request_env(req),
        script_file,
    };
    let mut r = cgi::execute(&ctx);
    crate::compression::finalize(scope, req, &mut r, script_name.as_bytes());
    r
}

fn apply_rewrite_effects(scope: &mut crate::config::Scope, effects: &crate::rewrite::Effects) {
    for (name, value) in &effects.env {
        scope.environment_policy.set_env.retain(|(n, _)| n != name);
        scope.environment_policy.unset_env.retain(|n| n != name);
        match value {
            Some(value) => scope
                .environment_policy
                .set_env
                .push((name.clone(), value.clone())),
            None => scope.environment_policy.unset_env.push(name.clone()),
        }
    }
    for name in &effects.vary {
        if !scope
            .header_policy
            .vary
            .iter()
            .any(|v| v.eq_ignore_ascii_case(name))
        {
            scope.header_policy.vary.push(name.clone());
        }
    }
    for cookie in &effects.cookies {
        if !scope.header_policy.cookies.contains(cookie) {
            scope.header_policy.cookies.push(cookie.clone());
        }
    }
    if let Some(handler) = &effects.handler {
        if !scope
            .mapping_policy
            .handlers
            .iter()
            .any(|h| h.ext == "*" && h.handler == *handler)
        {
            scope.mapping_policy.handlers.push(crate::config::Handler {
                ext: "*".into(),
                handler: handler.clone(),
            });
        }
    }
    if let Some(content_type) = &effects.content_type {
        scope.content_policy.force_type = Some(content_type.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_boundaries() {
        assert_eq!(
            alias_remainder("/icons/", "/icons/a.png"),
            Some("a.png".into())
        );
        assert_eq!(alias_remainder("/icons/", "/icons"), Some("".into()));
        assert_eq!(alias_remainder("/icons/", "/iconsx"), None);
        assert_eq!(alias_remainder("/foo", "/foo/bar"), Some("/bar".into()));
        assert_eq!(alias_remainder("/foo", "/foobar"), None);
    }
}
