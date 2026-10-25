//! Listener management and request dispatch.

use crate::access::{self, Access};
use crate::cgi::{self, CgiContext};
use crate::config::{Config, EncodedSlashes, Options, Scope, VHost};
use crate::fastcgi;
use crate::files::{
    directory_index_name, error_response, mime_type, resolve_target_checked, serve_directory,
    serve_file, simple_html, Target,
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
use std::os::unix::fs::MetadataExt;
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
                                            false,
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
    tls: bool,
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
            let ws_server_name = server_name_for_public(&cfg, &req, local_port);
            let _ws_server_name_guard = crate::expr::set_server_name(&ws_server_name);
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
            let Some((root, rel, _script_alias)) = map_path(&cfg, vhost, &norm) else {
                let _ = write_ws_error(stream, &cfg, 404, b"no mapping");
                return Ok(());
            };
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
                https: crate::expr::request_is_https()
                    || local_port == 443
                    || vhost.map(|v| v.ssl.engine).unwrap_or(cfg.ssl.engine),
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
                let mut proxy_urls = vec![target.proxy_url.as_str()];
                if let Some(logical) = target.logical_url.as_deref() {
                    proxy_urls.push(logical);
                }
                cfg.apply_proxy_access_urls(vhost, &mut scope, &proxy_urls, &req, peer.ip());
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

        let mut resp = dispatch_with_scheme(&cfg, &req, peer, &local_ip, local_port, tls);
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
        let body_sent = match write_response(stream, &mut resp, &opts) {
            Ok(sent) => sent,
            // The head or body was partially written, or the response failed
            // its own framing checks.  Reusing this connection would let the
            // next response be read as a continuation of this body.
            Err(_) => return Ok(()),
        };
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
            handle_connection(
                &cfg,
                &logger,
                &mut bridge,
                peer,
                &local_ip,
                local_port,
                true,
            )
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
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    path: &str,
    server_name: &str,
    port: u16,
    https: bool,
) -> String {
    let authority = if cfg.use_canonical_name {
        // `UseCanonicalName On` pins redirects to the configured ServerName;
        // the client Host header must not turn them into open redirects.
        // Apache uses the directive verbatim, including any explicit port, and
        // does not append the listening port to a bare ServerName.
        vhost
            .and_then(|v| v.server_name.as_deref())
            .or(cfg.server_name.as_deref())
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                if (!https && port == 80) || (https && port == 443) {
                    server_name.to_string()
                } else {
                    format!("{server_name}:{port}")
                }
            })
    } else {
        req.header_str("host")
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                if (!https && port == 80) || (https && port == 443) {
                    server_name.to_string()
                } else {
                    format!("{server_name}:{port}")
                }
            })
    };
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
    if cfg.use_canonical_name {
        if let Some(name) = &cfg.server_name {
            return strip_port(name).to_string();
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
    dispatch_with_scheme(cfg, req, peer, local_ip, local_port, false)
}

pub(crate) fn dispatch_with_scheme(
    cfg: &Config,
    req: &Request,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
    tls: bool,
) -> Response {
    crate::expr::with_connection(tls, local_port, || {
        dispatch_inner_request(cfg, req, peer, local_ip, local_port)
    })
}

fn dispatch_inner_request(
    cfg: &Config,
    req: &Request,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
) -> Response {
    let host = host_header(req).unwrap_or("");
    let path = String::from_utf8_lossy(&req.raw_path).into_owned();
    let vhost = cfg.select_vhost(local_port, if host.is_empty() { None } else { Some(host) });
    let https_for_cache = crate::expr::request_is_https()
        || local_port == 443
        || vhost.map(|v| v.ssl.engine).unwrap_or(cfg.ssl.engine);
    let server_name_for_cache = server_name_for(cfg, req, local_port);
    let _server_name_guard = crate::expr::set_server_name(&server_name_for_cache);
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
        local_ip,
    );
    if let Some(cache_ctx) = &cache_scope {
        if let Some(resp) = crate::cache::lookup(
            cfg,
            vhost,
            req,
            host,
            &path,
            &cache_ctx.scope,
            peer.ip(),
            &cache_ctx.grant,
            &cache_ctx.key,
            &cache_ctx.target,
        ) {
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
    if let Some(cache_ctx) = cache_scope {
        crate::cache::store(
            cfg,
            vhost,
            req,
            host,
            &path,
            &cache_ctx.scope,
            peer.ip(),
            &mut resp,
            &cache_ctx.grant,
            &cache_ctx.key,
            &cache_ctx.target,
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

/// Re-evaluate policy for a target selected by a transform (PATH_INFO split,
/// FastCGI script resolution, alias target).  The returned grant is bound to
/// the target path and, for CGIs, to the opened inode by the caller.
#[allow(clippy::too_many_arguments)]
fn authorize_resolved_target(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    peer: IpAddr,
    target_fs: &Path,
    target_url: &str,
    proxy_url: Option<&str>,
    local_port: u16,
    server_name: &str,
    local_ip: &str,
) -> Result<(access::AccessGrant, access::ResourceKey, Scope), Response> {
    let (mut target_scope, config_conditionals, htaccess_conditionals) =
        match evaluate_scope_for_path(cfg, vhost, target_fs, target_url, req, peer) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("vapached: target scope error: {e}");
                return Err(error_response(
                    cfg,
                    vhost,
                    &cfg.global,
                    500,
                    req,
                    target_url,
                    local_port,
                    server_name,
                    peer,
                    local_ip,
                ));
            }
        };
    apply_scope_conditionals(
        cfg,
        vhost,
        &mut target_scope,
        &config_conditionals,
        &htaccess_conditionals,
        target_fs,
        target_url,
        req,
        peer,
    );
    let mut key = access::ResourceKey::request(vhost, req, target_url, Some(target_fs), proxy_url);
    let grant = helper_access_response(
        cfg,
        vhost,
        &target_scope,
        req,
        target_url,
        local_port,
        server_name,
        peer,
        local_ip,
        &mut key,
    )?;
    Ok((grant, key, target_scope))
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

/// Re-authorize the URL the client actually requested after an internal
/// rewrite changed the target.  Apache keeps `<Location>`/`<LocationMatch>`
/// policy for the original URL across internal rewrites, including when the
/// rewrite chain ends in a proxy or redirect rather than a static file.
#[allow(clippy::too_many_arguments)]
fn authorize_original_request(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    url_path: &str,
    fs_path: &Path,
    local_port: u16,
    server_name: &str,
    peer: SocketAddr,
    local_ip: &str,
    rewrite_effects: &crate::rewrite::Effects,
) -> Result<(), Response> {
    let (mut original_scope, config_conditionals, htaccess_conditionals) =
        match evaluate_scope_for_path(cfg, vhost, fs_path, url_path, req, peer.ip()) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("vapached: original URL scope error after rewrite: {e}");
                return Err(error_response(
                    cfg,
                    vhost,
                    &cfg.global,
                    500,
                    req,
                    url_path,
                    local_port,
                    server_name,
                    peer.ip(),
                    local_ip,
                ));
            }
        };
    // Rewrite `[E=...]` effects apply before authorization.  The original URL
    // gate must see the same environment as the final target scope; otherwise
    // an original-URL `Require expr`/`SetEnvIf` rule can be bypassed by a
    // rewrite that changes the environment.
    apply_rewrite_effects(&mut original_scope, rewrite_effects);
    apply_scope_conditionals(
        cfg,
        vhost,
        &mut original_scope,
        &config_conditionals,
        &htaccess_conditionals,
        fs_path,
        url_path,
        req,
        peer.ip(),
    );
    let mut original_resource =
        access::ResourceKey::request(vhost, req, url_path, Some(fs_path), None);
    helper_access_response(
        cfg,
        vhost,
        &original_scope,
        req,
        url_path,
        local_port,
        server_name,
        peer.ip(),
        local_ip,
        &mut original_resource,
    )
    .map(|_| ())
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
    let original_req = req;
    let original_url_path = url_path.clone();
    let original_norm = norm.clone();
    let Some((original_root, original_rel, _)) = map_path(cfg, vhost, &original_norm) else {
        // A regex alias expanded outside its configured base.  The mapping is
        // invalid; do not fall back to a different root.
        return error_response(
            cfg,
            vhost,
            base_scope,
            404,
            req,
            &original_url_path,
            local_port,
            &server_name,
            peer.ip(),
            local_ip,
        );
    };
    let original_fs_path = original_root.join(original_rel);

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
        let Some(mapped) = map_path(cfg, vhost, &norm) else {
            return error_response(
                cfg,
                vhost,
                base_scope,
                404,
                owned_req.as_ref().unwrap_or(req),
                &url_path,
                local_port,
                &server_name,
                peer.ip(),
                local_ip,
            );
        };
        (root, rel, script_alias) = mapped;
        fs_path = root.join(&rel);
        // After a rewrite has changed the query, the target scope must be
        // evaluated with the rewritten request context.  The original URL is
        // still reauthorized separately with `original_req`.
        let current_req = owned_req.as_ref().unwrap_or(req);
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
                    current_req,
                    peer.ip(),
                    &layers,
                );
            scope = evaluated;
            config_conditionals = conditionals;
            htaccess_conditionals = access_conditionals;
        } else {
            let (cached_scope, conditionals) =
                cfg.effective_scope_req_cached(vhost, &fs_path, &url_path, current_req, peer.ip());
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
            current_req,
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
            current_req,
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
            current_req,
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
            current_req,
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
            current_req,
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
                let mut proxy_urls = vec![target.proxy_url.as_str()];
                if let Some(logical) = target.logical_url.as_deref() {
                    proxy_urls.push(logical);
                }
                cfg.apply_proxy_access_urls(vhost, &mut scope, &proxy_urls, current_req, peer.ip());
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
                // A terminal proxy outcome returns before the post-loop
                // original-URL check.  Enforce the original URL policy here
                // as well; otherwise `/admin -> /front -> [P]` bypasses
                // `<Location "/admin">`.
                if original_url_path != url_path
                    || original_fs_path != fs_path
                    || original_req.query != current_req.query
                    || !rewrite_effects.is_empty()
                {
                    if let Err(r) = authorize_original_request(
                        cfg,
                        vhost,
                        original_req,
                        &original_url_path,
                        &original_fs_path,
                        local_port,
                        &server_name,
                        peer,
                        local_ip,
                        &rewrite_effects,
                    ) {
                        return r;
                    }
                }
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
                // A positive redirect is also a terminal outcome.  Do not let
                // it escape the original URL's authorization after a rewrite.
                if status < 400
                    && (original_url_path != url_path
                        || original_fs_path != fs_path
                        || original_req.query != current_req.query
                        || !rewrite_effects.is_empty())
                {
                    if let Err(r) = authorize_original_request(
                        cfg,
                        vhost,
                        original_req,
                        &original_url_path,
                        &original_fs_path,
                        local_port,
                        &server_name,
                        peer,
                        local_ip,
                        &rewrite_effects,
                    ) {
                        return r;
                    }
                }
                let location = if location.starts_with("//") {
                    format!("{}:{}", if https { "https" } else { "http" }, location)
                } else if location.starts_with('/') {
                    absolute_url_scheme(
                        cfg,
                        vhost,
                        current_req,
                        &location,
                        &server_name,
                        local_port,
                        https,
                    )
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
                scope.header_policy.apply(&mut r.headers, r.status < 400);
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

    // An internal rewrite must not erase authorization attached to the URL the
    // client actually requested.  Apache keeps `<Location>`/`<LocationMatch>`
    // policy for the original URL across internal rewrites; require both the
    // original URL scope and the final target scope to allow the request.
    if original_url_path != url_path
        || original_fs_path != fs_path
        || original_req.query != req.query
        || !rewrite_effects.is_empty()
    {
        if let Err(r) = authorize_original_request(
            cfg,
            vhost,
            original_req,
            &original_url_path,
            &original_fs_path,
            local_port,
            &server_name,
            peer,
            local_ip,
            &rewrite_effects,
        ) {
            return r;
        }
    }

    // Redirects are evaluated after rewrites but before access control and
    // filesystem mapping, matching Apache's URL translation order.
    if let Some((red, loc)) = match_redirect(&scope, &url_path) {
        let loc = if loc.is_empty() {
            String::new()
        } else if loc.starts_with('/') {
            absolute_url_scheme(cfg, vhost, req, &loc, &server_name, local_port, https)
        } else {
            loc
        };
        let mut r = if loc.is_empty() {
            simple_html(red.status, "", None)
        } else {
            simple_html(
                red.status,
                &format!("The document has moved to {loc}"),
                Some(&loc),
            )
        };
        if req.method == "HEAD" {
            r.body = Body::Empty;
        }
        scope.header_policy.apply(&mut r.headers, r.status < 400);
        crate::compression::finalize(&scope, req, &mut r, url_path.as_bytes());
        return r;
    }

    let proxy_target = proxy::match_target_req(cfg, &scope, &url_path, Some(req));
    let fastcgi_target = fastcgi::match_proxy(&scope, &url_path, &root);
    // Apache resolves prefix and regex proxy routes in configuration order.
    // Selecting FastCGI first regardless of order lets a regex PHP route
    // capture a URL that an earlier `ProxyPass` sends to an upstream gateway.
    let fastcgi_wins = match (&fastcgi_target, &proxy_target) {
        (Some(f), Some(p)) => f.route_order < p.route_order,
        (Some(_), None) => true,
        _ => false,
    };
    // Only the selected route's proxy identity participates in `<Proxy>`
    // authorization; a losing later route must not deny it.
    let mut selected_proxy_url: Option<String> = None;
    if fastcgi_wins {
        if let Some(target) = &fastcgi_target {
            let logical = target.logical_url.as_deref().unwrap_or("");
            let proxy_urls = if logical.is_empty() {
                Vec::new()
            } else {
                vec![logical]
            };
            if !proxy_urls.is_empty() {
                cfg.apply_proxy_access_urls(vhost, &mut scope, &proxy_urls, req, peer.ip());
            }
            selected_proxy_url = target.logical_url.clone();
        }
    } else if let Some(target) = &proxy_target {
        let mut proxy_urls = vec![target.proxy_url.as_str()];
        if let Some(logical) = target.logical_url.as_deref() {
            proxy_urls.push(logical);
        }
        cfg.apply_proxy_access_urls(vhost, &mut scope, &proxy_urls, req, peer.ip());
        selected_proxy_url = Some(target.proxy_url.clone());
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
        selected_proxy_url.as_deref(),
    );
    let mut grant = match helper_access_response(
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

    if fastcgi_wins {
        if let Some(target) = fastcgi_target {
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
    if !fastcgi_wins
        && proxy_target.is_none()
        && proxy::balancer_unavailable(cfg, &scope, &url_path)
    {
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

    let follow_symlinks = scope.effective_options().contains(Options::FOLLOW_SYMLINKS);
    let owner_match_only = !follow_symlinks
        && scope
            .effective_options()
            .contains(Options::SYMLINKS_IF_OWNER_MATCH);
    let follow = follow_symlinks || owner_match_only;

    match resolve_target_checked(&root, &rel, follow, owner_match_only) {
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
            // With `DirectorySlash Off`, Apache does not redirect `/dir` to
            // `/dir/`.  Authorization must still use the canonical directory
            // URL, otherwise `<Location "/dir/">` is skipped and an autoindex
            // listing for the protected directory leaks its entries.
            let mut auth_url = url_path.clone();
            if !url_path.ends_with('/') && !scope.content_policy.directory_slash.unwrap_or(true) {
                let canonical = format!("{}/", url_path.trim_end_matches('/'));
                match authorize_resolved_target(
                    cfg,
                    vhost,
                    req,
                    peer.ip(),
                    &fs_path,
                    &canonical,
                    None,
                    local_port,
                    &server_name,
                    local_ip,
                ) {
                    Ok((target_grant, _target_resource, target_scope)) => {
                        scope = target_scope;
                        grant = target_grant;
                        auth_url = canonical;
                    }
                    Err(r) => return r,
                }
            }
            if let Some(name) =
                directory_index_name(cfg, &scope, req, &file, &auth_url, &req.raw_path)
            {
                let index_url = format!(
                    "{}/{}",
                    auth_url.trim_end_matches('/'),
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
                &auth_url,
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
            // CGI PATH_INFO: try progressively shorter script names.  The
            // requested suffix must not select the handler: `/protected.sh/x.cgi`
            // is only executable when `protected.sh` itself is configured as a
            // CGI script.  Policy is then re-evaluated for the actual script
            // path before the script inode is executed.
            if let Some(st) = cgi::find_script_checked(&root, &rel, follow, owner_match_only) {
                let script_name = if st.path_info.is_empty() {
                    url_path.clone()
                } else {
                    url_path
                        .strip_suffix(&st.path_info)
                        .unwrap_or(&url_path)
                        .to_string()
                };
                let script_base = st
                    .rel_script
                    .file_name()
                    .map(|n| n.as_encoded_bytes())
                    .unwrap_or(b"");
                let requested_base = norm.rsplit(|b| *b == b'/').next().unwrap_or(&norm);
                let path_info_selected_cgi = cgi::is_cgi(cfg, &scope, requested_base, false);
                if script_alias || cgi::is_cgi(cfg, &scope, script_base, false) {
                    let script_fs = root.join(&st.rel_script);
                    let (target_grant, target_resource, target_scope) =
                        match authorize_resolved_target(
                            cfg,
                            vhost,
                            req,
                            peer.ip(),
                            &script_fs,
                            &script_name,
                            None,
                            local_port,
                            &server_name,
                            local_ip,
                        ) {
                            Ok(v) => v,
                            Err(r) => return r,
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
                        &target_scope,
                        &target_grant,
                        &target_resource,
                        Some(&st.file),
                        Some(&st.meta),
                    );
                }
                if path_info_selected_cgi {
                    // A suffix such as `/.cgi` must not turn an arbitrary
                    // executable into a script.  Fail closed rather than
                    // falling through to a different handler.
                    return error_response(
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

pub(crate) fn map_path(
    cfg: &Config,
    vhost: Option<&VHost>,
    norm: &[u8],
) -> Option<(PathBuf, PathBuf, bool)> {
    let url = String::from_utf8_lossy(norm);
    let base_scope = vhost.map(|v| &v.scope).unwrap_or(&cfg.global);
    // Apache's alias table is ordered: the first matching `Alias`,
    // `ScriptAlias`, `AliasMatch` or `ScriptAliasMatch` wins.  A later, more
    // specific alias that overlaps an earlier one never matches.
    for a in &base_scope.mapping_policy.aliases {
        if a.regex.is_none() {
            if let Some(rest) = alias_remainder(&a.virtual_path, &url) {
                let rel = PathBuf::from(rest.trim_start_matches('/'));
                return Some((a.fs_path.clone(), rel, a.script));
            }
            continue;
        }
        let Some(regex) = &a.regex else {
            continue;
        };
        let Some(caps) = regex.captures(&url) else {
            continue;
        };
        let Some(template) = &a.target_template else {
            continue;
        };
        let mut expanded = template.clone();
        for i in (0..caps.len()).rev() {
            let value = caps.get(i).map(|m| m.as_str()).unwrap_or("");
            expanded = expanded.replace(&format!("${i}"), value);
        }
        let target = PathBuf::from(&expanded);
        let target = if target.is_absolute() {
            target
        } else {
            cfg.server_root.join(target)
        };
        let target = clean_alias_path(&target);
        // A regex alias may only resolve inside the stable alias base derived
        // from its replacement prefix.  Falling back to `target.parent()` as a
        // new root would silently change both the served object and the
        // `<Directory>`/`.htaccess` authorization base.  The component-aware
        // byte check is the verified kernel; `strip_prefix` remains the
        // allocation-free way to obtain the relative target after admission.
        if a.fs_path.as_os_str().is_empty()
            || !crate::verified::path_under_base(
                target.as_os_str().as_encoded_bytes(),
                a.fs_path.as_os_str().as_encoded_bytes(),
            )
        {
            return None;
        }
        let Ok(rel) = target.strip_prefix(&a.fs_path) else {
            return None;
        };
        return Some((a.fs_path.clone(), rel.to_path_buf(), a.script));
    }
    let root = cfg.documentation_root_for(vhost);
    let rel = PathBuf::from(OsStr::from_bytes(&norm[1..]));
    Some((root, rel, false))
}

fn clean_alias_path(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        use std::path::Component::*;
        match c {
            Prefix(_) | RootDir => out.push(c.as_os_str()),
            CurDir => {}
            ParentDir => {
                out.pop();
            }
            Normal(x) => out.push(x),
        }
    }
    out
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

fn match_redirect<'a>(
    scope: &'a Scope,
    url: &str,
) -> Option<(&'a crate::config::Redirect, String)> {
    // Redirect and RedirectMatch share one ordered table, matching Apache's
    // first-match behavior (a later overlapping redirect is unreachable).
    for r in &scope.mapping_policy.redirects {
        if let Some(regex) = &r.regex {
            let Some(caps) = regex.captures(url) else {
                continue;
            };
            let mut location = r.to.clone();
            for i in (0..caps.len()).rev() {
                let value = caps.get(i).map(|m| m.as_str()).unwrap_or("");
                location = location.replace(&format!("${i}"), value);
            }
            return Some((r, location));
        }
        let m = if r.from.ends_with('/') {
            url.starts_with(&r.from)
        } else {
            url == r.from || url.starts_with(&format!("{}/", r.from))
        };
        if m {
            let suffix = if r.from.ends_with('/') {
                &url[r.from.len()..]
            } else if url.len() > r.from.len() {
                &url[r.from.len()..]
            } else {
                ""
            };
            return Some((r, format!("{}{}", r.to, suffix)));
        }
    }
    None
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
    // `ProxyPassMatch`/`SetHandler` can resolve PATH_INFO to a real script
    // whose own `<Files>`/`<Directory>` policy differs from the requested URL.
    // Re-evaluate policy for the script target before binding the backend.
    let script_url = if target.path_info.is_empty() {
        url_path.to_string()
    } else {
        url_path
            .strip_suffix(&target.path_info)
            .unwrap_or(url_path)
            .to_string()
    };
    let proxy_identity = target.script_filename.to_string_lossy().into_owned();
    let (target_grant, target_resource, target_scope) = match authorize_resolved_target(
        cfg,
        vhost,
        req,
        peer.ip(),
        &target.script_filename,
        &script_url,
        Some(&proxy_identity),
        local_port,
        server_name,
        local_ip,
    ) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let scope = &target_scope;
    let grant = &target_grant;
    let resource = &target_resource;
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
    let remote_user = grant.key().identity.as_deref();
    let auth_type = remote_user.and_then(|_| match scope.authorization.auth_type.as_deref() {
        Some(kind) if kind.eq_ignore_ascii_case("basic") => Some("Basic"),
        _ => None,
    });
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
        https: crate::expr::request_is_https()
            || local_port == 443
            || vhost.map(|v| v.ssl.engine).unwrap_or(cfg.ssl.engine),
        server_name,
        host: server_name,
        follow_symlinks: true,
        env: &scope.request_env(req),
        remote_user,
        auth_type,
        script_file: None,
    };
    let mut r = fastcgi::execute(&ctx, scope, target);
    scope.header_policy.apply(&mut r.headers, r.status < 400);
    r
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
        let Some(bound) = grant.bind_file(resource, meta) else {
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
        };
        let mut expected = resource.clone();
        expected.file_dev = Some(meta.dev());
        expected.file_ino = Some(meta.ino());
        if !bound.require(&expected) {
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
    let remote_user = grant.key().identity.as_deref();
    let auth_type = remote_user.and_then(|_| match scope.authorization.auth_type.as_deref() {
        Some(kind) if kind.eq_ignore_ascii_case("basic") => Some("Basic"),
        _ => None,
    });
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
        https: crate::expr::request_is_https()
            || local_port == 443
            || vhost.map(|v| v.ssl.engine).unwrap_or(cfg.ssl.engine),
        server_name,
        host: server_name,
        follow_symlinks: follow,
        env: &scope.request_env(req),
        remote_user,
        auth_type,
        script_file,
    };
    let mut r = cgi::execute(&ctx);
    scope.header_policy.apply(&mut r.headers, r.status < 400);
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
            scope
                .mapping_policy
                .handlers
                .push(crate::config::Handler::add("*".into(), handler.clone()));
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

    #[test]
    fn verified_path_containment_uses_component_boundaries() {
        assert!(vapache_verified::path_under_base(
            b"/srv/www/a.txt",
            b"/srv/www"
        ));
        assert!(vapache_verified::path_under_base(b"/srv/www", b"/srv/www"));
        assert!(vapache_verified::path_under_base(
            b"/srv/www/a.txt",
            b"/srv/www/"
        ));
        assert!(vapache_verified::path_under_base(b"/etc/passwd", b"/"));
        assert!(!vapache_verified::path_under_base(
            b"/srv/www2/a.txt",
            b"/srv/www"
        ));
        assert!(!vapache_verified::path_under_base(b"/srv/w", b"/srv/www"));
        assert!(!vapache_verified::path_under_base(b"/srv/www", b""));
    }

    #[test]
    fn regex_alias_and_redirect_expand_captures() {
        let dir = std::env::temp_dir().join(format!("vapache-server-map-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        std::fs::write(
            &conf,
            "Listen 127.0.0.1:0\n\
             Alias /foo/ \"/srv/a/\"\n\
             Alias /foo/bar/ \"/srv/b/\"\n\
             AliasMatch \"^/pub/(.*)$\" \"/srv/private/$1\"\n\
             RedirectMatch 404 \"^/secret/(.*)$\"\n",
        )
        .unwrap();
        let cfg =
            Config::load(&conf, &dir, &Default::default(), &Default::default(), false).unwrap();
        let (root, rel, script) = map_path(&cfg, None, b"/pub/a/b.txt").unwrap();
        assert_eq!(root, PathBuf::from("/srv/private"));
        assert_eq!(rel, PathBuf::from("a/b.txt"));
        assert!(!script);
        // The first overlapping prefix alias wins, even though the second is
        // more specific.
        let (root, rel, _) = map_path(&cfg, None, b"/foo/bar/x").unwrap();
        assert_eq!(root, PathBuf::from("/srv/a"));
        assert_eq!(rel, PathBuf::from("bar/x"));
        let (red, location) = match_redirect(&cfg.global, "/secret/file").unwrap();
        assert_eq!(red.status, 404);
        assert!(location.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn regex_alias_cannot_re_root_outside_its_configured_base() {
        let dir = std::env::temp_dir().join(format!(
            "vapache-server-alias-escape-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        std::fs::write(
            &conf,
            format!(
                "ServerRoot \"{}\"\n\
                 Listen 127.0.0.1:0\n\
                 AliasMatch \"^/capture(.*)$\" \"$1\"\n\
                 AliasMatch \"^/fixed$\" \"/srv/fixed/index.html\"\n",
                dir.display()
            ),
        )
        .unwrap();
        let cfg =
            Config::load(&conf, &dir, &Default::default(), &Default::default(), false).unwrap();
        // Capture-only absolute replacements outside ServerRoot are a failed
        // mapping, not a new parent-rooted target.
        assert!(map_path(&cfg, None, b"/capture/tmp/elsewhere/secret.txt").is_none());
        // A fixed absolute target still maps relative to its stable parent.
        let (root, rel, _) = map_path(&cfg, None, b"/fixed").unwrap();
        assert_eq!(root, PathBuf::from("/srv/fixed"));
        assert_eq!(rel, PathBuf::from("index.html"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
