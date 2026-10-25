//! Minimal HTTP/1.1 reverse proxy for `ProxyPass`/`ProxyPassReverse`.
//!
//! Covers HTTP and HTTPS upstreams, prefix/regex routing, chunked or
//! fixed-length bodies, `Location` rewriting, round-robin `balancer://`
//! members, compression and WebSocket tunneling over TCP/TLS.  Health checks,
//! failover and connection pooling are follow-ups.

use crate::config::{
    Balancer, BalancerMember, Config, HealthTemplate, ProxyReverseRule, Scope, VHost,
};
use crate::http::{Body, Request, Response};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, RootCertStore, StreamOwned};
use sha1::{Digest, Sha1};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_PROXY_HEAD: usize = 64 * 1024;
const MAX_PROXY_BODY: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug)]
struct HttpBackend {
    host: String,
    port: u16,
    base: String,
    tls: bool,
}

trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

#[derive(Clone)]
pub struct Target {
    backend: HttpBackend,
    path: String,
    suffix: String,
    reverse: Vec<ProxyReverseRule>,
    balancer: Option<String>,
    fail_on_status: Vec<u16>,
    /// Backend URL used for `<Proxy>` / `<ProxyMatch>` matching.
    pub proxy_url: String,
}

impl Target {
    /// Exact backend/path identity used for resource binding.
    pub(crate) fn binding_key(&self) -> String {
        let key = vapache_verified::proxy_target_key(
            self.backend.host.as_bytes(),
            self.backend.port,
            self.backend.tls,
            self.path.as_bytes(),
        );
        key.iter().map(|b| format!("{b:02x}")).collect()
    }
}

const MAX_PROXY_HEADERS: usize = 200;
const MAX_PROXY_LINE: usize = 16 * 1024;
const MAX_PROXY_TRAILER_BYTES: usize = 64 * 1024;
const MAX_PROXY_TRAILERS: usize = 64;

fn canonical_proxy_url(backend: &HttpBackend, path: &str) -> String {
    let scheme = if backend.tls { "https" } else { "http" };
    let default_port = if backend.tls { 443 } else { 80 };
    let authority = if backend.port == default_port {
        backend.host.clone()
    } else {
        format!("{}:{}", backend.host, backend.port)
    };
    let path = if path.is_empty() { "/" } else { path };
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    format!("{scheme}://{authority}{path}")
}

fn parse_http_url(value: &str) -> Option<HttpBackend> {
    let value = value.trim();
    let (rest, tls, default_port) = if let Some(rest) = value.strip_prefix("http://") {
        (rest, false, 80)
    } else if let Some(rest) = value.strip_prefix("https://") {
        (rest, true, 443)
    } else if let Some(rest) = value.strip_prefix("ws://") {
        (rest, false, 80)
    } else if let Some(rest) = value.strip_prefix("wss://") {
        (rest, true, 443)
    } else {
        return None;
    };
    let (authority, base) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    // Bracketed IPv6 literals contain colons; do not split them as a port.
    let (host, port) = if let Some(inside) = authority.strip_prefix('[') {
        let (host, after) = inside.split_once(']')?;
        let port = if let Some(port) = after.strip_prefix(':') {
            port.parse().ok()?
        } else if after.is_empty() {
            default_port
        } else {
            return None;
        };
        (format!("[{host}]"), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (authority.to_string(), default_port),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some(HttpBackend {
        host,
        port,
        base,
        tls,
    })
}

fn dead_map() -> &'static Mutex<HashMap<String, std::time::Instant>> {
    static DEAD: OnceLock<Mutex<HashMap<String, std::time::Instant>>> = OnceLock::new();
    DEAD.get_or_init(|| Mutex::new(HashMap::new()))
}

fn mark_dead(name: &str, member: &str) {
    let mut guard = dead_map().lock().unwrap_or_else(|e| e.into_inner());
    guard.insert(format!("{name}|{member}"), std::time::Instant::now());
}

fn is_dead(name: &str, member: &str) -> bool {
    let key = parse_http_url(member)
        .map(|b| format!("{name}|{}:{}", b.host, b.port))
        .unwrap_or_else(|| format!("{name}|{member}"));
    let guard = dead_map().lock().unwrap_or_else(|e| e.into_inner());
    guard
        .get(&key)
        .map(|t| t.elapsed() < std::time::Duration::from_secs(10))
        .unwrap_or(false)
}

#[derive(Default)]
struct MemberHealth {
    healthy: bool,
    passes: u32,
    fails: u32,
}

#[derive(Clone)]
struct HealthSpec {
    key: String,
    url: String,
    method: String,
    uri: String,
    interval: Duration,
    passes: u32,
    fails: u32,
    ca_file: Option<std::path::PathBuf>,
}

fn health_map() -> &'static Mutex<HashMap<String, MemberHealth>> {
    static HEALTH: OnceLock<Mutex<HashMap<String, MemberHealth>>> = OnceLock::new();
    HEALTH.get_or_init(|| Mutex::new(HashMap::new()))
}

fn health_key(name: &str, member: &str) -> String {
    format!("{name}|{member}")
}

fn member_is_healthy(name: &str, member: &str) -> bool {
    let guard = health_map().lock().unwrap_or_else(|e| e.into_inner());
    guard
        .get(&health_key(name, member))
        .map(|h| h.healthy)
        .unwrap_or(true)
}

fn update_health(spec: &HealthSpec, ok: bool) {
    let mut guard = health_map().lock().unwrap_or_else(|e| e.into_inner());
    let entry = guard
        .entry(spec.key.clone())
        .or_insert_with(|| MemberHealth {
            healthy: true,
            passes: 0,
            fails: 0,
        });
    if ok {
        entry.passes = entry.passes.saturating_add(1);
        entry.fails = 0;
        if entry.passes >= spec.passes.max(1) {
            entry.healthy = true;
        }
    } else {
        entry.fails = entry.fails.saturating_add(1);
        entry.passes = 0;
        if entry.fails >= spec.fails.max(1) {
            entry.healthy = false;
        }
    }
}

fn balancer_specs(cfg: &Config, balancer: &Balancer) -> Vec<HealthSpec> {
    if !balancer.health_enabled() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for member in &balancer.members {
        let template = member
            .template
            .as_ref()
            .and_then(|name| cfg.health_templates.get(name));
        let health = template.unwrap_or(&balancer.health) as &HealthTemplate;
        let method = member
            .hcmethod
            .clone()
            .or_else(|| health.method.clone())
            .unwrap_or_else(|| "GET".into());
        let uri = member
            .hcuri
            .clone()
            .or_else(|| health.uri.clone())
            .unwrap_or_else(|| "/".into());
        let interval = member
            .hcinterval
            .or(health.interval)
            .unwrap_or(Duration::from_secs(5));
        let passes = member.hcpasses.or(health.passes).unwrap_or(1);
        let fails = member.hcfails.or(health.fails).unwrap_or(1);
        out.push(HealthSpec {
            key: health_key(&balancer.name, &member.url),
            url: member.url.clone(),
            method,
            uri,
            interval,
            passes,
            fails,
            ca_file: cfg.global.proxy_policy.proxy_ca_file.clone(),
        });
    }
    out
}

/// Start background active health checks for every balancer that has a
/// health-check template or member parameters.  The server calls this before
/// dropping privileges; the lightweight checker threads only use TCP.
pub fn start_health_checks(cfg: &Config) {
    static STARTED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let started = STARTED.get_or_init(|| Mutex::new(HashSet::new()));
    for balancer in &cfg.balancers {
        let specs = balancer_specs(cfg, balancer);
        if specs.is_empty() {
            continue;
        }
        let key = format!(
            "{}:{}",
            balancer.name,
            specs
                .iter()
                .map(|s| s.url.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );
        {
            let mut guard = started.lock().unwrap_or_else(|e| e.into_inner());
            if !guard.insert(key) {
                continue;
            }
        }
        std::thread::spawn(move || loop {
            for spec in &specs {
                let ok = check_health(spec);
                update_health(spec, ok);
            }
            let wait = specs
                .iter()
                .map(|s| s.interval)
                .min()
                .unwrap_or(Duration::from_secs(5))
                .max(Duration::from_millis(250));
            std::thread::sleep(wait);
        });
    }
}

fn check_health(spec: &HealthSpec) -> bool {
    let Some(backend) = parse_http_url(&spec.url) else {
        return false;
    };
    let mut scope = Scope::default();
    scope.proxy_policy.proxy_ca_file = spec.ca_file.clone();
    let timeout = Duration::from_secs(5);
    let Ok(mut stream) = connect(&backend, &scope, timeout) else {
        return false;
    };
    let mut path = join_path(&backend.base, &spec.uri);
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    path = encode_proxy_path(&path);
    let method = match spec.method.to_ascii_uppercase().as_str() {
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        _ => "GET",
    };
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        backend.host, backend.port
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut reader = BufReader::new(stream);
    match read_line(&mut reader) {
        Ok(line) => line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .map(|s| (200..400).contains(&s))
            .unwrap_or(false),
        Err(_) => false,
    }
}

fn sticky_route(
    balancer: &Balancer,
    req: Option<&Request>,
    override_cookie: Option<&str>,
) -> Option<String> {
    let cookie_names: Vec<&str> = override_cookie
        .or(balancer.sticky_cookie.as_deref())?
        .split('|')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let cookie = req?.header_str("cookie")?;
    for pair in cookie.split(';') {
        let pair = pair.trim();
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        if !cookie_names
            .iter()
            .any(|candidate| name.trim().eq_ignore_ascii_case(candidate))
        {
            continue;
        }
        let value = value.trim();
        let sep = balancer.sticky_sep.as_deref().unwrap_or(".");
        if !sep.is_empty() {
            if let Some((_, route)) = value.rsplit_once(sep) {
                return Some(route.to_string());
            }
        }
        return Some(value.to_string());
    }
    None
}

fn next_balancer_member(
    balancer: &Balancer,
    req: Option<&Request>,
    exclude: Option<&HashSet<String>>,
    sticky_override: Option<&str>,
) -> Option<HttpBackend> {
    if balancer.members.is_empty() {
        return None;
    }
    let active = balancer.health_enabled();
    let is_excluded = |m: &BalancerMember| {
        exclude
            .and_then(|set| parse_http_url(&m.url).map(|b| set.contains(&backend_key(&b))))
            .unwrap_or(false)
    };
    let available = |m: &&BalancerMember| {
        (!active || member_is_healthy(&balancer.name, &m.url)) && !is_excluded(m)
    };
    if let Some(route) = sticky_route(balancer, req, sticky_override) {
        if let Some(member) = balancer.members.iter().find(|m| {
            m.route.as_deref() == Some(route.as_str())
                && (!active || member_is_healthy(&balancer.name, &m.url))
                && !is_dead(&balancer.name, &m.url)
                && !is_excluded(m)
        }) {
            return parse_http_url(&member.url);
        }
    }
    let mut viable: Vec<&BalancerMember> = balancer.members.iter().filter(available).collect();
    if viable.is_empty() {
        return None;
    }
    let not_dead: Vec<&BalancerMember> = viable
        .iter()
        .copied()
        .filter(|m| !is_dead(&balancer.name, &m.url))
        .collect();
    if !not_dead.is_empty() {
        viable = not_dead;
    }
    static COUNTERS: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();
    let counters = COUNTERS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = counters.lock().unwrap_or_else(|e| e.into_inner());
    let start = *guard.entry(balancer.name.clone()).or_insert(0);
    let index = start % viable.len();
    *guard.entry(balancer.name.clone()).or_insert(0) = start.wrapping_add(1);
    parse_http_url(&viable[index].url)
}

fn resolve_backend(
    cfg: &Config,
    raw: &str,
    suffix: &str,
    req: Option<&Request>,
    sticky_override: Option<&str>,
) -> Option<(HttpBackend, String)> {
    if let Some(name) = raw.trim().strip_prefix("balancer://") {
        let name = name.trim_end_matches('/');
        let balancer = cfg.balancers.iter().find(|b| b.name == name)?;
        let backend = next_balancer_member(balancer, req, None, sticky_override)?;
        let path = join_path(&backend.base, suffix);
        return Some((backend, path));
    }
    let backend = parse_http_url(raw)?;
    let path = join_path(&backend.base, suffix);
    Some((backend, path))
}

fn join_path(base: &str, suffix: &str) -> String {
    if suffix.is_empty() {
        return base.to_string();
    }
    if base == "/" {
        format!("/{suffix}")
    } else {
        format!(
            "{}/{}",
            base.trim_end_matches('/'),
            suffix.trim_start_matches('/')
        )
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

/// Resolve an absolute URL produced by `RewriteRule ... [P]`.  The query
/// string is handled by the caller (it is forwarded separately from the
/// request), so only the path portion belongs in `Target`.
pub fn target_from_url(cfg: &Config, scope: &Scope, url: &str, req: &Request) -> Option<Target> {
    let path_part = url.split_once('?').map(|(p, _)| p).unwrap_or(url);
    let (backend, path) = resolve_backend(cfg, path_part, "", Some(req), None)?;
    let balancer = path_part
        .trim()
        .strip_prefix("balancer://")
        .map(|name| name.trim_end_matches('/').to_string());
    let fail_on_status = balancer
        .as_ref()
        .and_then(|name| cfg.balancers.iter().find(|b| b.name == *name))
        .map(|b| b.fail_on_status.clone())
        .unwrap_or_default();
    let proxy_url = canonical_proxy_url(&backend, &path);
    Some(Target {
        path,
        suffix: String::new(),
        backend,
        reverse: scope.proxy_policy.proxy_reverses.clone(),
        balancer,
        fail_on_status,
        proxy_url,
    })
}

/// True when the request matches a balancer route but every member is
/// currently unhealthy.  Apollo-style callers use this to return 503 rather
/// than accidentally falling through to a document-root 404.
pub fn balancer_unavailable(cfg: &Config, scope: &Scope, url_path: &str) -> bool {
    for rule in &scope.proxy_policy.proxy_passes {
        if prefix_suffix(&rule.prefix, url_path).is_none() {
            continue;
        }
        if rule.backend.trim_start().starts_with("balancer://")
            && resolve_backend(cfg, &rule.backend, "", None, None).is_none()
        {
            return true;
        }
    }
    for rule in &scope.proxy_policy.proxy_rules {
        if !rule.pattern.is_match(url_path) {
            continue;
        }
        if rule.backend.trim_start().starts_with("balancer://")
            && resolve_backend(cfg, &rule.backend, "", None, None).is_none()
        {
            return true;
        }
    }
    false
}

pub fn match_target(cfg: &Config, scope: &Scope, url_path: &str) -> Option<Target> {
    match_target_req(cfg, scope, url_path, None)
}

/// True when the URL matches a configured proxy route, without selecting a
/// backend or advancing balancer state.
pub fn matches_route(scope: &Scope, url_path: &str) -> bool {
    scope
        .proxy_policy
        .proxy_passes
        .iter()
        .any(|rule| prefix_suffix(&rule.prefix, url_path).is_some())
        || scope
            .proxy_policy
            .proxy_rules
            .iter()
            .any(|rule| rule.pattern.is_match(url_path))
}

pub fn match_target_req(
    cfg: &Config,
    scope: &Scope,
    url_path: &str,
    req: Option<&Request>,
) -> Option<Target> {
    for rule in &scope.proxy_policy.proxy_passes {
        let Some(suffix) = prefix_suffix(&rule.prefix, url_path) else {
            continue;
        };
        if let Some((backend, path)) = resolve_backend(
            cfg,
            &rule.backend,
            suffix,
            req,
            rule.sticky_cookie.as_deref(),
        ) {
            let balancer = rule
                .backend
                .strip_prefix("balancer://")
                .map(|n| n.trim_end_matches('/').to_string());
            let fail_on_status = balancer
                .as_ref()
                .and_then(|name| cfg.balancers.iter().find(|b| b.name == *name))
                .map(|b| b.fail_on_status.clone())
                .unwrap_or_default();
            let proxy_url = canonical_proxy_url(&backend, &path);
            return Some(Target {
                path,
                suffix: suffix.to_string(),
                backend,
                reverse: scope.proxy_policy.proxy_reverses.clone(),
                balancer,
                fail_on_status,
                proxy_url,
            });
        }
    }
    for rule in &scope.proxy_policy.proxy_rules {
        let Some(caps) = rule.pattern.captures(url_path) else {
            continue;
        };
        let captured = caps
            .get(1)
            .or_else(|| caps.get(0))
            .map(|m| m.as_str())
            .unwrap_or(url_path)
            .trim_start_matches('/');
        let replaces = rule.backend.contains("$1");
        let raw = if replaces {
            rule.backend.replace("$1", captured)
        } else {
            rule.backend.clone()
        };
        if let Some((backend, path)) =
            resolve_backend(cfg, &raw, if replaces { "" } else { captured }, req, None)
        {
            let path = if replaces {
                parse_http_url(&path).map(|b| b.base).unwrap_or(path)
            } else {
                path
            };
            let balancer = rule
                .backend
                .strip_prefix("balancer://")
                .map(|n| n.trim_end_matches('/').to_string());
            let fail_on_status = balancer
                .as_ref()
                .and_then(|name| cfg.balancers.iter().find(|b| b.name == *name))
                .map(|b| b.fail_on_status.clone())
                .unwrap_or_default();
            let proxy_url = canonical_proxy_url(&backend, &path);
            return Some(Target {
                path,
                suffix: if replaces {
                    String::new()
                } else {
                    captured.to_string()
                },
                backend,
                reverse: scope.proxy_policy.proxy_reverses.clone(),
                balancer,
                fail_on_status,
                proxy_url,
            });
        }
    }
    None
}

fn encode_proxy_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        if b <= b' '
            || b >= 0x7f
            || matches!(
                b,
                b'"' | b'<' | b'>' | b'\\' | b'^' | b'`' | b'{' | b'|' | b'}' | b'%' | b'?' | b'#'
            )
        {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        } else {
            out.push(b as char);
        }
    }
    out
}

fn hop_by_hop(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("content-length")
}

fn forwarded_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("x-forwarded-for")
        || name.eq_ignore_ascii_case("forwarded")
        || name.eq_ignore_ascii_case("x-forwarded-proto")
        || name.eq_ignore_ascii_case("x-forwarded-host")
        || name.eq_ignore_ascii_case("x-real-ip")
}

fn connection_tokens(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|token| crate::verified::valid_token(token.as_bytes()))
        .map(|token| token.to_ascii_lowercase())
        .collect()
}

fn request_connection_tokens(req: &Request) -> Vec<String> {
    let mut tokens = Vec::new();
    for name in ["connection", "proxy-connection"] {
        if let Some(value) = req.header_str(name) {
            tokens.extend(connection_tokens(value));
        }
    }
    tokens
}

fn read_line(reader: &mut impl BufRead) -> std::io::Result<String> {
    let mut line = Vec::new();
    let n = reader.read_until(b'\n', &mut line)?;
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "eof",
        ));
    }
    if line.len() > MAX_PROXY_LINE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "proxy line too long",
        ));
    }
    while line.last() == Some(&b'\n') || line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

fn read_chunked(reader: &mut impl BufRead, out: &mut Vec<u8>) -> std::io::Result<()> {
    loop {
        let line = read_line(reader)?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad chunk"))?;
        if size == 0 {
            // Bound both trailer bytes and count; an untrusted backend must
            // not be able to turn trailers into an unbounded read.
            let mut trailer_bytes = 0usize;
            let mut trailer_count = 0usize;
            loop {
                let line = read_line(reader)?;
                if line.is_empty() {
                    return Ok(());
                }
                trailer_count += 1;
                trailer_bytes = trailer_bytes.saturating_add(line.len() + 2);
                if trailer_count > MAX_PROXY_TRAILERS || trailer_bytes > MAX_PROXY_TRAILER_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "proxy trailers too large",
                    ));
                }
            }
        }
        if out.len() + size > MAX_PROXY_BODY {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "proxy body too large",
            ));
        }
        let start = out.len();
        out.resize(start + size, 0);
        reader.read_exact(&mut out[start..])?;
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?;
        if crlf != *b"\r\n" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad chunk crlf",
            ));
        }
    }
}

fn rewrite_location(location: &mut String, reverse: &[ProxyReverseRule]) {
    for rule in reverse {
        let backend = rule.backend.trim_end_matches('/');
        if location.starts_with(backend) {
            let rest = &location[backend.len()..];
            let front = rule.front.trim_end_matches('/');
            if rest.is_empty() {
                *location = format!("{front}/");
            } else if rest.starts_with('/') {
                *location = format!("{front}{rest}");
            }
            return;
        }
    }
}

fn error(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    req: &Request,
    path: &str,
    port: u16,
    host: &str,
    peer: std::net::IpAddr,
    local_ip: &str,
) -> Response {
    crate::files::error_response(
        cfg, vhost, scope, 502, req, path, port, host, peer, local_ip,
    )
}

pub fn is_websocket(req: &Request) -> bool {
    if req.method != "GET" {
        return false;
    }
    let upgrade = req
        .header_str("upgrade")
        .map(|v| {
            v.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("websocket"))
        })
        .unwrap_or(false);
    let connection = req
        .header_str("connection")
        .map(|v| {
            v.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);
    let version_ok = req
        .header_str("sec-websocket-version")
        .map(str::trim)
        .map(|v| v == "13")
        .unwrap_or(false);
    let key_len = req
        .header_str("sec-websocket-key")
        .and_then(|key| {
            STANDARD
                .decode(key.trim())
                .or_else(|_| STANDARD_NO_PAD.decode(key.trim()))
                .ok()
        })
        .map(|key| key.len() == 16)
        .unwrap_or(false);
    upgrade && connection && version_ok && key_len
}

fn websocket_accept(key: &str) -> Option<String> {
    let key = key.trim();
    let decoded = STANDARD
        .decode(key)
        .or_else(|_| STANDARD_NO_PAD.decode(key))
        .ok()?;
    if decoded.len() != 16 {
        return None;
    }
    // RFC 6455 hashes the base64 text of the client key, not its decoded bytes.
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    Some(STANDARD.encode(hasher.finalize()))
}

fn response_header<'a>(head: &'a [u8], name: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(head).ok()?;
    for line in text.split("\r\n").skip(1) {
        let (n, v) = line.split_once(':')?;
        if n.trim().eq_ignore_ascii_case(name) {
            return Some(v.trim());
        }
    }
    None
}

async fn read_async_head<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut response = Vec::new();
    loop {
        if let Some(p) = response.windows(4).position(|w| w == b"\r\n\r\n") {
            return Ok(response[..p + 4].to_vec());
        }
        if response.len() > MAX_PROXY_HEAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "websocket headers too large",
            ));
        }
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "websocket upstream closed",
            ));
        }
        response.extend_from_slice(&buf[..n]);
    }
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

async fn connect_async(
    backend: &HttpBackend,
    scope: &Scope,
    timeout: Duration,
) -> std::io::Result<Box<dyn AsyncReadWrite>> {
    let mut stream = None;
    for addr in tokio::net::lookup_host((backend.host.as_str(), backend.port)).await? {
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                stream = Some(s);
                break;
            }
            _ => {}
        }
    }
    let stream = stream.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "cannot connect upstream")
    })?;
    stream.set_nodelay(true)?;
    if !backend.tls {
        return Ok(Box::new(stream));
    }
    let name = ServerName::try_from(backend.host.clone())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad TLS host"))?;
    let connector = tokio_rustls::TlsConnector::from(client_config(scope)?);
    let tls = tokio::time::timeout(timeout, connector.connect(name, stream))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timeout")
        })??;
    Ok(Box::new(tls))
}

/// Tunnel a WebSocket upgrade over any combination of clear/TLS client and
/// clear/TLS upstream.  The caller supplies the already-parsed request and
/// any bytes buffered after its headers.
#[allow(clippy::too_many_arguments)]
pub async fn websocket_async<S>(
    cfg: &Config,
    scope: &Scope,
    req: &Request,
    target: &Target,
    grant: &crate::access::AccessGrant,
    resource: &crate::access::ResourceKey,
    mut client: S,
    peer: SocketAddr,
    https: bool,
    host: &str,
    initial: &[u8],
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let binding = target.binding_key();
    let Some(bound) = grant.bind_backend(resource, binding.clone()) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "access grant does not cover websocket target",
        ));
    };
    let mut expected = resource.clone();
    expected.backend_target = Some(binding);
    if !bound.require(&expected) || resource.proxy_url.as_deref() != Some(target.proxy_url.as_str())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "access grant does not cover websocket target",
        ));
    }
    let timeout = cfg.timeout.max(Duration::from_secs(5));
    let mut upstream = connect_async(&target.backend, scope, timeout).await?;
    let mut path = target.path.clone();
    if !req.query.is_empty() {
        path.push('?');
        path.push_str(&String::from_utf8_lossy(&req.query));
    }
    let mut head = format!(
        "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n",
        path, target.backend.host, target.backend.port
    );
    let request_tokens = request_connection_tokens(req);
    for (name, value) in req.headers.iter() {
        if hop_by_hop(name)
            || forwarded_header(name)
            || request_tokens
                .iter()
                .any(|token| token == &name.to_ascii_lowercase())
            || name.eq_ignore_ascii_case("expect")
        {
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(&String::from_utf8_lossy(value));
        head.push_str("\r\n");
    }
    head.push_str(&format!("X-Forwarded-For: {}\r\n", peer.ip()));
    head.push_str(&format!(
        "X-Forwarded-Proto: {}\r\n",
        if https { "https" } else { "http" }
    ));
    if !host.is_empty() {
        head.push_str(&format!("X-Forwarded-Host: {host}\r\n"));
    }
    head.push_str("\r\n");
    upstream.write_all(head.as_bytes()).await?;
    let response = read_async_head(&mut upstream).await?;
    let status_line = String::from_utf8_lossy(&response);
    let status = status_line
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if status == 101 {
        let key = req.header_str("sec-websocket-key").unwrap_or("");
        let expected = websocket_accept(key).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid WebSocket client key",
            )
        })?;
        let upgrade_ok = response_header(&response, "upgrade")
            .map(|v| {
                v.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("websocket"))
            })
            .unwrap_or(false);
        let connection_ok = response_header(&response, "connection")
            .map(|v| {
                v.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
            })
            .unwrap_or(false);
        let accept_ok = response_header(&response, "sec-websocket-accept")
            .map(|v| v.eq_ignore_ascii_case(&expected))
            .unwrap_or(false);
        if !upgrade_ok || !connection_ok || !accept_ok {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid WebSocket backend handshake",
            ));
        }
    }
    client.write_all(&response).await?;
    if status != 101 {
        return Ok(());
    }
    if !initial.is_empty() {
        upstream.write_all(initial).await?;
    }
    client.flush().await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

fn client_config(scope: &Scope) -> std::io::Result<Arc<rustls::ClientConfig>> {
    let mut roots = RootCertStore::empty();
    if let Some(path) = &scope.proxy_policy.proxy_ca_file {
        let data = std::fs::read(path)?;
        let mut cursor = Cursor::new(data);
        for cert in rustls_pemfile::certs(&mut cursor) {
            let cert = cert.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            roots
                .add(cert)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn connect_tcp(backend: &HttpBackend, timeout: Duration) -> std::io::Result<TcpStream> {
    let mut tcp = None;
    let mut last = None;
    for addr in (backend.host.as_str(), backend.port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let tcp = tcp.ok_or_else(|| {
        last.unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address"))
    })?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    Ok(tcp)
}

fn connect(
    backend: &HttpBackend,
    scope: &Scope,
    timeout: Duration,
) -> std::io::Result<Box<dyn ReadWrite>> {
    let tcp = connect_tcp(backend, timeout)?;
    if !backend.tls {
        return Ok(Box::new(tcp));
    }
    let name = ServerName::try_from(backend.host.clone())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad TLS host"))?;
    let conn = ClientConnection::new(client_config(scope)?, name)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Box::new(StreamOwned::new(conn, tcp)))
}

#[allow(clippy::too_many_arguments)]
struct Pooled {
    stream: Box<dyn ReadWrite>,
    at: std::time::Instant,
}

fn pool() -> &'static Mutex<HashMap<String, Vec<Pooled>>> {
    static POOL: OnceLock<Mutex<HashMap<String, Vec<Pooled>>>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(HashMap::new()))
}

fn backend_key(backend: &HttpBackend) -> String {
    format!(
        "{}:{}:{}",
        backend.host,
        backend.port,
        if backend.tls { "tls" } else { "plain" }
    )
}

fn take_pooled(key: &str) -> Option<Box<dyn ReadWrite>> {
    let mut guard = pool().lock().unwrap_or_else(|e| e.into_inner());
    let list = guard.get_mut(key)?;
    let now = std::time::Instant::now();
    while let Some(entry) = list.pop() {
        if now.duration_since(entry.at) <= Duration::from_secs(30) {
            return Some(entry.stream);
        }
    }
    None
}

fn release_pooled(key: &str, stream: Box<dyn ReadWrite>) {
    let mut guard = pool().lock().unwrap_or_else(|e| e.into_inner());
    let list = guard.entry(key.to_string()).or_default();
    if list.len() < 8 {
        list.push(Pooled {
            stream,
            at: std::time::Instant::now(),
        });
    }
}

fn connect_pooled(
    backend: &HttpBackend,
    scope: &Scope,
    timeout: Duration,
) -> std::io::Result<(Box<dyn ReadWrite>, bool)> {
    let key = backend_key(backend);
    if let Some(stream) = take_pooled(&key) {
        return Ok((stream, true));
    }
    Ok((connect(backend, scope, timeout)?, false))
}

struct PoolBodyReader {
    inner: Option<BufReader<Box<dyn ReadWrite>>>,
    remaining: u64,
    key: String,
    reusable: bool,
}

impl PoolBodyReader {
    fn finish(&mut self) {
        if let Some(reader) = self.inner.take() {
            if self.reusable {
                release_pooled(&self.key, reader.into_inner());
            }
        }
    }
}

impl Read for PoolBodyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            self.finish();
            return Ok(0);
        }
        let want = (self.remaining as usize).min(buf.len());
        let Some(reader) = self.inner.as_mut() else {
            return Ok(0);
        };
        let n = reader.read(&mut buf[..want])?;
        if n == 0 {
            self.remaining = 0;
            self.finish();
            return Ok(0);
        }
        self.remaining -= n as u64;
        if self.remaining == 0 {
            self.finish();
        }
        Ok(n)
    }
}

impl Drop for PoolBodyReader {
    fn drop(&mut self) {
        if self.remaining == 0 {
            self.finish();
        }
    }
}

fn proxy_once(
    mut stream: Box<dyn ReadWrite>,
    target: &Target,
    req: &Request,
    scope: &Scope,
    url_path: &str,
    peer: SocketAddr,
    https: bool,
    host: &str,
) -> std::io::Result<(Response, Option<Box<dyn ReadWrite>>)> {
    let mut path = encode_proxy_path(&target.path);
    if !req.query.is_empty() {
        path.push('?');
        path.push_str(&String::from_utf8_lossy(&req.query));
    }
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: keep-alive\r\n",
        req.method, path, target.backend.host, target.backend.port
    );
    let body_len = req.body_len();
    if body_len > 0 {
        head.push_str(&format!("Content-Length: {body_len}\r\n"));
    }
    let request_tokens = request_connection_tokens(req);
    for (name, value) in req.headers.iter() {
        if hop_by_hop(name)
            || forwarded_header(name)
            || request_tokens
                .iter()
                .any(|token| token == &name.to_ascii_lowercase())
            || name.eq_ignore_ascii_case("expect")
        {
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(&String::from_utf8_lossy(value));
        head.push_str("\r\n");
    }
    head.push_str(&format!("X-Forwarded-For: {}\r\n", peer.ip()));
    head.push_str(&format!(
        "X-Forwarded-Proto: {}\r\n",
        if https { "https" } else { "http" }
    ));
    if !host.is_empty() {
        head.push_str(&format!("X-Forwarded-Host: {host}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    if let Some(reader) = req.body_reader() {
        let mut reader = reader?;
        std::io::copy(&mut reader, &mut stream)?;
    } else if !req.body.is_empty() {
        stream.write_all(&req.body)?;
    }

    let mut reader = BufReader::new(stream);
    let status_line = read_line(&mut reader)?;
    let mut bits = status_line.split_whitespace();
    let version = bits
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad status"))?
        .to_string();
    let status: u16 = bits
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad status"))?;
    if !(100..=599).contains(&status) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad status",
        ));
    }
    // A normal proxy response cannot be an interim/upgrade response.  The
    // WebSocket path has a separate exact 101 handshake.  Refusing these here
    // prevents a backend from smuggling a second response through the body
    // path.
    if (100..200).contains(&status) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected interim proxy response",
        ));
    }
    let mut headers: Vec<(String, Vec<u8>)> = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut saw_content_length = false;
    let mut chunked = false;
    let mut saw_transfer_encoding = false;
    let mut connection: Option<String> = None;
    let mut connection_header_tokens: Vec<String> = Vec::new();
    let mut header_count = 0usize;
    let mut head_bytes = status_line.len();
    loop {
        let line = read_line(&mut reader)?;
        if line.is_empty() {
            break;
        }
        header_count += 1;
        head_bytes += line.len() + 2;
        if header_count > MAX_PROXY_HEADERS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "too many proxy headers",
            ));
        }
        if head_bytes > MAX_PROXY_HEAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "proxy headers too large",
            ));
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed proxy response header",
            ));
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if !crate::verified::valid_token(name.as_bytes()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid proxy response header name",
            ));
        }
        if name == "content-length" {
            if saw_content_length {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "duplicate Content-Length from proxy",
                ));
            }
            saw_content_length = true;
            content_length = Some(value.parse().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "bad Content-Length from proxy",
                )
            })?);
            continue;
        }
        if name == "transfer-encoding" {
            if saw_transfer_encoding {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "duplicate Transfer-Encoding from proxy",
                ));
            }
            saw_transfer_encoding = true;
            let mut encodings = value.split(',').map(str::trim);
            let first = encodings.next().unwrap_or("");
            if !first.eq_ignore_ascii_case("chunked") || encodings.next().is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported Transfer-Encoding from proxy",
                ));
            }
            chunked = true;
            continue;
        }
        if name == "connection" {
            connection = Some(value.to_ascii_lowercase());
            connection_header_tokens.extend(connection_tokens(value));
            continue;
        }
        if hop_by_hop(&name) {
            continue;
        }
        if name == "location" {
            let Some(clean) = crate::verified::sanitize_header_value(value.as_bytes()) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid proxy Location header value",
                ));
            };
            let mut loc = String::from_utf8_lossy(&clean).into_owned();
            rewrite_location(&mut loc, &target.reverse);
            headers.push((name, loc.into_bytes()));
            continue;
        }
        let Some(clean) = crate::verified::sanitize_header_value(value.as_bytes()) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid proxy response header value",
            ));
        };
        headers.push((name, clean));
    }
    headers.retain(|(name, _)| {
        !connection_header_tokens
            .iter()
            .any(|token| token.eq_ignore_ascii_case(name))
    });
    if saw_content_length && saw_transfer_encoding {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "proxy response has both Content-Length and Transfer-Encoding",
        ));
    }
    if (300..400).contains(&status) {
        // Apache's proxy reverse rules also cover relative Location values.
        if let Some((_, value)) = headers.iter_mut().find(|(n, _)| n == "location") {
            let mut loc = String::from_utf8_lossy(value).into_owned();
            rewrite_location(&mut loc, &target.reverse);
            *value = loc.into_bytes();
        }
    }
    let mut keep_alive = version != "HTTP/1.0";
    if let Some(connection) = connection.as_deref() {
        if connection.split(',').any(|v| v.trim() == "close") {
            keep_alive = false;
        } else if connection.split(',').any(|v| v.trim() == "keep-alive") {
            keep_alive = true;
        }
    }
    let no_body =
        req.method == "HEAD" || status == 204 || status == 304 || (100..200).contains(&status);
    // Large fixed-length upstream bodies are forwarded without buffering the
    // whole response in memory.  The pool connection is returned only after
    // the body reader reaches EOF, preserving HTTP/1.1 framing.
    if !no_body && !chunked {
        if let Some(n) = content_length {
            const STREAM_THRESHOLD: usize = 256 * 1024;
            if n > STREAM_THRESHOLD {
                let body = PoolBodyReader {
                    inner: Some(reader),
                    remaining: n as u64,
                    key: backend_key(&target.backend),
                    reusable: false,
                };
                let mut response = Response::new(status);
                response.headers = headers
                    .into_iter()
                    .map(|(n, v)| (std::borrow::Cow::Owned(n), v))
                    .collect();
                response.body = Body::Stream {
                    reader: Box::new(body),
                    len: n as u64,
                };
                crate::compression::finalize(scope, req, &mut response, url_path.as_bytes());
                return Ok((response, None));
            }
        }
    }
    let mut body = Vec::new();
    // Do not pool backend connections.  A compliant backend is not assumed;
    // leftover bytes after a fixed/chunked body could otherwise be reused as
    // the next response.  Closing after every response removes that
    // request-smuggling primitive.
    let mut reusable = false;
    if !no_body {
        if chunked {
            read_chunked(&mut reader, &mut body)?;
        } else if let Some(n) = content_length {
            if n > MAX_PROXY_BODY {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "proxy body too large",
                ));
            }
            body.resize(n, 0);
            reader.read_exact(&mut body)?;
        } else {
            reusable = false;
            Read::by_ref(&mut reader)
                .take(MAX_PROXY_BODY as u64 + 1)
                .read_to_end(&mut body)?;
            if body.len() > MAX_PROXY_BODY {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "proxy body too large",
                ));
            }
        }
    }
    if status == 101 || !keep_alive {
        reusable = false;
    }
    let mut response = Response::new(status);
    response.headers = headers
        .into_iter()
        .map(|(n, v)| (std::borrow::Cow::Owned(n), v))
        .collect();
    response.body = if body.is_empty() {
        Body::Empty
    } else {
        Body::Bytes(body)
    };
    crate::compression::finalize(scope, req, &mut response, url_path.as_bytes());
    let returned = if reusable {
        Some(reader.into_inner())
    } else {
        None
    };
    Ok((response, returned))
}

fn alternate_target(
    cfg: &Config,
    target: &Target,
    tried: &HashSet<String>,
    req: &Request,
) -> Option<Target> {
    let name = target.balancer.as_ref()?;
    let balancer = cfg.balancers.iter().find(|b| b.name == *name)?;
    let backend = next_balancer_member(balancer, Some(req), Some(tried), None)?;
    let path = join_path(&backend.base, &target.suffix);
    Some(Target {
        path,
        suffix: target.suffix.clone(),
        backend,
        reverse: target.reverse.clone(),
        balancer: Some(name.clone()),
        fail_on_status: balancer.fail_on_status.clone(),
        proxy_url: target.proxy_url.clone(),
    })
}

pub fn execute(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    req: &Request,
    url_path: &str,
    target: &Target,
    peer: SocketAddr,
    local_port: u16,
    https: bool,
    host: &str,
    local_ip: &str,
    grant: &crate::access::AccessGrant,
    resource: &crate::access::ResourceKey,
) -> Response {
    let binding = target.binding_key();
    let Some(bound) = grant.bind_backend(resource, binding.clone()) else {
        return error(
            cfg,
            vhost,
            scope,
            req,
            url_path,
            local_port,
            host,
            peer.ip(),
            local_ip,
        );
    };
    let mut expected = resource.clone();
    expected.backend_target = Some(binding);
    if !bound.require(&expected) || resource.proxy_url.as_deref() != Some(target.proxy_url.as_str())
    {
        return error(
            cfg,
            vhost,
            scope,
            req,
            url_path,
            local_port,
            host,
            peer.ip(),
            local_ip,
        );
    }
    let timeout = cfg.timeout.max(Duration::from_secs(5));
    let mut current = target.clone();
    let mut tried: HashSet<String> = HashSet::new();
    loop {
        let key = backend_key(&current.backend);
        tried.insert(key.clone());
        let mut retried = false;
        let result = loop {
            let (stream, was_pooled) = match connect_pooled(&current.backend, scope, timeout) {
                Ok(v) => v,
                Err(e) => break Err(e),
            };
            match proxy_once(stream, &current, req, scope, url_path, peer, https, host) {
                Ok((response, reusable)) => {
                    if let Some(stream) = reusable {
                        release_pooled(&key, stream);
                    }
                    break Ok(response);
                }
                Err(e) if was_pooled && !retried => {
                    retried = true;
                    continue;
                }
                Err(e) => break Err(e),
            }
        };
        match result {
            Ok(response) => {
                let failed_status =
                    current.balancer.is_some() && current.fail_on_status.contains(&response.status);
                if failed_status {
                    if let Some(name) = &current.balancer {
                        mark_dead(
                            name,
                            &format!("{}:{}", current.backend.host, current.backend.port),
                        );
                    }
                    if let Some(next) = alternate_target(cfg, &current, &tried, req) {
                        current = next;
                        continue;
                    }
                }
                return response;
            }
            Err(e) => {
                eprintln!("vapache proxy error: {e}");
                if let Some(name) = &current.balancer {
                    mark_dead(
                        name,
                        &format!("{}:{}", current.backend.host, current.backend.port),
                    );
                }
                if let Some(next) = alternate_target(cfg, &current, &tried, req) {
                    current = next;
                    continue;
                }
                return error(
                    cfg,
                    vhost,
                    scope,
                    req,
                    url_path,
                    local_port,
                    host,
                    peer.ip(),
                    local_ip,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Headers, Version};

    #[allow(clippy::too_many_arguments)]
    fn execute(
        cfg: &Config,
        vhost: Option<&VHost>,
        scope: &Scope,
        req: &Request,
        url_path: &str,
        target: &Target,
        peer: SocketAddr,
        local_port: u16,
        https: bool,
        host: &str,
        local_ip: &str,
    ) -> Response {
        let resource = crate::access::ResourceKey::request(
            vhost,
            req,
            url_path,
            None,
            Some(target.proxy_url.as_str()),
        );
        super::execute(
            cfg,
            vhost,
            scope,
            req,
            url_path,
            target,
            peer,
            local_port,
            https,
            host,
            local_ip,
            &crate::access::test_grant(),
            &resource,
        )
    }
    use std::collections::HashMap;
    use std::fs;
    use std::net::TcpListener;

    fn config(root: &Path) -> Config {
        let path = root.join("httpd.conf");
        fs::write(&path, "Listen 127.0.0.1:0\n").unwrap();
        Config::load(&path, root, &HashMap::new(), &HashMap::new(), false).unwrap()
    }

    fn req(path: &str) -> Request {
        Request {
            method: "GET".into(),
            target: path.as_bytes().to_vec(),
            raw_path: path.as_bytes().to_vec(),
            query: Vec::new(),
            version: Version::Http11,
            headers: Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    #[test]
    fn proxies_http_and_rewrites_location() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
            }
            s.write_all(
                format!(
                    "HTTP/1.1 302 Found\r\nContent-Type: text/plain\r\nLocation: http://127.0.0.1:{port}/new\r\nContent-Length: 2\r\n\r\nok"
                )
                .as_bytes(),
            )
            .unwrap();
        });

        let dir = std::env::temp_dir().join(format!("vapache-proxy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = config(&dir);
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/api".into(),
                backend: format!("http://127.0.0.1:{port}/"),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
            });
        scope
            .proxy_policy
            .proxy_reverses
            .push(crate::config::ProxyReverseRule {
                front: "/api".into(),
                backend: format!("http://127.0.0.1:{port}/"),
            });
        let target = match_target(&cfg, &scope, "/api/hello").unwrap();
        let request = req("/api/hello");
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let resp = execute(
            &cfg,
            None,
            &scope,
            &request,
            "/api/hello",
            &target,
            peer,
            80,
            false,
            "localhost",
            "127.0.0.1",
        );
        assert_eq!(resp.status, 302);
        assert_eq!(
            resp.headers
                .iter()
                .find(|(n, _)| n == "location")
                .map(|(_, v)| v.as_slice()),
            Some(b"/api/new".as_slice())
        );
        match resp.body {
            Body::Bytes(b) => assert_eq!(b, b"ok"),
            _ => panic!("expected bytes"),
        }
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;
    use crate::http::{Headers, Version};

    #[allow(clippy::too_many_arguments)]
    fn execute(
        cfg: &Config,
        vhost: Option<&VHost>,
        scope: &Scope,
        req: &Request,
        url_path: &str,
        target: &Target,
        peer: SocketAddr,
        local_port: u16,
        https: bool,
        host: &str,
        local_ip: &str,
    ) -> Response {
        let resource = crate::access::ResourceKey::request(
            vhost,
            req,
            url_path,
            None,
            Some(target.proxy_url.as_str()),
        );
        super::execute(
            cfg,
            vhost,
            scope,
            req,
            url_path,
            target,
            peer,
            local_port,
            https,
            host,
            local_ip,
            &crate::access::test_grant(),
            &resource,
        )
    }
    use std::collections::HashMap;
    use std::fs;
    use std::net::TcpListener;

    fn config(root: &Path) -> Config {
        let path = root.join("httpd.conf");
        fs::write(&path, "Listen 127.0.0.1:0\n").unwrap();
        Config::load(&path, root, &HashMap::new(), &HashMap::new(), false).unwrap()
    }

    fn req(path: &str) -> Request {
        Request {
            method: "GET".into(),
            target: path.as_bytes().to_vec(),
            raw_path: path.as_bytes().to_vec(),
            query: Vec::new(),
            version: Version::Http11,
            headers: Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    fn target(cfg: &Config, port: u16) -> Target {
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/app".into(),
                backend: format!("http://127.0.0.1:{port}/"),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
            });
        match_target(cfg, &scope, "/app/chunked").unwrap()
    }

    #[test]
    fn decodes_chunked_upstream_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).unwrap();
            s.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
            )
            .unwrap();
        });
        let dir = std::env::temp_dir().join(format!("vapache-proxy-more-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = config(&dir);
        let scope = {
            let mut s = Scope::default();
            s.proxy_policy
                .proxy_passes
                .push(crate::config::ProxyPassRule {
                    prefix: "/app".into(),
                    backend: format!("http://127.0.0.1:{port}/"),
                    sticky_cookie: None,
                    fail_on_status: Vec::new(),
                });
            s
        };
        let r = execute(
            &cfg,
            None,
            &scope,
            &req("/app/chunked"),
            "/app/chunked",
            &target(&cfg, port),
            "127.0.0.1:1".parse().unwrap(),
            80,
            false,
            "localhost",
            "127.0.0.1",
        );
        assert_eq!(r.status, 200);
        match r.body {
            Body::Bytes(b) => assert_eq!(b, b"Wikipedia"),
            _ => panic!("expected bytes"),
        }
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn connection_failure_returns_502() {
        let dir = std::env::temp_dir().join(format!("vapache-proxy-fail-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = config(&dir);
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/app".into(),
                backend: "http://127.0.0.1:1/".into(),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
            });
        let t = match_target(&cfg, &scope, "/app/x").unwrap();
        let r = execute(
            &cfg,
            None,
            &scope,
            &req("/app/x"),
            "/app/x",
            &t,
            "127.0.0.1:1".parse().unwrap(),
            80,
            false,
            "localhost",
            "127.0.0.1",
        );
        assert_eq!(r.status, 502);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn balancer_round_robins_between_members() {
        let dir = std::env::temp_dir().join(format!("vapache-proxy-bal-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut cfg = config(&dir);
        cfg.balancers = vec![crate::config::Balancer {
            name: "cluster".into(),
            health: crate::config::HealthTemplate::default(),
            sticky_cookie: None,
            sticky_sep: None,
            fail_on_status: Vec::new(),
            members: vec![
                BalancerMember {
                    url: "http://127.0.0.1:9001/".into(),
                    ..BalancerMember::default()
                },
                BalancerMember {
                    url: "http://127.0.0.1:9002/".into(),
                    ..BalancerMember::default()
                },
            ],
        }];
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/bal".into(),
                backend: "balancer://cluster/".into(),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
            });
        let first = match_target(&cfg, &scope, "/bal/x").unwrap();
        let second = match_target(&cfg, &scope, "/bal/x").unwrap();
        assert_ne!(first.backend.port, second.backend.port);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_does_not_reuse_keepalive_connection() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let accepts_thread = accepts.clone();
        let stop_thread = stop.clone();
        let handle = std::thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        accepts_thread.fetch_add(1, Ordering::Relaxed);
                        std::thread::spawn(move || {
                            let mut buf = Vec::new();
                            loop {
                                buf.clear();
                                let mut byte = [0u8; 1];
                                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                    match stream.read(&mut byte) {
                                        Ok(0) | Err(_) => return,
                                        Ok(_) => buf.push(byte[0]),
                                    }
                                }
                                if stream
                                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                                    .is_err()
                                {
                                    return;
                                }
                            }
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        let dir = std::env::temp_dir().join(format!("vapache-proxy-pool-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = config(&dir);
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/pool".into(),
                backend: format!("http://127.0.0.1:{port}/"),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
            });
        let request = req("/pool/x");
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        for _ in 0..3 {
            let target = match_target(&cfg, &scope, "/pool/x").unwrap();
            let response = execute(
                &cfg,
                None,
                &scope,
                &request,
                "/pool/x",
                &target,
                peer,
                80,
                false,
                "localhost",
                "127.0.0.1",
            );
            assert_eq!(response.status, 200);
        }
        // Pooling is deliberately disabled: a backend must not be able to
        // leave bytes that are consumed as the next response.
        assert_eq!(accepts.load(Ordering::Relaxed), 3);
        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn passive_balancer_failover_skips_dead_member() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let live = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut s, _) = listener.accept().unwrap();
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).unwrap();
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .unwrap();
            }
        });
        let dir =
            std::env::temp_dir().join(format!("vapache-proxy-failover-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut cfg = config(&dir);
        cfg.balancers = vec![crate::config::Balancer {
            name: "failover".into(),
            health: crate::config::HealthTemplate::default(),
            sticky_cookie: None,
            sticky_sep: None,
            fail_on_status: Vec::new(),
            members: vec![
                BalancerMember {
                    url: "http://127.0.0.1:1/".into(),
                    ..BalancerMember::default()
                },
                BalancerMember {
                    url: format!("http://127.0.0.1:{live}/"),
                    ..BalancerMember::default()
                },
            ],
        }];
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/fo".into(),
                backend: "balancer://failover/".into(),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
            });
        let req = req("/fo/x");
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let first = match_target(&cfg, &scope, "/fo/x").unwrap();
        let r1 = execute(
            &cfg,
            None,
            &scope,
            &req,
            "/fo/x",
            &first,
            peer,
            80,
            false,
            "localhost",
            "127.0.0.1",
        );
        assert_eq!(r1.status, 200);
        let second = match_target(&cfg, &scope, "/fo/x").unwrap();
        let r2 = execute(
            &cfg,
            None,
            &scope,
            &req,
            "/fo/x",
            &second,
            peer,
            80,
            false,
            "localhost",
            "127.0.0.1",
        );
        assert_eq!(r2.status, 200);
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn large_fixed_length_proxy_body_is_streamed() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = vec![b'z'; 300 * 1024];
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).unwrap();
            let _ = s.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = s.write_all(&body);
        });
        let dir = std::env::temp_dir().join(format!("vapache-proxy-stream-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = config(&dir);
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/stream".into(),
                backend: format!("http://127.0.0.1:{port}/"),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
            });
        let request = req("/stream/x");
        let target = match_target(&cfg, &scope, "/stream/x").unwrap();
        let mut response = execute(
            &cfg,
            None,
            &scope,
            &request,
            "/stream/x",
            &target,
            "127.0.0.1:1".parse().unwrap(),
            80,
            false,
            "localhost",
            "127.0.0.1",
        );
        assert_eq!(response.status, 200);
        match &mut response.body {
            Body::Stream { reader, len } => {
                assert_eq!(*len, 300 * 1024);
                let mut all = Vec::new();
                reader.read_to_end(&mut all).unwrap();
                assert_eq!(all.len(), 300 * 1024);
            }
            _ => panic!("expected streamed body"),
        }
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn failonstatus_retries_another_member() {
        let a = TcpListener::bind("127.0.0.1:0").unwrap();
        let b = TcpListener::bind("127.0.0.1:0").unwrap();
        let p1 = a.local_addr().unwrap().port();
        let p2 = b.local_addr().unwrap().port();
        let h1 = std::thread::spawn(move || {
            let (mut s, _) = a.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).unwrap();
            let _ = s
                .write_all(b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        });
        let h2 = std::thread::spawn(move || {
            let (mut s, _) = b.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).unwrap();
            let _ =
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        });
        let dir =
            std::env::temp_dir().join(format!("vapache-proxy-failstatus-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut cfg = config(&dir);
        cfg.balancers = vec![crate::config::Balancer {
            name: "failstatus".into(),
            health: crate::config::HealthTemplate::default(),
            sticky_cookie: None,
            sticky_sep: None,
            fail_on_status: vec![500],
            members: vec![
                BalancerMember {
                    url: format!("http://127.0.0.1:{p1}/"),
                    ..BalancerMember::default()
                },
                BalancerMember {
                    url: format!("http://127.0.0.1:{p2}/"),
                    ..BalancerMember::default()
                },
            ],
        }];
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/fs".into(),
                backend: "balancer://failstatus/".into(),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
            });
        let request = req("/fs/x");
        let target = match_target(&cfg, &scope, "/fs/x").unwrap();
        let response = execute(
            &cfg,
            None,
            &scope,
            &request,
            "/fs/x",
            &target,
            "127.0.0.1:1".parse().unwrap(),
            80,
            false,
            "localhost",
            "127.0.0.1",
        );
        assert_eq!(response.status, 200);
        h1.join().unwrap();
        h2.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sticky_session_selects_route_member() {
        let dir = std::env::temp_dir().join(format!("vapache-proxy-sticky-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut cfg = config(&dir);
        cfg.balancers = vec![crate::config::Balancer {
            name: "sticky".into(),
            health: crate::config::HealthTemplate::default(),
            sticky_cookie: Some("JSESSIONID".into()),
            sticky_sep: None,
            fail_on_status: Vec::new(),
            members: vec![
                BalancerMember {
                    url: "http://127.0.0.1:9001/".into(),
                    route: Some("node1".into()),
                    ..BalancerMember::default()
                },
                BalancerMember {
                    url: "http://127.0.0.1:9002/".into(),
                    route: Some("node2".into()),
                    ..BalancerMember::default()
                },
            ],
        }];
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/sticky".into(),
                backend: "balancer://sticky/".into(),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
            });
        let mut request = req("/sticky/x");
        request.headers.insert("cookie", "JSESSIONID=abc.node2");
        let target = match_target_req(&cfg, &scope, "/sticky/x", Some(&request)).unwrap();
        assert_eq!(target.backend.port, 9002);
        // ProxyPass can supply the sticky cookie directly.
        cfg.balancers[0].sticky_cookie = None;
        scope.proxy_policy.proxy_passes[0].sticky_cookie = Some("JSESSIONID|jsessionid".into());
        let target = match_target_req(&cfg, &scope, "/sticky/x", Some(&request)).unwrap();
        assert_eq!(target.backend.port, 9002);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_rejects_ambiguous_backend_framing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            let _ = sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            );
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let target = Target {
            backend: HttpBackend {
                host: "127.0.0.1".into(),
                port,
                base: "/".into(),
                tls: false,
            },
            path: "/".into(),
            suffix: String::new(),
            reverse: Vec::new(),
            balancer: None,
            fail_on_status: Vec::new(),
            proxy_url: "http://127.0.0.1/".into(),
        };
        let request = req("/");
        let result = proxy_once(
            Box::new(stream),
            &target,
            &request,
            &Scope::default(),
            "/",
            "127.0.0.1:1".parse().unwrap(),
            false,
            "localhost",
        );
        assert!(result.is_err());
        handle.join().unwrap();
    }

    #[test]
    fn proxy_path_is_encoded_exactly_once() {
        assert_eq!(encode_proxy_path("/a%2Fb?x#y"), "/a%252Fb%3Fx%23y");
        assert_eq!(encode_proxy_path("/space here"), "/space%20here");
    }

    #[test]
    fn canonical_proxy_url_tracks_backend_and_ipv6() {
        let backend = parse_http_url("http://[::1]:8080/base/").unwrap();
        assert_eq!(backend.host, "[::1]");
        assert_eq!(backend.port, 8080);
        assert_eq!(
            canonical_proxy_url(&backend, "/base/x"),
            "http://[::1]:8080/base/x"
        );
        let default_port = parse_http_url("https://example.test/").unwrap();
        assert_eq!(
            canonical_proxy_url(&default_port, "/x"),
            "https://example.test/x"
        );
    }

    #[test]
    fn proxy_pass_auth_url_is_the_outbound_target() {
        let dir =
            std::env::temp_dir().join(format!("vapache-proxy-auth-url-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = config(&dir);
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/app".into(),
                backend: "http://127.0.0.1:9000/".into(),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
            });
        let target = match_target(&cfg, &scope, "/app/x").unwrap();
        assert_eq!(target.proxy_url, "http://127.0.0.1:9000/x");
        let expected: String = vapache_verified::proxy_target_key(b"127.0.0.1", 9000, false, b"/x")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(target.binding_key(), expected);
        let other = match_target(&cfg, &scope, "/app/y").unwrap();
        assert_ne!(target.binding_key(), other.binding_key());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn regex_proxy_pass_match_targets() {
        let dir = std::env::temp_dir().join(format!("vapache-proxy-regex-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = config(&dir);
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_rules
            .push(crate::config::ProxyRule {
                pattern: std::sync::Arc::new(regex::Regex::new("^/(.*\\.php)$").unwrap()),
                backend: "http://127.0.0.1:9000/$1".into(),
            });
        let t = match_target(&cfg, &scope, "/index.php").unwrap();
        assert_eq!(t.path, "/index.php");
        let _ = fs::remove_dir_all(&dir);
    }
}
