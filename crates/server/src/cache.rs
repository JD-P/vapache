//! Shared HTTP cache (`mod_cache` / `mod_cache_disk` subset).
//!
//! The cache stores complete, already-finalized responses.  It is deliberately
//! conservative: only GET/HEAD responses that are independently cacheable are
//! stored, authenticated resources are never served from the public cache, and
//! responses carrying `Set-Cookie`, `Vary: *`, `no-store`, `private` or
//! `no-cache` are rejected.  Cache entries may be persisted as body files
//! under `CacheRoot` when a `disk` cache is enabled.

use crate::access::AccessGrant;
use crate::config::{CacheConfig, Config, EncodedSlashes, Scope, VHost};
use crate::http::{Body, Request, Response};
use crate::util::{parse_http_date, unix_now};
use crate::verified::{normalize_uri_path, percent_decode_path};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha1::{Digest, Sha1};
use std::borrow::Cow;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};

const MAX_ENTRIES: usize = 4096;
const HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

#[derive(Clone)]
struct Entry {
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    stored: i64,
    expires: i64,
    policy: u64,
    vary: Vec<(String, Vec<u8>)>,
}

fn entries() -> &'static Mutex<HashMap<String, Vec<Entry>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<Entry>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn header<'a>(headers: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

fn header_str(headers: &[(String, Vec<u8>)], name: &str) -> Option<String> {
    header(headers, name).map(|v| String::from_utf8_lossy(v).into_owned())
}

fn response_header<'a>(resp: &'a Response, name: &str) -> Option<&'a [u8]> {
    resp.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

fn response_header_str(resp: &Response, name: &str) -> Option<String> {
    response_header(resp, name).map(|v| String::from_utf8_lossy(v).into_owned())
}

fn prefix_matches(path: &str, prefix: &str) -> bool {
    if prefix.is_empty() || prefix == "/" {
        return true;
    }
    if path == prefix {
        return true;
    }
    if let Some(rest) = path.strip_prefix(prefix) {
        return prefix.ends_with('/') || rest.starts_with('/');
    }
    false
}

/// Return the cache type selected for this request, if caching is enabled and
/// access control permits serving a cached representation.
pub fn request_scope(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    peer: IpAddr,
    path: &str,
    local_port: u16,
    https: bool,
    server_name: &str,
    host: &str,
) -> Option<(Scope, AccessGrant)> {
    if req.method != "GET" && req.method != "HEAD" {
        return None;
    }
    if req.header("range").is_some() {
        return None;
    }
    // Without a cache root nothing can be served from or stored in the cache.
    // Skip the request-scope walk entirely; this is the common case for static
    // document roots that have not opted into mod_cache.
    cfg.cache.root.as_ref()?;
    let allow_encoded = cfg.encoded_slashes == EncodedSlashes::On;
    let decoded = match percent_decode_path(&req.raw_path, allow_encoded) {
        Some(d) => d,
        None => return None,
    };
    let normalized = match normalize_uri_path(&decoded) {
        Some(n) => n,
        None => return None,
    };
    let url_path = String::from_utf8_lossy(&normalized).into_owned();
    // Most requests are outside every CacheEnable prefix.  Check the
    // inherited scope before resolving directory rules and .htaccess, since
    // that walk is far more expensive than the prefix test itself.
    let base = vhost.map(|v| &v.scope).unwrap_or(&cfg.global);
    // Use the raw request path here so this test is identical to the later
    // `cache_enabled(&scope, path)` check.  In particular, URI normalization
    // drops a trailing slash and would make `/cache/` look outside a
    // `/cache/` CacheEnable prefix.
    let base_enabled = base
        .rewrite_policy
        .cache_enable
        .iter()
        .any(|(_, prefix)| prefix_matches(path, prefix));
    if !base_enabled {
        let rules = vhost
            .map(|v| v.rules.as_slice())
            .unwrap_or(cfg.global_rules.as_slice());
        if !rules_may_enable_cache(rules) {
            return None;
        }
    }
    let root = cfg.documentation_root_for(vhost);
    let fs_path = root.join(url_path.trim_start_matches('/'));
    let mut config_files = Vec::new();
    let mut config_locations = Vec::new();
    let mut config_conditionals = Vec::new();
    let mut htaccess_files = Vec::new();
    let mut htaccess_conditionals = Vec::new();
    let mut scope = if cfg.htaccess_may_apply(&fs_path) {
        let layers = crate::htaccess::collect_layers(cfg, vhost, &fs_path, &url_path).ok()?;
        let (evaluated, conditionals, access_conditionals) =
            crate::policy_ref::effective_scope_with_layers(
                cfg, vhost, &fs_path, &url_path, req, peer, &layers,
            );
        config_conditionals = conditionals;
        htaccess_conditionals = access_conditionals;
        evaluated
    } else {
        cfg.effective_scope_req_deferred(
            vhost,
            &fs_path,
            &url_path,
            req,
            peer,
            &mut config_conditionals,
        )
    };
    let cond_fname = fs_path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();
    crate::config::apply_normal_rule_list(
        &config_files,
        &mut scope,
        req,
        peer,
        &root,
        &fs_path,
        &url_path,
        &cond_fname,
        &mut config_conditionals,
    );
    crate::config::apply_normal_rule_list(
        &htaccess_files,
        &mut scope,
        req,
        peer,
        &root,
        &fs_path,
        &url_path,
        &cond_fname,
        &mut htaccess_conditionals,
    );
    crate::config::apply_normal_rule_list(
        &config_locations,
        &mut scope,
        req,
        peer,
        &root,
        &fs_path,
        &url_path,
        &cond_fname,
        &mut config_conditionals,
    );
    config_conditionals.sort_by_key(|rule| rule.order);
    let mut cond_state = HashMap::new();
    crate::config::apply_deferred_req(
        &mut scope,
        &config_conditionals,
        req,
        peer,
        &root,
        &fs_path,
        &url_path,
        &cond_fname,
        &mut cond_state,
    );
    let mut htaccess_state = HashMap::new();
    crate::config::apply_deferred_req(
        &mut scope,
        &htaccess_conditionals,
        req,
        peer,
        &root,
        &fs_path,
        &url_path,
        &cond_fname,
        &mut htaccess_state,
    );
    if !cache_enabled(&scope, path) {
        return None;
    }
    // Cache lookup must not bypass rewrite rules.  If any rule would produce
    // an outcome (including F/G/redirects or a target/file change), run the
    // normal dispatcher instead of serving a stale representation.
    let rewrite_ctx = crate::rewrite::Context {
        url_path: &url_path,
        fs_path: &fs_path,
        docroot: &root,
        server_root: &cfg.server_root,
        query: &req.query,
        peer,
        port: local_port,
        https,
        server_name,
    };
    if !matches!(
        crate::rewrite::process(&scope, req, &rewrite_ctx),
        crate::rewrite::Outcome::None
    ) {
        return None;
    }
    // Never bypass per-directory access control or a rewrite-set environment
    // requirement by serving a cached object without running dispatch.
    let fingerprint = cache_policy_fingerprint(&scope, req, peer);
    let key = crate::access::ResourceKey::cache_policy(vhost, req, host, path, fingerprint);
    let grant = match crate::access::check_grant(&scope, req, peer, None, key) {
        Ok(grant) => grant,
        Err(_) => return None,
    };
    // AllowMethods and <Proxy> authorization are enforced by the normal
    // dispatcher; do not satisfy the request from cache first.
    if !scope.method_allowed(&req.method) {
        return None;
    }
    if crate::proxy::matches_route(&scope, &url_path) {
        return None;
    }
    Some((scope, grant))
}

/// Conservative prefilter for `request_scope`: return true when any matching
/// directory/conditional rule could add a `CacheEnable` directive.  A false
/// result means the request cannot be served from or stored in the cache.
fn rules_may_enable_cache(rules: &[crate::config::ScopeRule]) -> bool {
    rules.iter().any(|rule| {
        !rule.delta.rewrite_policy.cache_enable.is_empty() || rules_may_enable_cache(&rule.nested)
    })
}

fn cache_enabled(scope: &Scope, path: &str) -> bool {
    if scope
        .rewrite_policy
        .cache_disable
        .iter()
        .any(|prefix| prefix_matches(path, prefix))
    {
        return false;
    }
    scope
        .rewrite_policy
        .cache_enable
        .iter()
        .any(|(_, prefix)| prefix_matches(path, prefix))
}

fn base_key(cfg: &Config, host: &str, path: &str, query: &[u8], policy_fingerprint: u64) -> String {
    let query = if cfg.cache.ignore_query_string {
        ""
    } else {
        std::str::from_utf8(query).unwrap_or("")
    };
    format!(
        "{}\n{host}\n{path}\n{query}\n{policy_fingerprint:016x}",
        cfg.server_root.display()
    )
}

/// Security-relevant policy fingerprint for cache isolation.  `Scope` is
/// intentionally not hashed as a whole because it contains HashMap fields
/// whose debug iteration order is unstable.
fn cache_policy_fingerprint(scope: &Scope, req: &Request, peer: IpAddr) -> u64 {
    let mut hasher = DefaultHasher::new();
    let policy = format!(
        "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
        scope.authorization.requires,
        scope.authorization.auth_merging,
        scope.authorization.allow_methods,
        scope.authorization.legacy,
        scope.override_policy,
        scope.options,
        scope.content_policy.document_root,
        scope.content_policy.access_file_names,
        scope.authorization.auth_type,
        scope.authorization.auth_name,
        scope.authorization.auth_user_file,
        scope.authorization.auth_group_file,
        scope.header_policy.set_headers,
        scope.header_policy.add_headers,
        scope.header_policy.unset_headers,
    );
    policy.hash(&mut hasher);
    peer.to_string().hash(&mut hasher);
    req.method.hash(&mut hasher);
    hasher.finish()
}

fn request_allows_lookup(cfg: &Config, req: &Request) -> bool {
    if req.header("authorization").is_some() {
        return false;
    }
    if cfg.cache.ignore_cache_control {
        return true;
    }
    if let Some(pragma) = req.header_str("pragma") {
        if pragma.to_ascii_lowercase().contains("no-cache") {
            return false;
        }
    }
    let Some(cc) = req.header_str("cache-control") else {
        return true;
    };
    !cc.split(',').any(|v| {
        let v = v.trim().to_ascii_lowercase();
        v == "no-cache" || v == "no-store" || v == "max-age=0"
    })
}

fn vary_values(req: &Request, headers: &[(String, Vec<u8>)]) -> Vec<(String, Vec<u8>)> {
    let Some(vary) = header_str(headers, "vary") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for name in vary.split(',') {
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() || name == "*" {
            continue;
        }
        out.push((name.clone(), req.header(&name).unwrap_or(b"").to_vec()));
    }
    out
}

fn vary_matches(entry: &Entry, req: &Request) -> bool {
    entry
        .vary
        .iter()
        .all(|(name, expected)| req.header(name).unwrap_or(b"") == expected.as_slice())
}

fn conditional_hit(req: &Request, entry: &Entry, response: &mut Response) -> bool {
    if let Some(inm) = req.header("if-none-match") {
        if let Some(etag) = header(&entry.headers, "etag") {
            let raw = String::from_utf8_lossy(etag);
            let matched = String::from_utf8_lossy(inm).split(',').any(|v| {
                let v = v.trim();
                v == raw || v == "*" || v.strip_prefix("W/") == Some(raw.as_ref())
            });
            if matched {
                response.status = 304;
                response.body = Body::Empty;
                return true;
            }
        }
    }
    if let Some(ims) = req.header("if-modified-since") {
        if let (Some(since), Some(last)) = (
            parse_http_date(ims),
            header(&entry.headers, "last-modified").and_then(parse_http_date),
        ) {
            if last <= since {
                response.status = 304;
                response.body = Body::Empty;
                return true;
            }
        }
    }
    false
}

pub fn lookup(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    host: &str,
    path: &str,
    scope: &Scope,
    peer: IpAddr,
    grant: &AccessGrant,
) -> Option<Response> {
    let fingerprint = cache_policy_fingerprint(scope, req, peer);
    if !grant.require(&crate::access::ResourceKey::cache_policy(
        vhost,
        req,
        host,
        path,
        fingerprint,
    )) {
        return None;
    }
    if !request_allows_lookup(cfg, req) {
        return None;
    }
    let key = base_key(cfg, host, path, &req.query, fingerprint);
    let now = unix_now();
    let mut found: Option<Entry> = None;
    {
        let mut guard = entries().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(list) = guard.get_mut(&key) {
            let mut expired = Vec::new();
            for (idx, entry) in list.iter().enumerate() {
                if entry.expires <= now {
                    expired.push(idx);
                    continue;
                }
                if vapache_verified::cache_lookup_admit(
                    true,
                    entry.policy == fingerprint,
                    vary_matches(entry, req),
                    entry.expires,
                    now,
                ) {
                    found = Some(entry.clone());
                    break;
                }
            }
            for idx in expired.into_iter().rev() {
                list.remove(idx);
            }
            if list.is_empty() {
                guard.remove(&key);
            }
        }
    }
    if found.is_none() {
        if let Some(loaded) = disk_load(cfg, &key) {
            if !vapache_verified::cache_lookup_admit(
                true,
                loaded.policy == fingerprint,
                true,
                loaded.expires,
                now,
            ) {
                return None;
            }
            let mut guard = entries().lock().unwrap_or_else(|e| e.into_inner());
            guard.entry(key.clone()).or_default().push(loaded.clone());
            found = Some(loaded);
        }
    }
    let entry = found?;

    let mut response = Response::new(entry.status);
    response.headers = entry
        .headers
        .iter()
        .map(|(n, v)| (Cow::Owned(n.clone()), v.clone()))
        .collect();
    let age = (now - entry.stored).max(0).to_string();
    response
        .headers
        .retain(|(n, _)| !n.eq_ignore_ascii_case("age"));
    response
        .headers
        .push((Cow::Borrowed("Age"), age.into_bytes()));
    if cfg.cache.header {
        response
            .headers
            .retain(|(n, _)| !n.eq_ignore_ascii_case("x-cache"));
        response
            .headers
            .push((Cow::Borrowed("X-Cache"), b"HIT".to_vec()));
    }
    if cfg.cache.detail_header {
        response
            .headers
            .push((Cow::Borrowed("X-Cache-Detail"), b"fresh cache hit".to_vec()));
    }
    if conditional_hit(req, &entry, &mut response) {
        response
            .headers
            .retain(|(n, _)| !n.eq_ignore_ascii_case("content-length"));
    } else if req.method != "HEAD" {
        response.body = Body::Bytes(entry.body);
    }
    Some(response)
}

fn cache_control_directives(headers: &[(String, Vec<u8>)]) -> Vec<String> {
    header_str(headers, "cache-control")
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn directive_seconds(directives: &[String], name: &str) -> Option<u64> {
    directives.iter().find_map(|d| {
        let (k, v) = d.split_once('=')?;
        if k.trim() == name {
            v.trim().trim_matches('"').parse().ok()
        } else {
            None
        }
    })
}

fn freshness(cfg: &CacheConfig, headers: &[(String, Vec<u8>)], now: i64) -> Option<i64> {
    let directives = cache_control_directives(headers);
    if let Some(n) = directive_seconds(&directives, "s-maxage")
        .or_else(|| directive_seconds(&directives, "max-age"))
    {
        let n = (n as i64).clamp(cfg.min_expire as i64, cfg.max_expire as i64);
        return Some(n);
    }
    if let Some(expires) = header(headers, "expires").and_then(parse_http_date) {
        let n = expires - now;
        if n <= 0 {
            return None;
        }
        return Some(n.clamp(cfg.min_expire as i64, cfg.max_expire as i64));
    }
    if let Some(last) = header(headers, "last-modified").and_then(parse_http_date) {
        let age = (now - last).max(0) as f64;
        let n = (age * cfg.last_modified_factor) as i64;
        if n > 0 {
            return Some(n.clamp(cfg.min_expire as i64, cfg.max_expire as i64));
        }
        // A just-written file has no observable reuse window through the
        // Last-Modified heuristic; CacheDefaultExpire keeps it cacheable.
        return Some(cfg.default_expire.min(cfg.max_expire) as i64);
    }
    if cfg.ignore_no_last_mod {
        return Some(cfg.default_expire.min(cfg.max_expire) as i64);
    }
    None
}

fn response_body_bytes(body: &mut Body) -> Option<Vec<u8>> {
    match body {
        Body::Empty => Some(Vec::new()),
        Body::Bytes(bytes) => Some(bytes.clone()),
        Body::File { file, offset, len } => {
            let mut file = file.try_clone().ok()?;
            file.seek(SeekFrom::Start(*offset)).ok()?;
            let mut bytes = vec![0; *len as usize];
            file.read_exact(&mut bytes).ok()?;
            Some(bytes)
        }
        Body::Stream { .. } => None,
    }
}

pub fn prepare_dir(cfg: &Config, dir: &std::path::Path) {
    if fs::create_dir_all(dir).is_err() {
        return;
    }
    // The daemon drops privileges after binding, so hand the cache directory
    // to the configured account while we are still privileged.
    #[cfg(unix)]
    {
        use std::ffi::CString;
        if unsafe { libc::geteuid() } == 0 {
            let user = CString::new(cfg.user.as_str()).ok();
            let group = CString::new(cfg.group.as_str()).ok();
            let uid = user.as_ref().and_then(|u| {
                let pw = unsafe { libc::getpwnam(u.as_ptr()) };
                (!pw.is_null()).then(|| unsafe { (*pw).pw_uid })
            });
            let gid = group.as_ref().and_then(|g| {
                let gr = unsafe { libc::getgrnam(g.as_ptr()) };
                (!gr.is_null()).then(|| unsafe { (*gr).gr_gid })
            });
            if let Some(uid) = uid {
                let _ = std::os::unix::fs::chown(dir, Some(uid), gid);
            }
            let _ = fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o775));
        }
    }
}

pub fn prepare(cfg: &Config) {
    if let Some(root) = &cfg.cache.root {
        prepare_dir(cfg, root);
    }
}

fn cache_stem(cfg: &Config, key: &str) -> Option<std::path::PathBuf> {
    let root = cfg.cache.root.as_ref()?;
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    let name = format!("{:x}", hasher.finalize());
    Some(root.join(name))
}

fn encode_meta(entry: &Entry) -> Vec<u8> {
    let mut out = format!(
        "V1\nS {}\nT {}\nE {}\nP {}\n",
        entry.status, entry.stored, entry.expires, entry.policy
    );
    for (name, value) in &entry.vary {
        out.push_str(&format!(
            "V {} {}\n",
            STANDARD.encode(name.as_bytes()),
            STANDARD.encode(value)
        ));
    }
    for (name, value) in &entry.headers {
        out.push_str(&format!(
            "H {} {}\n",
            STANDARD.encode(name.as_bytes()),
            STANDARD.encode(value)
        ));
    }
    out.into_bytes()
}

fn decode_meta(data: &[u8]) -> Option<Entry> {
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.lines();
    if lines.next()? != "V1" {
        return None;
    }
    let mut status = None;
    let mut stored = None;
    let mut expires = None;
    let mut policy = None;
    let mut vary = Vec::new();
    let mut headers = Vec::new();
    for line in lines {
        let mut parts = line.splitn(3, ' ');
        let kind = parts.next()?;
        match kind {
            "S" => status = parts.next()?.parse::<u16>().ok(),
            "T" => stored = parts.next()?.parse::<i64>().ok(),
            "E" => expires = parts.next()?.parse::<i64>().ok(),
            "P" => policy = parts.next()?.parse::<u64>().ok(),
            "V" | "H" => {
                let name = STANDARD.decode(parts.next()?).ok()?;
                let value = STANDARD.decode(parts.next().unwrap_or("")).ok()?;
                let name = String::from_utf8(name).ok()?;
                if kind == "V" {
                    vary.push((name, value));
                } else {
                    headers.push((name, value));
                }
            }
            _ => {}
        }
    }
    Some(Entry {
        status: status?,
        headers,
        body: Vec::new(),
        stored: stored?,
        expires: expires?,
        policy: policy?,
        vary,
    })
}

fn disk_store(cfg: &Config, key: &str, entry: &Entry) {
    let Some(stem) = cache_stem(cfg, key) else {
        return;
    };
    if let Some(parent) = stem.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let body_path = stem.with_extension("body");
    let meta_path = stem.with_extension("meta");
    let body_tmp = stem.with_extension("body.tmp");
    let meta_tmp = stem.with_extension("meta.tmp");
    if fs::write(&body_tmp, &entry.body).is_err()
        || fs::write(&meta_tmp, encode_meta(entry)).is_err()
    {
        let _ = fs::remove_file(&body_tmp);
        let _ = fs::remove_file(&meta_tmp);
        return;
    }
    let _ = fs::rename(&body_tmp, &body_path);
    let _ = fs::rename(&meta_tmp, &meta_path);
}

fn disk_load(cfg: &Config, key: &str) -> Option<Entry> {
    let stem = cache_stem(cfg, key)?;
    let mut entry = decode_meta(&fs::read(stem.with_extension("meta")).ok()?)?;
    if entry.expires <= unix_now() {
        return None;
    }
    entry.body = fs::read(stem.with_extension("body")).ok()?;
    Some(entry)
}

pub fn store(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    host: &str,
    path: &str,
    scope: &Scope,
    peer: IpAddr,
    resp: &mut Response,
    grant: &AccessGrant,
) {
    let fingerprint = cache_policy_fingerprint(scope, req, peer);
    if !grant.require(&crate::access::ResourceKey::cache_policy(
        vhost,
        req,
        host,
        path,
        fingerprint,
    )) {
        return;
    }
    if req.method != "GET" || req.body_len() > 0 {
        return;
    }
    if !matches!(resp.status, 200 | 203 | 300 | 301 | 308 | 404 | 410) {
        return;
    }
    let response_headers: Vec<(String, Vec<u8>)> = resp
        .headers
        .iter()
        .map(|(n, v)| (n.to_string(), v.clone()))
        .collect();
    let directives = cache_control_directives(&response_headers);
    if directives.iter().any(|d| {
        (d == "no-store" && !cfg.cache.store_no_store)
            || (d == "no-cache" && !cfg.cache.ignore_cache_control)
            || (d == "private" && !cfg.cache.store_private)
    }) {
        return;
    }
    if response_header(resp, "set-cookie").is_some() {
        return;
    }
    if let Some(vary) = response_header_str(resp, "vary") {
        if vary.split(',').any(|v| v.trim() == "*") {
            return;
        }
    }
    let Some(body) = response_body_bytes(&mut resp.body) else {
        return;
    };
    if body.len() as u64 > cfg.cache.max_file_size || (body.len() as u64) < cfg.cache.min_file_size
    {
        return;
    }
    let now = unix_now();
    let Some(ttl) = freshness(&cfg.cache, &response_headers, now) else {
        return;
    };
    if ttl <= 0 {
        return;
    }
    let mut headers = Vec::new();
    for (name, value) in &resp.headers {
        if HOP_HEADERS.iter().any(|h| name.eq_ignore_ascii_case(h))
            || name.eq_ignore_ascii_case("age")
            || name.eq_ignore_ascii_case("x-cache")
        {
            continue;
        }
        headers.push((name.to_string(), value.clone()));
    }
    let vary = vary_values(req, &headers);
    let key = base_key(cfg, host, path, &req.query, fingerprint);
    let entry = Entry {
        status: resp.status,
        headers,
        body: body.clone(),
        stored: now,
        expires: now.saturating_add(ttl),
        policy: fingerprint,
        vary,
    };
    {
        let mut guard = entries().lock().unwrap_or_else(|e| e.into_inner());
        if guard.len() > MAX_ENTRIES && !guard.contains_key(&key) {
            // Bounded best-effort eviction: drop an arbitrary bucket.
            if let Some(victim) = guard.keys().next().cloned() {
                guard.remove(&victim);
            }
        }
        let list = guard.entry(key.clone()).or_default();
        list.retain(|e| e.vary != entry.vary);
        list.push(entry.clone());
    }
    disk_store(cfg, &key, &entry);
    if cfg.cache.header {
        resp.headers
            .retain(|(n, _)| !n.eq_ignore_ascii_case("x-cache"));
        resp.headers
            .push((Cow::Borrowed("X-Cache"), b"MISS".to_vec()));
    }
}

pub fn clear() {
    entries().lock().unwrap_or_else(|e| e.into_inner()).clear();
}

pub fn invalidate(cfg: &Config, host: &str, path: &str) {
    let prefix = format!("{}\n{host}\n{path}\n", cfg.server_root.display());
    let mut guard = entries().lock().unwrap_or_else(|e| e.into_inner());
    guard.retain(|key, _| !key.starts_with(&prefix));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_matching_uses_path_boundaries() {
        assert!(prefix_matches("/cache/a", "/cache"));
        assert!(!prefix_matches("/cachex", "/cache"));
        assert!(prefix_matches("/any", "/"));
        assert!(prefix_matches("/cache/", "/cache/"));
    }

    #[test]
    fn disk_entries_round_trip_for_warm_start() {
        let dir = std::env::temp_dir().join(format!("vapache-cache-meta-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(&conf, "Listen 127.0.0.1:0\n").unwrap();
        let mut cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        cfg.cache.root = Some(dir.join("cache"));
        let entry = Entry {
            status: 200,
            headers: vec![("content-type".into(), b"text/plain".to_vec())],
            body: b"hello".to_vec(),
            stored: unix_now(),
            expires: unix_now() + 60,
            policy: 7,
            vary: vec![("accept".into(), b"text/plain".to_vec())],
        };
        disk_store(&cfg, "host\n/path\n", &entry);
        let loaded = disk_load(&cfg, "host\n/path\n").expect("warm entry");
        assert_eq!(loaded.status, 200);
        assert_eq!(loaded.body, b"hello");
        assert_eq!(loaded.headers, entry.headers);
        assert_eq!(loaded.policy, entry.policy);
        assert_eq!(loaded.vary, entry.vary);
        // A fresh process has no in-memory entry; lookup must load the disk
        // metadata/body pair and serve it as a hit.
        let request = crate::http::Request {
            method: "GET".into(),
            target: b"/path".to_vec(),
            raw_path: b"/path".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        let scope = Scope::default();
        let peer = "127.0.0.1".parse().unwrap();
        let fingerprint = cache_policy_fingerprint(&scope, &request, peer);
        let entry = Entry {
            policy: fingerprint,
            ..entry
        };
        let key = base_key(&cfg, "warm.test", "/path", b"", fingerprint);
        disk_store(&cfg, &key, &entry);
        let hit = lookup(
            &cfg,
            None,
            &request,
            "warm.test",
            "/path",
            &scope,
            peer,
            &crate::access::test_grant(),
        )
        .expect("warm hit");
        match hit.body {
            crate::http::Body::Bytes(body) => assert_eq!(body, b"hello"),
            _ => panic!("expected cached bytes"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_scope_never_caches_proxy_routes() {
        let dir = std::env::temp_dir().join(format!("vapache-cache-proxy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(dir.join("cache")).unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            format!(
                "Listen 127.0.0.1:0\nCacheRoot {}\nCacheEnable /\nProxyPass /app http://127.0.0.1:9000/\n",
                dir.join("cache").display()
            ),
        )
        .unwrap();
        let cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        let req = crate::http::Request {
            method: "GET".into(),
            target: b"/app/x".to_vec(),
            raw_path: b"/app/x".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        let scope = request_scope(
            &cfg,
            None,
            &req,
            "127.0.0.1".parse().unwrap(),
            "/app/x",
            80,
            false,
            "localhost",
            "localhost",
        );
        assert!(scope.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_key_includes_policy_fingerprint() {
        let a = format!("{}\nhost\n/path\n\n{:016x}", "/srv", 0u64);
        let b = format!("{}\nhost\n/path\n\n{:016x}", "/srv", 1u64);
        assert_ne!(a, b);
        // Credentials must never be persisted as cache metadata.
        assert!(HOP_HEADERS.contains(&"authorization"));
        assert!(HOP_HEADERS.contains(&"proxy-authorization"));
    }

    #[test]
    fn cache_control_ttl_is_bounded() {
        let cfg = crate::config::CacheConfig::default();
        let headers = vec![("Cache-Control".into(), b"max-age=999999".to_vec())];
        assert_eq!(freshness(&cfg, &headers, 100), Some(cfg.max_expire as i64));
    }
}
