//! Shared HTTP cache (`mod_cache` / `mod_cache_disk` subset).
//!
//! The cache stores complete, already-finalized responses.  It is deliberately
//! conservative: only GET/HEAD responses that are independently cacheable are
//! stored, authenticated resources are never served from the public cache, and
//! responses carrying `Set-Cookie`, `Vary: *`, `no-store`, `private` or
//! `no-cache` are rejected.  Cache entries may be persisted as body files
//! under `CacheRoot` when a `disk` cache is enabled.

use crate::access::AccessGrant;
use crate::config::{CacheConfig, Config, Scope, VHost};
use crate::http::{Body, Request, Response};
use crate::util::{parse_http_date, unix_now};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha1::{Digest, Sha1};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

const MAX_ENTRIES: usize = 4096;
/// The on-disk cache has its own hard entry cap; the in-memory key cap alone
/// would still let unique URLs fill the cache filesystem (F44).
const MAX_DISK_ENTRIES: usize = 4096;
/// Bound the number of stored variants for one key before evicting the oldest
/// representation.
const MAX_VARIANTS_PER_KEY: usize = 32;
/// Full-strength policy/request digest.  The previous 64-bit fingerprint was
/// collision-prone for an attacker who can vary request headers and force
/// variants of one cache key.  A SHA-256 digest is still compared exactly.
type PolicyFingerprint = [u8; 32];
/// Configuration generation for persisted cache entries.  A reload bumps this
/// value; entries from an older generation are never served, even if their
/// body/meta files survived the reload cleanup.
static CACHE_EPOCH: AtomicU64 = AtomicU64::new(1);

fn current_epoch() -> u64 {
    CACHE_EPOCH.load(Ordering::SeqCst)
}

fn bump_epoch() -> u64 {
    CACHE_EPOCH.fetch_add(1, Ordering::SeqCst) + 1
}
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
    policy: PolicyFingerprint,
    epoch: u64,
    vary: Vec<(String, Vec<u8>)>,
}

fn entries() -> &'static Mutex<HashMap<String, Vec<Entry>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<Entry>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Default)]
struct DiskUsageState {
    total: u64,
    /// stem -> (accounted bytes, oldest modification time)
    stems: HashMap<PathBuf, (u64, SystemTime)>,
}

fn disk_usage() -> &'static Mutex<HashMap<PathBuf, DiskUsageState>> {
    static USAGE: OnceLock<Mutex<HashMap<PathBuf, DiskUsageState>>> = OnceLock::new();
    USAGE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn disk_stem(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_string_lossy();
    let base = name
        .strip_suffix(".body.tmp")
        .or_else(|| name.strip_suffix(".meta.tmp"))
        .or_else(|| name.strip_suffix(".body"))
        .or_else(|| name.strip_suffix(".meta"))?;
    Some(path.with_file_name(base))
}

fn disk_stem_files(stem: &Path) -> [PathBuf; 4] {
    [
        stem.with_extension("body"),
        stem.with_extension("meta"),
        stem.with_extension("body.tmp"),
        stem.with_extension("meta.tmp"),
    ]
}

fn remove_disk_stem_files(stem: &Path) {
    for path in disk_stem_files(stem) {
        let _ = fs::remove_file(path);
    }
}

fn scan_disk_usage(root: &Path) -> DiskUsageState {
    let mut state = DiskUsageState::default();
    fn walk(dir: &Path, state: &mut DiskUsageState) {
        let Ok(read) = fs::read_dir(dir) else {
            return;
        };
        for entry in read.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => walk(&path, state),
                Ok(ft) if ft.is_file() => {
                    let Some(stem) = disk_stem(&path) else {
                        continue;
                    };
                    let Ok(meta) = entry.metadata() else {
                        continue;
                    };
                    let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                    let slot = state.stems.entry(stem).or_insert((0, modified));
                    slot.0 = slot.0.saturating_add(meta.len());
                    if modified < slot.1 {
                        slot.1 = modified;
                    }
                }
                _ => {}
            }
        }
    }
    walk(root, &mut state);
    state.total = state.stems.values().map(|(size, _)| *size).sum();
    state
}

fn remove_disk_stem(cfg: &Config, stem: &Path) {
    remove_disk_stem_files(stem);
    let Some(root) = &cfg.cache.root else {
        return;
    };
    let mut roots = disk_usage().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(usage) = roots.get_mut(root) {
        if let Some((size, _)) = usage.stems.remove(stem) {
            usage.total = usage.total.saturating_sub(size);
        }
    }
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

pub struct CacheContext {
    pub scope: Scope,
    pub grant: AccessGrant,
    /// Fully qualified cache key binding listener, vhost, URL, mapped target
    /// and policy.  Lookup and store must use this exact key.
    pub key: String,
    pub target: std::path::PathBuf,
    /// Effective cache URL.  For a directory request this is the selected
    /// `DirectoryIndex` URL, so lookup and store authorize the same resource.
    pub path: String,
}

/// Return the cache type selected for this request, if caching is enabled and
/// access control permits serving a cached representation.
#[allow(clippy::too_many_arguments)]
/// Compatibility entry point for callers that do not already hold a
/// `RequestPlan`.  Production dispatch/cache integration uses
/// `request_scope_with_plan` so the cache and dispatcher share one identity.
#[allow(clippy::too_many_arguments)]
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
    local_ip: &str,
) -> Option<CacheContext> {
    let allow_encoded = cfg.encoded_slashes == crate::config::EncodedSlashes::On;
    let plan =
        crate::request_plan::RequestPlan::from_request(cfg, vhost, req, allow_encoded).ok()?;
    request_scope_with_plan(
        cfg,
        vhost,
        req,
        peer,
        &plan,
        path,
        local_port,
        https,
        server_name,
        host,
        local_ip,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn request_scope_with_plan(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    peer: IpAddr,
    plan: &crate::request_plan::RequestPlan,
    path: &str,
    local_port: u16,
    https: bool,
    server_name: &str,
    host: &str,
    local_ip: &str,
) -> Option<CacheContext> {
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
    // F55/I51: a lossy URL conversion can collapse distinct byte paths into
    // one cache identity.  The plan already rejected a non-UTF-8 canonical
    // path; keep the cache decision on that same identity.
    let url_path = plan.url_path().to_string();
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
    // Authorizing a document-root path that an Alias never serves would let
    // a cached alias response bypass the alias target's Directory/access-file
    // policy.  The plan already used dispatch's mapping and access layers.
    let root = plan.root().to_path_buf();
    let rel = plan.rel().to_path_buf();
    let script_alias = plan.script_alias();
    let mapped_fs_path = plan.fs_path().to_path_buf();
    let mut scope = plan.effective_scope(cfg, vhost, req, peer);
    // Cache lookup must not bypass rewrite rules.  If any rule would produce
    // an outcome (including F/G/redirects or a target/file change), run the
    // normal dispatcher instead of serving a stale representation.
    let rewrite_ctx = crate::rewrite::Context::for_plan(
        plan,
        &cfg.server_root,
        &req.query,
        peer,
        local_port,
        https,
        server_name,
    );
    if !matches!(
        crate::rewrite::process(&scope, req, &rewrite_ctx),
        crate::rewrite::Outcome::None
    ) {
        return None;
    }
    // A CGI PATH_INFO URL dispatches to the script prefix, not to the
    // nonexistent full path.  Bind cache policy and the cache target to that
    // script so a later `<Files "script.cgi">` deny is part of the scope and
    // fingerprint rather than being bypassed by `/script.cgi/<info>`.
    let mut fs_path = mapped_fs_path;
    let mut cache_url_path = url_path.clone();
    let follow_symlinks = scope
        .effective_options()
        .contains(crate::config::Options::FOLLOW_SYMLINKS);
    let owner_match_only = !follow_symlinks
        && scope
            .effective_options()
            .contains(crate::config::Options::SYMLINKS_IF_OWNER_MATCH);
    let follow = follow_symlinks || owner_match_only;
    if let Some(st) = crate::cgi::find_script_checked(&root, &rel, follow, owner_match_only) {
        if !st.path_info.is_empty() {
            let script_base = st
                .rel_script
                .file_name()
                .map(|n| n.as_encoded_bytes())
                .unwrap_or(b"");
            if script_alias || crate::cgi::is_cgi(cfg, &scope, script_base, false) {
                let script_url = url_path
                    .strip_suffix(&st.path_info)
                    .unwrap_or(&url_path)
                    .to_string();
                fs_path = root.join(&st.rel_script);
                cache_url_path = script_url.clone();
                let target = crate::request_plan::CanonicalTarget::from_url_path(&script_url)?;
                let script_plan = crate::request_plan::RequestPlan::from_fs_target(
                    cfg,
                    vhost,
                    target,
                    root.clone(),
                    fs_path.clone(),
                    script_alias,
                )
                .ok()?;
                let mut script_scope = script_plan.effective_scope(cfg, vhost, req, peer);
                // The PATH_INFO script target must keep the lexical script
                // URL's execution/list policy as well as its own canonical
                // policy.  The handler map comes from the script URL, not the
                // PATH_INFO spelling.
                let lexical = crate::request_plan::CanonicalTarget::from_url_path(&script_url)?;
                let lexical_plan =
                    crate::request_plan::RequestPlan::resolve(cfg, vhost, lexical).ok()?;
                let lexical_scope = lexical_plan.effective_scope(cfg, vhost, req, peer);
                script_scope.restrict_with(&lexical_scope);
                script_scope.restrict_policy_with(&scope);
                scope = script_scope;
            }
        }
    }
    // A directory URL is not the representation that dispatch will serve.
    // Resolve `DirectoryIndex` before the cache decision and rebind the cache
    // target, URL and policy to that index.  Without this, a cached directory
    // response outlives a live `<Files "index.html">` deny and a dynamic index
    // can be shared across queries under `CacheIgnoreQueryString` (F52).
    let current_rel = fs_path.strip_prefix(&root).unwrap_or(&rel);
    let mut directory_target = false;
    let mut index_selected = false;
    if let crate::files::Target::Directory { file, .. } =
        crate::files::resolve_target_checked(&root, current_rel, follow, owner_match_only)
    {
        directory_target = true;
        if let Some(index) =
            crate::files::directory_index_target(cfg, &scope, req, &file, &url_path, &req.raw_path)
        {
            // The cache identity must preserve the exact index name bytes.
            // Reject a non-UTF-8 index name rather than sharing a lossy key.
            let index_name = std::str::from_utf8(&index.name).ok()?;
            let index_url = format!("{}/{}", url_path.trim_end_matches('/'), index_name);
            let index_fs = crate::files::fd_path(&index.file)
                .unwrap_or_else(|| fs_path.join(std::ffi::OsStr::from_bytes(&index.name)));
            let target = crate::request_plan::CanonicalTarget::from_url_path(&index_url)?;
            let index_plan = crate::request_plan::RequestPlan::from_fs_target(
                cfg,
                vhost,
                target,
                root.clone(),
                index_fs.clone(),
                script_alias,
            )
            .ok()?;
            let mut index_scope = index_plan.effective_scope(cfg, vhost, req, peer);
            // The selected index has its own URL identity; conjoin that
            // lexical scope and the directory URL's non-handler policy.
            let lexical = crate::request_plan::CanonicalTarget::from_url_path(&index_url)?;
            let lexical_plan =
                crate::request_plan::RequestPlan::resolve(cfg, vhost, lexical).ok()?;
            let lexical_scope = lexical_plan.effective_scope(cfg, vhost, req, peer);
            index_scope.restrict_with(&lexical_scope);
            index_scope.restrict_policy_with(&scope);
            scope = index_scope;
            fs_path = index_fs;
            cache_url_path = index_url;
            index_selected = true;
        }
    }
    // The opened/canonical target may differ from the URL-mapped path when a
    // document root, alias target or in-root component is a symlink.  The
    // cache must use the same two-identity meet as dispatch before deciding
    // that a representation is servable (F60/I61).
    if let Ok(actual) = std::fs::canonicalize(&fs_path) {
        if actual != fs_path {
            let target = crate::request_plan::CanonicalTarget::from_url_path(&cache_url_path)?;
            let target_plan = crate::request_plan::RequestPlan::from_fs_target(
                cfg,
                vhost,
                target,
                root.clone(),
                actual.clone(),
                script_alias,
            )
            .ok()?;
            let mut target_scope = target_plan.effective_scope(cfg, vhost, req, peer);
            target_scope.restrict_with(&scope);
            scope = target_scope;
            fs_path = actual;
        }
    }
    if !vapache_verified::cache_directory_index_bind_admit(
        directory_target,
        index_selected,
        index_selected,
        index_selected,
    ) {
        return None;
    }
    if !cache_enabled(&scope, &cache_url_path) {
        return None;
    }
    // A local ErrorDocument is selected only after dispatch fails.  It is an
    // internal subrequest with its own handler/query policy, so a *missing*
    // URL must not be represented by that subrequest's response (F56/I52).
    // Existing targets may still use the cache; `store` additionally refuses
    // any response that actually came from a local error document.
    let local_error_document = scope
        .error_policy
        .documents
        .iter()
        .any(|(_, doc)| matches!(doc, crate::config::ErrorDoc::Local(_)));
    if local_error_document && !fs_path.exists() {
        if !vapache_verified::cache_local_error_document_admit(true, true) {
            return None;
        }
    }
    // `CacheIgnoreQueryString` is safe for static representations, but a
    // query-driven CGI/FastCGI/proxy/server-status/SetHandler response cannot
    // be shared across distinct queries.  Classify every non-default handler,
    // not just the proxy forms known to `match_proxy` (F52/F54/I49/I53).
    if cfg.cache.ignore_query_string && !req.query.is_empty() {
        let name = fs_path
            .file_name()
            .map(|n| n.as_encoded_bytes())
            .unwrap_or(b"");
        let handler = crate::config::effective_handler(&scope, name)
            .map(str::trim)
            .filter(|h| {
                !h.is_empty()
                    && !h.eq_ignore_ascii_case("default-handler")
                    && !h.eq_ignore_ascii_case("none")
            })
            .is_some();
        let dynamic = script_alias
            || crate::cgi::is_cgi(cfg, &scope, name, false)
            || handler
            || crate::fastcgi::match_proxy(&scope, &cache_url_path, &root).is_some()
            || crate::proxy::matches_route(&scope, &cache_url_path);
        if !vapache_verified::cache_dynamic_handler_admit(handler, dynamic) {
            return None;
        }
        if !vapache_verified::cache_ignore_query_admit(
            cfg.cache.ignore_query_string,
            !req.query.is_empty(),
            dynamic,
        ) {
            return None;
        }
    }
    // Never bypass per-directory access control or a rewrite-set environment
    // requirement by serving a cached object without running dispatch.
    let fingerprint = cache_policy_fingerprint(&scope, req, peer, &fs_path);
    let resource =
        crate::access::ResourceKey::cache_policy(vhost, req, host, &cache_url_path, fingerprint);
    let grant = match crate::access::check_grant(
        &scope,
        req,
        peer,
        None,
        &cache_url_path,
        Some(&fs_path),
        resource,
    ) {
        Ok(grant) => grant,
        Err(_) => return None,
    };
    // AllowMethods and <Proxy> authorization are enforced by the normal
    // dispatcher; do not satisfy the request from cache first.
    if !scope.method_allowed(&req.method) {
        return None;
    }
    if crate::proxy::matches_route(&scope, &cache_url_path) {
        return None;
    }
    let key = base_key(
        cfg,
        vhost,
        local_ip,
        local_port,
        https,
        host,
        &cache_url_path,
        &req.query,
        &fs_path,
        fingerprint,
    );
    Some(CacheContext {
        scope,
        grant,
        key,
        target: fs_path,
        path: cache_url_path,
    })
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

#[allow(clippy::too_many_arguments)]
fn base_key(
    cfg: &Config,
    vhost: Option<&VHost>,
    local_ip: &str,
    local_port: u16,
    https: bool,
    host: &str,
    path: &str,
    query: &[u8],
    target: &std::path::Path,
    policy_fingerprint: PolicyFingerprint,
) -> String {
    // F55/I51: every byte-bearing component is hex encoded, so raw query,
    // path and filesystem-target bytes cannot collide with an empty value or
    // with each other.  `CacheIgnoreQueryString` is an explicit opt-in.
    let query = if cfg.cache.ignore_query_string {
        String::new()
    } else {
        key_component(query)
    };
    let vhost_id = vhost
        .and_then(|v| cfg.vhosts.iter().position(|x| std::ptr::eq(x, v)))
        .map(|i| i.to_string())
        .unwrap_or_else(|| "default".into());
    let policy_fingerprint = key_component(&policy_fingerprint);
    format!(
        "{}\n{host}\n{path}\n{query}\n{scheme}\n{local_ip}\n{local_port}\n{vhost_id}\n{target}\n{policy_fingerprint}",
        key_component(cfg.server_root.as_os_str().as_bytes()),
        host = key_component(host.as_bytes()),
        path = key_component(path.as_bytes()),
        scheme = if https { "https" } else { "http" },
        target = key_component(target.as_os_str().as_bytes()),
    )
}

/// Lossless ASCII hex for cache-key material.  The verifier proves the
/// encoding length; the runtime never uses a lossy string conversion here.
fn key_component(value: &[u8]) -> String {
    String::from_utf8(vapache_verified::cache_key_hex(value))
        .expect("cache key hex encoding is ASCII")
}

fn rewrite_map_material(map: &crate::config::RewriteMap) -> String {
    match map {
        crate::config::RewriteMap::Txt(entries) => {
            let mut entries: Vec<_> = entries.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            format!("txt:{entries:?}")
        }
        crate::config::RewriteMap::Rnd(entries) => {
            let mut entries: Vec<_> = entries.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            format!("rnd:{entries:?}")
        }
        crate::config::RewriteMap::Prg(program) => format!("prg:{program}"),
        crate::config::RewriteMap::Int(function) => format!("int:{function}"),
    }
}

/// Canonical material for every policy object that can affect authorization,
/// target selection or representation.  `Scope` is destructured so adding a
/// policy slice forces this function to make an explicit decision.  Most
/// policy objects have deterministic `Debug` output; rewrite maps contain a
/// `HashMap`, so their entries are canonicalized before hashing.
fn cache_policy_material(scope: &Scope) -> String {
    let Scope {
        options,
        override_policy,
        authorization,
        header_policy,
        content_policy,
        mapping_policy,
        error_policy,
        environment_policy,
        rewrite_policy,
        compression_policy,
        proxy_policy,
    } = scope;
    let crate::scope_policy::RewriteCachePolicy {
        rewrite_engine,
        rewrite_maps,
        cache_enable,
        cache_disable,
        rewrite_inherit,
        rewrite_base,
        rewrite_match_base,
        rewrite_rules,
        pending_rewrite_conds,
    } = rewrite_policy;
    let mut rewrite_maps: Vec<String> = rewrite_maps
        .iter()
        .map(|(name, map)| format!("{name}={}", rewrite_map_material(map)))
        .collect();
    rewrite_maps.sort();
    format!(
        "{options:?}|{override_policy:?}|{authorization:?}|{header_policy:?}|\
         {content_policy:?}|{mapping_policy:?}|{error_policy:?}|\
         {environment_policy:?}|{compression_policy:?}|{proxy_policy:?}|\
         {rewrite_engine:?}|{}|{cache_enable:?}|{cache_disable:?}|\
         {rewrite_inherit:?}|{rewrite_base:?}|{rewrite_match_base:?}|\
         {rewrite_rules:?}|{pending_rewrite_conds:?}",
        rewrite_maps.join(","),
    )
}

/// Security-relevant policy fingerprint for cache isolation.
fn cache_policy_fingerprint(
    scope: &Scope,
    req: &Request,
    peer: IpAddr,
    target: &std::path::Path,
) -> PolicyFingerprint {
    // Length-prefix every field so concatenation cannot make two different
    // material tuples look identical.  Hash the exact bytes with SHA-256; a
    // 64-bit `DefaultHasher` fingerprint was not collision-resistant enough
    // for a value that decides whether two cache entries may be shared.
    let mut material = Vec::new();
    fingerprint_field(&mut material, cache_policy_material(scope).as_bytes());
    fingerprint_field(&mut material, peer.to_string().as_bytes());
    fingerprint_field(&mut material, req.method.as_bytes());
    fingerprint_field(&mut material, target.as_os_str().as_bytes());
    // Configuration expressions (`Require expr`, `SetEnvIf`, rewrite
    // conditions) can read any request header.  The compiled policy text is
    // not enough to identify the branch a request takes, so bind the complete
    // request header set into the policy fingerprint.  This also partitions
    // non-credential tenant/feature headers and cookies even when the response
    // did not name them in `Vary`.
    for (name, value) in req.headers.iter() {
        fingerprint_field(&mut material, name.as_bytes());
        fingerprint_field(&mut material, value);
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, &material);
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(digest.as_ref());
    fingerprint
}

fn fingerprint_field(out: &mut Vec<u8>, field: &[u8]) {
    // Verified four-byte big-endian framing; see
    // `cache_fingerprint_field_injective`.
    out.extend_from_slice(&vapache_verified::cache_fingerprint_field(field));
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

fn combined_header(headers: &[(String, Vec<u8>)], name: &str) -> Option<String> {
    let mut found = false;
    let mut out = String::new();
    for (n, v) in headers {
        if !n.eq_ignore_ascii_case(name) {
            continue;
        }
        found = true;
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&String::from_utf8_lossy(v));
    }
    found.then_some(out)
}

fn vary_values(req: &Request, headers: &[(String, Vec<u8>)]) -> Vec<(String, Vec<u8>)> {
    // Multiple `Vary` field lines are legal and equivalent to one
    // comma-separated list.  Collapsing to the first line silently dropped
    // later dimensions such as Cookie on a response that also varied by
    // Accept-Encoding.
    let Some(vary) = combined_header(headers, "vary") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for name in vary.split(',') {
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() || name == "*" {
            continue;
        }
        if out.iter().any(|(n, _)| n == &name) {
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

#[allow(clippy::too_many_arguments)]
pub fn lookup(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    host: &str,
    path: &str,
    scope: &Scope,
    peer: IpAddr,
    grant: &AccessGrant,
    cache_key: &str,
    target: &std::path::Path,
) -> Option<Response> {
    let fingerprint = cache_policy_fingerprint(scope, req, peer, target);
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
    let key = cache_key.to_string();
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
                    entry.epoch == current_epoch(),
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
                vary_matches(&loaded, req),
                loaded.epoch == current_epoch(),
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
        // Large cached representations are already persisted as a body file.
        // Serve that file through the file-body path so the plain-TCP writer
        // can use sendfile instead of copying the whole body from user memory.
        const FILE_BODY_THRESHOLD: usize = 64 * 1024;
        let mut served_file = false;
        if entry.body.len() > FILE_BODY_THRESHOLD {
            if let Some(stem) = cache_stem(cfg, cache_key) {
                let path = stem.with_extension("body");
                if let Ok(file) = fs::File::open(&path) {
                    if let Ok(meta) = file.metadata() {
                        if meta.is_file() && meta.len() == entry.body.len() as u64 {
                            response.body = Body::File {
                                file,
                                offset: 0,
                                len: meta.len(),
                            };
                            served_file = true;
                        }
                    }
                }
            }
        }
        if !served_file {
            response.body = Body::Bytes(entry.body);
        }
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
        let n = vapache_verified::cache_ttl_clamp(
            n as i64,
            cfg.min_expire as i64,
            cfg.max_expire as i64,
        );
        return Some(n);
    }
    if let Some(expires) = header(headers, "expires").and_then(parse_http_date) {
        let n = expires - now;
        if n <= 0 {
            return None;
        }
        return Some(vapache_verified::cache_ttl_clamp(
            n,
            cfg.min_expire as i64,
            cfg.max_expire as i64,
        ));
    }
    if let Some(last) = header(headers, "last-modified").and_then(parse_http_date) {
        let age = (now - last).max(0) as f64;
        let n = (age * cfg.last_modified_factor) as i64;
        if n > 0 {
            return Some(vapache_verified::cache_ttl_clamp(
                n,
                cfg.min_expire as i64,
                cfg.max_expire as i64,
            ));
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
        "V3\nS {}\nT {}\nE {}\nP {}\nG {}\n",
        entry.status,
        entry.stored,
        entry.expires,
        STANDARD.encode(entry.policy),
        entry.epoch
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
    let version = lines.next()?;
    if version != "V1" && version != "V2" && version != "V3" {
        return None;
    }
    let mut status = None;
    let mut stored = None;
    let mut expires = None;
    let mut policy = None;
    // V1 entries predate the configuration-generation field and are never
    // admissible in a live configuration.
    let mut epoch = Some(0u64);
    let mut vary = Vec::new();
    let mut headers = Vec::new();
    for line in lines {
        let mut parts = line.splitn(3, ' ');
        let kind = parts.next()?;
        match kind {
            "S" => status = parts.next()?.parse::<u16>().ok(),
            "T" => stored = parts.next()?.parse::<i64>().ok(),
            "E" => expires = parts.next()?.parse::<i64>().ok(),
            "P" => {
                let raw = STANDARD.decode(parts.next()?).ok()?;
                policy = Some(<[u8; 32]>::try_from(raw.as_slice()).ok()?);
            }
            "G" => epoch = parts.next()?.parse::<u64>().ok(),
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
        epoch: epoch?,
        vary,
    })
}

fn disk_store(cfg: &Config, key: &str, entry: &Entry) {
    let Some(stem) = cache_stem(cfg, key) else {
        return;
    };
    let Some(root) = &cfg.cache.root else {
        return;
    };
    if let Some(parent) = stem.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let meta = encode_meta(entry);
    let incoming = (entry.body.len() as u64).saturating_add(meta.len() as u64);
    // A single representation larger than the whole disk budget is never
    // written; `CacheMaxFileSize` already bounds the body, while this covers
    // metadata and the total quota.
    if incoming > cfg.cache.max_disk_size {
        return;
    }
    let mut roots = disk_usage().lock().unwrap_or_else(|e| e.into_inner());
    let usage = roots
        .entry(root.clone())
        .or_insert_with(|| scan_disk_usage(root));
    let old_size = usage.stems.get(&stem).map(|(size, _)| *size).unwrap_or(0);
    let old_count = usize::from(old_size > 0);
    let mut projected = vapache_verified::cache_disk_projected(usage.total, old_size, incoming);
    let mut entries = usage
        .stems
        .len()
        .saturating_sub(old_count)
        .saturating_add(1);
    if projected > cfg.cache.max_disk_size || entries > MAX_DISK_ENTRIES {
        let mut victims: Vec<(PathBuf, u64, SystemTime)> = usage
            .stems
            .iter()
            .filter(|(candidate, _)| candidate.as_path() != stem)
            .map(|(candidate, (size, modified))| (candidate.clone(), *size, *modified))
            .collect();
        victims.sort_by_key(|(_, _, modified)| *modified);
        for (victim, size, _) in victims {
            if projected <= cfg.cache.max_disk_size && entries <= MAX_DISK_ENTRIES {
                break;
            }
            remove_disk_stem_files(&victim);
            if usage.stems.remove(&victim).is_some() {
                usage.total = usage.total.saturating_sub(size);
                projected = vapache_verified::cache_disk_evict(projected, size);
                entries = entries.saturating_sub(1);
            }
        }
        if projected > cfg.cache.max_disk_size || entries > MAX_DISK_ENTRIES {
            return;
        }
    }
    let body_path = stem.with_extension("body");
    let meta_path = stem.with_extension("meta");
    let body_tmp = stem.with_extension("body.tmp");
    let meta_tmp = stem.with_extension("meta.tmp");
    if fs::write(&body_tmp, &entry.body).is_err() || fs::write(&meta_tmp, &meta).is_err() {
        let _ = fs::remove_file(&body_tmp);
        let _ = fs::remove_file(&meta_tmp);
        return;
    }
    if fs::rename(&body_tmp, &body_path).is_err() || fs::rename(&meta_tmp, &meta_path).is_err() {
        let _ = fs::remove_file(&body_tmp);
        let _ = fs::remove_file(&meta_tmp);
        let _ = fs::remove_file(&body_path);
        let _ = fs::remove_file(&meta_path);
        return;
    }
    let actual = fs::metadata(&body_path)
        .map(|m| m.len())
        .unwrap_or(entry.body.len() as u64)
        .saturating_add(
            fs::metadata(&meta_path)
                .map(|m| m.len())
                .unwrap_or(meta.len() as u64),
        );
    usage.total = vapache_verified::cache_disk_projected(usage.total, old_size, actual);
    usage.stems.insert(stem, (actual, SystemTime::now()));
}

fn disk_load(cfg: &Config, key: &str) -> Option<Entry> {
    let stem = cache_stem(cfg, key)?;
    let meta = match fs::read(stem.with_extension("meta")) {
        Ok(meta) => meta,
        Err(_) => return None,
    };
    let mut entry = match decode_meta(&meta) {
        Some(entry) => entry,
        None => {
            remove_disk_stem(cfg, &stem);
            return None;
        }
    };
    // A reload changes the generation and expiry makes the representation
    // unusable.  Remove both files instead of leaving them to fill the cache
    // filesystem (F44).
    if entry.epoch != current_epoch() || entry.expires <= unix_now() {
        remove_disk_stem(cfg, &stem);
        return None;
    }
    match fs::read(stem.with_extension("body")) {
        Ok(body) => entry.body = body,
        Err(_) => {
            remove_disk_stem(cfg, &stem);
            return None;
        }
    }
    Some(entry)
}

#[allow(clippy::too_many_arguments)]
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
    cache_key: &str,
    target: &std::path::Path,
) {
    // An ErrorDocument body belongs to the internal error target, not to the
    // URL that failed.  Never persist it under the original key (F56/I52).
    if !vapache_verified::cache_local_error_document_admit(
        crate::files::local_error_document_response(),
        true,
    ) {
        return;
    }
    let fingerprint = cache_policy_fingerprint(scope, req, peer, target);
    if !grant.require(&crate::access::ResourceKey::cache_policy(
        vhost,
        req,
        host,
        path,
        fingerprint,
    )) {
        return;
    }
    // Credentialed responses are never placed in the shared cache.  The
    // cache has no identity dimension, so storing one and hoping a later
    // policy check rejects a different identity is not sufficient.
    let credential_free = req.header("authorization").is_none() && req.header("cookie").is_none();
    if !vapache_verified::cache_store_request_admit(
        req.method == "GET",
        req.body_len() == 0,
        credential_free,
    ) {
        return;
    }
    if !vapache_verified::cache_store_status_admit(resp.status) {
        return;
    }
    let response_headers: Vec<(String, Vec<u8>)> = resp
        .headers
        .iter()
        .map(|(n, v)| (n.to_string(), v.clone()))
        .collect();
    let directives = cache_control_directives(&response_headers);
    let no_store = directives.iter().any(|d| d == "no-store");
    let no_cache = directives.iter().any(|d| d == "no-cache");
    let private = directives.iter().any(|d| d == "private");
    if !vapache_verified::cache_store_control_admit(
        no_store,
        no_cache,
        private,
        cfg.cache.store_no_store,
        cfg.cache.ignore_cache_control,
        cfg.cache.store_private,
    ) {
        return;
    }
    let set_cookie = response_header(resp, "set-cookie").is_some();
    let response_headers_for_vary: Vec<(String, Vec<u8>)> = resp
        .headers
        .iter()
        .map(|(n, v)| (n.to_string(), v.clone()))
        .collect();
    let vary_star = combined_header(&response_headers_for_vary, "vary")
        .map(|v| v.split(',').any(|part| part.trim() == "*"))
        .unwrap_or(false);
    let Some(body) = response_body_bytes(&mut resp.body) else {
        return;
    };
    let size_ok = body.len() as u64 <= cfg.cache.max_file_size
        && (body.len() as u64) >= cfg.cache.min_file_size;
    if !vapache_verified::cache_store_shape_admit(set_cookie, vary_star, size_ok) {
        return;
    }
    let now = unix_now();
    let Some(ttl) = freshness(&cfg.cache, &response_headers, now) else {
        return;
    };
    if !vapache_verified::cache_store_ttl_admit(ttl) {
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
    let key = cache_key.to_string();
    let entry = Entry {
        status: resp.status,
        headers,
        body: body.clone(),
        stored: now,
        expires: vapache_verified::cache_expiry(now, ttl),
        policy: fingerprint,
        epoch: current_epoch(),
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
        while list.len() > MAX_VARIANTS_PER_KEY {
            list.remove(0);
        }
    }
    disk_store(cfg, &key, &entry);
    if cfg.cache.header {
        resp.headers
            .retain(|(n, _)| !n.eq_ignore_ascii_case("x-cache"));
        resp.headers
            .push((Cow::Borrowed("X-Cache"), b"MISS".to_vec()));
    }
}

/// Invalidate every cache representation for a new configuration generation.
/// The in-memory map is cleared and the persisted body/meta files are removed.
/// The epoch bump additionally rejects any stale file a concurrent writer could
/// recreate while cleanup is in progress.
pub fn clear(cfg: &Config) {
    bump_epoch();
    entries().lock().unwrap_or_else(|e| e.into_inner()).clear();
    invalidate_disk(cfg);
}

/// Remove persisted cache files.  Disk filenames are SHA-1 digests of the full
/// key, so a host/path prefix cannot be mapped back to a filename without an
/// index.  Unsafe methods are rare compared with cache hits and correctness
/// matters more than preserving unrelated entries, so drop every persisted
/// representation and let the next GET repopulate the cache.
fn invalidate_disk(cfg: &Config) {
    let Some(root) = &cfg.cache.root else {
        return;
    };
    disk_usage()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(root);
    fn remove_cache_files(dir: &std::path::Path) {
        let Ok(read) = fs::read_dir(dir) else {
            return;
        };
        for entry in read.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => remove_cache_files(&path),
                Ok(ft) if ft.is_file() => {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if name.ends_with(".body")
                        || name.ends_with(".meta")
                        || name.ends_with(".body.tmp")
                        || name.ends_with(".meta.tmp")
                    {
                        let _ = fs::remove_file(&path);
                    }
                }
                _ => {}
            }
        }
    }
    remove_cache_files(root);
}

pub fn invalidate(cfg: &Config, host: &str, path: &str) {
    // Keep the prefix in the same lossless encoding as `base_key`; a lossy
    // `display()` prefix no longer matches keys and would leave stale entries
    // after an unsafe method (F55/I51).
    let prefix = format!(
        "{}\n{}\n{}\n",
        key_component(cfg.server_root.as_os_str().as_bytes()),
        key_component(host.as_bytes()),
        key_component(path.as_bytes()),
    );
    let mut guard = entries().lock().unwrap_or_else(|e| e.into_inner());
    guard.retain(|key, _| !key.starts_with(&prefix));
    drop(guard);
    invalidate_disk(cfg);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_request() -> crate::http::Request {
        crate::http::Request {
            method: "GET".into(),
            target: b"/x".to_vec(),
            raw_path: b"/x".to_vec(),
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
            policy: [7u8; 32],
            epoch: current_epoch(),
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
        let target = std::path::Path::new("/srv/path");
        let fingerprint = cache_policy_fingerprint(&scope, &request, peer, target);
        let entry = Entry {
            policy: fingerprint,
            vary: Vec::new(),
            ..entry
        };
        let key = base_key(
            &cfg,
            None,
            "127.0.0.1",
            80,
            false,
            "warm.test",
            "/path",
            b"",
            target,
            fingerprint,
        );
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
            &key,
            target,
        )
        .expect("warm hit");
        match hit.body {
            crate::http::Body::Bytes(body) => assert_eq!(body, b"hello"),
            _ => panic!("expected cached bytes"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn large_cache_hit_is_served_from_the_disk_body_file() {
        let (dir, cfg) = disk_test_config("file-body");
        let request = test_request();
        let peer = "127.0.0.1".parse().unwrap();
        let scope = Scope::default();
        let target = std::path::Path::new("/srv/large.bin");
        let mut entry = disk_entry(&vec![b'z'; 128 * 1024], unix_now() + 60);
        entry.policy = cache_policy_fingerprint(&scope, &request, peer, target);
        let key = "host\n/large.bin\n";
        disk_store(&cfg, key, &entry);
        let hit = lookup(
            &cfg,
            None,
            &request,
            "localhost",
            "/large.bin",
            &scope,
            peer,
            &crate::access::test_grant(),
            key,
            target,
        )
        .expect("large cache hit");
        match hit.body {
            Body::File { len, .. } => assert_eq!(len, 128 * 1024),
            _ => panic!("large cached body should use the file-body path"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disk_entries_from_an_older_generation_are_not_served() {
        let dir = std::env::temp_dir().join(format!("vapache-cache-epoch-{}", std::process::id()));
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
            body: b"stale".to_vec(),
            stored: unix_now(),
            expires: unix_now() + 60,
            policy: [7u8; 32],
            epoch: current_epoch().saturating_sub(1),
            vary: Vec::new(),
        };
        disk_store(&cfg, "old\n/path\n", &entry);
        assert!(disk_load(&cfg, "old\n/path\n").is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_info_cache_target_is_the_actual_script() {
        let dir =
            std::env::temp_dir().join(format!("vapache-cache-pathinfo-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let cgi = dir.join("www").join("cgi");
        fs::create_dir_all(&cgi).unwrap();
        fs::write(cgi.join("wallet.cgi"), "#!/bin/sh\nexit 0\n").unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            format!(
                "Listen 127.0.0.1:0\n\
DocumentRoot \"{www}\"\n\
CacheRoot \"{cache}\"\n\
CacheEnable disk /\n\
CacheDefaultExpire 60\n\
AddHandler cgi-script .cgi\n\
<Directory \"{www}\">\n\
    Options +ExecCGI\n\
    Require all granted\n\
</Directory>\n",
                www = dir.join("www").display(),
                cache = dir.join("cache").display(),
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
        let request = crate::http::Request {
            method: "GET".into(),
            target: b"/cgi/wallet.cgi/foo".to_vec(),
            raw_path: b"/cgi/wallet.cgi/foo".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        let ctx = request_scope(
            &cfg,
            None,
            &request,
            "127.0.0.1".parse().unwrap(),
            "/cgi/wallet.cgi/foo",
            80,
            false,
            "localhost",
            "localhost",
            "127.0.0.1",
        )
        .expect("path-info cache scope");
        assert_eq!(ctx.target, cgi.join("wallet.cgi"));
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
            "127.0.0.1",
        );
        assert!(scope.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_policy_fingerprint_binds_header_driven_policy_inputs() {
        let dir = std::env::temp_dir().join(format!("vapache-cache-fp-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(&conf, "Listen 127.0.0.1:0\n").unwrap();
        let cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        let scope = Scope::default();
        let peer = "127.0.0.1".parse().unwrap();
        let target = std::path::Path::new("/srv/tenant.txt");
        let request = |tenant: &str| {
            let mut headers = crate::http::Headers::default();
            headers.insert("x-tenant", tenant.as_bytes().to_vec());
            crate::http::Request {
                method: "GET".into(),
                target: b"/tenant.txt".to_vec(),
                raw_path: b"/tenant.txt".to_vec(),
                query: Vec::new(),
                version: crate::http::Version::Http11,
                headers,
                body: Vec::new(),
                body_spool: None,
                keep_alive: true,
                expect_continue: false,
                framing: crate::verified::BodyFraming::None,
            }
        };
        let alpha = cache_policy_fingerprint(&scope, &request("alpha"), peer, target);
        let beta = cache_policy_fingerprint(&scope, &request("beta"), peer, target);
        assert_ne!(alpha, beta, "tenant header must partition the cache");
        let _ = cfg;
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_policy_fingerprint_binds_every_policy_field() {
        let request = test_request();
        let peer = "127.0.0.1".parse().unwrap();
        let target = std::path::Path::new("/srv/x");
        let fingerprint = |scope: &Scope| cache_policy_fingerprint(scope, &request, peer, target);
        let baseline = fingerprint(&Scope::default());

        let cases: Vec<(&str, fn(&mut Scope))> = vec![
            ("options.changes", |s| s.options.push_add(1)),
            ("override.mode", |s| {
                s.override_policy.set_mode(crate::config::OverrideMode::All)
            }),
            ("override.allow_list", |s| {
                s.override_policy.set_allow_list(vec!["Require".into()])
            }),
            ("override.nonfatal", |s| {
                s.override_policy
                    .set_nonfatal(crate::config::NonfatalMode::All)
            }),
            ("authorization.requires", |s| {
                s.authorization.add_require(
                    crate::config::RequireNode::Provider(crate::config::Require::AllGranted),
                    None,
                )
            }),
            ("authorization.auth_merging", |s| {
                s.authorization.auth_merging = Some(crate::config::AuthMerging::And)
            }),
            ("authorization.allow_methods", |s| {
                s.authorization.allow_methods = Some(crate::config::AllowMethods::Reset)
            }),
            ("authorization.legacy", |s| {
                s.authorization.legacy = Some(crate::config::LegacyAccess::default())
            }),
            ("authorization.auth_type", |s| {
                s.authorization.auth_type = Some("basic".into())
            }),
            ("authorization.auth_name", |s| {
                s.authorization.auth_name = Some("realm".into())
            }),
            ("authorization.auth_user_file", |s| {
                s.authorization.auth_user_file = Some("/tmp/users".into())
            }),
            ("authorization.auth_group_file", |s| {
                s.authorization.auth_group_file = Some("/tmp/groups".into())
            }),
            ("header.add_headers", |s| {
                s.header_policy.add_headers.push(("X-A".into(), "1".into()))
            }),
            ("header.set_headers", |s| {
                s.header_policy.set_headers.push(("X-A".into(), "1".into()))
            }),
            ("header.unset_headers", |s| {
                s.header_policy.unset_headers.push("X-A".into())
            }),
            ("header.always_add_headers", |s| {
                s.header_policy
                    .always_add_headers
                    .push(("X-A".into(), "1".into()))
            }),
            ("header.always_set_headers", |s| {
                s.header_policy
                    .always_set_headers
                    .push(("X-A".into(), "1".into()))
            }),
            ("header.always_unset_headers", |s| {
                s.header_policy.always_unset_headers.push("X-A".into())
            }),
            ("header.expires_active", |s| {
                s.header_policy.expires_active = Some(true)
            }),
            ("header.expires_default", |s| {
                s.header_policy.expires_default = Some("access plus 1 hour".into())
            }),
            ("header.expires_by_type", |s| {
                s.header_policy
                    .expires_by_type
                    .push(("text/html".into(), "access plus 1 hour".into()))
            }),
            ("header.cookies", |s| {
                s.header_policy.cookies.push("session".into())
            }),
            ("header.vary", |s| {
                s.header_policy.vary.push("Accept".into())
            }),
            ("content.document_root", |s| {
                s.content_policy.document_root = Some("/srv".into())
            }),
            ("content.directory_index", |s| {
                s.content_policy.directory_index = Some(vec!["index.html".into()])
            }),
            ("content.index_ignore", |s| {
                s.content_policy.index_ignore.push("*.secret".into())
            }),
            ("content.default_charset", |s| {
                s.content_policy.default_charset = Some("utf-8".into())
            }),
            ("content.file_etag", |s| {
                s.content_policy.file_etag = Some(1)
            }),
            ("content.enable_sendfile", |s| {
                s.content_policy.enable_sendfile = Some(true)
            }),
            ("content.directory_slash", |s| {
                s.content_policy.directory_slash = Some(false)
            }),
            ("content.add_types", |s| {
                s.content_policy
                    .add_types
                    .push(("text/plain".into(), ".txt".into()))
            }),
            ("content.remove_types", |s| {
                s.content_policy.remove_types.push(".txt".into())
            }),
            ("content.force_type", |s| {
                s.content_policy.force_type = Some("text/plain".into())
            }),
            ("content.access_file_names", |s| {
                s.content_policy.access_file_names = Some(vec![".htaccess".into()])
            }),
            ("mapping.aliases", |s| {
                s.mapping_policy.aliases.push(crate::config::Alias::prefix(
                    "/x".into(),
                    "/srv/x".into(),
                    false,
                ))
            }),
            ("mapping.redirects", |s| {
                s.mapping_policy.redirects.push(crate::config::Redirect {
                    from: "/x".into(),
                    to: "/y".into(),
                    status: 302,
                    regex: None,
                })
            }),
            ("mapping.handlers", |s| {
                s.mapping_policy
                    .handlers
                    .push(crate::config::Handler::add(".x".into(), "handler".into()))
            }),
            ("mapping.unsupported_filters", |s| {
                s.mapping_policy.unsupported_filters.push("INCLUDES".into())
            }),
            ("error.documents", |s| {
                s.error_policy
                    .push(404, crate::config::ErrorDoc::Text("missing".into()))
            }),
            ("environment.set_env", |s| {
                s.environment_policy.set_env.push(("A".into(), "1".into()))
            }),
            ("environment.unset_env", |s| {
                s.environment_policy.unset_env.push("A".into())
            }),
            ("environment.pass_env", |s| {
                s.environment_policy.pass_env.push("PATH".into())
            }),
            ("environment.set_env_if", |s| {
                s.environment_policy.set_env_if.push(
                    crate::config::parse_env_rule(
                        "SetEnvIf",
                        &["X-Test".into(), "yes".into(), "A=1".into()],
                    )
                    .unwrap(),
                )
            }),
            ("rewrite.engine", |s| {
                s.rewrite_policy.rewrite_engine = Some(true)
            }),
            ("rewrite.maps", |s| {
                s.rewrite_policy.rewrite_maps.push((
                    "m".into(),
                    crate::config::RewriteMap::Txt(std::collections::HashMap::from([(
                        "a".into(),
                        "b".into(),
                    )])),
                ))
            }),
            ("rewrite.cache_enable", |s| {
                s.rewrite_policy
                    .cache_enable
                    .push(("/".into(), "disk".into()))
            }),
            ("rewrite.cache_disable", |s| {
                s.rewrite_policy.cache_disable.push("/private".into())
            }),
            ("rewrite.inherit", |s| {
                s.rewrite_policy.rewrite_inherit = Some(true)
            }),
            ("rewrite.base", |s| {
                s.rewrite_policy.rewrite_base = Some("/base/".into())
            }),
            ("rewrite.match_base", |s| {
                s.rewrite_policy.rewrite_match_base = Some("/match/".into())
            }),
            ("rewrite.rules", |s| {
                s.rewrite_policy.rewrite_rules.push(
                    crate::config::parse_rewrite_rule(
                        &["^/x$".into(), "/y".into(), "[L]".into()],
                        "/",
                        false,
                    )
                    .unwrap(),
                )
            }),
            ("rewrite.pending_conds", |s| {
                s.rewrite_policy.pending_rewrite_conds.push(
                    crate::config::parse_rewrite_cond(&["%{REQUEST_URI}".into(), "^/x$".into()])
                        .unwrap(),
                )
            }),
            ("compression.rules", |s| {
                s.compression_policy
                    .compression_rules
                    .push(crate::config::CompressionRule::Set(vec![
                        crate::config::CompressionKind::Gzip,
                    ]))
            }),
            ("compression.deflate_level", |s| {
                s.compression_policy.deflate_level = Some(6)
            }),
            ("compression.brotli_quality", |s| {
                s.compression_policy.brotli_quality = Some(5)
            }),
            ("compression.deflate_alter_etag", |s| {
                s.compression_policy.deflate_alter_etag = Some(crate::config::AlterEtag::AddSuffix)
            }),
            ("compression.brotli_alter_etag", |s| {
                s.compression_policy.brotli_alter_etag = Some(crate::config::AlterEtag::Remove)
            }),
            ("proxy.rules", |s| {
                s.proxy_policy.proxy_rules.push(crate::config::ProxyRule {
                    pattern: std::sync::Arc::new(regex::Regex::new("^/x$").unwrap()),
                    backend: "http://127.0.0.1:9000/".into(),
                    route_order: 0,
                })
            }),
            ("proxy.passes", |s| {
                s.proxy_policy
                    .proxy_passes
                    .push(crate::config::ProxyPassRule {
                        prefix: "/x".into(),
                        backend: "http://127.0.0.1:9000/".into(),
                        sticky_cookie: None,
                        fail_on_status: Vec::new(),
                        route_order: 0,
                    })
            }),
            ("proxy.reverses", |s| {
                s.proxy_policy
                    .proxy_reverses
                    .push(crate::config::ProxyReverseRule {
                        front: "/x".into(),
                        backend: "http://127.0.0.1:9000/".into(),
                    })
            }),
            ("proxy.ca_file", |s| {
                s.proxy_policy.proxy_ca_file = Some("/tmp/ca.pem".into())
            }),
        ];

        for (name, mutate) in cases {
            let mut scope = Scope::default();
            mutate(&mut scope);
            assert_ne!(
                baseline,
                fingerprint(&scope),
                "cache fingerprint does not bind policy field {name}"
            );
        }
    }

    #[test]
    fn cache_policy_material_is_stable_for_rewrite_map_order() {
        let request = test_request();
        let peer = "127.0.0.1".parse().unwrap();
        let target = std::path::Path::new("/srv/x");
        let scope_with = |entries: [(&str, &str); 2]| {
            let mut scope = Scope::default();
            scope.rewrite_policy.rewrite_maps.push((
                "m".into(),
                crate::config::RewriteMap::Txt(
                    entries
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                ),
            ));
            scope
        };
        let a = scope_with([("a", "1"), ("b", "2")]);
        let b = scope_with([("b", "2"), ("a", "1")]);
        assert_eq!(
            cache_policy_fingerprint(&a, &request, peer, target),
            cache_policy_fingerprint(&b, &request, peer, target),
            "rewrite map iteration order must not change the cache fingerprint"
        );
    }

    #[test]
    fn cache_key_binds_every_request_and_listener_input() {
        let dir = std::env::temp_dir().join(format!("vapache-cache-key-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            format!(
                "Listen 127.0.0.1:8080\n\
                 ServerName localhost\n\
                 DocumentRoot \"{www}\"\n\
                 <VirtualHost *:8080>\n\
                     ServerName vhost.test\n\
                     DocumentRoot \"{www}\"\n\
                 </VirtualHost>\n",
                www = dir.display()
            ),
        )
        .unwrap();
        let mut cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        let target = std::path::Path::new("/srv/x");
        let key = |cfg: &Config,
                   vhost: Option<&VHost>,
                   local_ip: &str,
                   local_port: u16,
                   https: bool,
                   host: &str,
                   path: &str,
                   query: &[u8],
                   target: &std::path::Path,
                   fingerprint: PolicyFingerprint| {
            base_key(
                cfg,
                vhost,
                local_ip,
                local_port,
                https,
                host,
                path,
                query,
                target,
                fingerprint,
            )
        };
        let baseline = key(
            &cfg,
            None,
            "127.0.0.1",
            8080,
            false,
            "example.test",
            "/x",
            b"",
            target,
            [7u8; 32],
        );
        let variants = [
            key(
                &cfg,
                None,
                "127.0.0.2",
                8080,
                false,
                "example.test",
                "/x",
                b"",
                target,
                [7u8; 32],
            ),
            key(
                &cfg,
                None,
                "127.0.0.1",
                8081,
                false,
                "example.test",
                "/x",
                b"",
                target,
                [7u8; 32],
            ),
            key(
                &cfg,
                None,
                "127.0.0.1",
                8080,
                true,
                "example.test",
                "/x",
                b"",
                target,
                [7u8; 32],
            ),
            key(
                &cfg,
                None,
                "127.0.0.1",
                8080,
                false,
                "other.test",
                "/x",
                b"",
                target,
                [7u8; 32],
            ),
            key(
                &cfg,
                None,
                "127.0.0.1",
                8080,
                false,
                "example.test",
                "/y",
                b"",
                target,
                [7u8; 32],
            ),
            key(
                &cfg,
                None,
                "127.0.0.1",
                8080,
                false,
                "example.test",
                "/x",
                b"a=1",
                target,
                [7u8; 32],
            ),
            key(
                &cfg,
                None,
                "127.0.0.1",
                8080,
                false,
                "example.test",
                "/x",
                b"",
                std::path::Path::new("/srv/y"),
                [7u8; 32],
            ),
            key(
                &cfg,
                None,
                "127.0.0.1",
                8080,
                false,
                "example.test",
                "/x",
                b"",
                target,
                [8u8; 32],
            ),
        ];
        for (index, variant) in variants.iter().enumerate() {
            assert_ne!(baseline, *variant, "cache key input {index} is not bound");
        }

        let original_root = cfg.server_root.clone();
        cfg.server_root = dir.join("other-root");
        assert_ne!(
            baseline,
            key(
                &cfg,
                None,
                "127.0.0.1",
                8080,
                false,
                "example.test",
                "/x",
                b"",
                target,
                [7u8; 32]
            ),
            "server root is not bound"
        );
        cfg.server_root = original_root;

        let vhost = cfg.vhosts.first().expect("configured vhost");
        assert_ne!(
            baseline,
            key(
                &cfg,
                Some(vhost),
                "127.0.0.1",
                8080,
                false,
                "example.test",
                "/x",
                b"",
                target,
                [7u8; 32]
            ),
            "vhost identity is not bound"
        );

        let request = test_request();
        let peer = "127.0.0.1".parse().unwrap();
        let fingerprint = |req: &crate::http::Request, peer: IpAddr, target: &std::path::Path| {
            cache_policy_fingerprint(&Scope::default(), req, peer, target)
        };
        let baseline_fp = fingerprint(&request, peer, target);
        let mut other = test_request();
        other.method = "HEAD".into();
        assert_ne!(baseline_fp, fingerprint(&other, peer, target), "method");
        other = test_request();
        other
            .headers
            .insert("x-tenant", "alpha".as_bytes().to_vec());
        assert_ne!(baseline_fp, fingerprint(&other, peer, target), "header");
        assert_ne!(
            baseline_fp,
            fingerprint(&request, "127.0.0.2".parse().unwrap(), target),
            "peer"
        );
        assert_ne!(
            baseline_fp,
            fingerprint(&request, peer, std::path::Path::new("/srv/y")),
            "resolved target"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_key_includes_policy_fingerprint() {
        let a = format!("{}\nhost\n/path\n\n{}", "/srv", key_component(&[0u8; 32]));
        let b = format!("{}\nhost\n/path\n\n{}", "/srv", key_component(&[1u8; 32]));
        assert_ne!(a, b);
        // Credentials must never be persisted as cache metadata.
        assert!(HOP_HEADERS.contains(&"authorization"));
        assert!(HOP_HEADERS.contains(&"proxy-authorization"));
    }

    #[test]
    fn ignore_query_string_never_shares_dynamic_cgi_representations() {
        let dir =
            std::env::temp_dir().join(format!("vapache-cache-ignore-query-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let cgi = dir.join("www").join("cgi");
        fs::create_dir_all(&cgi).unwrap();
        fs::write(cgi.join("wallet.cgi"), "#!/bin/sh\nexit 0\n").unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            format!(
                "Listen 127.0.0.1:0\n\
DocumentRoot \"{www}\"\n\
CacheRoot \"{cache}\"\n\
CacheEnable disk /\n\
CacheIgnoreQueryString On\n\
CacheDefaultExpire 60\n\
AddHandler cgi-script .cgi\n\
<Directory \"{www}\">\n\
    Options +ExecCGI\n\
    Require all granted\n\
</Directory>\n",
                www = dir.join("www").display(),
                cache = dir.join("cache").display(),
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
        let request = crate::http::Request {
            method: "GET".into(),
            target: b"/cgi/wallet.cgi?nonce=1".to_vec(),
            raw_path: b"/cgi/wallet.cgi".to_vec(),
            query: b"nonce=1".to_vec(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        assert!(request_scope(
            &cfg,
            None,
            &request,
            "127.0.0.1".parse().unwrap(),
            "/cgi/wallet.cgi",
            80,
            false,
            "localhost",
            "localhost",
            "127.0.0.1",
        )
        .is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_key_is_injective_over_raw_bytes() {
        let dir =
            std::env::temp_dir().join(format!("vapache-cache-key-bytes-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(&conf, "Listen 127.0.0.1:0\n").unwrap();
        let cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        let key = |query: &[u8], target: &std::path::Path| {
            base_key(
                &cfg,
                None,
                "127.0.0.1",
                80,
                false,
                "example.test",
                "/index.php",
                query,
                target,
                [7u8; 32],
            )
        };
        let target = std::path::Path::new("/srv/index.php");
        assert_ne!(key(b"", target), key(b"\xff", target));
        assert_ne!(key(b"?a=\xff", target), key(b"?a=\xfe", target));
        // The UTF-8 replacement bytes of a lossy conversion must not share a
        // key with the raw invalid byte (F55/I51).
        assert_ne!(key(b"\xff", target), key(b"\xef\xbf\xbd", target));
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let invalid_target = std::path::Path::new(OsStr::from_bytes(b"/srv/\xff"));
        assert_ne!(key(b"", target), key(b"", invalid_target));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_rejects_non_utf8_paths() {
        let dir = std::env::temp_dir().join(format!(
            "vapache-cache-non-utf8-path-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let www = dir.join("www");
        fs::create_dir_all(&www).unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            format!(
                "Listen 127.0.0.1:0\n\
DocumentRoot \"{www}\"\n\
CacheRoot \"{cache}\"\n\
CacheEnable disk /\n\
<Directory \"{www}\">\n\
    Require all granted\n\
</Directory>\n",
                www = www.display(),
                cache = dir.join("cache").display(),
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
        let request = crate::http::Request {
            method: "GET".into(),
            target: b"/\xff".to_vec(),
            raw_path: b"/\xff".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        assert!(request_scope(
            &cfg,
            None,
            &request,
            "127.0.0.1".parse().unwrap(),
            "/\u{fffd}",
            80,
            false,
            "localhost",
            "localhost",
            "127.0.0.1",
        )
        .is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ignore_query_string_bypasses_set_handler_and_server_status() {
        for handler in ["proxy:unix:/nonexistent|fcgi://localhost", "server-status"] {
            let dir = std::env::temp_dir().join(format!(
                "vapache-cache-handler-{}-{}",
                handler.contains("server-status") as u8,
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            let www = dir.join("www");
            fs::create_dir_all(&www).unwrap();
            fs::write(www.join("direct.php"), "not executed\n").unwrap();
            let conf = dir.join("httpd.conf");
            fs::write(
                &conf,
                format!(
                    "Listen 127.0.0.1:0\n\
DocumentRoot \"{www}\"\n\
CacheRoot \"{cache}\"\n\
CacheEnable disk /\n\
CacheIgnoreQueryString On\n\
<FilesMatch \"\\.php$\">\n\
    SetHandler \"{handler}\"\n\
</FilesMatch>\n\
<Directory \"{www}\">\n\
    Require all granted\n\
</Directory>\n",
                    www = www.display(),
                    cache = dir.join("cache").display(),
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
            let request = crate::http::Request {
                method: "GET".into(),
                target: b"/direct.php?token=alpha".to_vec(),
                raw_path: b"/direct.php".to_vec(),
                query: b"token=alpha".to_vec(),
                version: crate::http::Version::Http11,
                headers: crate::http::Headers::default(),
                body: Vec::new(),
                body_spool: None,
                keep_alive: true,
                expect_continue: false,
                framing: crate::verified::BodyFraming::None,
            };
            assert!(
                request_scope(
                    &cfg,
                    None,
                    &request,
                    "127.0.0.1".parse().unwrap(),
                    "/direct.php",
                    80,
                    false,
                    "localhost",
                    "localhost",
                    "127.0.0.1",
                )
                .is_none(),
                "dynamic handler {handler} was treated as static"
            );
            let _ = fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn local_error_document_is_never_cache_scoped() {
        let dir = std::env::temp_dir().join(format!(
            "vapache-cache-error-document-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let www = dir.join("www");
        fs::create_dir_all(&www).unwrap();
        fs::write(www.join("404.html"), "missing\n").unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            format!(
                "Listen 127.0.0.1:0\n\
DocumentRoot \"{www}\"\n\
CacheRoot \"{cache}\"\n\
CacheEnable disk /\n\
ErrorDocument 404 /404.html\n\
<Directory \"{www}\">\n\
    Require all granted\n\
</Directory>\n",
                www = www.display(),
                cache = dir.join("cache").display(),
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
        let request = crate::http::Request {
            method: "GET".into(),
            target: b"/missing".to_vec(),
            raw_path: b"/missing".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        assert!(request_scope(
            &cfg,
            None,
            &request,
            "127.0.0.1".parse().unwrap(),
            "/missing",
            80,
            false,
            "localhost",
            "localhost",
            "127.0.0.1",
        )
        .is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn directory_index_binds_cache_target_and_live_policy() {
        let dir =
            std::env::temp_dir().join(format!("vapache-cache-dir-index-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let www = dir.join("www");
        fs::create_dir_all(www.join("dir")).unwrap();
        fs::write(www.join("dir/index.html"), "index\n").unwrap();
        fs::write(www.join("dir/.htaccess"), "# no deny\n").unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            format!(
                "Listen 127.0.0.1:0\n\
DocumentRoot \"{www}\"\n\
CacheRoot \"{cache}\"\n\
CacheEnable disk /\n\
DirectoryIndex index.html\n\
<Directory \"{www}\">\n\
    AllowOverride All\n\
    Require all granted\n\
</Directory>\n",
                www = www.display(),
                cache = dir.join("cache").display(),
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
        let request = crate::http::Request {
            method: "GET".into(),
            target: b"/dir/".to_vec(),
            raw_path: b"/dir/".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        let ctx = request_scope(
            &cfg,
            None,
            &request,
            "127.0.0.1".parse().unwrap(),
            "/dir/",
            80,
            false,
            "localhost",
            "localhost",
            "127.0.0.1",
        )
        .expect("directory index cache scope");
        assert_eq!(ctx.target, www.join("dir/index.html"));
        assert_eq!(ctx.path, "/dir/index.html");

        fs::write(
            www.join("dir/.htaccess"),
            "<Files \"index.html\">\n    Require all denied\n</Files>\n",
        )
        .unwrap();
        assert!(request_scope(
            &cfg,
            None,
            &request,
            "127.0.0.1".parse().unwrap(),
            "/dir/",
            80,
            false,
            "localhost",
            "localhost",
            "127.0.0.1",
        )
        .is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_control_ttl_is_bounded() {
        let cfg = crate::config::CacheConfig::default();
        let headers = vec![("Cache-Control".into(), b"max-age=999999".to_vec())];
        assert_eq!(freshness(&cfg, &headers, 100), Some(cfg.max_expire as i64));

        // A reversed configuration pair must disable reuse instead of
        // panicking in `i64::clamp` (verified `cache_ttl_clamp`).
        let mut reversed = crate::config::CacheConfig::default();
        reversed.min_expire = 60;
        reversed.max_expire = 5;
        assert_eq!(freshness(&reversed, &headers, 100), Some(0));
        assert_eq!(vapache_verified::cache_expiry(i64::MAX - 1, 10), i64::MAX);
    }

    #[test]
    fn verified_cache_store_and_accounting_gates_cover_edge_cases() {
        assert!(vapache_verified::cache_store_request_admit(
            true, true, true
        ));
        assert!(!vapache_verified::cache_store_request_admit(
            false, true, true
        ));
        assert!(!vapache_verified::cache_store_request_admit(
            true, false, true
        ));
        assert!(!vapache_verified::cache_store_request_admit(
            true, true, false
        ));

        assert!(vapache_verified::cache_store_status_admit(200));
        assert!(vapache_verified::cache_store_status_admit(404));
        assert!(!vapache_verified::cache_store_status_admit(500));

        assert!(!vapache_verified::cache_store_control_admit(
            true, false, false, false, false, false
        ));
        assert!(vapache_verified::cache_store_control_admit(
            true, false, false, true, false, false
        ));
        assert!(!vapache_verified::cache_store_control_admit(
            false, true, false, false, false, false
        ));

        assert!(vapache_verified::cache_store_shape_admit(
            false, false, true
        ));
        assert!(!vapache_verified::cache_store_shape_admit(
            true, false, true
        ));
        assert!(!vapache_verified::cache_store_shape_admit(
            false, true, true
        ));
        assert!(!vapache_verified::cache_store_shape_admit(
            false, false, false
        ));
        assert!(vapache_verified::cache_store_ttl_admit(1));
        assert!(!vapache_verified::cache_store_ttl_admit(0));

        assert_eq!(vapache_verified::cache_disk_projected(10, 20, 3), 3);
        assert_eq!(vapache_verified::cache_disk_evict(10, 20), 0);
    }

    fn disk_test_config(name: &str) -> (std::path::PathBuf, Config) {
        let dir =
            std::env::temp_dir().join(format!("vapache-cache-quota-{}-{name}", std::process::id()));
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
        (dir, cfg)
    }

    fn disk_entry(body: &[u8], expires: i64) -> Entry {
        Entry {
            status: 200,
            headers: vec![("content-type".into(), b"text/plain".to_vec())],
            body: body.to_vec(),
            stored: unix_now(),
            expires,
            policy: [7u8; 32],
            epoch: current_epoch(),
            vary: Vec::new(),
        }
    }

    #[test]
    fn disk_cache_enforces_total_quota_and_rejects_oversize_entries() {
        let (dir, mut cfg) = disk_test_config("evict");
        cfg.cache.max_disk_size = 6_000;
        disk_store(
            &cfg,
            "first",
            &disk_entry(&vec![b'a'; 4_000], unix_now() + 60),
        );
        let first = cache_stem(&cfg, "first").unwrap();
        assert!(first.with_extension("body").is_file());
        disk_store(
            &cfg,
            "second",
            &disk_entry(&vec![b'b'; 4_000], unix_now() + 60),
        );
        let second = cache_stem(&cfg, "second").unwrap();
        assert!(second.with_extension("body").is_file());
        assert!(!first.with_extension("body").exists());
        assert!(!first.with_extension("meta").exists());

        // A single entry larger than the total budget is never persisted.
        cfg.cache.max_disk_size = 128;
        disk_store(
            &cfg,
            "oversize",
            &disk_entry(&vec![b'c'; 1_024], unix_now() + 60),
        );
        let oversize = cache_stem(&cfg, "oversize").unwrap();
        assert!(!oversize.with_extension("body").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disk_cache_deletes_expired_entries_on_lookup() {
        let (dir, cfg) = disk_test_config("expired");
        disk_store(&cfg, "expired", &disk_entry(b"stale", unix_now() - 1));
        let stem = cache_stem(&cfg, "expired").unwrap();
        assert!(stem.with_extension("body").is_file());
        assert!(disk_load(&cfg, "expired").is_none());
        assert!(!stem.with_extension("body").exists());
        assert!(!stem.with_extension("meta").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
