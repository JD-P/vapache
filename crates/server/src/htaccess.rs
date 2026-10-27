//! Per-directory `.htaccess` overrides.
//!
//! Only the security-sensitive and commonly used per-directory directives are
//! implemented.  Parsing is fail-closed: an unknown directive, an unsupported
//! section, an unreadable file or a file over the size limit produces a 500
//! instead of silently ignoring a possible access-control rule.

use crate::config::{
    normalize_rewrite_base, parse_filter_tokens, parse_ip_net, parse_require, parse_rewrite_cond,
    parse_rewrite_rule, AlterEtag, AuthMerging, CompressionRule, ConditionBranch, Config, ErrorDoc,
    HostSpec, MatchKind, MethodSet, NonfatalMode, Options, Order, OverrideCategories,
    OverrideCategory, OverrideMode, Require, RequireNode, Satisfy, Scope, ScopeRule, VHost,
};
use crate::config_frontend::{logical_lines, tokenize_config};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

const MAX_HTACCESS: u64 = 1024 * 1024;

pub fn apply(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &mut Scope,
    fs_path: &Path,
    url_path: &str,
) -> Result<(), String> {
    apply_req(
        cfg,
        vhost,
        scope,
        fs_path,
        url_path,
        None,
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
    )
}

pub fn apply_req(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &mut Scope,
    fs_path: &Path,
    url_path: &str,
    req: Option<&crate::http::Request>,
    peer: std::net::IpAddr,
) -> Result<(), String> {
    let mut config_files = Vec::new();
    let mut files = Vec::new();
    let mut deferred = Vec::new();
    let result = apply_req_deferred(
        cfg,
        vhost,
        scope,
        fs_path,
        url_path,
        req,
        peer,
        &mut files,
        &mut deferred,
        false,
        &mut config_files,
    );
    if result.is_err() {
        return result;
    }
    if let Some(req) = req {
        let fname = fs_path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        let docroot = cfg.documentation_root_for(vhost);
        crate::config::apply_normal_rule_list(
            &files,
            scope,
            req,
            peer,
            &docroot,
            fs_path,
            url_path,
            &fname,
            &mut deferred,
        );
        deferred.sort_by_key(|rule| rule.order);
        let mut chain_state: HashMap<usize, bool> = HashMap::new();
        crate::config::apply_deferred_req(
            scope,
            &deferred,
            req,
            peer,
            &docroot,
            fs_path,
            url_path,
            &fname,
            &mut chain_state,
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn apply_req_deferred(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &mut Scope,
    fs_path: &Path,
    url_path: &str,
    req: Option<&crate::http::Request>,
    peer: std::net::IpAddr,
    files: &mut Vec<crate::config::ScopeRule>,
    deferred: &mut Vec<crate::config::ScopeRule>,
    apply_config_dirs: bool,
    config_files: &mut Vec<crate::config::ScopeRule>,
) -> Result<(), String> {
    apply_req_deferred_with_root(
        cfg,
        vhost,
        scope,
        fs_path,
        url_path,
        req,
        peer,
        files,
        deferred,
        apply_config_dirs,
        config_files,
        None,
    )
}

/// The access-file walk with the actual URL-mapping root supplied by
/// `map_path()`.  The root is only a URL/base label for `RewriteBase`; it is
/// never an authorization boundary.  Every ancestor directory participates
/// when its effective `AllowOverride` policy permits an access file (F50/F51).
#[allow(clippy::too_many_arguments)]
pub fn apply_req_deferred_with_root(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &mut Scope,
    fs_path: &Path,
    url_path: &str,
    req: Option<&crate::http::Request>,
    peer: std::net::IpAddr,
    files: &mut Vec<crate::config::ScopeRule>,
    deferred: &mut Vec<crate::config::ScopeRule>,
    apply_config_dirs: bool,
    config_files: &mut Vec<crate::config::ScopeRule>,
    mapping_root: Option<&Path>,
) -> Result<(), String> {
    let root = mapping_root
        .map(Path::to_path_buf)
        .unwrap_or_else(|| access_root_for(cfg, vhost, fs_path));
    let start = walk_start(fs_path);
    let dirs = ancestor_dirs(start);
    let can_read_access = cfg.override_enabled && cfg.override_applicable(fs_path);
    let mut ignored_locations = Vec::new();
    for dir in dirs {
        // A PATH_INFO request maps to `script.cgi/info`; the immediate
        // "parent" is the script file, not a directory.  Only real
        // directories can contain access files.
        let is_dir = crate::files::is_dir_cached(&dir);
        if !is_dir {
            continue;
        }
        if apply_config_dirs {
            if let Some(req) = req {
                cfg.apply_directory_rules_for_dir(
                    vhost,
                    scope,
                    req,
                    peer,
                    &dir,
                    fs_path,
                    url_path,
                    config_files,
                    &mut ignored_locations,
                    deferred,
                );
            }
        }
        if !can_read_access {
            continue;
        }
        // Ancestors above every override-enabled directory cannot contribute
        // an access-file layer; skip their existence probes (F50 still covers
        // an enabled ancestor itself).
        if !cfg.access_file_dir_applicable(&dir) {
            continue;
        }
        // Resolving a per-directory scope walks the vhost and rule lists.  The
        // overwhelmingly common case is a tree with no access files at all, so
        // avoid that work unless an access file is actually present here.
        let mut has_access_file = false;
        for name in &cfg.access_file_names {
            match crate::files::metadata_cached(&dir.join(name)) {
                Ok(meta) if meta.is_file() => {
                    has_access_file = true;
                    break;
                }
                _ => {}
            }
        }
        if !has_access_file {
            continue;
        }
        let dir_scope = cfg.effective_scope_cached(vhost, &dir, url_path);
        let mode = dir_scope.override_policy.mode();
        let allow_list = dir_scope.override_policy.allow_list();
        let nonfatal = dir_scope.override_policy.nonfatal();
        if !mode.is_enabled() && allow_list.is_empty() {
            continue;
        }
        for name in cfg.access_file_names_for(&dir_scope) {
            let path = dir.join(&name);
            let delta = match crate::files::metadata_cached(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("{}: {e}", path.display())),
                Ok(m) if !m.is_file() => {
                    return Err(format!("{}: not a regular file", path.display()))
                }
                Ok(m) if m.len() > MAX_HTACCESS => {
                    return Err(format!("{}: access file too large", path.display()))
                }
                Ok(meta) => {
                    let identity =
                        crate::request_plan::LayerIdentity::new(&root, &dir, fs_path, url_path);
                    parse_cached(cfg, &path, mode, allow_list, nonfatal, &identity, &meta)?
                }
            };
            scope.merge(&delta.scope);
            let fname = fs_path
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_default();
            let docroot = cfg.documentation_root_for(vhost);
            if req.is_some() {
                for rule in &delta.rules {
                    if rule.condition.is_some() || rule.branch != ConditionBranch::Normal {
                        deferred.push(rule.clone());
                    } else if matches!(rule.kind, MatchKind::Files(_) | MatchKind::FilesMatch(_)) {
                        files.push(rule.clone());
                    }
                }
            } else {
                crate::config::apply_rules_config(&delta.rules, scope, fs_path, url_path, &fname);
            }
        }
    }
    if apply_config_dirs {
        cfg.apply_directory_match_rules(
            vhost,
            scope,
            fs_path,
            url_path,
            config_files,
            &mut ignored_locations,
            deferred,
        );
    }
    Ok(())
}

fn walk_start(fs_path: &Path) -> &Path {
    if crate::files::is_dir_cached(fs_path) {
        fs_path
    } else {
        fs_path.parent().unwrap_or(fs_path)
    }
}

/// Every ancestor of `start`, from the filesystem root down to `start`.
/// Access-file authorization is directory-based, so this list is independent
/// of `DocumentRoot` and of any alias root (F50).
fn ancestor_dirs(start: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut cur = Some(start);
    while let Some(d) = cur {
        dirs.push(d.to_path_buf());
        let Some(parent) = d.parent() else {
            break;
        };
        cur = Some(parent);
    }
    // The parent walk already produces leaf-to-root order; reversing is
    // equivalent to sorting by component count for normal absolute paths and
    // avoids repeated `Path::components` parsing on every request.
    dirs.reverse();
    dirs.dedup();
    dirs
}

/// Fallback mapping root used only for URL/`RewriteBase` derivation when a
/// compatibility caller does not supply the root returned by `map_path()`.
/// For a document-root target this is `DocumentRoot`; for an
/// `Alias`/`ScriptAlias` target outside the document root it is the alias
/// target directory.  This value never bounds which ancestors contribute an
/// access file: Apache walks every ancestor whose `<Directory>` permits
/// `AllowOverride` (F50/F51).  Production authorization callers always pass
/// the URL-selected root explicitly.
fn access_root_for(cfg: &Config, vhost: Option<&VHost>, fs_path: &Path) -> PathBuf {
    let docroot = cfg.documentation_root_for(vhost);
    if fs_path == docroot || fs_path.starts_with(&docroot) {
        return docroot;
    }
    let base = vhost.map(|v| &v.scope).unwrap_or(&cfg.global);
    // Best-effort compatibility reconstruction only.  This containment-based
    // search cannot distinguish overlapping aliases; production callers use
    // the root selected by the URL mapping instead (F51/I48).
    for alias in &base.mapping_policy.aliases {
        if alias.fs_path.as_os_str().is_empty() {
            continue;
        }
        if fs_path == alias.fs_path || fs_path.starts_with(&alias.fs_path) {
            // A single-file target's access root is its parent directory.
            // Returning the file path made every `dir.starts_with(root)` test
            // fail and silently skipped the target directory's `.htaccess`
            // (F39/I36).  This applies to regex aliases too: a replacement
            // ending in `/` whose stable prefix names a file still has a file
            // base (F47/I44).
            if !alias.fs_path.is_dir() {
                return alias
                    .fs_path
                    .parent()
                    .unwrap_or(&alias.fs_path)
                    .to_path_buf();
            }
            return alias.fs_path.clone();
        }
    }
    docroot
}

/// Parse the access files that affect a request into pure layers.  Filesystem
/// I/O and parsing stay here; the merge is performed by
/// `policy_ref::effective_scope_with_layers`, so the interleaving has a single
/// implementation shared with the reference evaluator.
pub fn collect_layers(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    url_path: &str,
) -> Result<Vec<crate::policy_ref::AccessLayer>, String> {
    collect_layers_with_root(cfg, vhost, fs_path, url_path, None)
}

/// The lexical URL-mapped counterpart of a target directory when the mapping
/// root itself contains a symlink.  This is used only to inherit the
/// `AllowOverride` policy attached to the URL-mapped `<Directory>`; access
/// files are still read from the explicit target's own canonical directories
/// (F59/I60).
fn mapped_policy_dir(root: &Path, canonical_root: Option<&Path>, dir: &Path) -> Option<PathBuf> {
    if dir.starts_with(root) {
        return Some(dir.to_path_buf());
    }
    let canonical_root = canonical_root?;
    let rel = dir.strip_prefix(canonical_root).ok()?;
    Some(root.join(rel))
}

/// Collect access-file layers using the actual alias/mapping root selected by
/// `map_path()` for URL-base derivation.  The ancestor walk itself is not
/// bounded by that root (F50/F51) or by the lexical spelling of a symlinked
/// root (F59): layer files are always read from `fs_path`'s ancestors.
pub fn collect_layers_with_root(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    url_path: &str,
    mapping_root: Option<&Path>,
) -> Result<Vec<crate::policy_ref::AccessLayer>, String> {
    let root = match mapping_root {
        Some(root) => {
            // Callers pass the root returned by `map_path()` for the URL that
            // actually matched; they never infer it from alias containment.
            debug_assert!(crate::verified::alias_mapping_root_admit(true, false));
            root.to_path_buf()
        }
        None => access_root_for(cfg, vhost, fs_path),
    };
    let canonical_root = if fs_path.starts_with(&root) {
        None
    } else {
        fs::canonicalize(&root).ok()
    };
    if !cfg.htaccess_may_apply(fs_path)
        && !mapped_policy_dir(&root, canonical_root.as_deref(), fs_path)
            .is_some_and(|mapped| cfg.htaccess_may_apply(&mapped))
    {
        return Ok(Vec::new());
    }
    let start = walk_start(fs_path);
    let dirs = ancestor_dirs(start);
    let mut layers = Vec::new();
    for dir in dirs {
        // Ancestors above every override-enabled directory cannot contribute
        // an accessible layer (F50 still covers an enabled ancestor itself).
        let mapped_dir = mapped_policy_dir(&root, canonical_root.as_deref(), &dir);
        let policy_applicable = cfg.access_file_dir_applicable(&dir)
            || mapped_dir
                .as_deref()
                .is_some_and(|mapped| mapped != dir && cfg.access_file_dir_applicable(mapped));
        if !policy_applicable {
            continue;
        }
        let is_dir = crate::files::is_dir_cached(&dir);
        if !is_dir {
            continue;
        }
        let mut dir_scope = cfg.effective_scope_cached(vhost, &dir, url_path);
        if let Some(mapped) = mapped_dir.as_deref().filter(|mapped| *mapped != dir) {
            let mapped_scope = cfg.effective_scope_cached(vhost, mapped, url_path);
            if mapped_scope.override_policy.is_enabled() {
                dir_scope = mapped_scope;
            }
        }
        let mode = dir_scope.override_policy.mode();
        let allow_list = dir_scope.override_policy.allow_list();
        let nonfatal = dir_scope.override_policy.nonfatal();
        if !crate::verified::access_walk_dir_admit(
            is_dir,
            mode.is_enabled() || !allow_list.is_empty(),
        ) {
            continue;
        }
        let identity = crate::request_plan::LayerIdentity::new(&root, &dir, fs_path, url_path);
        let mut layer = crate::policy_ref::AccessLayer {
            identity: identity.clone(),
            scope: Arc::new(Scope::default()),
            files: Vec::new(),
            conditionals: Vec::new(),
        };
        let mut found = false;
        for name in cfg.access_file_names_for(&dir_scope) {
            let path = dir.join(&name);
            let meta = match crate::files::metadata_cached(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("{}: {e}", path.display())),
                Ok(m) if !m.is_file() => {
                    return Err(format!("{}: not a regular file", path.display()))
                }
                Ok(m) if m.len() > MAX_HTACCESS => {
                    return Err(format!("{}: access file too large", path.display()))
                }
                Ok(m) => m,
            };
            let parsed = parse_cached(cfg, &path, mode, allow_list, nonfatal, &identity, &meta)?;
            if found {
                Arc::make_mut(&mut layer.scope).merge(&parsed.scope);
            } else {
                // Preserve AuthMerging on the first access file; the cached
                // parsed scope is shared rather than cloned per request.
                layer.scope = Arc::clone(&parsed.scope);
            }
            for rule in &parsed.rules {
                add_layer_rule(&mut layer, rule);
            }
            found = true;
        }
        if found {
            layers.push(layer);
        }
    }
    Ok(layers)
}

fn add_layer_rule(layer: &mut crate::policy_ref::AccessLayer, rule: &ScopeRule) {
    let slot = crate::verified::access_layer_slot(
        rule.condition.is_some(),
        rule.branch == ConditionBranch::Normal,
        matches!(rule.kind, MatchKind::Files(_) | MatchKind::FilesMatch(_)),
    );
    match slot {
        crate::verified::AccessLayerSlot::Conditional => layer.conditionals.push(rule.clone()),
        crate::verified::AccessLayerSlot::Files => layer.files.push(rule.clone()),
        crate::verified::AccessLayerSlot::TopLevel => {}
    }
}

/// Diagnostic trace for `--explain`: which access files are present, which
/// override policy applies, and how many rules each parsed file contributes.
pub fn trace_access_files(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    url_path: &str,
) -> Vec<String> {
    trace_access_files_with_root(cfg, vhost, fs_path, url_path, None)
}

/// `--explain` trace using the actual mapping root for URL-base derivation.
/// Like `collect_layers_with_root`, it reports every ancestor access file that
/// can participate, not only files below `DocumentRoot`/the alias target.
pub fn trace_access_files_with_root(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    url_path: &str,
    mapping_root: Option<&Path>,
) -> Vec<String> {
    let mut out = Vec::new();
    let root = mapping_root
        .map(Path::to_path_buf)
        .unwrap_or_else(|| access_root_for(cfg, vhost, fs_path));
    let canonical_root = if fs_path.starts_with(&root) {
        None
    } else {
        fs::canonicalize(&root).ok()
    };
    if !cfg.htaccess_may_apply(fs_path)
        && !mapped_policy_dir(&root, canonical_root.as_deref(), fs_path)
            .is_some_and(|mapped| cfg.htaccess_may_apply(&mapped))
    {
        out.push("skipped (no override-enabled directory in path)".into());
        return out;
    }
    let start = walk_start(fs_path);
    let dirs = ancestor_dirs(start);
    let mut found = false;
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        let mapped_dir = mapped_policy_dir(&root, canonical_root.as_deref(), &dir);
        let policy_applicable = cfg.access_file_dir_applicable(&dir)
            || mapped_dir
                .as_deref()
                .is_some_and(|mapped| mapped != dir && cfg.access_file_dir_applicable(mapped));
        if !policy_applicable {
            continue;
        }
        let mut dir_scope = cfg.effective_scope_cached(vhost, &dir, url_path);
        if let Some(mapped) = mapped_dir.as_deref().filter(|mapped| *mapped != dir) {
            let mapped_scope = cfg.effective_scope_cached(vhost, mapped, url_path);
            if mapped_scope.override_policy.is_enabled() {
                dir_scope = mapped_scope;
            }
        }
        let mode = dir_scope.override_policy.mode();
        let allow_list = dir_scope.override_policy.allow_list();
        let nonfatal = dir_scope.override_policy.nonfatal();
        if !mode.is_enabled() && allow_list.is_empty() {
            continue;
        }
        for name in cfg.access_file_names_for(&dir_scope) {
            let path = dir.join(&name);
            let Ok(meta) = fs::metadata(&path) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            found = true;
            let identity = crate::request_plan::LayerIdentity::new(&root, &dir, fs_path, url_path);
            match parse_cached(cfg, &path, mode, allow_list, nonfatal, &identity, &meta) {
                Ok(parsed) => out.push(format!(
                    "{} mode={:?} list={:?} nonfatal={:?} rules={}",
                    path.display(),
                    mode,
                    allow_list,
                    nonfatal,
                    parsed.rules.len()
                )),
                Err(e) => out.push(format!("{} ERROR: {e}", path.display())),
            }
        }
    }
    if !found {
        out.push("no access files present in override-enabled path".into());
    }
    out
}

#[cfg(test)]
fn rule_matches(kind: &MatchKind, fname: &str, url_path: &str) -> bool {
    match kind {
        MatchKind::Always => true,
        MatchKind::Files(re) | MatchKind::FilesMatch(re) => re.is_match(fname),
        MatchKind::Location(prefix) => {
            let base = prefix.trim_end_matches('/');
            base.is_empty()
                || url_path == base
                || (url_path.starts_with(base)
                    && url_path.as_bytes().get(base.len()) == Some(&b'/'))
        }
        MatchKind::LocationMatch(re) => re.is_match(url_path),
        MatchKind::Directory(p) => Path::new(url_path).starts_with(p),
        MatchKind::DirectoryMatch(re) => re.is_match(url_path),
    }
}

struct Parsed {
    scope: Arc<Scope>,
    rules: Vec<ScopeRule>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    path: PathBuf,
    server_root: PathBuf,
    dev: u64,
    ino: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    size: u64,
    mode: u32,
    allow_list: Vec<String>,
    nonfatal: u8,
    identity: crate::request_plan::LayerIdentity,
}

fn mode_key(mode: OverrideMode) -> u32 {
    match mode {
        OverrideMode::None => 0,
        OverrideMode::All => 1,
        OverrideMode::Categories(c) => 2 | (c.0 << 1),
    }
}

fn cache() -> &'static Mutex<HashMap<CacheKey, Arc<Parsed>>> {
    static CACHE: OnceLock<Mutex<HashMap<CacheKey, Arc<Parsed>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn parse_cached(
    cfg: &Config,
    path: &Path,
    mode: OverrideMode,
    allow_list: &[String],
    nonfatal: NonfatalMode,
    identity: &crate::request_plan::LayerIdentity,
    meta: &fs::Metadata,
) -> Result<Arc<Parsed>, String> {
    let key = CacheKey {
        path: path.to_path_buf(),
        server_root: cfg.server_root.clone(),
        dev: meta.dev(),
        ino: meta.ino(),
        mtime: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
        ctime: meta.ctime(),
        ctime_nsec: meta.ctime_nsec(),
        size: meta.len(),
        mode: mode_key(mode),
        allow_list: allow_list.to_vec(),
        nonfatal: match nonfatal {
            NonfatalMode::None => 0,
            NonfatalMode::Override => 1,
            NonfatalMode::Unknown => 2,
            NonfatalMode::All => 3,
        },
        identity: identity.clone(),
    };
    {
        let guard = cache().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(parsed) = guard.get(&key) {
            return Ok(Arc::clone(parsed));
        }
    }
    // Parse outside the lock: a slow filesystem read must not serialize
    // unrelated requests.  Duplicate parses on a race are harmless.
    let parsed = Arc::new(parse_file_with_list(
        cfg, path, mode, allow_list, nonfatal, identity,
    )?);
    let mut guard = cache().lock().unwrap_or_else(|e| e.into_inner());
    if guard.len() >= 512 {
        guard.clear();
    }
    guard.insert(key, Arc::clone(&parsed));
    Ok(parsed)
}

#[cfg(test)]
fn parse_file(
    cfg: &Config,
    path: &Path,
    mode: OverrideMode,
    base_url: &str,
) -> Result<Parsed, String> {
    let dir = path.parent().unwrap_or(path);
    let identity = crate::request_plan::LayerIdentity::with_url_mount(dir, dir, base_url);
    parse_file_with_list(cfg, path, mode, &[], NonfatalMode::None, &identity)
}

fn parse_file_with_list(
    cfg: &Config,
    path: &Path,
    mode: OverrideMode,
    allow_list: &[String],
    nonfatal: NonfatalMode,
    identity: &crate::request_plan::LayerIdentity,
) -> Result<Parsed, String> {
    let data = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if data.len() as u64 > MAX_HTACCESS {
        return Err(format!("{}: .htaccess file too large", path.display()));
    }
    let text = String::from_utf8_lossy(&data);
    let lines = logical_lines(&text);
    let mut scope = Scope::default();
    let mut rules = Vec::new();
    scope.rewrite_policy.rewrite_base = Some(identity.url_mount.clone());
    scope.rewrite_policy.rewrite_match_base = Some(identity.url_mount.clone());
    let mut i = 0;
    let mut next_chain = 0usize;
    parse_block(
        cfg,
        &lines,
        &mut i,
        &mut scope,
        &mut rules,
        mode,
        allow_list,
        nonfatal,
        None,
        false,
        &mut next_chain,
        None,
    )
    .map_err(|e| format!("{}: {e}", path.display()))?;
    for rule in &mut scope.rewrite_policy.rewrite_rules {
        rule.subject_dir = Some(identity.dir.clone());
    }
    Ok(Parsed {
        scope: Arc::new(scope),
        rules,
    })
}

fn parse_block(
    cfg: &Config,
    lines: &[String],
    i: &mut usize,
    scope: &mut Scope,
    rules: &mut Vec<ScopeRule>,
    mode: OverrideMode,
    allow_list: &[String],
    nonfatal: NonfatalMode,
    end: Option<&str>,
    require_only: bool,
    next_chain: &mut usize,
    limit: Option<&MethodSet>,
) -> Result<(), String> {
    let mut current_chain: Option<usize> = None;
    while *i < lines.len() {
        let line = &lines[*i];
        *i += 1;
        let line_ir = match crate::config_frontend::parse_line(line) {
            Ok(line) => line,
            Err(e) => return Err(format!("line {}: {e}", *i)),
        };
        match line_ir {
            crate::config_frontend::ConfigLine::SectionEnd { name } => {
                return match end {
                    Some(expected) if expected == name => Ok(()),
                    Some(expected) => Err(format!(
                        "line {}: closing </{name}> does not match <{expected}>",
                        *i
                    )),
                    None => Err(format!("line {}: unexpected closing </{name}>", *i)),
                };
            }
            crate::config_frontend::ConfigLine::SectionStart { name, args } => {
                if limit.is_some()
                    && !matches!(
                        name.as_str(),
                        "limit"
                            | "limitexcept"
                            | "requireall"
                            | "requireany"
                            | "requirenone"
                            | "ifmodule"
                    )
                {
                    return Err(format!(
                        "line {}: <{name}> is not allowed inside a method-limited section",
                        *i
                    ));
                }
                match name.as_str() {
                    "if" | "iffile" | "elseif" | "else" => {
                        // Apache applies the override category to the directives
                        // inside an <If> section, not to the section itself.
                        if require_only {
                            return Err(format!("line {}: <{name}> is not allowed here", *i));
                        }
                        let (branch, chain, condition) = if name == "if" || name == "iffile" {
                            let expression = if name == "if" {
                                crate::expr::parse(&args.join(" "))
                                    .map_err(|e| format!("line {}: {e}", *i))?
                            } else {
                                let path = args.get(1).cloned().unwrap_or_default();
                                crate::expr::Expr::FileTest(
                                    "-F".into(),
                                    Box::new(crate::expr::Expr::Str(path)),
                                )
                            };
                            let chain = *next_chain;
                            *next_chain += 1;
                            current_chain = Some(chain);
                            (ConditionBranch::Normal, Some(chain), Some(expression))
                        } else {
                            let Some(chain) = current_chain else {
                                return Err(format!("line {}: <{name}> has no preceding <If>", *i));
                            };
                            if name == "elseif" {
                                let expression = crate::expr::parse(&args.join(" "))
                                    .map_err(|e| format!("line {}: {e}", *i))?;
                                (ConditionBranch::ElseIf, Some(chain), Some(expression))
                            } else {
                                if args.len() > 1 {
                                    return Err(format!(
                                        "line {}: <Else> does not take arguments",
                                        *i
                                    ));
                                }
                                current_chain = None;
                                (ConditionBranch::Else, Some(chain), None)
                            }
                        };
                        let mut inner = Scope::default();
                        let mut inner_rules = Vec::new();
                        parse_block(
                            cfg,
                            lines,
                            i,
                            &mut inner,
                            &mut inner_rules,
                            mode,
                            allow_list,
                            nonfatal,
                            Some(&name),
                            false,
                            next_chain,
                            None,
                        )?;
                        inner_rules.retain(|rule| matches!(rule.kind, MatchKind::Always));
                        rules.push(ScopeRule {
                            kind: MatchKind::Always,
                            delta: inner,
                            order: rules.len(),
                            condition,
                            branch,
                            chain,
                            nested: inner_rules,
                        });
                    }
                    "requireall" | "requireany" | "requirenone" => {
                        if !mode.allows(OverrideCategory::AuthConfig) && allow_list.is_empty() {
                            if nonfatal.allows_override() {
                                skip_section(lines, i, &name)?;
                                continue;
                            }
                            return Err(format!(
                                "line {}: <{name}> is not allowed by AllowOverride",
                                *i
                            ));
                        }
                        let mut inner = Scope::default();
                        let mut inner_rules = Vec::new();
                        parse_block(
                            cfg,
                            lines,
                            i,
                            &mut inner,
                            &mut inner_rules,
                            mode,
                            allow_list,
                            nonfatal,
                            Some(&name),
                            true,
                            next_chain,
                            limit,
                        )?;
                        // Require sections only accept Require directives, so
                        // nested parse rules are not expected here.
                        debug_assert!(inner_rules.is_empty());
                        let mut nodes = Vec::new();
                        let inner_entries = if let Some(crate::config::AuthPolicy::List(entries)) =
                            inner.authorization.requires.take()
                        {
                            entries
                        } else {
                            Vec::new()
                        };
                        for entry in inner_entries {
                            debug_assert_eq!(entry.limit.as_ref(), limit);
                            nodes.push(entry.node);
                        }
                        if !nodes.is_empty() {
                            let node = match name.as_str() {
                                "requireall" => RequireNode::All(nodes),
                                "requireany" => RequireNode::Any(nodes),
                                _ => RequireNode::None(nodes),
                            };
                            scope.add_require(node, limit);
                        }
                    }
                    "limit" | "limitexcept" => {
                        if require_only {
                            return Err(format!("line {}: <{name}> is not allowed here", *i));
                        }
                        if !(mode.allows(OverrideCategory::AuthConfig)
                            || mode.allows(OverrideCategory::Limit)
                            || !allow_list.is_empty())
                        {
                            if nonfatal.allows_override() {
                                skip_section(lines, i, &name)?;
                                continue;
                            }
                            return Err(format!(
                                "line {}: <{name}> is not allowed by AllowOverride",
                                *i
                            ));
                        }
                        let methods = crate::config::parse_method_set_args(&name, &args, true)
                            .map_err(|e| format!("line {}: {e}", *i))?;
                        let combined = match limit {
                            Some(outer) => outer.intersect(&methods),
                            None => methods,
                        };
                        if combined.is_empty() {
                            return Err(format!(
                                "line {}: nested <{name}> excludes every HTTP method",
                                *i
                            ));
                        }
                        if matches!(limit, Some(outer) if combined == *outer) {
                            return Err(format!(
                            "line {}: nested <{name}> does not further restrict the enclosing method set",
                            *i
                        ));
                        }
                        parse_block(
                            cfg,
                            lines,
                            i,
                            scope,
                            rules,
                            mode,
                            allow_list,
                            nonfatal,
                            Some(&name),
                            false,
                            next_chain,
                            Some(&combined),
                        )?;
                    }
                    "files" | "filesmatch" => {
                        // The override category applies to the directives inside
                        // the section, not to the section itself.
                        if require_only {
                            return Err(format!("line {}: <{name}> is not allowed here", *i));
                        }
                        let pat = args.join(" ");
                        let kind =
                            if name == "files" {
                                crate::config::compile_files_pattern(&args)
                                    .map_err(|e| format!("line {}: {e}", *i))?
                            } else {
                                MatchKind::FilesMatch(crate::config::compile_regex(&pat).map_err(
                                    |e| format!("line {}: bad FilesMatch regex: {e}", *i),
                                )?)
                            };
                        let mut inner = Scope::default();
                        let mut inner_rules = Vec::new();
                        parse_block(
                            cfg,
                            lines,
                            i,
                            &mut inner,
                            &mut inner_rules,
                            mode,
                            allow_list,
                            nonfatal,
                            Some(&name),
                            false,
                            next_chain,
                            None,
                        )?;
                        rules.push(ScopeRule {
                            kind,
                            delta: inner,
                            order: rules.len(),
                            condition: None,
                            branch: ConditionBranch::Normal,
                            chain: None,
                            nested: inner_rules,
                        });
                    }
                    "ifmodule" => {
                        let active = ifmodule_active(&args);
                        if active {
                            parse_block(
                                cfg,
                                lines,
                                i,
                                scope,
                                rules,
                                mode,
                                allow_list,
                                nonfatal,
                                Some(&name),
                                require_only,
                                next_chain,
                                limit,
                            )?;
                        } else {
                            skip_section(lines, i, &name)?;
                        }
                    }
                    "ifdefine" => {
                        // The configuration parser only exposes definitions to
                        // the main config.  Refuse rather than risk applying a
                        // conditional access rule in the wrong environment.
                        return Err(format!(
                            "line {}: <IfDefine> is not supported in .htaccess",
                            *i
                        ));
                    }
                    _ => {
                        if nonfatal.allows_unknown() {
                            skip_section(lines, i, &name)?;
                            continue;
                        }
                        return Err(format!(
                            "line {}: unsupported .htaccess section <{name}>",
                            *i
                        ));
                    }
                }
            }
            crate::config_frontend::ConfigLine::Directive { name, args } => {
                if require_only && name != "require" {
                    return Err(format!(
                        "line {}: only Require directives are allowed in a Require section",
                        *i
                    ));
                }
                if limit.is_some()
                    && !matches!(
                        name.as_str(),
                        "require" | "order" | "allow" | "deny" | "satisfy"
                    )
                {
                    return Err(format!(
                    "line {}: directive '{name}' is not allowed inside a method-limited section",
                    *i
                ));
                }
                if !directive_allowed_list(mode, allow_list, &name, &args) {
                    if nonfatal.allows_override() {
                        continue;
                    }
                    return Err(format!(
                        "line {}: directive '{name}' is not allowed by AllowOverride",
                        *i
                    ));
                }
                if directive_category(&name).is_none() && nonfatal.allows_unknown() {
                    continue;
                }
                apply_directive(cfg, scope, &name, &args, limit)
                    .map_err(|e| format!("line {}: {e}", *i))?;
            }
        }
    }
    if let Some(expected) = end {
        return Err(format!("missing closing </{expected}>"));
    }
    Ok(())
}

fn skip_section(lines: &[String], i: &mut usize, name: &str) -> Result<(), String> {
    let mut depth = 1usize;
    while *i < lines.len() {
        let line = &lines[*i];
        *i += 1;
        let Ok(toks) = tokenize_config(line) else {
            continue;
        };
        let Some(first) = toks.first() else {
            continue;
        };
        if first.starts_with("</") {
            let close = first
                .trim_start_matches("</")
                .trim_end_matches('>')
                .to_ascii_lowercase();
            if close == name && depth == 1 {
                return Ok(());
            }
            if close == name {
                depth -= 1;
            }
        } else if first.starts_with('<') {
            depth += 1;
        }
    }
    Err(format!("missing closing </{name}>"))
}

/// `.htaccess` cannot see `LoadModule` state, so a positive `<IfModule>`
/// must not silently hide directives that the server actually implements.
/// Parse the block for every module name; unknown modules inside such a block
/// still fail closed if their directives are unsupported.  For a negated
/// module, only skip the block when the module is one of the built-ins below
/// (treating an unknown, possibly-loaded module as present is the
/// conservative choice for access rules).
fn ifmodule_active(args: &[String]) -> bool {
    let Some(name) = args.first() else {
        return false;
    };
    let (negated, name) = match name.strip_prefix('!') {
        Some(n) => (true, n),
        None => (false, name.as_str()),
    };
    let builtin = [
        "mod_authz_core.c",
        "authz_core_module",
        "mod_authz_user.c",
        "authz_user_module",
        "mod_authz_groupfile.c",
        "authz_groupfile_module",
        "mod_authn_core.c",
        "authn_core_module",
        "mod_authz_host.c",
        "authz_host_module",
        "mod_access_compat.c",
        "access_compat_module",
        "mod_auth_basic.c",
        "auth_basic_module",
        "mod_authn_file.c",
        "authn_file_module",
        "mod_alias.c",
        "alias_module",
        "mod_dir.c",
        "dir_module",
        "mod_mime.c",
        "mime_module",
        "mod_headers.c",
        "headers_module",
        "mod_setenvif.c",
        "setenvif_module",
        "mod_rewrite.c",
        "rewrite_module",
        "mod_cgi.c",
        "cgi_module",
        "mod_autoindex.c",
        "autoindex_module",
        "mod_deflate.c",
        "deflate_module",
        "mod_brotli.c",
        "brotli_module",
        "mod_filter.c",
        "filter_module",
        "mod_expires.c",
        "expires_module",
        "mod_env.c",
        "env_module",
        "mod_remoteip.c",
        "remoteip_module",
        "mod_proxy.c",
        "proxy_module",
        "mod_proxy_http.c",
        "proxy_http_module",
        "mod_proxy_fcgi.c",
        "proxy_fcgi_module",
        "mod_cache.c",
        "cache_module",
        "mod_cache_disk.c",
        "cache_disk_module",
        "mod_ssl.c",
        "ssl_module",
    ]
    .iter()
    .any(|m| m.eq_ignore_ascii_case(name));
    if negated {
        !builtin
    } else {
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectiveDisposition {
    /// The directive must change the parsed scope or add a rule.
    Effectful,
    /// The directive is accepted only because its effect is genuinely local
    /// to presentation/metadata and cannot select an access or mapping branch.
    Inert,
    /// The directive is recognized but refused in `.htaccess`.
    Reject,
}

/// Authoritative disposition table for every directive the `.htaccess` parser
/// recognizes.  `apply_directive` refuses names absent from this table, and
/// `directive_category` derives the AllowOverride category from it.  The test
/// matrix in this module must cover every entry with an observable effect.
const DIRECTIVE_SPECS: &[(&str, OverrideCategory, DirectiveDisposition)] = &[
    (
        "addcharset",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Inert,
    ),
    (
        "adddefaultcharset",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "adddescription",
        OverrideCategory::Indexes,
        DirectiveDisposition::Inert,
    ),
    (
        "addencoding",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Inert,
    ),
    (
        "addhandler",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "addinputfilter",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "addlanguage",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Inert,
    ),
    (
        "addoutputfilter",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "addoutputfilterbytype",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "addtype",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "allow",
        OverrideCategory::Limit,
        DirectiveDisposition::Effectful,
    ),
    (
        "allowmethods",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Reject,
    ),
    (
        "authbasicprovider",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Inert,
    ),
    (
        "authgroupfile",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Effectful,
    ),
    (
        "authmerging",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Effectful,
    ),
    (
        "authname",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Effectful,
    ),
    (
        "authtype",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Effectful,
    ),
    (
        "authuserfile",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Effectful,
    ),
    (
        "browsermatch",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "browsermatchnocase",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "brotlialteretag",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "brotlicompressionalteretag",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "brotlicompressionquality",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "deflatealteretag",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "deflatebuffersize",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Inert,
    ),
    (
        "deflatecompressionlevel",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "deflatefilternote",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Inert,
    ),
    (
        "deflatememlevel",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Inert,
    ),
    (
        "deflatewindowssize",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Inert,
    ),
    (
        "deny",
        OverrideCategory::Limit,
        DirectiveDisposition::Effectful,
    ),
    (
        "directoryindex",
        OverrideCategory::Indexes,
        DirectiveDisposition::Effectful,
    ),
    (
        "directoryslash",
        OverrideCategory::Indexes,
        DirectiveDisposition::Effectful,
    ),
    (
        "enablesendfile",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "errordocument",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "expiresactive",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "expiresbytype",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "expiresdefault",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "fileetag",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "forcetype",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "header",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "headername",
        OverrideCategory::Indexes,
        DirectiveDisposition::Inert,
    ),
    (
        "indexignore",
        OverrideCategory::Indexes,
        DirectiveDisposition::Effectful,
    ),
    (
        "indexoptions",
        OverrideCategory::Indexes,
        DirectiveDisposition::Inert,
    ),
    (
        "options",
        OverrideCategory::Options,
        DirectiveDisposition::Effectful,
    ),
    (
        "order",
        OverrideCategory::Limit,
        DirectiveDisposition::Effectful,
    ),
    (
        "passenv",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "readmefile",
        OverrideCategory::Indexes,
        DirectiveDisposition::Inert,
    ),
    (
        "redirect",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "redirectmatch",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "redirectpermanent",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "redirecttemp",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "removecharset",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Inert,
    ),
    (
        "removeencoding",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Inert,
    ),
    (
        "removehandler",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "removetype",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "requestheader",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Reject,
    ),
    (
        "require",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Effectful,
    ),
    (
        "rewritebase",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "rewritecond",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "rewriteengine",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "rewriteoptions",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "rewriterule",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "satisfy",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Effectful,
    ),
    (
        "sethandler",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "setenv",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "setenvif",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "setenvifnocase",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "setinputfilter",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "setoutputfilter",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "unsetenv",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
];

#[cfg(test)]
static TEST_REJECT_SPEC: (&str, OverrideCategory, DirectiveDisposition) = (
    "coverage-reject",
    OverrideCategory::FileInfo,
    DirectiveDisposition::Reject,
);
#[cfg(test)]
static TEST_UNHANDLED_SPEC: (&str, OverrideCategory, DirectiveDisposition) = (
    "coverage-unhandled",
    OverrideCategory::FileInfo,
    DirectiveDisposition::Effectful,
);

fn directive_spec(
    name: &str,
) -> Option<&'static (&'static str, OverrideCategory, DirectiveDisposition)> {
    #[cfg(test)]
    {
        if name == TEST_REJECT_SPEC.0 {
            return Some(&TEST_REJECT_SPEC);
        }
        if name == TEST_UNHANDLED_SPEC.0 {
            return Some(&TEST_UNHANDLED_SPEC);
        }
    }
    DIRECTIVE_SPECS.iter().find(|spec| spec.0 == name)
}

fn directive_category(name: &str) -> Option<OverrideCategory> {
    directive_spec(name).map(|spec| spec.1)
}

#[cfg(test)]
fn directive_allowed(mode: OverrideMode, name: &str, args: &[String]) -> bool {
    directive_allowed_list(mode, &[], name, args)
}

fn directive_allowed_list(
    mode: OverrideMode,
    allow_list: &[String],
    name: &str,
    args: &[String],
) -> bool {
    if allow_list
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(name))
    {
        return true;
    }
    if name == "options" {
        if mode.allows(OverrideCategory::Options) {
            return true;
        }
        if !mode.allows_any_option() {
            return false;
        }
        if args.is_empty() {
            return false;
        }
        // Apache 2.4 uses `AllowOverride Options=ExecCGI,Includes,...` for
        // per-option permissions.  Removing an option still requires
        // permission for that option; only `Options None` is always allowed
        // once any Options override is enabled.
        return args.iter().all(|arg| {
            let flag = arg.trim_start_matches(['+', '-']).to_ascii_lowercase();
            if flag == "none" {
                return true;
            }
            let bit = match flag.as_str() {
                "all" => OverrideCategories::OPTIONS,
                "execcgi" => OverrideCategories::EXEC_CGI,
                "includes" => OverrideCategories::INCLUDES,
                "includesnoexec" => OverrideCategories::INCLUDES_NOEXEC,
                "followsymlinks" => OverrideCategories::OPT_FOLLOW_SYMLINKS,
                "indexes" => OverrideCategories::OPT_INDEXES,
                "multiviews" => OverrideCategories::OPT_MULTIVIEWS,
                "symlinksifownermatch" => OverrideCategories::OPT_SYMLINKS_IF_OWNER_MATCH,
                _ => return false,
            };
            mode.allows_flag(bit)
        });
    }
    match directive_category(name) {
        Some(cat) => mode.allows(cat),
        // Unknown directives fall through to apply_directive, which rejects
        // them.  Do not let them bypass a category check.
        None => true,
    }
}

fn apply_directive(
    cfg: &Config,
    scope: &mut Scope,
    name: &str,
    args: &[String],
    limit: Option<&MethodSet>,
) -> Result<(), String> {
    let Some(spec) = directive_spec(name) else {
        return Err(format!("unsupported .htaccess directive '{name}'"));
    };
    if spec.2 == DirectiveDisposition::Reject {
        return Err(match name {
            "allowmethods" => {
                "AllowMethods is only allowed in directory configuration, not .htaccess".into()
            }
            "requestheader" => {
                "RequestHeader is not implemented in .htaccess; refusing to ignore a request-mutating directive"
                    .into()
            }
            _ => format!("unsupported .htaccess directive '{name}'"),
        });
    }
    let first = args.first().map(String::as_str).unwrap_or("");
    match name {
        "require" => {
            let provider = parse_require(args);
            if let Require::Unsupported(msg) = &provider {
                if crate::config::require_syntax_error(msg) {
                    return Err(msg.clone());
                }
            }
            scope.add_require(RequireNode::Provider(provider), limit);
        }
        "authtype" => scope.authorization.auth_type = Some(first.to_ascii_lowercase()),
        "authname" => scope.authorization.auth_name = Some(first.to_string()),
        "authuserfile" => scope.authorization.auth_user_file = Some(server_path(cfg, first)),
        "authgroupfile" => scope.authorization.auth_group_file = Some(server_path(cfg, first)),
        "authbasicprovider" => {
            if !first.eq_ignore_ascii_case("file") {
                return Err("only the `file` AuthBasicProvider is supported".into());
            }
        }
        "options" => apply_options(scope, args)?,
        "directoryindex" => scope.content_policy.directory_index = Some(args.to_vec()),
        "errordocument" => {
            if args.len() < 2 {
                return Ok(());
            }
            let Ok(code) = args[0].parse::<u16>() else {
                return Err("ErrorDocument requires a numeric status".into());
            };
            let target = args[1..].join(" ");
            let doc = if target.starts_with("http://") || target.starts_with("https://") {
                ErrorDoc::External(target)
            } else if target.starts_with('/') {
                ErrorDoc::Local(target)
            } else {
                ErrorDoc::Text(target)
            };
            scope.error_policy.documents.push((code, doc));
        }
        "addtype" => {
            if args.len() >= 2 {
                scope
                    .content_policy
                    .add_types
                    .push((args[0].clone(), args[1..].join(" ")));
            }
        }
        "removetype" => scope
            .content_policy
            .remove_types
            .extend(args.iter().cloned()),
        "addhandler" => {
            if args.len() < 2 {
                return Ok(());
            }
            for ext in &args[1..] {
                scope
                    .mapping_policy
                    .handlers
                    .push(crate::config::Handler::add(
                        ext.trim_start_matches('.').to_ascii_lowercase(),
                        args[0].clone(),
                    ));
            }
        }
        "removehandler" => {
            for ext in args {
                scope
                    .mapping_policy
                    .handlers
                    .push(crate::config::Handler::remove(
                        ext.trim_start_matches('.').to_ascii_lowercase(),
                    ));
            }
        }
        "sethandler" => scope
            .mapping_policy
            .handlers
            .push(crate::config::Handler::add("*".into(), first.to_string())),
        "forcetype" => scope.content_policy.force_type = Some(first.to_string()),
        "adddefaultcharset" => {
            if !first.eq_ignore_ascii_case("off") {
                scope.content_policy.default_charset = Some(first.to_string());
            }
        }
        "addoutputfilterbytype" => {
            if args.len() < 2 {
                return Ok(());
            }
            let kinds = parse_filter_tokens(scope, &args[..1]);
            for kind in kinds {
                scope
                    .compression_policy
                    .compression_rules
                    .push(CompressionRule::ByType(
                        kind,
                        args[1..].iter().map(|s| s.to_ascii_lowercase()).collect(),
                    ));
            }
        }
        "addoutputfilter" => {
            if args.len() < 2 {
                return Ok(());
            }
            let kinds = parse_filter_tokens(scope, &args[..1]);
            for kind in kinds {
                scope
                    .compression_policy
                    .compression_rules
                    .push(CompressionRule::ByExt(
                        kind,
                        args[1..].iter().map(|s| s.to_ascii_lowercase()).collect(),
                    ));
            }
        }
        "setoutputfilter" => {
            let kinds = parse_filter_tokens(scope, args);
            if !kinds.is_empty() {
                scope
                    .compression_policy
                    .compression_rules
                    .push(CompressionRule::Set(kinds));
            }
        }
        "setinputfilter" | "addinputfilter" => {
            for token in args {
                for part in token.split(';') {
                    let part = part.trim();
                    if !part.is_empty()
                        && !scope
                            .mapping_policy
                            .unsupported_filters
                            .iter()
                            .any(|f| f.eq_ignore_ascii_case(part))
                    {
                        scope
                            .mapping_policy
                            .unsupported_filters
                            .push(part.to_string());
                    }
                }
            }
        }
        "deflatecompressionlevel" => {
            if let Some(n) = first.parse::<u32>().ok().filter(|n| *n <= 9) {
                scope.compression_policy.deflate_level = Some(n);
            }
        }
        "brotlicompressionquality" => {
            if let Some(n) = first.parse::<u32>().ok().filter(|n| *n <= 11) {
                scope.compression_policy.brotli_quality = Some(n);
            }
        }
        "deflatealteretag" => {
            if let Some(v) = AlterEtag::parse(first) {
                scope.compression_policy.deflate_alter_etag = Some(v);
            }
        }
        "brotlialteretag" | "brotlicompressionalteretag" => {
            if let Some(v) = AlterEtag::parse(first) {
                scope.compression_policy.brotli_alter_etag = Some(v);
            }
        }
        "deflatefilternote" | "deflatebuffersize" | "deflatememlevel" | "deflatewindowssize" => {}
        "header" => apply_header(scope, args)?,
        "order" => {
            let order = match first.to_ascii_lowercase().as_str() {
                "allow,deny" | "mutual-failure" => Order::AllowDeny,
                "deny,allow" => Order::DenyAllow,
                other => return Err(format!("unknown Order '{other}'")),
            };
            scope.add_order(order, limit);
        }
        "allow" | "deny" => {
            if !args
                .first()
                .map(|s| s.eq_ignore_ascii_case("from"))
                .unwrap_or(false)
            {
                return Err(format!("{name} must be followed by 'from'"));
            }
            for a in &args[1..] {
                let host = if a.eq_ignore_ascii_case("all") {
                    HostSpec::All
                } else if let Some((net, bits)) = parse_ip_net(a) {
                    HostSpec::Net(net, bits)
                } else {
                    return Err(format!("unsupported {name} host '{a}'"));
                };
                if name == "allow" {
                    scope.add_allow(host, limit);
                } else {
                    scope.add_deny(host, limit);
                }
            }
        }
        "satisfy" => {
            let satisfy = match first.to_ascii_lowercase().as_str() {
                "all" => Satisfy::All,
                "any" => Satisfy::Any,
                _ => return Err("Satisfy requires 'all' or 'any'".into()),
            };
            scope.add_satisfy(satisfy, limit);
        }
        "authmerging" => {
            scope.authorization.auth_merging = Some(match first.to_ascii_lowercase().as_str() {
                "off" => AuthMerging::Off,
                "and" => AuthMerging::And,
                "or" => AuthMerging::Or,
                _ => return Err("AuthMerging requires Off, And or Or".into()),
            });
        }
        "rewriteengine" => {
            let on = first.eq_ignore_ascii_case("on");
            let off = first.eq_ignore_ascii_case("off");
            if on || off {
                scope.rewrite_policy.rewrite_engine = Some(on);
            } else {
                return Err("RewriteEngine requires On or Off".into());
            }
        }
        "rewritebase" => scope.rewrite_policy.rewrite_base = Some(normalize_rewrite_base(first)),
        "rewritecond" => scope
            .rewrite_policy
            .pending_rewrite_conds
            .push(parse_rewrite_cond(args)?),
        "rewriterule" => {
            let match_base = scope
                .rewrite_policy
                .rewrite_match_base
                .as_deref()
                .unwrap_or("/");
            let subst_base = scope
                .rewrite_policy
                .rewrite_base
                .as_deref()
                .unwrap_or(match_base);
            let mut rule = parse_rewrite_rule(args, match_base, true)?;
            rule.base = normalize_rewrite_base(subst_base);
            rule.conditions = std::mem::take(&mut scope.rewrite_policy.pending_rewrite_conds);
            scope.rewrite_policy.rewrite_rules.push(rule);
        }
        "rewriteoptions" => {
            scope.rewrite_policy.rewrite_inherit =
                Some(args.iter().any(|a| a.eq_ignore_ascii_case("Inherit")));
        }
        "redirect" | "redirectpermanent" | "redirecttemp" => {
            let mut args = args.to_vec();
            if name == "redirectpermanent" {
                args.insert(0, "301".into());
            } else if name == "redirecttemp" {
                args.insert(0, "302".into());
            }
            apply_redirect(scope, &args)?
        }
        "redirectmatch" => apply_redirect_match(scope, args)?,
        "fileetag" => {
            let mut v = 0u32;
            for a in args {
                match a.to_ascii_lowercase().as_str() {
                    "none" => v = 0,
                    "all" => v = crate::config::ETAG_ALL,
                    "inode" => v |= crate::config::ETAG_INODE,
                    "mtime" => v |= crate::config::ETAG_MTIME,
                    "size" => v |= crate::config::ETAG_SIZE,
                    _ => {}
                }
            }
            scope.content_policy.file_etag = Some(v);
        }
        "enablesendfile" => {
            scope.content_policy.enable_sendfile = Some(first.eq_ignore_ascii_case("on"))
        }
        "directoryslash" => {
            scope.content_policy.directory_slash = Some(first.eq_ignore_ascii_case("on"))
        }
        "expiresactive" => {
            scope.header_policy.expires_active = Some(first.eq_ignore_ascii_case("on"))
        }
        "expiresdefault" => scope.header_policy.expires_default = Some(args.join(" ")),
        "expiresbytype" => {
            if args.len() >= 2 {
                scope
                    .header_policy
                    .expires_by_type
                    .push((args[0].to_ascii_lowercase(), args[1..].join(" ")));
            }
        }
        "setenv" => {
            let Some(name) = args.first() else {
                return Err("SetEnv requires a variable".into());
            };
            scope
                .environment_policy
                .set_env
                .push((name.clone(), args[1..].join(" ")));
        }
        "unsetenv" => scope
            .environment_policy
            .unset_env
            .extend(args.iter().cloned()),
        "passenv" => scope
            .environment_policy
            .pass_env
            .extend(args.iter().cloned()),
        "setenvif" | "setenvifnocase" | "browsermatch" | "browsermatchnocase" => {
            scope
                .environment_policy
                .set_env_if
                .push(crate::config::parse_env_rule(name, args)?);
        }
        "indexignore" => {
            scope
                .content_policy
                .index_ignore
                .extend(args.iter().cloned());
        }
        // These are explicitly reviewed as inert in `DIRECTIVE_SPECS`.  They
        // do not affect access decisions, request mutation, handler selection
        // or response framing; accepting them keeps common .htaccess files
        // usable until the corresponding presentation filters are implemented.
        "addcharset" | "addlanguage" | "addencoding" | "removecharset" | "removeencoding"
        | "adddescription" | "indexoptions" | "readmefile" | "headername" => {}
        _ => return Err(format!("unsupported .htaccess directive '{name}'")),
    }
    Ok(())
}

fn apply_options(scope: &mut Scope, args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        scope.options.push_set(Options::empty().0);
        return Ok(());
    }
    for a in args {
        let (sign, flag) = match a.as_bytes().first() {
            Some(b'+') => (1, &a[1..]),
            Some(b'-') => (-1, &a[1..]),
            _ => (0, a.as_str()),
        };
        let opt = match flag.to_ascii_lowercase().as_str() {
            "none" => Options::empty(),
            "all" => Options::all(),
            "indexes" => Options(Options::INDEXES),
            "followsymlinks" => Options(Options::FOLLOW_SYMLINKS),
            "symlinksifownermatch" => Options(Options::SYMLINKS_IF_OWNER_MATCH),
            "execcgi" => Options(Options::EXEC_CGI),
            "includes" => Options(Options::INCLUDES),
            "includesnoexec" => Options(Options::INCLUDES_NOEXEC),
            "multiviews" => Options(Options::MULTIVIEWS),
            _ => return Err(format!("unsupported Options flag '{a}'")),
        };
        match sign {
            1 => scope.options.push_add(opt.0),
            -1 => scope.options.push_remove(opt.0),
            _ if flag.eq_ignore_ascii_case("none") => scope.options.push_set(Options::empty().0),
            _ if flag.eq_ignore_ascii_case("all") => scope.options.push_set(Options::all().0),
            _ => scope.options.push_add(opt.0),
        }
    }
    Ok(())
}

fn apply_header(scope: &mut Scope, args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("Header requires an action and name".into());
    }
    let mut idx = 0;
    let always = args[0].eq_ignore_ascii_case("always");
    if always || args[0].eq_ignore_ascii_case("onsuccess") {
        idx = 1;
    }
    if args.len() < idx + 2 {
        return Err("Header requires an action and name".into());
    }
    let action = args[idx].to_ascii_lowercase();
    let name = args[idx + 1].trim_end_matches(':').to_string();
    match (action.as_str(), always) {
        ("set", true) => {
            let value = args[idx + 2..].join(" ");
            scope.header_policy.always_set_headers.push((name, value));
        }
        ("set", false) => {
            let value = args[idx + 2..].join(" ");
            scope.header_policy.set_headers.push((name, value));
        }
        ("add", true) => {
            let value = args[idx + 2..].join(" ");
            scope.header_policy.always_add_headers.push((name, value));
        }
        ("add", false) => {
            let value = args[idx + 2..].join(" ");
            scope.header_policy.add_headers.push((name, value));
        }
        ("unset", true) => scope.header_policy.always_unset_headers.push(name),
        ("unset", false) => scope.header_policy.unset_headers.push(name),
        _ => return Err(format!("unsupported Header action '{action}'")),
    }
    Ok(())
}

fn apply_redirect(scope: &mut Scope, args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("Redirect requires a source and target".into());
    }
    let (status, rest) = match args[0].parse::<u16>() {
        Ok(s) => (s, &args[1..]),
        _ => (302, args),
    };
    debug_assert!(!rest.is_empty());
    scope
        .mapping_policy
        .redirects
        .push(crate::config::Redirect {
            from: rest[0].clone(),
            to: rest[1..].join(" "),
            status,
            regex: None,
        });
    Ok(())
}

fn apply_redirect_match(scope: &mut Scope, args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("RedirectMatch requires a pattern".into());
    }
    let (status, rest) = match args[0].parse::<u16>() {
        Ok(s) => (s, &args[1..]),
        _ => (302, args),
    };
    debug_assert!(!rest.is_empty());
    let regex = crate::config::compile_regex(&rest[0])
        .map_err(|e| format!("bad RedirectMatch regex: {e}"))?;
    scope
        .mapping_policy
        .redirects
        .push(crate::config::Redirect {
            from: String::new(),
            to: rest[1..].join(" "),
            status,
            regex: Some(std::sync::Arc::new(regex)),
        });
    Ok(())
}

fn server_path(cfg: &Config, value: &str) -> PathBuf {
    let p = PathBuf::from(value);
    if p.is_absolute() {
        p
    } else {
        cfg.server_root.join(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthPolicy, OverrideCategories, RequireEntry};
    use std::collections::HashMap;
    use std::fs;

    fn require_entries(policy: Option<AuthPolicy>) -> Vec<RequireEntry> {
        match policy {
            Some(AuthPolicy::List(entries)) => entries,
            other => panic!("expected a flat Require list, got {other:?}"),
        }
    }

    #[test]
    fn override_categories_gate_security_directives() {
        let req = vec!["all".into(), "denied".into()];
        let args = |s: &str| vec![s.to_string()];
        let all = OverrideMode::All;
        let auth = OverrideMode::Categories(OverrideCategories(OverrideCategories::AUTH_CONFIG));
        let file = OverrideMode::Categories(OverrideCategories(OverrideCategories::FILE_INFO));
        let limit = OverrideMode::Categories(OverrideCategories(OverrideCategories::LIMIT));
        let indexes = OverrideMode::Categories(OverrideCategories(OverrideCategories::INDEXES));
        let options = OverrideMode::Categories(OverrideCategories(OverrideCategories::OPTIONS));
        let opt_indexes =
            OverrideMode::Categories(OverrideCategories(OverrideCategories::OPT_INDEXES));

        assert!(directive_allowed(all, "require", &req));
        assert!(directive_allowed(auth, "require", &req));
        assert!(!directive_allowed(file, "require", &req));
        assert!(!directive_allowed(limit, "require", &req));
        assert!(directive_allowed(limit, "order", &args("allow,deny")));
        assert!(!directive_allowed(auth, "order", &args("allow,deny")));
        assert!(directive_allowed(file, "header", &args("set X yes")));
        assert!(!directive_allowed(auth, "header", &args("set X yes")));
        assert!(directive_allowed(
            indexes,
            "directoryindex",
            &args("index.html")
        ));
        assert!(!directive_allowed(
            file,
            "directoryindex",
            &args("index.html")
        ));
        assert!(directive_allowed(options, "options", &args("+Indexes")));
        assert!(directive_allowed(opt_indexes, "options", &args("+Indexes")));
        assert!(!directive_allowed(
            opt_indexes,
            "options",
            &args("+ExecCGI")
        ));
        assert!(directive_allowed(all, "satisfy", &args("any")));
        assert!(directive_allowed(auth, "satisfy", &args("any")));
        assert!(!directive_allowed(opt_indexes, "satisfy", &args("any")));
        assert!(!directive_allowed(OverrideMode::None, "require", &req));
    }

    fn tempdir(name: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("vapache-htaccess-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn config(root: &Path, text: &str) -> Config {
        let path = root.join("httpd.conf");
        fs::write(&path, text).unwrap();
        Config::load(&path, root, &HashMap::new(), &HashMap::new(), false).unwrap()
    }

    #[test]
    fn parses_access_auth_and_media_directives() {
        let dir = tempdir("directives");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(
            &file,
            concat!(
                "# comment\n",
                "AuthType Basic\n",
                "AuthName \"Test Realm\"\n",
                "AuthUserFile users\n",
                "AuthGroupFile groups\n",
                "Require valid-user\n",
                "Options -Indexes +FollowSymLinks\n",
                "DirectoryIndex index.html index.cgi\n",
                "ErrorDocument 404 /not-found.html\n",
                "AddType text/x-test .t\n",
                "RemoveType .bad\n",
                "ForceType text/plain\n",
                "Header set X-Test yes\n",
                "Header unset X-Old\n",
                "Header always add X-Added value with spaces\n",
            ),
        )
        .unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        assert_eq!(p.scope.authorization.auth_type.as_deref(), Some("basic"));
        assert_eq!(
            p.scope.authorization.auth_name.as_deref(),
            Some("Test Realm")
        );
        assert_eq!(
            p.scope.authorization.auth_user_file.as_deref(),
            Some(dir.join("users").as_path())
        );
        let entries = require_entries(p.scope.authorization.requires.clone());
        assert!(matches!(
            entries.as_slice(),
            [RequireEntry {
                node: RequireNode::Provider(crate::config::Require::ValidUser { negate: false }),
                limit: None,
            }]
        ));
        assert_eq!(
            p.scope.content_policy.directory_index.as_deref(),
            Some(&["index.html".to_string(), "index.cgi".to_string()][..])
        );
        assert!(p.scope.error_document(404).is_some());
        assert_eq!(
            p.scope.content_policy.force_type.as_deref(),
            Some("text/plain")
        );
        assert!(p
            .scope
            .header_policy
            .set_headers
            .iter()
            .any(|(n, v)| n == "X-Test" && v == "yes"));
        assert!(p
            .scope
            .header_policy
            .unset_headers
            .iter()
            .any(|n| n == "X-Old"));
        assert!(p
            .scope
            .header_policy
            .always_add_headers
            .iter()
            .any(|(n, v)| n == "X-Added" && v == "value with spaces"));
        let opts = p.scope.effective_options();
        assert!(!opts.contains(Options::INDEXES));
        assert!(opts.contains(Options::FOLLOW_SYMLINKS));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn setenv_directives_affect_require_and_are_not_discarded() {
        let dir = tempdir("setenv");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(
            &file,
            concat!(
                "SetEnv STATIC yes\n",
                "SetEnvIf X-Block yes BLOCK=1\n",
                "<Files \"secret.txt\">\n",
                "Require expr \"%{ENV:BLOCK} == ''\"\n",
                "</Files>\n",
            ),
        )
        .unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        assert_eq!(
            p.scope.environment_policy.set_env,
            vec![("STATIC".to_string(), "yes".to_string())]
        );
        assert_eq!(p.scope.environment_policy.set_env_if.len(), 1);
        let mut req = crate::http::Request {
            method: "GET".into(),
            target: b"/secret.txt".to_vec(),
            raw_path: b"/secret.txt".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        req.headers.push("X-Block", "yes");
        let env = p.scope.request_env(&req, "/");
        assert!(env.iter().any(|(n, v)| n == "STATIC" && v == "yes"));
        assert!(env.iter().any(|(n, v)| n == "BLOCK" && v == "1"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn indexignore_patterns_are_modeled() {
        let dir = tempdir("indexignore");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(&file, "IndexIgnore *.secret backup-?\n").unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        assert_eq!(
            p.scope.content_policy.index_ignore,
            vec!["*.secret".to_string(), "backup-?".to_string()]
        );
        assert!(crate::config::glob_match(
            p.scope.content_policy.index_ignore[0].as_bytes(),
            b"wallet.secret"
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_require_groups_and_files_sections() {
        let dir = tempdir("sections");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(
            &file,
            concat!(
                "<RequireAny>\n",
                "Require ip 127.0.0.1\n",
                "<RequireNone>\n",
                "Require all granted\n",
                "</RequireNone>\n",
                "</RequireAny>\n",
                "<Files \"secret.txt\">\n",
                "Require all denied\n",
                "</Files>\n",
                "<FilesMatch \"\\.bak$\">\n",
                "Options -Indexes\n",
                "</FilesMatch>\n",
            ),
        )
        .unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        let entries = require_entries(p.scope.authorization.requires.clone());
        assert_eq!(entries.len(), 1);
        assert_eq!(p.rules.len(), 2);
        assert!(rule_matches(&p.rules[0].kind, "secret.txt", "/secret.txt"));
        assert!(!rule_matches(&p.rules[0].kind, "other.txt", "/other.txt"));
        assert!(rule_matches(&p.rules[1].kind, "old.bak", "/old.bak"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ifmodule_skips_unknown_but_parses_supported() {
        let dir = tempdir("ifmodule");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(
            &file,
            concat!(
                "<IfModule mod_rewrite.c>\n",
                "RewriteEngine On\n",
                "</IfModule>\n",
                "<IfModule mod_authz_core.c>\n",
                "Require all denied\n",
                "</IfModule>\n",
            ),
        )
        .unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        let entries = require_entries(p.scope.authorization.requires.clone());
        assert!(matches!(
            entries.as_slice(),
            [RequireEntry {
                node: RequireNode::Provider(crate::config::Require::AllDenied),
                limit: None,
            }]
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unsupported_directives_and_sections_fail_closed() {
        let dir = tempdir("errors");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        for text in [
            "RewriteMap example txt:/tmp/map.txt\n",
            "<Limit GET>\nOptions +Indexes\n</Limit>\n",
            "<IfDefine FOO>\nRequire all granted\n</IfDefine>\n",
            "<Files \"x\">\n",
            "Require all granted\n</Nope>\n",
            "<Limit BOGUS>\nRequire all granted\n</Limit>\n",
            "<Limit POST>\n<Limit POST>\nRequire all granted\n</Limit>\n</Limit>\n",
            "<Else>\nRequire all granted\n</Else>\n",
            "AllowMethods POST\n",
        ] {
            fs::write(&file, text).unwrap();
            assert!(
                parse_file(&cfg, &file, OverrideMode::All, "/").is_err(),
                "{text}"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_if_elseif_else_chains() {
        let dir = tempdir("elseif");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(
            &file,
            concat!(
                "<If \"%{HTTP:X-Test} == 'a'\">\n",
                "Header set X-Branch a\n",
                "</If>\n",
                "<ElseIf \"%{HTTP:X-Test} == 'b'\">\n",
                "Header set X-Branch b\n",
                "</ElseIf>\n",
                "<Else>\n",
                "Header set X-Branch c\n",
                "</Else>\n",
            ),
        )
        .unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        assert_eq!(p.rules.len(), 3);
        assert_eq!(p.rules[0].branch, ConditionBranch::Normal);
        assert_eq!(p.rules[1].branch, ConditionBranch::ElseIf);
        assert_eq!(p.rules[2].branch, ConditionBranch::Else);
        assert!(p.rules.iter().all(|rule| rule.chain == p.rules[0].chain));

        fs::write(
            &file,
            "<If \"1\">\n<If \"1\">\nHeader set X-Nested yes\n</If>\n</If>\n",
        )
        .unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].nested.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_authmerging() {
        let dir = tempdir("authmerging");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(&file, "AuthMerging And\nRequire all granted\n").unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        assert_eq!(p.scope.authorization.auth_merging, Some(AuthMerging::And));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn records_unsupported_filters() {
        let dir = tempdir("filters");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(&file, "SetOutputFilter INCLUDES\n").unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        assert!(p
            .scope
            .mapping_policy
            .unsupported_filters
            .iter()
            .any(|f| f.eq_ignore_ascii_case("INCLUDES")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn requestheader_is_rejected_instead_of_silently_ignored() {
        let dir = tempdir("requestheader");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        for line in [
            "RequestHeader set X-Block yes\n",
            "RequestHeader append X-Block yes\n",
            "RequestHeader unset X-Block\n",
            "RequestHeader echo X-Block\n",
        ] {
            fs::write(&file, line).unwrap();
            match parse_file(&cfg, &file, OverrideMode::All, "/") {
                Ok(_) => panic!("RequestHeader must be rejected: {line}"),
                Err(err) => assert!(err.contains("RequestHeader"), "{line}: {err}"),
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ExpectedEffect {
        Changed,
        Inert,
        Error,
    }

    struct DirectiveCase {
        name: &'static str,
        args: &'static [&'static str],
        effect: ExpectedEffect,
    }

    const DIRECTIVE_CASES: &[DirectiveCase] = &[
        DirectiveCase {
            name: "addcharset",
            args: &["utf-8", ".txt"],
            effect: ExpectedEffect::Inert,
        },
        DirectiveCase {
            name: "adddefaultcharset",
            args: &["utf-8"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "adddescription",
            args: &["x", ".txt"],
            effect: ExpectedEffect::Inert,
        },
        DirectiveCase {
            name: "addencoding",
            args: &["gzip", ".gz"],
            effect: ExpectedEffect::Inert,
        },
        DirectiveCase {
            name: "addhandler",
            args: &["cgi-script", ".cgi"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "addinputfilter",
            args: &["INCLUDES"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "addlanguage",
            args: &["en", ".txt"],
            effect: ExpectedEffect::Inert,
        },
        DirectiveCase {
            name: "addoutputfilter",
            args: &["DEFLATE", ".txt"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "addoutputfilterbytype",
            args: &["DEFLATE", "text/plain"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "addtype",
            args: &["text/plain", ".foo"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "allow",
            args: &["from", "all"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "allowmethods",
            args: &["POST"],
            effect: ExpectedEffect::Error,
        },
        DirectiveCase {
            name: "authbasicprovider",
            args: &["file"],
            effect: ExpectedEffect::Inert,
        },
        DirectiveCase {
            name: "authgroupfile",
            args: &["/tmp/htgroup"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "authmerging",
            args: &["And"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "authname",
            args: &["TestRealm"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "authtype",
            args: &["Basic"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "authuserfile",
            args: &["/tmp/htpasswd"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "browsermatch",
            args: &["yes", "FOO=bar"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "browsermatchnocase",
            args: &["yes", "FOO=bar"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "brotlialteretag",
            args: &["AddSuffix"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "brotlicompressionalteretag",
            args: &["AddSuffix"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "brotlicompressionquality",
            args: &["5"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "deflatealteretag",
            args: &["AddSuffix"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "deflatebuffersize",
            args: &["4096"],
            effect: ExpectedEffect::Inert,
        },
        DirectiveCase {
            name: "deflatecompressionlevel",
            args: &["6"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "deflatefilternote",
            args: &["foo"],
            effect: ExpectedEffect::Inert,
        },
        DirectiveCase {
            name: "deflatememlevel",
            args: &["8"],
            effect: ExpectedEffect::Inert,
        },
        DirectiveCase {
            name: "deflatewindowssize",
            args: &["15"],
            effect: ExpectedEffect::Inert,
        },
        DirectiveCase {
            name: "deny",
            args: &["from", "all"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "directoryindex",
            args: &["index.html"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "directoryslash",
            args: &["Off"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "enablesendfile",
            args: &["On"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "errordocument",
            args: &["404", "/notfound.html"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "expiresactive",
            args: &["On"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "expiresbytype",
            args: &["text/html", "access plus 1 hour"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "expiresdefault",
            args: &["access plus 1 hour"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "fileetag",
            args: &["None"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "forcetype",
            args: &["text/plain"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "header",
            args: &["set", "X-Test", "yes"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "headername",
            args: &["HEADER"],
            effect: ExpectedEffect::Inert,
        },
        DirectiveCase {
            name: "indexignore",
            args: &["*.secret"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "indexoptions",
            args: &["FancyIndexing"],
            effect: ExpectedEffect::Inert,
        },
        DirectiveCase {
            name: "options",
            args: &["+Indexes"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "order",
            args: &["deny,allow"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "passenv",
            args: &["PATH"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "readmefile",
            args: &["README"],
            effect: ExpectedEffect::Inert,
        },
        DirectiveCase {
            name: "redirect",
            args: &["/old", "/new"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "redirectmatch",
            args: &["^/old(.*)$", "/new$1"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "redirectpermanent",
            args: &["/old", "/new"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "redirecttemp",
            args: &["/old", "/new"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "removecharset",
            args: &[".txt"],
            effect: ExpectedEffect::Inert,
        },
        DirectiveCase {
            name: "removeencoding",
            args: &[".gz"],
            effect: ExpectedEffect::Inert,
        },
        DirectiveCase {
            name: "removehandler",
            args: &[".cgi"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "removetype",
            args: &[".foo"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "requestheader",
            args: &["set", "X-Test", "yes"],
            effect: ExpectedEffect::Error,
        },
        DirectiveCase {
            name: "require",
            args: &["all", "granted"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "rewritebase",
            args: &["/other/"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "rewritecond",
            args: &["%{REQUEST_URI}", "^/x$"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "rewriteengine",
            args: &["On"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "rewriteoptions",
            args: &["Inherit"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "rewriterule",
            args: &["^/old$", "/new", "[L]"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "satisfy",
            args: &["all"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "sethandler",
            args: &["cgi-script"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "setenv",
            args: &["FOO", "bar"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "setenvif",
            args: &["X-Test", "yes", "FOO=bar"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "setenvifnocase",
            args: &["X-Test", "yes", "FOO=bar"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "setinputfilter",
            args: &["INCLUDES"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "setoutputfilter",
            args: &["DEFLATE"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "unsetenv",
            args: &["FOO"],
            effect: ExpectedEffect::Changed,
        },
    ];

    fn scope_signature(scope: &Scope) -> String {
        format!("{scope:?}")
    }

    #[test]
    fn htaccess_directive_matrix_is_exhaustive_and_matches_behavior() {
        let dir = tempdir("directive-matrix");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(&file, "").unwrap();
        let baseline = match parse_file(&cfg, &file, OverrideMode::All, "/dir/") {
            Ok(parsed) => scope_signature(&parsed.scope),
            Err(e) => panic!("empty .htaccess failed: {e}"),
        };

        let registry: std::collections::BTreeSet<&str> =
            DIRECTIVE_SPECS.iter().map(|spec| spec.0).collect();
        assert_eq!(
            registry.len(),
            DIRECTIVE_SPECS.len(),
            "duplicate directive in DIRECTIVE_SPECS"
        );
        let cases: std::collections::BTreeSet<&str> =
            DIRECTIVE_CASES.iter().map(|case| case.name).collect();
        assert_eq!(
            cases.len(),
            DIRECTIVE_CASES.len(),
            "duplicate directive in DIRECTIVE_CASES"
        );
        assert_eq!(
            cases, registry,
            "every recognized .htaccess directive needs exactly one effect case"
        );

        for case in DIRECTIVE_CASES {
            let line = if case.args.is_empty() {
                format!("{}\n", case.name)
            } else {
                format!("{} {}\n", case.name, case.args.join(" "))
            };
            fs::write(&file, &line).unwrap();
            let parsed = parse_file(&cfg, &file, OverrideMode::All, "/dir/");
            match case.effect {
                ExpectedEffect::Error => assert!(
                    parsed.is_err(),
                    "{} must fail closed, parsed successfully",
                    case.name
                ),
                ExpectedEffect::Inert => {
                    let parsed = match parsed {
                        Ok(parsed) => parsed,
                        Err(e) => panic!("{} must parse as inert: {e}", case.name),
                    };
                    assert_eq!(
                        scope_signature(&parsed.scope),
                        baseline,
                        "{} is marked inert but changed the scope",
                        case.name
                    );
                }
                ExpectedEffect::Changed => {
                    let parsed = match parsed {
                        Ok(parsed) => parsed,
                        Err(e) => panic!("{} must apply an effect: {e}", case.name),
                    };
                    assert_ne!(
                        scope_signature(&parsed.scope),
                        baseline,
                        "{} is marked effectful but did not change the scope",
                        case.name
                    );
                }
            }
            // A directive with no AllowOverride category would bypass the
            // override gate.  Every recognized directive must be denied when
            // overrides are disabled.
            assert!(
                parse_file(&cfg, &file, OverrideMode::None, "/dir/").is_err(),
                "{} is not gated by AllowOverride None",
                case.name
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn htaccess_rejects_unknown_main_config_only_directives_and_sections() {
        let dir = tempdir("rejected-surface");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        for line in [
            "DefinitelyNotADirective on\n",
            "ProxyBlock 169.254.169.254\n",
            "AcceptPathInfo Off\n",
            "SetEnvIfExpr \"true\" X=1\n",
            "AuthzProviderAlias ldap-group foo\n",
            "<Directory /srv>\nRequire all denied\n</Directory>\n",
            "<Location />\nRequire all denied\n</Location>\n",
            "<Proxy http://example.test/>\nRequire all denied\n</Proxy>\n",
            "<IfDefine PROD>\nRequire all denied\n</IfDefine>\n",
        ] {
            fs::write(&file, line).unwrap();
            match parse_file(&cfg, &file, OverrideMode::All, "/dir/") {
                Ok(_) => panic!("must fail closed: {line}"),
                Err(e) => assert!(
                    e.contains("unsupported") || e.contains("not supported"),
                    "{line}: {e}"
                ),
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_method_limited_sections() {
        let dir = tempdir("limit-sections");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(
            &file,
            concat!(
                "<Limit POST PUT>\n",
                "Require valid-user\n",
                "Allow from 10.0.0.0/8\n",
                "Satisfy Any\n",
                "</Limit>\n",
                "<LimitExcept GET HEAD>\n",
                "Require all denied\n",
                "</LimitExcept>\n",
            ),
        )
        .unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        let entries = require_entries(p.scope.authorization.requires.clone());
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].limit,
            Some(MethodSet::Only(vec!["POST".into(), "PUT".into()]))
        );
        assert_eq!(
            entries[1].limit,
            Some(MethodSet::Except(vec!["GET".into()]))
        );
        let legacy = p.scope.authorization.legacy.clone().expect("legacy rules");
        assert!(legacy.allow[0].applies("POST"));
        assert!(!legacy.allow[0].applies("GET"));
        assert!(legacy.satisfy[0].applies("PUT"));
        assert!(!legacy.satisfy[0].applies("GET"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_walks_ancestors_and_honours_allow_override() {
        let dir = tempdir("apply");
        let www = dir.join("www");
        fs::create_dir_all(www.join("sub")).unwrap();
        fs::write(www.join("sub").join("file.txt"), "body\n").unwrap();
        fs::write(www.join(".htaccess"), "Require all denied\n").unwrap();
        fs::write(
            www.join("sub").join(".htaccess"),
            "Require all granted\nHeader set X-Child yes\n",
        )
        .unwrap();
        let cfg_text = format!(
            "Listen 127.0.0.1:0\nDocumentRoot \"{}\"\n<Directory \"{}\">\nAllowOverride All\n</Directory>\n",
            www.display(),
            www.display()
        );
        let cfg = config(&dir, &cfg_text);
        let file = www.join("sub").join("file.txt");
        let mut scope = cfg.effective_scope(None, &file, "/sub/file.txt");
        apply(&cfg, None, &mut scope, &file, "/sub/file.txt").unwrap();
        let entries = require_entries(scope.authorization.requires);
        assert!(matches!(
            entries.as_slice(),
            [RequireEntry {
                node: RequireNode::Provider(crate::config::Require::AllGranted),
                limit: None,
            }]
        ));
        assert!(scope
            .header_policy
            .set_headers
            .iter()
            .any(|(n, v)| n == "X-Child" && v == "yes"));

        let no_override = config(
            &dir,
            &format!("Listen 127.0.0.1:0\nDocumentRoot \"{}\"\n", www.display()),
        );
        let mut scope = no_override.effective_scope(None, &file, "/sub/file.txt");
        apply(&no_override, None, &mut scope, &file, "/sub/file.txt").unwrap();
        assert!(scope.authorization.requires.is_none());
        assert!(scope.header_policy.set_headers.is_empty());

        // A parent directory can enable overrides while a child disables them.
        // The parent's rules still apply; the child's file must be ignored.
        let parent_only = config(
            &dir,
            &format!(
                "Listen 127.0.0.1:0\nDocumentRoot \"{}\"\n<Directory \"{}\">\nAllowOverride All\n</Directory>\n<Directory \"{}\">\nAllowOverride None\n</Directory>\n",
                www.display(),
                www.display(),
                www.join("sub").display()
            ),
        );
        let mut scope = parent_only.effective_scope(None, &file, "/sub/file.txt");
        apply(&parent_only, None, &mut scope, &file, "/sub/file.txt").unwrap();
        let entries = require_entries(scope.authorization.requires);
        assert!(matches!(
            entries.as_slice(),
            [RequireEntry {
                node: RequireNode::Provider(crate::config::Require::AllDenied),
                limit: None,
            }]
        ));
        assert!(scope.header_policy.set_headers.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn allow_override_categories_are_enforced_per_directive() {
        let dir = tempdir("categories");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        let mode = |flag| OverrideMode::Categories(crate::config::OverrideCategories(flag));

        fs::write(&file, "Require all granted\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::AUTH_CONFIG), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::FILE_INFO), "/").is_err());

        fs::write(&file, "Options -Indexes\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::OPTIONS), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::AUTH_CONFIG), "/").is_err());

        fs::write(&file, "ErrorDocument 404 /missing\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::FILE_INFO), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::AUTH_CONFIG), "/").is_err());

        fs::write(&file, "Satisfy any\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::AUTH_CONFIG), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::OPTIONS), "/").is_err());

        fs::write(&file, "<Limit POST>\nRequire valid-user\n</Limit>\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::AUTH_CONFIG), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::LIMIT), "/").is_err());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::FILE_INFO), "/").is_err());

        fs::write(&file, "<Limit POST>\nAllow from all\n</Limit>\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::LIMIT), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::AUTH_CONFIG), "/").is_err());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::FILE_INFO), "/").is_err());

        fs::write(
            &file,
            "<Files \"secret\">\nHeader set X-Test yes\n</Files>\n",
        )
        .unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::FILE_INFO), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::AUTH_CONFIG), "/").is_err());

        fs::write(&file, "Options +ExecCGI\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::EXEC_CGI), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::OPTIONS), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::INCLUDES), "/").is_err());

        fs::write(&file, "Options +Includes\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::INCLUDES), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::EXEC_CGI), "/").is_err());

        fs::write(&file, "Options +Indexes\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::OPT_INDEXES), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::EXEC_CGI), "/").is_err());

        fs::write(&file, "Options None\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::EXEC_CGI), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::AUTH_CONFIG), "/").is_err());

        fs::write(&file, "Options +MadeUpOption\n").unwrap();
        assert!(parse_file(&cfg, &file, OverrideMode::All, "/").is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rewrite_directives_use_directory_and_rewrite_bases() {
        let dir = tempdir("rewrite-parse");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(
            &file,
            concat!(
                "RewriteEngine On\n",
                "RewriteCond %{QUERY_STRING} ^x=1$ [NC]\n",
                "RewriteBase /other/\n",
                "RewriteRule ^old\\.html$ new.html [L]\n",
            ),
        )
        .unwrap();
        let p = parse_file(
            &cfg,
            &file,
            OverrideMode::Categories(crate::config::OverrideCategories(
                crate::config::OverrideCategories::FILE_INFO,
            )),
            "/sub/",
        )
        .unwrap();
        assert_eq!(p.scope.rewrite_policy.rewrite_engine, Some(true));
        assert_eq!(p.scope.rewrite_policy.rewrite_rules.len(), 1);
        let rule = &p.scope.rewrite_policy.rewrite_rules[0];
        assert_eq!(rule.match_base, "/sub/");
        assert_eq!(rule.base, "/other/");
        assert!(rule.per_dir);
        assert_eq!(rule.subject_dir.as_deref(), Some(dir.as_path()));
        assert_eq!(rule.conditions[0].test, "%{QUERY_STRING}");
        assert!(rule.conditions[0].flags.nocase);

        // Unsupported flags and malformed conditions must fail closed.
        fs::write(&file, "RewriteEngine On\nRewriteRule ^x y [UNKNOWN]\n").unwrap();
        assert!(parse_file(&cfg, &file, OverrideMode::All, "/").is_err());
        fs::write(&file, "RewriteCond %{REQUEST_URI} [\nRewriteRule ^x y\n").unwrap();
        assert!(parse_file(&cfg, &file, OverrideMode::All, "/").is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_hits_and_invalidates_on_metadata_change() {
        let dir = tempdir("cache");
        let www = dir.join("www");
        fs::create_dir_all(www.join("sub")).unwrap();
        fs::write(www.join("sub").join("file.txt"), "body\n").unwrap();
        let ht = www.join(".htaccess");
        fs::write(&ht, "Require all denied\n").unwrap();
        let cfg = config(
            &dir,
            &format!(
                "Listen 127.0.0.1:0\nDocumentRoot \"{}\"\n<Directory \"{}\">\nAllowOverride All\n</Directory>\n",
                www.display(),
                www.display()
            ),
        );
        let file = www.join("sub").join("file.txt");
        for _ in 0..2 {
            let mut scope = cfg.effective_scope(None, &file, "/sub/file.txt");
            apply(&cfg, None, &mut scope, &file, "/sub/file.txt").unwrap();
            let entries = require_entries(scope.authorization.requires.clone());
            assert!(matches!(
                entries.as_slice(),
                [RequireEntry {
                    node: RequireNode::Provider(crate::config::Require::AllDenied),
                    limit: None,
                }]
            ));
        }

        // Same-size content change: the cache must notice ctime/mtime even
        // though the length has not changed.
        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(&ht, "Header set X-Cache a\n").unwrap();
        let mut scope = cfg.effective_scope(None, &file, "/sub/file.txt");
        apply(&cfg, None, &mut scope, &file, "/sub/file.txt").unwrap();
        assert!(scope
            .header_policy
            .set_headers
            .iter()
            .any(|(n, v)| n == "X-Cache" && v == "a"));

        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(&ht, "Header set X-Cache b\n").unwrap();
        let mut scope = cfg.effective_scope(None, &file, "/sub/file.txt");
        apply(&cfg, None, &mut scope, &file, "/sub/file.txt").unwrap();
        assert!(scope
            .header_policy
            .set_headers
            .iter()
            .any(|(n, v)| n == "X-Cache" && v == "b"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn logical_lines_join_continuations_and_skip_comments() {
        let lines = crate::config_frontend::logical_lines(
            "# hi\nRequire all \\\n denied\n\nOptions -Indexes\n",
        );
        assert_eq!(lines, vec!["Require all  denied", "Options -Indexes"]);
    }

    fn request_with_header(name: &str, value: &str) -> crate::http::Request {
        let mut req = crate::http::Request {
            method: "GET".into(),
            target: b"/sub/secret.txt".to_vec(),
            raw_path: b"/sub/secret.txt".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        req.headers.push(name, value);
        req
    }

    #[test]
    fn access_walk_trace_collect_and_apply_request_paths() {
        let dir = tempdir("coverage-walk");
        let www = dir.join("www");
        for sub in ["sub", "empty", "bad", "oversize", "loop", "parse-error"] {
            fs::create_dir_all(www.join(sub)).unwrap();
        }
        fs::write(www.join("sub/secret.txt"), "secret\n").unwrap();
        fs::write(
            www.join(".htaccess"),
            concat!(
                "<Files \"secret.txt\">\n",
                "Header set X-FileRule yes\n",
                "</Files>\n",
                "<If \"%{HTTP:X-Branch} == 'yes'\">\n",
                "Header set X-CondRule yes\n",
                "</If>\n",
                "SetEnv ROOT yes\n",
            ),
        )
        .unwrap();
        fs::write(www.join(".htaccess2"), "SetEnv SECOND yes\n").unwrap();
        fs::write(www.join("sub/.htaccess"), "SetEnv SUB yes\n").unwrap();
        let cfg = config(
            &dir,
            &format!(
                "Listen 127.0.0.1:0\n\
                 DocumentRoot \"{}\"\n\
                 AccessFileName .htaccess .htaccess2\n\
                 <Directory \"{}\">\n\
                     AllowOverride All\n\
                 </Directory>\n",
                www.display(),
                www.display()
            ),
        );
        let file = www.join("sub/secret.txt");
        let req = request_with_header("X-Branch", "yes");
        let mut scope = Scope::default();
        apply_req(
            &cfg,
            None,
            &mut scope,
            &file,
            "/sub/secret.txt",
            Some(&req),
            "127.0.0.1".parse().unwrap(),
        )
        .unwrap();
        let env = scope.request_env(&req, "/x");
        for expected in ["ROOT", "SECOND", "SUB"] {
            assert!(
                env.iter().any(|(name, _)| name == expected),
                "missing {expected}: {env:?}"
            );
        }
        assert!(scope
            .header_policy
            .set_headers
            .iter()
            .any(|(name, _)| name == "X-FileRule"));
        assert!(scope
            .header_policy
            .set_headers
            .iter()
            .any(|(name, _)| name == "X-CondRule"));

        let layers = collect_layers(&cfg, None, &file, "/sub/secret.txt").unwrap();
        assert_eq!(layers.len(), 2);

        let trace = trace_access_files(&cfg, None, &file, "/sub/secret.txt").join("\n");
        assert!(trace.contains(".htaccess"));
        assert!(trace.contains(".htaccess2"));

        // The non-directory start and the outer configuration phase.
        let path_info = www.join("sub/secret.txt/more");
        let mut files = Vec::new();
        let mut deferred = Vec::new();
        let mut config_files = Vec::new();
        let mut scope = Scope::default();
        apply_req_deferred(
            &cfg,
            None,
            &mut scope,
            &www,
            "/",
            Some(&req),
            "127.0.0.1".parse().unwrap(),
            &mut files,
            &mut deferred,
            true,
            &mut config_files,
        )
        .unwrap();
        let mut files = Vec::new();
        let mut deferred = Vec::new();
        let mut config_files = Vec::new();
        let mut scope = Scope::default();
        apply_req_deferred(
            &cfg,
            None,
            &mut scope,
            &path_info,
            "/sub/secret.txt/more",
            Some(&req),
            "127.0.0.1".parse().unwrap(),
            &mut files,
            &mut deferred,
            true,
            &mut config_files,
        )
        .unwrap();

        // PATH_INFO starts at the script file; the trace must skip that
        // non-directory entry and still report the script's parent layers.
        let trace = trace_access_files(&cfg, None, &path_info, "/sub/secret.txt/more").join("\n");
        assert!(trace.contains(".htaccess"));

        // Metadata errors and parse errors are fail-closed.
        fs::create_dir_all(www.join("bad/.htaccess")).unwrap();
        assert!(collect_layers(&cfg, None, &www.join("bad/x"), "/bad/x").is_err());
        fs::write(
            www.join("oversize/.htaccess"),
            vec![b'#'; (MAX_HTACCESS + 1) as usize],
        )
        .unwrap();
        assert!(collect_layers(&cfg, None, &www.join("oversize/x"), "/oversize/x").is_err());
        std::os::unix::fs::symlink(".htaccess", www.join("loop/.htaccess")).unwrap();
        assert!(collect_layers(&cfg, None, &www.join("loop/x"), "/loop/x").is_err());
        fs::write(www.join("parse-error/.htaccess"), "Frobnicate something\n").unwrap();
        let trace =
            trace_access_files(&cfg, None, &www.join("parse-error/x"), "/parse-error/x").join("\n");
        assert!(trace.contains("ERROR"));

        // A tree with no access files at all, and a path outside every
        // override-enabled directory.
        let dir2 = tempdir("coverage-walk-empty");
        let www2 = dir2.join("www");
        fs::create_dir_all(www2.join("empty")).unwrap();
        fs::write(www2.join("empty/file.txt"), "x\n").unwrap();
        let cfg2 = config(
            &dir2,
            &format!(
                "Listen 127.0.0.1:0\nDocumentRoot \"{}\"\n<Directory \"{}\">\nAllowOverride All\n</Directory>\n",
                www2.display(),
                www2.display()
            ),
        );
        let trace =
            trace_access_files(&cfg2, None, &www2.join("empty/file.txt"), "/empty/file.txt")
                .join("\n");
        assert!(trace.contains("no access files present"));
        let trace = trace_access_files(&cfg2, None, Path::new("/outside/file"), "/file").join("\n");
        assert!(trace.contains("skipped"));
        assert!(
            collect_layers(&cfg2, None, Path::new("/outside/file"), "/file")
                .unwrap()
                .is_empty()
        );

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&dir2);
    }

    #[test]
    fn symlinked_mapping_root_trace_uses_canonical_target_layers() {
        let dir = tempdir("coverage-walk-symlink");
        let real = dir.join("real/public");
        let admin = real.join("admin");
        fs::create_dir_all(&admin).unwrap();
        fs::create_dir_all(dir.join("www")).unwrap();
        let root = dir.join("www/html");
        std::os::unix::fs::symlink(&real, &root).unwrap();
        fs::write(admin.join(".htaccess"), "Options -ExecCGI\n").unwrap();
        fs::write(admin.join("run.cgi"), "#!/bin/sh\n").unwrap();
        let cfg = config(
            &dir,
            &format!(
                "Listen 127.0.0.1:0\nDocumentRoot \"{}\"\n<Directory \"{}\">\nAllowOverride All\n</Directory>\n",
                root.display(),
                root.display()
            ),
        );
        let canonical = dir.join("real/public/admin/run.cgi");
        let trace =
            trace_access_files_with_root(&cfg, None, &canonical, "/admin/run.cgi", Some(&root))
                .join("\n");
        assert!(trace.contains(&admin.join(".htaccess").display().to_string()));
        let layers =
            collect_layers_with_root(&cfg, None, &canonical, "/admin/run.cgi", Some(&root))
                .unwrap();
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].identity.dir, admin);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn access_roots_rule_matching_and_path_helpers() {
        let dir = tempdir("coverage-root");
        let www = dir.join("www");
        let alias = dir.join("alias");
        fs::create_dir_all(&www).unwrap();
        fs::create_dir_all(&alias).unwrap();
        let target = alias.join("wallet.dat");
        fs::write(&target, "wallet\n").unwrap();
        let file_dir = dir.join("files");
        fs::create_dir_all(&file_dir).unwrap();
        let target = file_dir.join("wallet.dat");
        fs::write(&target, "wallet\n").unwrap();
        let regex_dir = dir.join("regex-files");
        fs::create_dir_all(&regex_dir).unwrap();
        let regex_target = regex_dir.join("wallet.dat");
        fs::write(&regex_target, "wallet\n").unwrap();
        let cfg = config(
            &dir,
            &format!(
                "ServerRoot \"{}\"\n\
                 Listen 127.0.0.1:0\n\
                 DocumentRoot \"{}\"\n\
                 Alias /dir \"{}/\"\n\
                 Alias /file \"{}\"\n\
                 AliasMatch \"^/regex-wallet$\" \"{}/\"\n\
                 AliasMatch \"^/cap(.*)$\" \"$1\"\n",
                dir.display(),
                www.display(),
                alias.display(),
                target.display(),
                regex_target.display()
            ),
        );
        assert_eq!(access_root_for(&cfg, None, &alias.join("x")), alias);
        assert_eq!(access_root_for(&cfg, None, &target), file_dir);
        assert_eq!(
            access_root_for(&cfg, None, &regex_target),
            regex_dir,
            "regex file target with trailing slash must use its parent"
        );
        assert_eq!(access_root_for(&cfg, None, &dir.join("other")), www);

        let re = |p: &str| regex::Regex::new(p).unwrap();
        assert!(rule_matches(&MatchKind::Always, "x", "/x"));
        assert!(rule_matches(&MatchKind::Files(re("x")), "x", "/x"));
        assert!(rule_matches(&MatchKind::FilesMatch(re("x")), "x", "/x"));
        assert!(rule_matches(
            &MatchKind::Location(String::new()),
            "x",
            "/any"
        ));
        assert!(rule_matches(&MatchKind::Location("/a/".into()), "x", "/a"));
        assert!(rule_matches(&MatchKind::Location("/a".into()), "x", "/a/b"));
        assert!(!rule_matches(&MatchKind::Location("/a".into()), "x", "/ab"));
        assert!(rule_matches(
            &MatchKind::LocationMatch(re("^/a")),
            "x",
            "/a/b"
        ));
        assert!(rule_matches(
            &MatchKind::Directory(PathBuf::from("/a")),
            "x",
            "/a/b"
        ));
        assert!(rule_matches(
            &MatchKind::DirectoryMatch(re("^/a")),
            "x",
            "/a/b"
        ));

        assert_eq!(mode_key(OverrideMode::None), 0);
        assert_eq!(
            crate::request_plan::layer_url_mount(&www, &www, &www.join("x"), "/x"),
            "/"
        );
        assert_eq!(
            crate::request_plan::layer_url_mount(
                &www,
                &alias,
                &alias.join("deep/file"),
                "/alias/deep/file"
            ),
            "/alias/"
        );
        assert_eq!(
            crate::request_plan::layer_url_mount(
                Path::new("/srv/www"),
                Path::new("/srv/www/a/b"),
                Path::new("/srv/www/a/b/f"),
                "/a/b/f"
            ),
            "/a/b/"
        );
        // F53: an alias target at the mapping root still has the URL mount,
        // not `/`, as its per-directory base.
        assert_eq!(
            crate::request_plan::layer_url_mount(
                Path::new("/srv/site"),
                Path::new("/srv/site"),
                Path::new("/srv/site/private/wallet.dat"),
                "/site/private/wallet.dat"
            ),
            "/site/"
        );
        assert_eq!(
            crate::request_plan::layer_url_mount(
                Path::new("/srv/site"),
                Path::new("/srv/site/private"),
                Path::new("/srv/site/private/wallet.dat"),
                "/site/private/wallet.dat"
            ),
            "/site/private/"
        );
        // A target deeper than the URL (fixed AliasMatch suffix) cannot be
        // described by URL depth; the layer uses Apache's filesystem
        // directory form.  Rewrite subject matching itself is carried by
        // `subject_dir`, not this substitution base (F58).
        assert_eq!(
            crate::request_plan::layer_url_mount(
                Path::new("/srv/site"),
                Path::new("/srv/site"),
                Path::new("/srv/site/sub1/sub2/private/wallet.dat"),
                "/m/private/wallet.dat"
            ),
            "/srv/site/"
        );
        assert_eq!(
            crate::request_plan::layer_url_mount(
                Path::new("/srv/site"),
                Path::new("/srv/site"),
                Path::new("/other/wallet.dat"),
                "/other/wallet.dat"
            ),
            "/srv/site/"
        );
        assert_eq!(
            crate::request_plan::layer_url_mount(
                Path::new("/srv/site"),
                Path::new("/other"),
                Path::new("/srv/site/wallet.dat"),
                "/other/deep/wallet.dat"
            ),
            "/other/"
        );
        assert_eq!(
            crate::request_plan::layer_url_mount(
                Path::new("/srv"),
                Path::new("/srv/site"),
                Path::new("/other/wallet.dat"),
                "/other/wallet.dat"
            ),
            "/srv/site/"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parser_section_and_directive_error_branches() {
        let dir = tempdir("coverage-parse-errors");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        let parse = |text: &str, mode: OverrideMode, nonfatal: NonfatalMode, allow: &[String]| {
            fs::write(&file, text).unwrap();
            let identity = crate::request_plan::LayerIdentity::with_url_mount(&dir, &dir, "/");
            parse_file_with_list(&cfg, &file, mode, allow, nonfatal, &identity)
        };

        let all = OverrideMode::All;
        let cases: &[(&str, bool)] = &[
            ("Header \"unterminated\n", false),
            ("<Files \"x\">\n</If>\n", false),
            ("<Limit GET>\n<Files \"x\">\n</Files>\n</Limit>\n", false),
            (
                "<RequireAll>\n<If \"true\">\nRequire all granted\n</If>\n</RequireAll>\n",
                false,
            ),
            (
                "<IfFile ignored path>\nHeader set X-IfFile yes\n</IfFile>\n",
                true,
            ),
            ("<If \"true\">\n</If>\n<Else extra more>\n</Else>\n", false),
            (
                "<If \"true\">\n<FilesMatch \"[\">\n</FilesMatch>\n</If>\n",
                false,
            ),
            (
                "<IfModule mod_authz_core.c>\n<FilesMatch \"[\">\n</FilesMatch>\n</IfModule>\n",
                false,
            ),
            ("<RequireAll>\n</RequireAll>\n", true),
            (
                "<RequireAll>\n<Limit GET>\nRequire all granted\n</Limit>\n</RequireAll>\n",
                false,
            ),
            (
                "<Limit GET>\n<Limit POST>\nRequire all granted\n</Limit>\n</Limit>\n",
                false,
            ),
            (
                "<RequireAll>\n<Files \"x\">\nRequire all granted\n</Files>\n</RequireAll>\n",
                false,
            ),
            (
                "<FilesMatch \"[\">\nRequire all granted\n</FilesMatch>\n",
                false,
            ),
            (
                "<IfModule !mod_rewrite.c>\nRequire all denied\n</IfModule>\n",
                true,
            ),
            ("<IfModule>\nRequire all denied\n</IfModule>\n", true),
            (
                "<IfModule !mod_not_builtin.c>\nRequire all denied\n</IfModule>\n",
                true,
            ),
            ("<RequireAll>\nHeader set X y\n</RequireAll>\n", false),
            ("SetEnv\n", false),
            ("Options\n", true),
            ("Options All\n", true),
            ("Options Indexes\n", true),
            ("Header always\n", false),
            ("Header always set\n", false),
            ("Header always set X yes\n", true),
            ("Header add X yes\n", true),
            ("Header bogus X y\n", false),
            ("Redirect\n", false),
            ("Redirect 301 /old /new\n", true),
            ("RedirectMatch 301 ^/old /new\n", true),
            ("FileETag Inode MTime Size All\n", true),
            ("AuthBasicProvider ldap\n", false),
            ("ErrorDocument x /x\n", false),
            ("ErrorDocument 404 http://example.test/x\n", true),
            ("ErrorDocument 404 plain text\n", true),
            ("Order bogus\n", false),
            ("Allow all\n", false),
            ("Allow from bogus\n", false),
            ("Satisfy bogus\n", false),
            ("AuthMerging bogus\n", false),
            ("RewriteEngine bogus\n", false),
            ("ReadmeFile README\n", true),
        ];
        for (text, ok) in cases {
            let result = parse(text, all, NonfatalMode::None, &[]);
            assert_eq!(result.is_ok(), *ok, "{text:?}");
        }

        // Nonfatal=Override/Unknown skip restricted material instead of
        // failing the whole request.
        for text in [
            "<RequireAll>\nRequire all denied\n</RequireAll>\n",
            "<Limit GET>\nRequire all denied\n</Limit>\n",
            "Options +Indexes\n",
        ] {
            assert!(parse(text, OverrideMode::None, NonfatalMode::Override, &[]).is_ok());
        }
        let unknown = parse(
            "<Unknown>\n\nplain text\n</Unknown>\n",
            OverrideMode::None,
            NonfatalMode::Unknown,
            &[],
        );
        assert!(unknown.is_ok(), "{:?}", unknown.err());
        let skipped = vec![
            String::new(),
            "\"unterminated".to_string(),
            "<Nested>".to_string(),
            "</Unknown>".to_string(),
            "</Unknown>".to_string(),
        ];
        let mut at = 0usize;
        assert!(skip_section(&skipped, &mut at, "unknown").is_ok());
        assert_eq!(at, skipped.len());
        let mut at = 0usize;
        assert!(skip_section(&["<Unknown>".to_string()], &mut at, "unknown").is_err());
        assert!(parse(
            "Frobnicate x\n",
            OverrideMode::None,
            NonfatalMode::Unknown,
            &[],
        )
        .is_ok());
        assert!(parse(
            "<Unknown>\nRequire all granted\n",
            OverrideMode::None,
            NonfatalMode::Unknown,
            &[],
        )
        .is_err());
        assert!(parse(
            "<RequireAll>\n\"unterminated\n</RequireAll>\n",
            OverrideMode::None,
            NonfatalMode::Override,
            &[],
        )
        .is_ok());
        assert!(parse(
            "<RequireAll>\nRequire all denied\n</RequireAll>\n",
            OverrideMode::None,
            NonfatalMode::None,
            &[],
        )
        .is_err());
        assert!(parse(
            "Require all granted\n",
            OverrideMode::None,
            NonfatalMode::None,
            &["require".to_string()],
        )
        .is_ok());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn directive_permission_edges_options_and_cached_metadata() {
        let args = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(directive_allowed_list(
            OverrideMode::None,
            &["require".to_string()],
            "require",
            &args(&["all", "granted"])
        ));
        assert!(!directive_allowed_list(
            OverrideMode::Categories(OverrideCategories(OverrideCategories::OPT_INDEXES)),
            &[],
            "options",
            &[]
        ));
        let per_option =
            OverrideMode::Categories(OverrideCategories(OverrideCategories::OPT_INDEXES));
        for flag in [
            "+All",
            "+Includes",
            "+IncludesNoExec",
            "+FollowSymLinks",
            "+Indexes",
            "+MultiViews",
            "+SymLinksIfOwnerMatch",
            "+MadeUp",
        ] {
            let _ = directive_allowed_list(per_option, &[], "options", &args(&[flag]));
        }

        let dir = tempdir("coverage-cache");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(&file, "Require all granted\n").unwrap();
        let meta = fs::metadata(&file).unwrap();
        let mut parsed = None;
        for nonfatal in [
            NonfatalMode::None,
            NonfatalMode::Override,
            NonfatalMode::Unknown,
            NonfatalMode::All,
        ] {
            parsed = Some(
                parse_cached(
                    &cfg,
                    &file,
                    OverrideMode::All,
                    &[],
                    nonfatal,
                    &crate::request_plan::LayerIdentity::with_url_mount(&dir, &dir, "/"),
                    &meta,
                )
                .unwrap(),
            );
        }
        let parsed = parsed.unwrap();
        {
            let mut guard = cache().lock().unwrap_or_else(|e| e.into_inner());
            for n in 0..512 {
                guard.insert(
                    CacheKey {
                        path: dir.join(format!("dummy-{n}")),
                        server_root: cfg.server_root.clone(),
                        dev: 0,
                        ino: n,
                        mtime: 0,
                        mtime_nsec: 0,
                        ctime: 0,
                        ctime_nsec: 0,
                        size: 0,
                        mode: 0,
                        allow_list: Vec::new(),
                        nonfatal: 0,
                        identity: crate::request_plan::LayerIdentity::with_url_mount(
                            &dir, &dir, "/",
                        ),
                    },
                    Arc::clone(&parsed),
                );
            }
        }
        assert!(parse_cached(
            &cfg,
            &file,
            OverrideMode::All,
            &[],
            NonfatalMode::None,
            &crate::request_plan::LayerIdentity::with_url_mount(&dir, &dir, "/"),
            &meta
        )
        .is_ok());

        let big = dir.join("big.htaccess");
        fs::write(&big, vec![b'#'; (MAX_HTACCESS + 1) as usize]).unwrap();
        assert!(parse_file(&cfg, &big, OverrideMode::All, "/").is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remaining_walk_trace_and_unreachable_defensive_branches() {
        let dir = tempdir("coverage-remaining");
        let www = dir.join("www");
        fs::create_dir_all(www.join("sub")).unwrap();
        fs::create_dir_all(www.join("none")).unwrap();
        fs::create_dir_all(www.join("nonfile")).unwrap();
        fs::create_dir_all(www.join("bad2")).unwrap();
        fs::write(www.join("sub/file.txt"), "x\n").unwrap();
        fs::write(www.join("none/.htaccess"), "Require all granted\n").unwrap();
        fs::write(www.join(".htaccess"), "Require all granted\n").unwrap();
        fs::create_dir_all(www.join("nonfile/.htaccess")).unwrap();
        fs::create_dir_all(www.join("bad2/.htaccess")).unwrap();
        fs::write(www.join("bad2/.htaccess2"), "Require all granted\n").unwrap();
        let mut cfg = config(
            &dir,
            &format!(
                "Listen 127.0.0.1:0\n\
                 DocumentRoot \"{}\"\n\
                 AccessFileName .htaccess .htaccess2\n\
                 <Directory \"{}\">\n\
                     AllowOverride All\n\
                 </Directory>\n\
                 <Directory \"{}/none\">\n\
                     AllowOverride None\n\
                 </Directory>\n",
                www.display(),
                www.display(),
                www.display()
            ),
        );
        cfg.access_file_names = vec![".htaccess".into(), ".htaccess2".into()];

        // trace_access_files with a directory start and a non-file access name.
        let trace = trace_access_files(&cfg, None, &www, "/").join("\n");
        assert!(trace.contains(".htaccess"));
        let trace = trace_access_files(&cfg, None, &www.join("nonfile/x"), "/nonfile/x").join("\n");
        assert!(!trace.contains("nonfile/.htaccess"));
        let layers = collect_layers(&cfg, None, &www.join("none/x"), "/none/x").unwrap();
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].identity.dir, www);
        let trace = trace_access_files(&cfg, None, &www.join("none/x"), "/none/x").join("\n");
        assert!(!trace.contains("none/.htaccess"));

        // apply_req_deferred error branches: ELOOP, non-regular, oversized.
        let mut scope = Scope::default();
        let mut files = Vec::new();
        let mut deferred = Vec::new();
        let mut config_files = Vec::new();
        assert!(apply_req_deferred(
            &cfg,
            None,
            &mut scope,
            &www.join("bad2/x"),
            "/bad2/x",
            None,
            "127.0.0.1".parse().unwrap(),
            &mut files,
            &mut deferred,
            false,
            &mut config_files,
        )
        .is_err());
        let req = request_with_header("X-Branch", "yes");
        assert!(apply_req(
            &cfg,
            None,
            &mut Scope::default(),
            &www.join("bad2/x"),
            "/bad2/x",
            Some(&req),
            "127.0.0.1".parse().unwrap(),
        )
        .is_err());
        std::os::unix::fs::symlink(".htaccess", www.join("sub/.htaccess")).unwrap();
        fs::write(www.join("sub/.htaccess2"), "Require all granted\n").unwrap();
        let mut scope = Scope::default();
        let mut files = Vec::new();
        let mut deferred = Vec::new();
        let mut config_files = Vec::new();
        assert!(apply_req_deferred(
            &cfg,
            None,
            &mut scope,
            &www.join("sub/file.txt"),
            "/sub/file.txt",
            None,
            "127.0.0.1".parse().unwrap(),
            &mut files,
            &mut deferred,
            false,
            &mut config_files,
        )
        .is_err());
        fs::remove_file(www.join("sub/.htaccess")).unwrap();
        fs::write(
            www.join("sub/.htaccess"),
            vec![b'#'; (MAX_HTACCESS + 1) as usize],
        )
        .unwrap();
        let mut scope = Scope::default();
        let mut files = Vec::new();
        let mut deferred = Vec::new();
        let mut config_files = Vec::new();
        assert!(apply_req_deferred(
            &cfg,
            None,
            &mut scope,
            &www.join("sub/file.txt"),
            "/sub/file.txt",
            None,
            "127.0.0.1".parse().unwrap(),
            &mut files,
            &mut deferred,
            false,
            &mut config_files,
        )
        .is_err());

        // A normal non-Files/non-conditional rule lands in the TopLevel slot.
        let mut layer = crate::policy_ref::AccessLayer {
            identity: crate::request_plan::LayerIdentity::new(&www, &www, &www.join("x"), "/x"),
            scope: Arc::new(Scope::default()),
            files: Vec::new(),
            conditionals: Vec::new(),
        };
        let top = ScopeRule {
            kind: MatchKind::Always,
            delta: Scope::default(),
            order: 0,
            condition: None,
            branch: ConditionBranch::Normal,
            chain: None,
            nested: Vec::new(),
        };
        add_layer_rule(&mut layer, &top);
        assert!(layer.files.is_empty() && layer.conditionals.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn direct_directive_errors_and_unknown_specs() {
        let dir = tempdir("coverage-directive-errors");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        let parse = |text: &str| {
            fs::write(&file, text).unwrap();
            parse_file(&cfg, &file, OverrideMode::All, "/")
        };
        for (text, ok) in [
            ("Require ip not-an-ip\n", false),
            ("Require dbm ignored\n", true),
            ("RedirectMatch\n", false),
            ("RedirectMatch 301\n", false),
            ("FileETag made-up\n", true),
            ("AddHandler cgi-script .cgi\n", true),
            ("AddHandler cgi-script\n", true),
            ("ErrorDocument 404\n", true),
            ("AddOutputFilterByType DEFLATE text/plain\n", true),
            ("AddOutputFilterByType DEFLATE\n", true),
            ("AddOutputFilter DEFLATE .html\n", true),
            ("AddOutputFilter DEFLATE\n", true),
            ("coverage-reject anything\n", false),
            ("coverage-unhandled anything\n", false),
        ] {
            let result = parse(text);
            assert_eq!(result.is_ok(), ok, "{text}: {:?}", result.err());
        }
        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod compression_tests {
    use super::*;
    use crate::config::OverrideCategories;
    use std::collections::HashMap;

    fn tempdir(name: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("vapache-htaccess-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn config(root: &Path, text: &str) -> Config {
        let path = root.join("httpd.conf");
        fs::write(&path, text).unwrap();
        Config::load(&path, root, &HashMap::new(), &HashMap::new(), false).unwrap()
    }

    #[test]
    fn parses_compression_filter_directives() {
        let dir = tempdir("compression");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(
            &file,
            concat!(
                "AddOutputFilterByType DEFLATE text/plain text/css\n",
                "AddOutputFilter BROTLI_COMPRESS .html\n",
                "SetOutputFilter DEFLATE\n",
                "DeflateCompressionLevel 9\n",
                "BrotliCompressionQuality 11\n",
                "DeflateAlterETag Remove\n",
                "BrotliAlterETag NoChange\n",
                "DeflateFilterNote ratio\n",
            ),
        )
        .unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        assert_eq!(p.scope.compression_policy.compression_rules.len(), 3);
        assert_eq!(p.scope.compression_policy.deflate_level, Some(9));
        assert_eq!(p.scope.compression_policy.brotli_quality, Some(11));
        assert_eq!(
            p.scope.compression_policy.deflate_alter_etag,
            Some(crate::config::AlterEtag::Remove)
        );
        assert_eq!(
            p.scope.compression_policy.brotli_alter_etag,
            Some(crate::config::AlterEtag::NoChange)
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
