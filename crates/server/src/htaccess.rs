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
    if result.is_ok() {
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
    }
    result
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
    let root = cfg.documentation_root_for(vhost);
    let start = if fs_path.is_dir() {
        fs_path
    } else {
        fs_path.parent().unwrap_or(fs_path)
    };
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
    let can_read_access = cfg.override_enabled && cfg.override_applicable(fs_path);
    let mut ignored_locations = Vec::new();
    for dir in dirs {
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
        if !can_read_access || !(dir.starts_with(&root) || dir == start) {
            continue;
        }
        // Resolving a per-directory scope walks the vhost and rule lists.  The
        // overwhelmingly common case is a tree with no access files at all, so
        // avoid that work unless an access file is actually present here.
        let mut has_access_file = false;
        for name in &cfg.access_file_names {
            match fs::metadata(dir.join(name)) {
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
            let delta = match fs::metadata(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("{}: {e}", path.display())),
                Ok(m) if !m.is_file() => {
                    return Err(format!("{}: not a regular file", path.display()))
                }
                Ok(m) if m.len() > MAX_HTACCESS => {
                    return Err(format!("{}: access file too large", path.display()))
                }
                Ok(meta) => {
                    let base = dir_url_base(&root, &dir, url_path);
                    parse_cached(cfg, &path, mode, allow_list, nonfatal, &base, &meta)?
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
    if !cfg.htaccess_may_apply(fs_path) {
        return Ok(Vec::new());
    }
    let root = cfg.documentation_root_for(vhost);
    let start = if fs_path.is_dir() {
        fs_path
    } else {
        fs_path.parent().unwrap_or(fs_path)
    };
    let mut dirs = Vec::new();
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
    let mut layers = Vec::new();
    for dir in dirs {
        if !(dir.starts_with(&root) || dir == start) {
            continue;
        }
        let dir_scope = cfg.effective_scope_cached(vhost, &dir, url_path);
        let mode = dir_scope.override_policy.mode();
        let allow_list = dir_scope.override_policy.allow_list();
        let nonfatal = dir_scope.override_policy.nonfatal();
        if !mode.is_enabled() && allow_list.is_empty() {
            continue;
        }
        let mut layer = crate::policy_ref::AccessLayer {
            dir: dir.clone(),
            scope: Arc::new(Scope::default()),
            files: Vec::new(),
            conditionals: Vec::new(),
        };
        let mut found = false;
        for name in cfg.access_file_names_for(&dir_scope) {
            let path = dir.join(&name);
            let meta = match fs::metadata(&path) {
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
            let base = dir_url_base(&root, &dir, url_path);
            let parsed = parse_cached(cfg, &path, mode, allow_list, nonfatal, &base, &meta)?;
            if found {
                Arc::make_mut(&mut layer.scope).merge(&parsed.scope);
            } else {
                // Preserve AuthMerging on the first access file; the cached
                // parsed scope is shared rather than cloned per request.
                layer.scope = Arc::clone(&parsed.scope);
            }
            for rule in &parsed.rules {
                let slot = crate::verified::access_layer_slot(
                    rule.condition.is_some(),
                    rule.branch == ConditionBranch::Normal,
                    matches!(rule.kind, MatchKind::Files(_) | MatchKind::FilesMatch(_)),
                );
                match slot {
                    crate::verified::AccessLayerSlot::Conditional => {
                        layer.conditionals.push(rule.clone())
                    }
                    crate::verified::AccessLayerSlot::Files => layer.files.push(rule.clone()),
                    crate::verified::AccessLayerSlot::TopLevel => {}
                }
            }
            found = true;
        }
        if found {
            layers.push(layer);
        }
    }
    Ok(layers)
}

/// Diagnostic trace for `--explain`: which access files are present, which
/// override policy applies, and how many rules each parsed file contributes.
pub fn trace_access_files(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    url_path: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    if !cfg.htaccess_may_apply(fs_path) {
        out.push("skipped (no override-enabled directory in path)".into());
        return out;
    }
    let root = cfg.documentation_root_for(vhost);
    let start = if fs_path.is_dir() {
        fs_path
    } else {
        fs_path.parent().unwrap_or(fs_path)
    };
    let mut dirs = Vec::new();
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
    let mut found = false;
    for dir in dirs {
        if !(dir.starts_with(&root) || dir == start) {
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
            let Ok(meta) = fs::metadata(&path) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            found = true;
            let base = dir_url_base(&root, &dir, url_path);
            match parse_cached(cfg, &path, mode, allow_list, nonfatal, &base, &meta) {
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
    base_url: String,
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
    base_url: &str,
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
        base_url: base_url.to_string(),
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
        cfg, path, mode, allow_list, nonfatal, base_url,
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
    parse_file_with_list(cfg, path, mode, &[], NonfatalMode::None, base_url)
}

fn parse_file_with_list(
    cfg: &Config,
    path: &Path,
    mode: OverrideMode,
    allow_list: &[String],
    nonfatal: NonfatalMode,
    base_url: &str,
) -> Result<Parsed, String> {
    let data = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if data.len() as u64 > MAX_HTACCESS {
        return Err(format!("{}: .htaccess file too large", path.display()));
    }
    let text = String::from_utf8_lossy(&data);
    let lines = logical_lines(&text);
    let mut scope = Scope::default();
    let mut rules = Vec::new();
    scope.rewrite_policy.rewrite_base = Some(normalize_rewrite_base(base_url));
    scope.rewrite_policy.rewrite_match_base = Some(normalize_rewrite_base(base_url));
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
    Ok(Parsed {
        scope: Arc::new(scope),
        rules,
    })
}

fn dir_url_base(root: &Path, dir: &Path, url_path: &str) -> String {
    if let Ok(rel) = dir.strip_prefix(root) {
        let rel = rel.to_string_lossy().replace('\\', "/");
        let rel = rel.trim_matches('/');
        return if rel.is_empty() {
            "/".into()
        } else {
            format!("/{rel}/")
        };
    }
    // Aliased content: derive the URL directory from the requested path.
    let parent = url_path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
    normalize_rewrite_base(parent)
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
                        if !inner_rules.is_empty() {
                            return Err(format!(
                                "line {}: nested sections are not allowed in <{name}>",
                                *i
                            ));
                        }
                        let mut nodes = Vec::new();
                        let inner_entries = match inner.authorization.requires.take() {
                            None => Vec::new(),
                            Some(crate::config::AuthPolicy::List(entries)) => entries,
                            Some(_) => {
                                return Err(format!(
                                    "line {}: AuthMerging is not allowed in <{name}>",
                                    *i
                                ))
                            }
                        };
                        for entry in inner_entries {
                            if entry.limit.as_ref() != limit {
                                return Err(format!(
                                "line {}: nested method-limited sections are not allowed in <{name}>",
                                *i
                            ));
                            }
                            nodes.push(entry.node);
                        }
                        let node = match name.as_str() {
                            "requireall" => RequireNode::All(nodes),
                            "requireany" => RequireNode::Any(nodes),
                            _ => RequireNode::None(nodes),
                        };
                        let has_items = match &node {
                            RequireNode::All(v) | RequireNode::Any(v) | RequireNode::None(v) => {
                                !v.is_empty()
                            }
                            RequireNode::Provider(_) => true,
                        };
                        if has_items {
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
            if close == name {
                depth -= 1;
                if depth == 0 {
                    return Ok(());
                }
            }
        } else if first.starts_with('<') {
            depth += 1;
        }
    }
    Err(format!("missing closing </{name}>"))
}

fn ifmodule_active(args: &[String]) -> bool {
    let Some(name) = args.first() else {
        return false;
    };
    let (negated, name) = match name.strip_prefix('!') {
        Some(n) => (true, n),
        None => (false, name.as_str()),
    };
    let supported = [
        "mod_authz_core.c",
        "authz_core_module",
        "mod_authz_user.c",
        "authz_user_module",
        "mod_authz_groupfile.c",
        "authz_groupfile_module",
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
        "mod_deflate.c",
        "deflate_module",
        "mod_brotli.c",
        "brotli_module",
        "mod_filter.c",
        "filter_module",
    ]
    .iter()
    .any(|m| m.eq_ignore_ascii_case(name));
    if negated {
        !supported
    } else {
        supported
    }
}

fn directive_category(name: &str) -> Option<OverrideCategory> {
    Some(match name {
        "require" | "authtype" | "authname" | "authuserfile" | "authgroupfile"
        | "authbasicprovider" | "authmerging" => OverrideCategory::AuthConfig,
        "options" => OverrideCategory::Options,
        "directoryindex" | "indexoptions" | "indexignore" | "adddescription" | "readmefile"
        | "headername" | "directoryslash" => OverrideCategory::Indexes,
        "order" | "allow" | "deny" => OverrideCategory::Limit,
        "addtype"
        | "removetype"
        | "addhandler"
        | "sethandler"
        | "forcetype"
        | "adddefaultcharset"
        | "header"
        | "redirect"
        | "errordocument"
        | "fileetag"
        | "enablesendfile"
        | "rewriteengine"
        | "rewritebase"
        | "rewritecond"
        | "rewriterule"
        | "rewriteoptions"
        | "expiresactive"
        | "expiresbytype"
        | "expiresdefault"
        | "setenv"
        | "setenvif"
        | "requestheader"
        | "addcharset"
        | "addlanguage"
        | "addencoding"
        | "removecharset"
        | "removeencoding"
        | "addoutputfilterbytype"
        | "addoutputfilter"
        | "setoutputfilter"
        | "deflatecompressionlevel"
        | "brotlicompressionquality"
        | "deflatealteretag"
        | "brotlialteretag"
        | "brotlicompressionalteretag"
        | "deflatefilternote"
        | "deflatebuffersize"
        | "deflatememlevel"
        | "deflatewindowssize" => OverrideCategory::FileInfo,
        "satisfy" => OverrideCategory::AuthConfig,
        _ => return None,
    })
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
            if args.len() >= 2 {
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
            if args.len() >= 2 {
                for ext in &args[1..] {
                    scope.mapping_policy.handlers.push(crate::config::Handler {
                        ext: ext.trim_start_matches('.').to_ascii_lowercase(),
                        handler: args[0].clone(),
                    });
                }
            }
        }
        "sethandler" => scope.mapping_policy.handlers.push(crate::config::Handler {
            ext: "*".into(),
            handler: first.to_string(),
        }),
        "forcetype" => scope.content_policy.force_type = Some(first.to_string()),
        "adddefaultcharset" => {
            if !first.eq_ignore_ascii_case("off") {
                scope.content_policy.default_charset = Some(first.to_string());
            }
        }
        "addoutputfilterbytype" => {
            if args.len() >= 2 {
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
        }
        "addoutputfilter" => {
            if args.len() >= 2 {
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
        "allowmethods" => {
            return Err(
                "AllowMethods is only allowed in directory configuration, not .htaccess".into(),
            )
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
        "redirect" => apply_redirect(scope, args)?,
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
        // These do not affect access decisions or response framing; accepting
        // them keeps common .htaccess files usable until environment filters
        // are implemented.
        "setenv" | "setenvif" | "requestheader" | "addcharset" | "addlanguage" | "addencoding"
        | "removecharset" | "removeencoding" | "adddescription" | "indexoptions"
        | "indexignore" | "readmefile" | "headername" => {}
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
            "none" => Some(Options::empty()),
            "all" => Some(Options::all()),
            "indexes" => Some(Options(Options::INDEXES)),
            "followsymlinks" => Some(Options(Options::FOLLOW_SYMLINKS)),
            "symlinksifownermatch" => Some(Options(Options::SYMLINKS_IF_OWNER_MATCH)),
            "execcgi" => Some(Options(Options::EXEC_CGI)),
            "includes" => Some(Options(Options::INCLUDES)),
            "includesnoexec" => Some(Options(Options::INCLUDES_NOEXEC)),
            "multiviews" => Some(Options(Options::MULTIVIEWS)),
            _ => return Err(format!("unsupported Options flag '{a}'")),
        };
        if let Some(o) = opt {
            match sign {
                1 => scope.options.push_add(o.0),
                -1 => scope.options.push_remove(o.0),
                _ if flag.eq_ignore_ascii_case("none") => {
                    scope.options.push_set(Options::empty().0)
                }
                _ if flag.eq_ignore_ascii_case("all") => scope.options.push_set(Options::all().0),
                _ => scope.options.push_add(o.0),
            }
        }
    }
    Ok(())
}

fn apply_header(scope: &mut Scope, args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("Header requires an action and name".into());
    }
    let mut idx = 0;
    if args[0].eq_ignore_ascii_case("always") || args[0].eq_ignore_ascii_case("onsuccess") {
        idx = 1;
    }
    if args.len() < idx + 2 {
        return Err("Header requires an action and name".into());
    }
    let action = args[idx].to_ascii_lowercase();
    let name = args[idx + 1].trim_end_matches(':').to_string();
    match action.as_str() {
        "set" => {
            let value = args[idx + 2..].join(" ");
            scope.header_policy.set_headers.push((name, value));
        }
        "add" => {
            let value = args[idx + 2..].join(" ");
            scope.header_policy.add_headers.push((name, value));
        }
        "unset" => scope.header_policy.unset_headers.push(name),
        _ => return Err(format!("unsupported Header action '{action}'")),
    }
    Ok(())
}

fn apply_redirect(scope: &mut Scope, args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("Redirect requires a source and target".into());
    }
    let (status, from, to) = if args[0].parse::<u16>().is_ok() && args.len() >= 3 {
        (
            args[0].parse().unwrap_or(302),
            args[1].clone(),
            args[2..].join(" "),
        )
    } else {
        (302, args[0].clone(), args[1..].join(" "))
    };
    scope
        .mapping_policy
        .redirects
        .push(crate::config::Redirect { from, to, status });
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
                node: RequireNode::Provider(crate::config::Require::ValidUser),
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
            .add_headers
            .iter()
            .any(|(n, v)| n == "X-Added" && v == "value with spaces"));
        let opts = p.scope.effective_options();
        assert!(!opts.contains(Options::INDEXES));
        assert!(opts.contains(Options::FOLLOW_SYMLINKS));
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
