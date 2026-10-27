//! One immutable request identity shared by dispatch, cache, access control,
//! rewrite evaluation and `--explain`.
//!
//! The recurring F50–F58 failures came from recomputing the same identities
//! in different places: the raw request target vs. the canonical URL path, and
//! an access-file layer's URL mount vs. its filesystem-relative rewrite
//! subject.  `RequestPlan` is built once per request/rewrite round and carries
//! those values, so policy consumers cannot silently disagree.

use crate::config::{Config, Scope, ScopeRule, VHost};
use crate::http::Request;
use crate::policy_ref::AccessLayer;
use crate::verified::{normalize_uri_path, percent_decode_path};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalError {
    /// The request path could not be percent-decoded.
    Decode,
    /// The decoded path was relative, malformed, or could not be normalized.
    Normalize,
}

impl CanonicalError {
    pub fn status(self) -> u16 {
        match self {
            CanonicalError::Decode => 404,
            CanonicalError::Normalize => 400,
        }
    }
}

/// The dispatcher-selected URL identity.  `url_path` is decoded, normalized
/// and query-free; `norm` is the mapping form used by `map_path()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalTarget {
    pub url_path: String,
    pub norm: Vec<u8>,
}

impl CanonicalTarget {
    pub fn from_request(req: &Request, allow_encoded: bool) -> Result<Self, CanonicalError> {
        let raw_path: &[u8] = if req.raw_path == b"*" {
            b"/"
        } else {
            &req.raw_path
        };
        Self::from_raw_path(raw_path, allow_encoded)
    }

    pub fn from_raw_path(raw_path: &[u8], allow_encoded: bool) -> Result<Self, CanonicalError> {
        let decoded = percent_decode_path(raw_path, allow_encoded).ok_or(CanonicalError::Decode)?;
        let trailing_slash = decoded.len() > 1 && decoded.ends_with(b"/");
        let norm = normalize_uri_path(&decoded).ok_or(CanonicalError::Normalize)?;
        if !crate::util::is_canonical_path(&norm) {
            // normalize_uri_path() proves this property; keep the guard as
            // defense in depth for non-verified callers.
            return Err(CanonicalError::Normalize); // coverage:ignore-line
        }
        let mut url_path = String::from_utf8_lossy(&norm).into_owned();
        if trailing_slash && url_path != "/" {
            url_path.push('/');
        }
        Ok(Self { url_path, norm })
    }

    /// Build a target from an internal rewrite result.  `norm` is retained as
    /// the mapping form because rewrite canonicalization already ran.
    pub fn from_normalized(norm: Vec<u8>, url_path: String) -> Self {
        Self { url_path, norm }
    }

    pub fn from_url_path(path: &str) -> Option<Self> {
        let trailing_slash = path.len() > 1 && path.ends_with('/');
        let norm = normalize_uri_path(path.as_bytes())?;
        let mut url_path = String::from_utf8_lossy(&norm).into_owned();
        if trailing_slash && url_path != "/" {
            url_path.push('/');
        }
        Some(Self { url_path, norm })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// `map_path()` rejected the URL (for example a regex alias expanded
    /// outside its configured base).
    Unmapped,
    /// An access file exists but could not be read or parsed.
    AccessFiles(String),
}

/// Identity of one access-file layer.
///
/// `dir` is the layer directory whose filesystem-relative path is Apache's
/// per-directory rewrite subject.  `mapping_root` is the URL-selected root
/// returned by `map_path()`.  `url_mount` is the URL prefix used only for
/// relative rewrite substitutions, never for subject matching.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LayerIdentity {
    pub dir: PathBuf,
    pub mapping_root: PathBuf,
    pub url_mount: String,
}

impl LayerIdentity {
    pub fn new(mapping_root: &Path, dir: &Path, fs_path: &Path, url_path: &str) -> Self {
        Self {
            dir: dir.to_path_buf(),
            mapping_root: mapping_root.to_path_buf(),
            url_mount: layer_url_mount(mapping_root, dir, fs_path, url_path),
        }
    }

    pub fn with_url_mount(mapping_root: &Path, dir: &Path, url_mount: &str) -> Self {
        Self {
            dir: dir.to_path_buf(),
            mapping_root: mapping_root.to_path_buf(),
            url_mount: crate::config::normalize_rewrite_base(url_mount),
        }
    }

    /// Apache's per-directory RewriteRule subject: the selected filesystem
    /// target relative to the layer directory.  Directory requests keep their
    /// trailing slash even though `map_path()` normalizes it from `fs_path`.
    pub fn subject(&self, fs_path: &Path, url_path: &str) -> Option<String> {
        layer_subject(&self.dir, fs_path, url_path)
    }
}

/// The single implementation of a per-directory rewrite subject.
pub fn layer_subject(dir: &Path, fs_path: &Path, url_path: &str) -> Option<String> {
    let rel = fs_path.strip_prefix(dir).ok()?;
    let mut subject = rel
        .to_string_lossy()
        .replace('\\', "/")
        .trim_matches('/')
        .to_string();
    if !subject.is_empty() && url_path.ends_with('/') {
        subject.push('/');
    }
    Some(subject)
}

/// The single implementation of a layer's relative-substitution base.
///
/// Layers at/below the URL mapping root use the URL mount.  A strict ancestor
/// of the mapping root has no URL-mount representation; Apache uses the
/// filesystem directory itself.  A fixed alias target deeper than the URL has
/// the same shape.  None of these branches is used for subject matching.
pub fn layer_url_mount(mapping_root: &Path, dir: &Path, fs_path: &Path, url_path: &str) -> String {
    let Some(rel) = fs_path.strip_prefix(dir).ok() else {
        return crate::config::normalize_rewrite_base(&dir.to_string_lossy());
    };
    if dir != mapping_root && mapping_root.starts_with(dir) {
        return crate::config::normalize_rewrite_base(&dir.to_string_lossy());
    }
    let depth = rel.components().count();
    let trimmed = url_path.trim_end_matches('/');
    let mut end = trimmed.len();
    let mut remaining = depth;
    let mut url_depth_sufficient = true;
    while remaining > 0 {
        let Some(slash) = trimmed[..end].rfind('/') else {
            url_depth_sufficient = false;
            break;
        };
        end = slash;
        remaining -= 1;
    }
    if !vapache_verified::htaccess_layer_url_base_admit(true, url_depth_sufficient) {
        return crate::config::normalize_rewrite_base(&dir.to_string_lossy());
    }
    crate::config::normalize_rewrite_base(&trimmed[..end])
}

/// Immutable mapping + access-layer identity for one request or rewrite round.
#[derive(Debug, Clone)]
pub struct RequestPlan {
    target: CanonicalTarget,
    root: PathBuf,
    rel: PathBuf,
    fs_path: PathBuf,
    script_alias: bool,
    layers: Vec<AccessLayer>,
}

impl RequestPlan {
    /// Canonicalize the client request and resolve it through the normal URL
    /// mapping.  This is the only place dispatch/cache/explain should build
    /// their initial plan.
    pub fn from_request(
        cfg: &Config,
        vhost: Option<&VHost>,
        req: &Request,
        allow_encoded: bool,
    ) -> Result<Self, CanonicalErrorOrPlan> {
        let target = CanonicalTarget::from_request(req, allow_encoded)
            .map_err(CanonicalErrorOrPlan::Canonical)?;
        Self::resolve(cfg, vhost, target).map_err(CanonicalErrorOrPlan::Plan)
    }

    pub fn resolve(
        cfg: &Config,
        vhost: Option<&VHost>,
        target: CanonicalTarget,
    ) -> Result<Self, PlanError> {
        let (root, rel, script_alias) =
            crate::server::map_path(cfg, vhost, &target.norm).ok_or(PlanError::Unmapped)?;
        Self::build(cfg, vhost, target, root, rel, script_alias)
    }

    /// Build a plan for an explicit filesystem target that may differ from
    /// the URL mapping (a symlink target or rewrite filesystem override).
    pub fn from_fs_target(
        cfg: &Config,
        vhost: Option<&VHost>,
        target: CanonicalTarget,
        root: PathBuf,
        fs_path: PathBuf,
        script_alias: bool,
    ) -> Result<Self, PlanError> {
        let rel = fs_path
            .strip_prefix(&root)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| {
                PathBuf::from(
                    fs_path
                        .file_name()
                        .map(|name| name.to_os_string())
                        .unwrap_or_default(),
                )
            });
        let mut plan = Self::build(cfg, vhost, target, root, rel, script_alias)?;
        plan.fs_path = fs_path;
        Ok(plan)
    }

    fn build(
        cfg: &Config,
        vhost: Option<&VHost>,
        target: CanonicalTarget,
        root: PathBuf,
        rel: PathBuf,
        script_alias: bool,
    ) -> Result<Self, PlanError> {
        let fs_path = root.join(&rel);
        let layers = if cfg.htaccess_may_apply(&fs_path) {
            crate::htaccess::collect_layers_with_root(
                cfg,
                vhost,
                &fs_path,
                &target.url_path,
                Some(&root),
            )
            .map_err(PlanError::AccessFiles)?
        } else {
            Vec::new()
        };
        Ok(Self {
            target,
            root,
            rel,
            fs_path,
            script_alias,
            layers,
        })
    }

    pub fn target(&self) -> &CanonicalTarget {
        &self.target
    }

    pub fn url_path(&self) -> &str {
        &self.target.url_path
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn rel(&self) -> &Path {
        &self.rel
    }

    pub fn fs_path(&self) -> &Path {
        &self.fs_path
    }

    pub fn script_alias(&self) -> bool {
        self.script_alias
    }

    pub fn layers(&self) -> &[AccessLayer] {
        &self.layers
    }

    /// Evaluate the complete configuration/access-file scope for this plan.
    /// The returned conditionals are not yet applied so dispatch can insert
    /// rewrite `[E=...]` effects first.
    pub fn evaluate_scope(
        &self,
        cfg: &Config,
        vhost: Option<&VHost>,
        req: &Request,
        peer: std::net::IpAddr,
    ) -> EvaluatedScope {
        if cfg.htaccess_may_apply(&self.fs_path) {
            let (scope, config_conditionals, access_conditionals) =
                crate::policy_ref::effective_scope_with_layers(
                    cfg,
                    vhost,
                    &self.fs_path,
                    &self.target.url_path,
                    req,
                    peer,
                    &self.layers,
                );
            EvaluatedScope {
                scope,
                config_conditionals: Arc::new(config_conditionals),
                access_conditionals: Arc::new(access_conditionals),
            }
        } else {
            let (scope, conditionals) = cfg.effective_scope_req_cached(
                vhost,
                &self.fs_path,
                &self.target.url_path,
                req,
                peer,
            );
            EvaluatedScope {
                scope,
                config_conditionals: conditionals,
                access_conditionals: Arc::new(Vec::new()),
            }
        }
    }

    /// Evaluate and apply every conditional phase.  Cache policy needs the
    /// final scope, while dispatch needs `evaluate_scope()` so it can insert
    /// rewrite effects before this call.
    pub fn effective_scope(
        &self,
        cfg: &Config,
        vhost: Option<&VHost>,
        req: &Request,
        peer: std::net::IpAddr,
    ) -> Scope {
        let mut evaluated = self.evaluate_scope(cfg, vhost, req, peer);
        evaluated.apply_conditionals(cfg, vhost, &self.fs_path, &self.target.url_path, req, peer);
        evaluated.scope
    }
}

#[derive(Debug)]
pub struct EvaluatedScope {
    pub scope: Scope,
    pub config_conditionals: Arc<Vec<ScopeRule>>,
    pub access_conditionals: Arc<Vec<ScopeRule>>,
}

impl EvaluatedScope {
    pub fn apply_conditionals(
        &mut self,
        cfg: &Config,
        vhost: Option<&VHost>,
        fs_path: &Path,
        url_path: &str,
        req: &Request,
        peer: std::net::IpAddr,
    ) {
        apply_conditionals(
            cfg,
            vhost,
            &mut self.scope,
            &self.config_conditionals,
            &self.access_conditionals,
            fs_path,
            url_path,
            req,
            peer,
        );
    }
}

/// Apply configuration and access-file conditional rules in one place.
#[allow(clippy::too_many_arguments)]
pub fn apply_conditionals(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &mut Scope,
    config_conditionals: &[ScopeRule],
    access_conditionals: &[ScopeRule],
    fs_path: &Path,
    url_path: &str,
    req: &Request,
    peer: std::net::IpAddr,
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
        access_conditionals,
        req,
        peer,
        &docroot,
        fs_path,
        url_path,
        &fname,
        &mut state,
    );
}

/// Error union used by the initial dispatch/cache plan construction.
#[derive(Debug)]
pub enum CanonicalErrorOrPlan {
    Canonical(CanonicalError),
    Plan(PlanError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_target_is_query_free_decoded_and_normalized() {
        let target = CanonicalTarget::from_raw_path(b"/%2eenv", false).unwrap();
        assert_eq!(target.url_path, "/.env");

        let target = CanonicalTarget::from_raw_path(b"/api/%2e%2e/secret", false).unwrap();
        assert_eq!(target.url_path, "/secret");
        assert_eq!(target.norm, b"/secret");

        let target = CanonicalTarget::from_raw_path(b"/dir/", false).unwrap();
        assert_eq!(target.url_path, "/dir/");
        assert_eq!(target.norm, b"/dir");
    }

    #[test]
    fn canonical_errors_are_fail_closed() {
        assert_eq!(CanonicalError::Decode.status(), 404);
        assert_eq!(CanonicalError::Normalize.status(), 400);
        assert!(CanonicalTarget::from_raw_path(b"relative", false).is_err());
        assert!(CanonicalTarget::from_raw_path(b"/%zz", false).is_err());
        assert!(CanonicalTarget::from_url_path("relative").is_none());
        let identity =
            LayerIdentity::with_url_mount(Path::new("/srv/www"), Path::new("/srv/www"), "sub");
        assert_eq!(identity.url_mount, "/sub/");
        assert_eq!(identity.mapping_root, Path::new("/srv/www"));
    }

    #[test]
    fn layer_subject_is_filesystem_relative_for_all_mapping_shapes() {
        assert_eq!(
            layer_subject(
                Path::new("/srv/www"),
                Path::new("/srv/www/wallet/public/.env"),
                "/wallet/.env"
            )
            .as_deref(),
            Some("wallet/public/.env")
        );
        assert_eq!(
            layer_subject(
                Path::new("/srv/www"),
                Path::new("/srv/www/wallet/public/private"),
                "/wallet/private/"
            )
            .as_deref(),
            Some("wallet/public/private/")
        );
        assert_eq!(
            layer_subject(
                Path::new("/srv/storage"),
                Path::new("/srv/storage/current/public/private/wallet.dat"),
                "/wallet/private/wallet.dat"
            )
            .as_deref(),
            Some("current/public/private/wallet.dat")
        );
        assert!(
            layer_subject(Path::new("/srv/www"), Path::new("/other/wallet"), "/wallet").is_none()
        );
    }

    fn load_config(text: &str) -> Config {
        let dir = std::env::temp_dir().join(format!(
            "vapache-plan-{}-{}",
            std::process::id(),
            text.len()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("httpd.conf");
        std::fs::write(&path, text).unwrap();
        Config::load(
            &path,
            &dir,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            false,
        )
        .unwrap_or_else(|errors| panic!("{errors:?}"))
    }

    #[test]
    fn fs_target_outside_mapping_root_keeps_explicit_path() {
        let cfg = load_config("Listen 127.0.0.1:0\n");
        let target = CanonicalTarget::from_url_path("/x").unwrap();
        let plan = RequestPlan::from_fs_target(
            &cfg,
            None,
            target,
            PathBuf::from("/srv/www"),
            PathBuf::from("/tmp/vapache-plan-outside/file.txt"),
            false,
        )
        .unwrap();
        assert_eq!(
            plan.fs_path(),
            Path::new("/tmp/vapache-plan-outside/file.txt")
        );
        assert_eq!(plan.rel(), Path::new("file.txt"));
        assert!(plan.layers().is_empty());
    }

    #[test]
    fn layer_url_mount_handles_alias_root_ancestor_and_depth_fallback() {
        assert_eq!(
            layer_url_mount(
                Path::new("/srv/site"),
                Path::new("/srv/site"),
                Path::new("/srv/site/private/wallet.dat"),
                "/site/private/wallet.dat"
            ),
            "/site/"
        );
        assert_eq!(
            layer_url_mount(
                Path::new("/srv/site/private"),
                Path::new("/srv/site/private"),
                Path::new("/srv/site/private/wallet.dat"),
                "/site/private/wallet.dat"
            ),
            "/site/private/"
        );
        assert_eq!(
            layer_url_mount(
                Path::new("/srv/www/wallet/public"),
                Path::new("/srv/www"),
                Path::new("/srv/www/wallet/public/.env"),
                "/wallet/.env"
            ),
            "/srv/www/"
        );
        assert_eq!(
            layer_url_mount(
                Path::new("/srv/site"),
                Path::new("/srv/site"),
                Path::new("/srv/site/sub1/sub2/file"),
                "/m/file"
            ),
            "/srv/site/"
        );
    }
}
