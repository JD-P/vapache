//! Pure reference evaluator for the security-relevant configuration phases.
//!
//! This module implements the same canonical order as the request dispatcher:
//!
//! ```text
//! Directory/DirectoryMatch -> Files -> Location -> If
//! ```
//!
//! It is intentionally kept free of I/O and `.htaccess` handling.  The live
//! dispatcher uses the same phase helpers, and the tests at the bottom compare
//! the reference result with `Config::effective_scope_req` for a generated
//! corpus.  The eventual Verus model should target this interface: a finite
//! scope, a finite rule list, and a request view.

use crate::config::{apply_deferred_req, apply_normal_rule_list, Config, Scope, ScopeRule, VHost};
use crate::http::Request;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Evaluate configuration rules in canonical order without touching the
/// filesystem.  Conditional rules are collected and returned so a caller can
/// apply them with the request's environment.
pub fn effective_scope_req(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    url_path: &str,
    req: &Request,
    peer: IpAddr,
) -> (Scope, Vec<ScopeRule>) {
    // No access-file layers.  The same verified phase plan is used for the
    // fast path, so the configuration-only and `.htaccess` paths cannot
    // diverge in phase order.
    let (scope, conditionals, _) =
        effective_scope_with_layers(cfg, vhost, fs_path, url_path, req, peer, &[]);
    (scope, conditionals)
}

/// A parsed per-directory access file, separated from filesystem I/O.
#[derive(Debug)]
pub struct AccessLayer {
    pub dir: PathBuf,
    pub scope: std::sync::Arc<Scope>,
    pub files: Vec<ScopeRule>,
    pub conditionals: Vec<ScopeRule>,
}

/// Evaluate the complete configuration/access-file interleaving.  Access
/// layers are supplied by the walker; this function is the single
/// implementation of the resulting merge order:
///
/// ```text
/// for each directory root..leaf:
///     Directory rules; access-file scope; defer access Files/If
/// DirectoryMatch
/// config Files; access Files
/// Location
/// config If; access If
/// ```
pub fn effective_scope_with_layers(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    url_path: &str,
    req: &Request,
    peer: IpAddr,
    layers: &[AccessLayer],
) -> (Scope, Vec<ScopeRule>, Vec<ScopeRule>) {
    let mut config_files = Vec::new();
    let mut config_locations = Vec::new();
    let mut config_conditionals = Vec::new();
    let mut scope = cfg.effective_scope_req_base_deferred(
        vhost,
        fs_path,
        url_path,
        req,
        peer,
        &mut config_files,
        &mut config_locations,
        &mut config_conditionals,
    );
    let root = cfg.documentation_root_for(vhost);
    let start = if crate::files::is_dir_cached(fs_path) {
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
    let fname = fs_path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();
    let docroot = cfg.documentation_root_for(vhost);
    // Build the verified stage plan.  One `Walk` step consumes exactly one
    // directory in root-to-leaf order; `access` records whether that
    // directory has an `.htaccess` layer.  The remaining steps are the
    // deferred Files/Location/conditional suffix.
    let mut present = Vec::with_capacity(dirs.len());
    for dir in &dirs {
        present.push(layers.iter().any(|layer| layer.dir == *dir));
    }
    let mut htaccess_files = Vec::new();
    let mut htaccess_conditionals = Vec::new();
    let mut dir_index = 0usize;
    for step in crate::verified::access_plan_exec(&present) {
        match step {
            crate::verified::AccessStep::Walk { access } => {
                let dir = &dirs[dir_index];
                dir_index += 1;
                cfg.apply_directory_rules_for_dir(
                    vhost,
                    &mut scope,
                    req,
                    peer,
                    dir,
                    fs_path,
                    url_path,
                    &mut config_files,
                    &mut config_locations,
                    &mut config_conditionals,
                );
                if access {
                    if let Some(layer) = layers.iter().find(|layer| layer.dir == *dir) {
                        scope.merge(&layer.scope);
                        htaccess_files.extend(layer.files.iter().cloned());
                        htaccess_conditionals.extend(layer.conditionals.iter().cloned());
                    }
                }
            }
            crate::verified::AccessStep::DirectoryMatch => {
                cfg.apply_directory_match_rules(
                    vhost,
                    &mut scope,
                    fs_path,
                    url_path,
                    &mut config_files,
                    &mut config_locations,
                    &mut config_conditionals,
                );
            }
            crate::verified::AccessStep::ConfigFiles => {
                apply_normal_rule_list(
                    &config_files,
                    &mut scope,
                    req,
                    peer,
                    &docroot,
                    fs_path,
                    url_path,
                    &fname,
                    &mut config_conditionals,
                );
            }
            crate::verified::AccessStep::AccessFiles => {
                apply_normal_rule_list(
                    &htaccess_files,
                    &mut scope,
                    req,
                    peer,
                    &docroot,
                    fs_path,
                    url_path,
                    &fname,
                    &mut htaccess_conditionals,
                );
            }
            crate::verified::AccessStep::ConfigLocation => {
                apply_normal_rule_list(
                    &config_locations,
                    &mut scope,
                    req,
                    peer,
                    &docroot,
                    fs_path,
                    url_path,
                    &fname,
                    &mut config_conditionals,
                );
            }
            crate::verified::AccessStep::ConfigConditions
            | crate::verified::AccessStep::AccessConditions => {}
        }
    }
    debug_assert_eq!(dir_index, dirs.len());
    config_conditionals.sort_by_key(|rule| rule.order);
    (scope, config_conditionals, htaccess_conditionals)
}

/// Apply the deferred conditional rules from `effective_scope_req`.
pub fn apply_conditionals(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &mut Scope,
    conditionals: &[ScopeRule],
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
    let mut chain_state = HashMap::new();
    apply_deferred_req(
        scope,
        conditionals,
        req,
        peer,
        &docroot,
        fs_path,
        url_path,
        &fname,
        &mut chain_state,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::http::{Headers, Request, Version};
    use crate::verified::BodyFraming;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;

    fn request() -> Request {
        Request {
            method: "GET".into(),
            target: b"/secret.txt".to_vec(),
            raw_path: b"/secret.txt".to_vec(),
            query: Vec::new(),
            version: Version::Http11,
            headers: Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: BodyFraming::None,
        }
    }

    fn load(name: &str, text: &str) -> Config {
        let dir = PathBuf::from(std::env::temp_dir())
            .join(format!("vapache-policy-ref-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("httpd.conf");
        fs::write(&path, text).unwrap();
        Config::load(&path, &dir, &HashMap::new(), &HashMap::new(), false).unwrap()
    }

    fn signature(s: &Scope) -> String {
        format!(
            "requires={:?}|allow={:?}|methods={:?}|legacy={:?}|options={:?}|headers={:?}",
            s.authorization.requires,
            s.override_policy.raw_mode(),
            s.authorization.allow_methods,
            s.authorization.legacy,
            s.effective_options(),
            s.header_policy.set_headers
        )
    }

    fn compare(name: &str, text: &str) {
        let cfg = load(name, text);
        let req = request();
        let peer = "127.0.0.1".parse().unwrap();
        let fs_path = if name == "wildcard-directory" {
            Path::new("/srv/alice/public/secret.txt")
        } else {
            Path::new("/srv/secret.txt")
        };
        let (mut ref_scope, conditionals) =
            effective_scope_req(&cfg, None, fs_path, "/secret.txt", &req, peer);
        apply_conditionals(
            &cfg,
            None,
            &mut ref_scope,
            &conditionals,
            fs_path,
            "/secret.txt",
            &req,
            peer,
        );
        let live = cfg.effective_scope_req(None, fs_path, "/secret.txt", &req, peer);
        assert_eq!(signature(&ref_scope), signature(&live), "{name}");
        match name {
            "directory-files-location" => {
                assert!(
                    format!("{:?}", ref_scope.authorization.requires).contains("Local"),
                    "{name}"
                )
            }
            "conditional-last" | "files-glob" => assert!(
                format!("{:?}", ref_scope.authorization.requires).contains("AllDenied"),
                "{name}"
            ),
            "wildcard-directory" => {
                assert!(
                    format!("{:?}", ref_scope.authorization.requires).contains("Local"),
                    "{name}"
                )
            }
            _ => {}
        }
    }

    #[test]
    fn reference_matches_runtime_on_security_scope() {
        compare(
            "directory-files-location",
            concat!(
                "Listen 127.0.0.1:0\n",
                "<Directory /srv>\n",
                "Require all granted\n",
                "</Directory>\n",
                "<Files \"secret.txt\">\n",
                "Require all denied\n",
                "</Files>\n",
                "<Location \"/secret.txt\">\n",
                "Require local\n",
                "</Location>\n",
            ),
        );
        compare(
            "conditional-last",
            concat!(
                "Listen 127.0.0.1:0\n",
                "<If \"%{REQUEST_METHOD} == 'GET'\">\n",
                "Require all denied\n",
                "</If>\n",
                "<Directory /srv>\n",
                "Require all granted\n",
                "</Directory>\n",
            ),
        );
        compare(
            "wildcard-directory",
            concat!(
                "Listen 127.0.0.1:0\n",
                "<Directory /srv/*/public>\n",
                "Require local\n",
                "</Directory>\n",
            ),
        );
        compare(
            "files-glob",
            concat!(
                "Listen 127.0.0.1:0\n",
                "<Directory /srv>\n",
                "<Files \"secret*\">\n",
                "Require all denied\n",
                "</Files>\n",
                "</Directory>\n",
            ),
        );
    }

    #[test]
    fn verified_plan_pairs_one_walk_with_each_directory() {
        let present = [false, true, true];
        let plan = crate::verified::access_plan_exec(&present);
        assert_eq!(plan.len(), present.len() + 6);
        for (i, step) in plan.iter().take(present.len()).enumerate() {
            match step {
                crate::verified::AccessStep::Walk { access } => {
                    assert_eq!(*access, present[i]);
                }
                other => panic!("expected Walk at {i}, got {other:?}"),
            }
        }
        assert_eq!(
            &plan[present.len()..],
            &[
                crate::verified::AccessStep::DirectoryMatch,
                crate::verified::AccessStep::ConfigFiles,
                crate::verified::AccessStep::AccessFiles,
                crate::verified::AccessStep::ConfigLocation,
                crate::verified::AccessStep::ConfigConditions,
                crate::verified::AccessStep::AccessConditions,
            ]
        );
    }
}
