//! Pure policy data intended to become the verified configuration core.
//!
//! This first migration moves `Options` out of the ad-hoc `Scope` vector into
//! an explicit policy object.  The representation is deliberately small and
//! algebraic: a sequence of `(Set|Add|Remove, option-bits)` operations.  The
//! evaluation step is already supplied by the verified `options_apply`
//! primitive.  Later migrations can move override and authorization policy
//! into the same module without changing the merge boundary.

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OptionsPolicy {
    changes: Vec<(u8, u32)>,
}

impl OptionsPolicy {
    /// Apache operation codes: 0 = set, 1 = add, 2 = remove.
    pub fn push(&mut self, op: u8, bits: u32) {
        if op == 0 {
            self.changes.clear();
        }
        self.changes.push((op, bits));
    }

    pub fn push_set(&mut self, bits: u32) {
        self.push(0, bits);
    }

    pub fn push_add(&mut self, bits: u32) {
        self.push(1, bits);
    }

    pub fn push_remove(&mut self, bits: u32) {
        self.push(2, bits);
    }

    /// Merge a child policy: child changes run after the inherited sequence,
    /// and a child `Set` resets the inherited sequence exactly as the previous
    /// `Scope::merge` loop did.
    pub fn merge_child(&mut self, child: &OptionsPolicy) {
        for &(op, bits) in &child.changes {
            self.push(op, bits);
        }
    }

    pub fn changes(&self) -> &[(u8, u32)] {
        &self.changes
    }

    /// Evaluate from the caller-supplied Apache default bits.
    pub fn effective_bits(&self, base: u32) -> u32 {
        let mut bits = base;
        for &(op, value) in &self.changes {
            bits = crate::verified::options_apply(bits, op, value);
        }
        bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_add_remove_are_ordered_and_set_resets() {
        let mut p = OptionsPolicy::default();
        p.push_add(0b10);
        p.push_add(0b100);
        p.push_set(0b1);
        assert_eq!(p.effective_bits(0b1), 0b1);
        p.push_remove(0b1);
        assert_eq!(p.effective_bits(0b1), 0);
    }

    #[test]
    fn child_set_resets_parent_history() {
        let mut parent = OptionsPolicy::default();
        parent.push_add(0b10);
        let mut child = OptionsPolicy::default();
        child.push_set(0b100);
        parent.merge_child(&child);
        assert_eq!(parent.effective_bits(0b1), 0b100);
    }
}

/// Override policy is the next migrated security slice.  It stores exactly
/// the three inherited values used by `.htaccess` gating, with child presence
/// preserving Apache's merge rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OverridePolicy {
    mode: Option<crate::config::OverrideMode>,
    allow_list: Option<Vec<String>>,
    nonfatal: Option<crate::config::NonfatalMode>,
}

impl OverridePolicy {
    pub fn set_mode(&mut self, mode: crate::config::OverrideMode) {
        self.mode = Some(mode);
    }

    pub fn set_allow_list(&mut self, list: Vec<String>) {
        self.allow_list = Some(list);
    }

    pub fn set_nonfatal(&mut self, nonfatal: crate::config::NonfatalMode) {
        self.nonfatal = Some(nonfatal);
    }

    pub fn raw_mode(&self) -> Option<crate::config::OverrideMode> {
        self.mode
    }

    pub fn mode(&self) -> crate::config::OverrideMode {
        self.mode.unwrap_or(crate::config::OverrideMode::None)
    }

    pub fn raw_allow_list(&self) -> Option<&[String]> {
        self.allow_list.as_deref()
    }

    pub fn allow_list(&self) -> &[String] {
        self.allow_list.as_deref().unwrap_or(&[])
    }

    pub fn raw_nonfatal(&self) -> Option<crate::config::NonfatalMode> {
        self.nonfatal
    }

    pub fn nonfatal(&self) -> crate::config::NonfatalMode {
        self.nonfatal.unwrap_or(crate::config::NonfatalMode::None)
    }

    pub fn is_enabled(&self) -> bool {
        self.mode().is_enabled() || !self.allow_list().is_empty()
    }

    pub fn merge_child(&mut self, child: &OverridePolicy) {
        if child.mode.is_some() {
            self.mode = child.mode;
        }
        if child.allow_list.is_some() {
            self.allow_list = child.allow_list.clone();
        }
        if child.nonfatal.is_some() {
            self.nonfatal = child.nonfatal;
        }
    }
}

#[cfg(test)]
mod override_tests {
    use super::*;
    use crate::config::{NonfatalMode, OverrideCategories, OverrideMode};

    #[test]
    fn child_presence_wins_for_override_fields() {
        let mut parent = OverridePolicy::default();
        parent.set_mode(OverrideMode::All);
        parent.set_allow_list(vec!["Require".into()]);
        parent.set_nonfatal(NonfatalMode::None);
        let mut child = OverridePolicy::default();
        child.set_mode(OverrideMode::Categories(OverrideCategories(
            OverrideCategories::AUTH_CONFIG,
        )));
        child.set_nonfatal(NonfatalMode::All);
        parent.merge_child(&child);
        assert_eq!(
            parent.raw_mode(),
            Some(OverrideMode::Categories(OverrideCategories(
                OverrideCategories::AUTH_CONFIG
            )))
        );
        assert_eq!(parent.raw_allow_list(), Some(&["Require".to_string()][..]));
        assert_eq!(parent.raw_nonfatal(), Some(NonfatalMode::All));
    }
}

/// Authorization policy for a scope.  This moves the inherited security
/// decision state out of `Scope` while preserving the exact merge rules:
/// `Require` child policy combines according to the child's `AuthMerging`,
/// `AllowMethods` and legacy access are child-presence fields.
#[derive(Debug, Clone, Default)]
pub struct AuthorizationPolicy {
    pub requires: Option<crate::config::AuthPolicy>,
    pub auth_merging: Option<crate::config::AuthMerging>,
    pub allow_methods: Option<crate::config::AllowMethods>,
    pub legacy: Option<crate::config::LegacyAccess>,
    pub auth_type: Option<String>,
    pub auth_name: Option<String>,
    pub auth_user_file: Option<std::path::PathBuf>,
    pub auth_group_file: Option<std::path::PathBuf>,
}

impl AuthorizationPolicy {
    pub fn add_require(
        &mut self,
        node: crate::config::RequireNode,
        limit: Option<&crate::config::MethodSet>,
    ) {
        let entry = crate::config::RequireEntry {
            node,
            limit: limit.cloned(),
        };
        self.requires = Some(match self.requires.take() {
            None => crate::config::AuthPolicy::List(vec![entry]),
            Some(crate::config::AuthPolicy::List(mut entries)) => {
                entries.push(entry);
                crate::config::AuthPolicy::List(entries)
            }
            Some(policy) => crate::config::AuthPolicy::Or(
                Box::new(policy),
                Box::new(crate::config::AuthPolicy::List(vec![entry])),
            ),
        });
    }

    pub fn method_allowed(&self, method: &str) -> bool {
        self.allow_methods
            .as_ref()
            .map(|allowed| allowed.allows(method))
            .unwrap_or(true)
    }

    pub fn allow_methods_header(&self) -> Option<String> {
        self.allow_methods
            .as_ref()
            .map(crate::config::AllowMethods::header)
    }

    pub fn legacy_mut(&mut self) -> &mut crate::config::LegacyAccess {
        self.legacy
            .get_or_insert_with(crate::config::LegacyAccess::default)
    }

    pub fn merge_child(&mut self, child: &AuthorizationPolicy) {
        if let Some(r) = &child.requires {
            let kind = crate::verified::auth_merge_kind(
                child.auth_merging == Some(crate::config::AuthMerging::And),
                child.auth_merging == Some(crate::config::AuthMerging::Or),
                self.requires.is_some(),
            );
            self.requires = Some(match kind {
                crate::verified::AuthMergeKind::And => {
                    let base = self.requires.take().expect("checked by auth_merge_kind");
                    crate::config::AuthPolicy::And(Box::new(base), Box::new(r.clone()))
                }
                crate::verified::AuthMergeKind::Or => {
                    let base = self.requires.take().expect("checked by auth_merge_kind");
                    crate::config::AuthPolicy::Or(Box::new(base), Box::new(r.clone()))
                }
                crate::verified::AuthMergeKind::Replace => r.clone(),
            });
        }
        if child.allow_methods.is_some() {
            self.allow_methods = child.allow_methods.clone();
        }
        if child.legacy.is_some() {
            self.legacy = child.legacy.clone();
        }
        if child.auth_type.is_some() {
            self.auth_type = child.auth_type.clone();
        }
        if child.auth_name.is_some() {
            self.auth_name = child.auth_name.clone();
        }
        if child.auth_user_file.is_some() {
            self.auth_user_file = child.auth_user_file.clone();
        }
        if child.auth_group_file.is_some() {
            self.auth_group_file = child.auth_group_file.clone();
        }
        // `auth_merging` is local to the section that declares it; it is not
        // inherited by later siblings.
    }
}

#[cfg(test)]
mod authorization_tests {
    use super::*;
    use crate::config::{AuthMerging, AuthPolicy, MethodSet, Require, RequireEntry, RequireNode};

    fn entry() -> RequireEntry {
        RequireEntry {
            node: RequireNode::Provider(Require::AllGranted),
            limit: None,
        }
    }

    #[test]
    fn auth_merging_uses_verified_three_way_decision() {
        let mut parent = AuthorizationPolicy {
            requires: Some(AuthPolicy::List(vec![entry()])),
            ..AuthorizationPolicy::default()
        };
        let child = AuthorizationPolicy {
            requires: Some(AuthPolicy::List(vec![entry()])),
            auth_merging: Some(AuthMerging::And),
            ..AuthorizationPolicy::default()
        };
        parent.merge_child(&child);
        assert!(matches!(parent.requires, Some(AuthPolicy::And(_, _))));
    }

    #[test]
    fn methods_and_legacy_merge_by_child_presence() {
        let mut parent = AuthorizationPolicy::default();
        parent.allow_methods = Some(crate::config::AllowMethods::Reset);
        let child = AuthorizationPolicy {
            allow_methods: Some(crate::config::AllowMethods::Only(vec!["GET".into()])),
            ..AuthorizationPolicy::default()
        };
        parent.merge_child(&child);
        assert_eq!(
            parent.allow_methods,
            Some(crate::config::AllowMethods::Only(vec!["GET".into()]))
        );
    }
}

/// Response-header and expiration policy for a scope.  This slice keeps the
/// append/child-presence rules explicit while moving the fields out of the
/// monolithic `Scope` struct.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderPolicy {
    pub add_headers: Vec<(String, String)>,
    pub set_headers: Vec<(String, String)>,
    pub unset_headers: Vec<String>,
    /// `Header always ...`: these also apply to error responses.
    pub always_add_headers: Vec<(String, String)>,
    pub always_set_headers: Vec<(String, String)>,
    pub always_unset_headers: Vec<String>,
    pub expires_active: Option<bool>,
    pub expires_default: Option<String>,
    pub expires_by_type: Vec<(String, String)>,
    pub cookies: Vec<String>,
    pub vary: Vec<String>,
}

fn merge_set_headers(parent: &mut Vec<(String, String)>, child: &[(String, String)]) {
    for (name, value) in child {
        // A child `Header set` replaces an inherited value with the same name
        // instead of emitting a duplicate field line.
        parent.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        parent.push((name.clone(), value.clone()));
    }
}

impl HeaderPolicy {
    pub fn merge_child(&mut self, child: &HeaderPolicy) {
        crate::verified::append_vec(&mut self.add_headers, &child.add_headers);
        merge_set_headers(&mut self.set_headers, &child.set_headers);
        crate::verified::append_vec(&mut self.unset_headers, &child.unset_headers);
        crate::verified::append_vec(&mut self.always_add_headers, &child.always_add_headers);
        merge_set_headers(&mut self.always_set_headers, &child.always_set_headers);
        crate::verified::append_vec(&mut self.always_unset_headers, &child.always_unset_headers);
        if child.expires_active.is_some() {
            self.expires_active = child.expires_active;
        }
        if child.expires_default.is_some() {
            self.expires_default = child.expires_default.clone();
        }
        crate::verified::append_vec(&mut self.expires_by_type, &child.expires_by_type);
        crate::verified::append_vec(&mut self.cookies, &child.cookies);
        crate::verified::append_vec(&mut self.vary, &child.vary);
    }

    /// Apply configured response headers in Apache order: set/add first, then
    /// unset removes any field with that name.  `include_onsuccess` is false
    /// for error responses, where only `Header always` applies.
    pub fn apply(
        &self,
        headers: &mut Vec<(std::borrow::Cow<'static, str>, Vec<u8>)>,
        include_onsuccess: bool,
    ) {
        let mut unset: Vec<&str> = self
            .always_unset_headers
            .iter()
            .map(String::as_str)
            .collect();
        let mut set: Vec<&(String, String)> = self.always_set_headers.iter().collect();
        let mut add: Vec<&(String, String)> = self.always_add_headers.iter().collect();
        if include_onsuccess {
            unset.extend(self.unset_headers.iter().map(String::as_str));
            set.extend(self.set_headers.iter());
            add.extend(self.add_headers.iter());
        }
        for (name, value) in set {
            headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
            headers.push((
                std::borrow::Cow::Owned(name.clone()),
                value.as_bytes().to_vec(),
            ));
        }
        for (name, value) in add {
            headers.push((
                std::borrow::Cow::Owned(name.clone()),
                value.as_bytes().to_vec(),
            ));
        }
        for name in unset {
            headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        }
    }
}

#[cfg(test)]
mod header_tests {
    use super::*;

    #[test]
    fn child_set_replaces_and_unset_removes_inherited_headers() {
        let mut parent = HeaderPolicy::default();
        parent.set_headers.push(("X-Set".into(), "one".into()));
        parent.unset_headers.push("X-Old".into());
        let mut child = HeaderPolicy::default();
        child.set_headers.push(("X-Set".into(), "two".into()));
        parent.merge_child(&child);
        assert_eq!(parent.set_headers, vec![("X-Set".into(), "two".into())]);
        let mut headers = vec![
            (std::borrow::Cow::Borrowed("X-Old"), b"leak".to_vec()),
            (std::borrow::Cow::Borrowed("X-Set"), b"one".to_vec()),
        ];
        parent.apply(&mut headers, true);
        assert!(!headers.iter().any(|(n, _)| n == "X-Old"));
        assert_eq!(
            headers
                .iter()
                .filter(|(n, _)| n == "X-Set")
                .map(|(_, v)| v.as_slice())
                .collect::<Vec<_>>(),
            vec![b"two".as_slice()]
        );
    }

    #[test]
    fn header_lists_append_and_scalars_child_win() {
        let mut parent = HeaderPolicy::default();
        parent.set_headers.push(("X-A".into(), "1".into()));
        parent.expires_active = Some(false);
        parent
            .expires_by_type
            .push(("text/html".into(), "1 hour".into()));
        let mut child = HeaderPolicy::default();
        child.add_headers.push(("X-B".into(), "2".into()));
        child.expires_active = Some(true);
        child
            .expires_by_type
            .push(("image/png".into(), "2 hours".into()));
        parent.merge_child(&child);
        assert_eq!(parent.set_headers, vec![("X-A".into(), "1".into())]);
        assert_eq!(parent.add_headers, vec![("X-B".into(), "2".into())]);
        assert_eq!(parent.expires_active, Some(true));
        assert_eq!(parent.expires_by_type.len(), 2);
    }
}

/// Environment/SetEnv policy.  All four fields are append-only; child entries
/// retain order after the inherited entries.
#[derive(Debug, Clone, Default)]
pub struct EnvironmentPolicy {
    pub set_env: Vec<(String, String)>,
    pub unset_env: Vec<String>,
    pub pass_env: Vec<String>,
    pub set_env_if: Vec<crate::config::EnvRule>,
}

impl EnvironmentPolicy {
    pub fn merge_child(&mut self, child: &EnvironmentPolicy) {
        crate::verified::append_vec(&mut self.set_env, &child.set_env);
        crate::verified::append_vec(&mut self.unset_env, &child.unset_env);
        crate::verified::append_vec(&mut self.pass_env, &child.pass_env);
        crate::verified::append_vec(&mut self.set_env_if, &child.set_env_if);
    }
}

#[cfg(test)]
mod environment_tests {
    use super::*;

    #[test]
    fn environment_lists_append_in_order() {
        let mut parent = EnvironmentPolicy::default();
        parent.set_env.push(("A".into(), "1".into()));
        let mut child = EnvironmentPolicy::default();
        child.set_env.push(("B".into(), "2".into()));
        child.unset_env.push("OLD".into());
        parent.merge_child(&child);
        assert_eq!(
            parent.set_env,
            vec![("A".into(), "1".into()), ("B".into(), "2".into())]
        );
        assert_eq!(parent.unset_env, vec!["OLD".to_string()]);
    }
}

/// Content/MIME and directory-response policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentPolicy {
    pub document_root: Option<std::path::PathBuf>,
    pub directory_index: Option<Vec<String>>,
    pub index_ignore: Vec<String>,
    pub default_charset: Option<String>,
    pub file_etag: Option<u32>,
    pub enable_sendfile: Option<bool>,
    pub directory_slash: Option<bool>,
    pub add_types: Vec<(String, String)>,
    pub remove_types: Vec<String>,
    pub force_type: Option<String>,
    pub access_file_names: Option<Vec<String>>,
}

impl ContentPolicy {
    pub fn merge_child(&mut self, child: &ContentPolicy) {
        if child.document_root.is_some() {
            self.document_root = child.document_root.clone();
        }
        if child.directory_index.is_some() {
            self.directory_index = child.directory_index.clone();
        }
        crate::verified::append_vec(&mut self.index_ignore, &child.index_ignore);
        if child.default_charset.is_some() {
            self.default_charset = child.default_charset.clone();
        }
        if child.file_etag.is_some() {
            self.file_etag = child.file_etag;
        }
        if child.enable_sendfile.is_some() {
            self.enable_sendfile = child.enable_sendfile;
        }
        if child.directory_slash.is_some() {
            self.directory_slash = child.directory_slash;
        }
        crate::verified::append_vec(&mut self.add_types, &child.add_types);
        crate::verified::append_vec(&mut self.remove_types, &child.remove_types);
        if child.force_type.is_some() {
            self.force_type = child.force_type.clone();
        }
        if child.access_file_names.is_some() {
            self.access_file_names = child.access_file_names.clone();
        }
    }
}

/// Alias/redirect/handler and unsupported-filter policy.
#[derive(Debug, Clone, Default)]
pub struct MappingPolicy {
    pub aliases: Vec<crate::config::Alias>,
    pub redirects: Vec<crate::config::Redirect>,
    pub handlers: Vec<crate::config::Handler>,
    pub unsupported_filters: Vec<String>,
}

impl MappingPolicy {
    pub fn merge_child(&mut self, child: &MappingPolicy) {
        crate::verified::append_vec(&mut self.aliases, &child.aliases);
        crate::verified::append_vec(&mut self.redirects, &child.redirects);
        crate::verified::append_vec(&mut self.handlers, &child.handlers);
        crate::verified::append_vec(&mut self.unsupported_filters, &child.unsupported_filters);
    }
}

#[cfg(test)]
mod content_mapping_tests {
    use super::*;

    #[test]
    fn content_options_child_override_and_types_append() {
        let mut parent = ContentPolicy::default();
        parent.add_types.push(("a".into(), ".a".into()));
        parent.file_etag = Some(1);
        let mut child = ContentPolicy::default();
        child.add_types.push(("b".into(), ".b".into()));
        child.file_etag = Some(2);
        child.directory_index = Some(vec!["index.html".into()]);
        parent.merge_child(&child);
        assert_eq!(parent.add_types.len(), 2);
        assert_eq!(parent.file_etag, Some(2));
        assert_eq!(
            parent.directory_index.as_deref(),
            Some(&["index.html".to_string()][..])
        );
    }

    #[test]
    fn mapping_lists_append_in_order() {
        let mut parent = MappingPolicy::default();
        parent.handlers.push(crate::config::Handler::add(
            ".php".into(),
            "php-script".into(),
        ));
        let mut child = MappingPolicy::default();
        child.handlers.push(crate::config::Handler::add(
            ".cgi".into(),
            "cgi-script".into(),
        ));
        child.unsupported_filters.push("INCLUDES".into());
        parent.merge_child(&child);
        assert_eq!(parent.handlers.len(), 2);
        assert_eq!(parent.unsupported_filters, vec!["INCLUDES".to_string()]);
    }
}

/// `ErrorDocument` policy: parent entries first, child entries appended;
/// lookup scans in reverse so child status codes win.
#[derive(Debug, Clone, Default)]
pub struct ErrorDocumentPolicy {
    pub documents: Vec<(u16, crate::config::ErrorDoc)>,
}

impl ErrorDocumentPolicy {
    pub fn push(&mut self, code: u16, doc: crate::config::ErrorDoc) {
        self.documents.push((code, doc));
    }

    pub fn get(&self, status: u16) -> Option<&crate::config::ErrorDoc> {
        self.documents
            .iter()
            .rev()
            .find(|(code, _)| *code == status)
            .map(|(_, doc)| doc)
    }

    pub fn merge_child(&mut self, child: &ErrorDocumentPolicy) {
        crate::verified::append_vec(&mut self.documents, &child.documents);
    }
}

/// Rewrite/cache policy.  `pending_rewrite_conds` is parser-local and is never
/// inherited; the remaining fields follow the existing child-wins/append rules.
#[derive(Debug, Clone, Default)]
pub struct RewriteCachePolicy {
    pub rewrite_engine: Option<bool>,
    pub rewrite_maps: Vec<(String, crate::config::RewriteMap)>,
    pub cache_enable: Vec<(String, String)>,
    pub cache_disable: Vec<String>,
    pub rewrite_inherit: Option<bool>,
    pub rewrite_base: Option<String>,
    pub rewrite_match_base: Option<String>,
    pub rewrite_rules: Vec<crate::config::RewriteRule>,
    pub pending_rewrite_conds: Vec<crate::config::RewriteCond>,
}

impl RewriteCachePolicy {
    pub fn merge_child(&mut self, child: &RewriteCachePolicy) {
        self.merge_child_with_rules(child, None);
    }

    /// Merge all rewrite/cache fields, optionally substituting a transformed
    /// rule list for the child's own rules.  This avoids cloning an entire
    /// `Scope` just to rewrite per-directory `RewriteRule` metadata.
    pub fn merge_child_with_rules(
        &mut self,
        child: &RewriteCachePolicy,
        transformed_rules: Option<&[crate::config::RewriteRule]>,
    ) {
        if child.rewrite_engine.is_some() {
            self.rewrite_engine = child.rewrite_engine;
        }
        crate::verified::append_vec(&mut self.rewrite_maps, &child.rewrite_maps);
        crate::verified::append_vec(&mut self.cache_enable, &child.cache_enable);
        crate::verified::append_vec(&mut self.cache_disable, &child.cache_disable);
        if child.rewrite_inherit.is_some() {
            self.rewrite_inherit = child.rewrite_inherit;
        }
        if child.rewrite_base.is_some() {
            self.rewrite_base = child.rewrite_base.clone();
        }
        if child.rewrite_match_base.is_some() {
            self.rewrite_match_base = child.rewrite_match_base.clone();
        }
        match transformed_rules {
            Some(rules) => crate::verified::append_vec(&mut self.rewrite_rules, rules),
            None => crate::verified::append_vec(&mut self.rewrite_rules, &child.rewrite_rules),
        }
        // pending conditions are section-local parser state.
    }
}

#[cfg(test)]
mod error_rewrite_tests {
    use super::*;

    #[test]
    fn error_documents_append_and_reverse_lookup_wins() {
        let mut parent = ErrorDocumentPolicy::default();
        parent.push(404, crate::config::ErrorDoc::Text("parent".into()));
        let mut child = ErrorDocumentPolicy::default();
        child.push(404, crate::config::ErrorDoc::Text("child".into()));
        child.push(500, crate::config::ErrorDoc::Text("server".into()));
        parent.merge_child(&child);
        assert!(matches!(
            parent.get(404),
            Some(crate::config::ErrorDoc::Text(text)) if text == "child"
        ));
        assert!(matches!(
            parent.get(500),
            Some(crate::config::ErrorDoc::Text(text)) if text == "server"
        ));
    }

    #[test]
    fn rewrite_scalars_child_win_and_cache_lists_append() {
        let mut parent = RewriteCachePolicy::default();
        parent.rewrite_engine = Some(false);
        parent.cache_enable.push(("/old".into(), "1".into()));
        let mut child = RewriteCachePolicy::default();
        child.rewrite_engine = Some(true);
        child.cache_enable.push(("/new".into(), "2".into()));
        child.cache_disable.push("/private".into());
        parent.merge_child(&child);
        assert_eq!(parent.rewrite_engine, Some(true));
        assert_eq!(parent.cache_enable.len(), 2);
        assert_eq!(parent.cache_disable, vec!["/private".to_string()]);
    }
}

/// Compression policy.
#[derive(Debug, Clone, Default)]
pub struct CompressionPolicy {
    pub compression_rules: Vec<crate::config::CompressionRule>,
    pub deflate_level: Option<u32>,
    pub brotli_quality: Option<u32>,
    pub deflate_alter_etag: Option<crate::config::AlterEtag>,
    pub brotli_alter_etag: Option<crate::config::AlterEtag>,
}

impl CompressionPolicy {
    pub fn merge_child(&mut self, child: &CompressionPolicy) {
        crate::verified::append_vec(&mut self.compression_rules, &child.compression_rules);
        if child.deflate_level.is_some() {
            self.deflate_level = child.deflate_level;
        }
        if child.brotli_quality.is_some() {
            self.brotli_quality = child.brotli_quality;
        }
        if child.deflate_alter_etag.is_some() {
            self.deflate_alter_etag = child.deflate_alter_etag;
        }
        if child.brotli_alter_etag.is_some() {
            self.brotli_alter_etag = child.brotli_alter_etag;
        }
    }
}

/// Proxy policy.  Backend containers/rules append; CA file uses child
/// presence.
#[derive(Debug, Clone, Default)]
pub struct ProxyPolicy {
    pub proxy_rules: Vec<crate::config::ProxyRule>,
    pub proxy_passes: Vec<crate::config::ProxyPassRule>,
    pub proxy_reverses: Vec<crate::config::ProxyReverseRule>,
    pub proxy_ca_file: Option<std::path::PathBuf>,
}

impl ProxyPolicy {
    pub fn merge_child(&mut self, child: &ProxyPolicy) {
        crate::verified::append_vec(&mut self.proxy_rules, &child.proxy_rules);
        crate::verified::append_vec(&mut self.proxy_passes, &child.proxy_passes);
        crate::verified::append_vec(&mut self.proxy_reverses, &child.proxy_reverses);
        if child.proxy_ca_file.is_some() {
            self.proxy_ca_file = child.proxy_ca_file.clone();
        }
    }
}

#[cfg(test)]
mod final_policy_tests {
    use super::*;

    #[test]
    fn document_root_and_auth_identity_use_child_presence() {
        let mut content = ContentPolicy::default();
        content.document_root = Some("/srv".into());
        let child = ContentPolicy {
            document_root: Some("/srv/site".into()),
            ..ContentPolicy::default()
        };
        content.merge_child(&child);
        assert_eq!(
            content.document_root.as_deref(),
            Some(std::path::Path::new("/srv/site"))
        );

        let mut auth = AuthorizationPolicy::default();
        auth.auth_type = Some("basic".into());
        let child = AuthorizationPolicy {
            auth_type: Some("digest".into()),
            auth_name: Some("realm".into()),
            ..AuthorizationPolicy::default()
        };
        auth.merge_child(&child);
        assert_eq!(auth.auth_type.as_deref(), Some("digest"));
        assert_eq!(auth.auth_name.as_deref(), Some("realm"));
    }

    #[test]
    fn compression_levels_child_win_and_proxy_ca_child_presence() {
        let mut compression = CompressionPolicy::default();
        compression.deflate_level = Some(1);
        let child = CompressionPolicy {
            deflate_level: Some(9),
            brotli_quality: Some(11),
            ..CompressionPolicy::default()
        };
        compression.merge_child(&child);
        assert_eq!(compression.deflate_level, Some(9));
        assert_eq!(compression.brotli_quality, Some(11));

        let mut proxy = ProxyPolicy::default();
        proxy.proxy_ca_file = Some("/old-ca.pem".into());
        let child = ProxyPolicy {
            proxy_ca_file: Some("/new-ca.pem".into()),
            ..ProxyPolicy::default()
        };
        proxy.merge_child(&child);
        assert_eq!(
            proxy.proxy_ca_file.as_deref(),
            Some(std::path::Path::new("/new-ca.pem"))
        );
    }
}
