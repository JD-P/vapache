//! Access control (`mod_authz_core`, `mod_authz_host`, `mod_access_compat`).
//!
//! Security rule: every path through this module is fail-closed.  A `Require`
//! provider we do not understand denies access, and any malformed
//! directive is rejected at configuration time.

use crate::config::{AuthPolicy, Order, Require, RequireNode, Satisfy, Scope};
use crate::http::Request;
use crate::verified::{
    combine_and, combine_or, ipv4_in_net, ipv6_in_net, require_none_result, PolicyResult,
};
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Identity {
    pub user: String,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Allowed,
    Denied,
    AuthRequired,
}

/// The concrete object and request context covered by an access decision.
///
/// A grant for `/public/file` cannot be reused to serve `/private/file`, a
/// different proxy target, or a cache entry for another request.  Paths are
/// canonical strings here; the opened file descriptor/proxy target still has
/// to be checked by the sink.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceKey {
    pub vhost: usize,
    pub method: String,
    pub url_path: String,
    pub fs_path: Option<PathBuf>,
    pub proxy_url: Option<String>,
    pub cache_host: Option<String>,
    pub cache_path: Option<String>,
    pub cache_query: Option<String>,
    pub identity: Option<String>,
    pub file_dev: Option<u64>,
    pub file_ino: Option<u64>,
    pub backend_target: Option<String>,
    pub policy_fingerprint: Option<u64>,
}

fn vhost_id(vhost: Option<&crate::config::VHost>) -> usize {
    vhost
        .map(|v| v as *const crate::config::VHost as usize)
        .unwrap_or(0)
}

impl ResourceKey {
    pub fn request(
        vhost: Option<&crate::config::VHost>,
        req: &Request,
        url_path: &str,
        fs_path: Option<&Path>,
        proxy_url: Option<&str>,
    ) -> Self {
        Self {
            vhost: vhost_id(vhost),
            method: req.method.clone(),
            url_path: url_path.to_string(),
            fs_path: fs_path.map(Path::to_path_buf),
            proxy_url: proxy_url.map(str::to_string),
            cache_host: None,
            cache_path: None,
            cache_query: None,
            identity: None,
            file_dev: None,
            file_ino: None,
            backend_target: None,
            policy_fingerprint: None,
        }
    }

    pub fn cache(
        vhost: Option<&crate::config::VHost>,
        req: &Request,
        host: &str,
        path: &str,
    ) -> Self {
        Self {
            vhost: vhost_id(vhost),
            method: req.method.clone(),
            url_path: path.to_string(),
            fs_path: None,
            proxy_url: None,
            cache_host: Some(host.to_string()),
            cache_path: Some(path.to_string()),
            cache_query: Some(String::from_utf8_lossy(&req.query).into_owned()),
            identity: None,
            file_dev: None,
            file_ino: None,
            backend_target: None,
            policy_fingerprint: None,
        }
    }

    pub fn cache_policy(
        vhost: Option<&crate::config::VHost>,
        req: &Request,
        host: &str,
        path: &str,
        policy_fingerprint: u64,
    ) -> Self {
        let mut key = Self::cache(vhost, req, host, path);
        key.policy_fingerprint = Some(policy_fingerprint);
        key
    }
}

/// Capability proving that the effective scope authorized a particular
/// resource for this request.  The key is checked by every body/tunnel sink.
#[derive(Debug)]
pub struct AccessGrant {
    key: ResourceKey,
    /// Test-only grants are intentionally wildcard; production grants are
    /// always constructed with a concrete key.
    wildcard: bool,
}

impl AccessGrant {
    pub fn require(&self, key: &ResourceKey) -> bool {
        self.wildcard || &self.key == key
    }

    pub fn key(&self) -> &ResourceKey {
        &self.key
    }

    /// Bind a grant that already covers `resource` to the exact outbound
    /// backend target selected by the proxy/FastCGI layer.
    pub(crate) fn bind_backend(
        &self,
        resource: &ResourceKey,
        backend_target: String,
    ) -> Option<AccessGrant> {
        if !self.require(resource) {
            return None;
        }
        let mut key = resource.clone();
        key.backend_target = Some(backend_target);
        Some(AccessGrant {
            key,
            wildcard: self.wildcard,
        })
    }

    /// Bind a grant that already covers `resource` to the opened inode.
    pub(crate) fn bind_file(
        &self,
        resource: &ResourceKey,
        meta: &std::fs::Metadata,
    ) -> Option<AccessGrant> {
        if !self.require(resource) {
            return None;
        }
        let mut key = resource.clone();
        key.file_dev = Some(meta.dev());
        key.file_ino = Some(meta.ino());
        Some(AccessGrant {
            key,
            wildcard: self.wildcard,
        })
    }
}

pub(crate) fn grant_if_allowed(access: Access, key: ResourceKey) -> Option<AccessGrant> {
    match access {
        Access::Allowed => Some(AccessGrant {
            key,
            wildcard: false,
        }),
        _ => None,
    }
}

#[cfg(test)]
pub fn test_grant() -> AccessGrant {
    AccessGrant {
        key: ResourceKey {
            vhost: 0,
            method: String::new(),
            url_path: String::new(),
            fs_path: None,
            proxy_url: None,
            cache_host: None,
            cache_path: None,
            cache_query: None,
            identity: None,
            file_dev: None,
            file_ino: None,
            backend_target: None,
            policy_fingerprint: None,
        },
        wildcard: true,
    }
}

pub(crate) fn check_grant(
    scope: &Scope,
    req: &Request,
    peer: IpAddr,
    identity: Option<&Identity>,
    key: ResourceKey,
) -> Result<AccessGrant, Access> {
    match check(scope, req, peer, identity) {
        Access::Allowed => Ok(AccessGrant {
            key,
            wildcard: false,
        }),
        other => Err(other),
    }
}

pub fn check(scope: &Scope, req: &Request, peer: IpAddr, identity: Option<&Identity>) -> Access {
    let host = scope
        .authorization
        .legacy
        .as_ref()
        .map(|_| legacy_check(scope, peer, &req.method));
    let docroot = scope
        .content_policy
        .document_root
        .as_deref()
        .unwrap_or(Path::new("/"));
    let auth = check_requires(scope, req, peer, identity, docroot);
    let satisfy = scope
        .authorization
        .legacy
        .as_ref()
        .map(|legacy| legacy.method_satisfy(&req.method))
        .unwrap_or(Satisfy::All);

    match satisfy {
        // Satisfy All (the default): the host-level check and the
        // authentication/authorization check must both pass.
        Satisfy::All => {
            if host == Some(Access::Denied) {
                Access::Denied
            } else {
                auth
            }
        }
        // Satisfy Any: a passing host check suppresses authentication.
        // Otherwise authorization may still grant access.
        Satisfy::Any => {
            if host != Some(Access::Denied) {
                Access::Allowed
            } else {
                auth
            }
        }
    }
}

/// Evaluate `<Require>` rules.  Rules are an implicit `RequireAny`; a rule
/// limited to another method is skipped.  If every rule was skipped, Apache's
/// root authorization section is itself method-limited and grants access.
fn check_requires(
    scope: &Scope,
    req: &Request,
    peer: IpAddr,
    identity: Option<&Identity>,
    docroot: &Path,
) -> Access {
    let Some(policy) = &scope.authorization.requires else {
        return Access::Allowed;
    };
    let env = scope.request_env(req);
    match eval_policy(policy, req, peer, identity, &env, true, docroot) {
        PolicyResult::Granted => Access::Allowed,
        // At the root, Apache treats a neutral authorization result as a
        // failure (403), never as an implicit grant.
        PolicyResult::Denied | PolicyResult::Neutral => Access::Denied,
        PolicyResult::AuthRequired => Access::AuthRequired,
    }
}

/// Evaluate an authorization policy.  `parent_and` mirrors Apache's section
/// logic: a method-limited section that does not apply is `GRANTED` under an
/// AND parent and `NEUTRAL` under an OR parent.
fn eval_policy(
    policy: &AuthPolicy,
    req: &Request,
    peer: IpAddr,
    identity: Option<&Identity>,
    env: &[(String, String)],
    parent_and: bool,
    docroot: &Path,
) -> PolicyResult {
    match policy {
        AuthPolicy::List(entries) => {
            let mut matched = false;
            let mut auth_required = false;
            for entry in entries {
                if !entry.applies(&req.method) {
                    continue;
                }
                matched = true;
                match eval_node(&entry.node, req, peer, identity, env, docroot) {
                    PolicyResult::Granted => return PolicyResult::Granted,
                    PolicyResult::Denied => {}
                    PolicyResult::AuthRequired => auth_required = true,
                    PolicyResult::Neutral => {}
                }
            }
            if !matched {
                return if parent_and {
                    PolicyResult::Granted
                } else {
                    PolicyResult::Neutral
                };
            }
            if auth_required {
                PolicyResult::AuthRequired
            } else {
                PolicyResult::Denied
            }
        }
        AuthPolicy::And(a, b) => combine_and(
            eval_policy(a, req, peer, identity, env, true, docroot),
            eval_policy(b, req, peer, identity, env, true, docroot),
        ),
        AuthPolicy::Or(a, b) => combine_or(
            eval_policy(a, req, peer, identity, env, false, docroot),
            eval_policy(b, req, peer, identity, env, false, docroot),
        ),
    }
}

/// Evaluate legacy `Order`/`Allow`/`Deny` rules for this request method.
fn legacy_check(scope: &Scope, peer: IpAddr, method: &str) -> Access {
    let Some(legacy) = &scope.authorization.legacy else {
        return Access::Allowed;
    };
    let order = legacy.method_order(method);
    let allow = legacy
        .allow
        .iter()
        .any(|entry| entry.applies(method) && entry.value.matches(peer));
    let deny = legacy
        .deny
        .iter()
        .any(|entry| entry.applies(method) && entry.value.matches(peer));
    match order {
        // allow,deny: default deny; deny overrides allow.
        Order::AllowDeny => {
            if allow && !deny {
                Access::Allowed
            } else {
                Access::Denied
            }
        }
        // deny,allow: default allow; allow overrides deny.
        Order::DenyAllow => {
            if deny && !allow {
                Access::Denied
            } else {
                Access::Allowed
            }
        }
    }
}

fn eval_node(
    node: &RequireNode,
    req: &Request,
    peer: IpAddr,
    identity: Option<&Identity>,
    env: &[(String, String)],
    docroot: &Path,
) -> PolicyResult {
    match node {
        RequireNode::Provider(r) => eval_require(r, req, peer, identity, env, docroot),
        RequireNode::All(items) => {
            // RequireAll: all children must pass, and at least one must grant.
            let mut result = PolicyResult::Neutral;
            for item in items {
                result = combine_and(result, eval_node(item, req, peer, identity, env, docroot));
                if result == PolicyResult::Denied {
                    return PolicyResult::Denied;
                }
            }
            result
        }
        RequireNode::Any(items) => {
            let mut result = PolicyResult::Neutral;
            for item in items {
                result = combine_or(result, eval_node(item, req, peer, identity, env, docroot));
                if result == PolicyResult::Granted {
                    return PolicyResult::Granted;
                }
            }
            result
        }
        RequireNode::None(items) => {
            // A negated group can fail or stay neutral, but can never grant
            // authorization by itself.
            let mut result = PolicyResult::Neutral;
            for item in items {
                result = combine_and(result, eval_node(item, req, peer, identity, env, docroot));
            }
            require_none_result(result)
        }
    }
}

fn eval_require(
    r: &Require,
    req: &Request,
    peer: IpAddr,
    identity: Option<&Identity>,
    env: &[(String, String)],
    docroot: &Path,
) -> PolicyResult {
    // Apache's negated providers can deny or stay neutral, but can never
    // independently grant access.
    fn decide(hit: bool, negate: bool) -> PolicyResult {
        if negate {
            if hit {
                PolicyResult::Denied
            } else {
                PolicyResult::Neutral
            }
        } else if hit {
            PolicyResult::Granted
        } else {
            PolicyResult::Denied
        }
    }
    match r {
        Require::AllGranted => PolicyResult::Granted,
        Require::AllDenied => PolicyResult::Denied,
        Require::Ip { negate, nets } => {
            let hit = nets.iter().any(|(n, b)| ip_in_net(peer, *n, *b));
            decide(hit, *negate)
        }
        Require::Local { negate } => decide(peer.is_loopback(), *negate),
        Require::Host { negate, names } => decide(reverse_dns_matches(peer, names), *negate),
        Require::Method { negate, methods } => {
            decide(methods.iter().any(|m| same_method(m, &req.method)), *negate)
        }
        Require::ValidUser { negate } => {
            // `Require not valid-user` must carry its negation.  Like every
            // other negated provider it can deny or stay neutral, but cannot
            // independently grant access.
            let hit = identity.is_some();
            if *negate {
                decide(hit, true)
            } else if hit {
                PolicyResult::Granted
            } else {
                PolicyResult::AuthRequired
            }
        }
        Require::User { negate, names } => {
            let Some(identity) = identity else {
                return PolicyResult::AuthRequired;
            };
            decide(names.iter().any(|n| n == &identity.user), *negate)
        }
        Require::Group { negate, names } => {
            let Some(identity) = identity else {
                return PolicyResult::AuthRequired;
            };
            decide(
                identity.groups.iter().any(|g| names.iter().any(|n| n == g)),
                *negate,
            )
        }
        Require::Env {
            negate,
            name,
            value,
        } => {
            let hit = env
                .iter()
                .rev()
                .find(|(n, _)| n == name)
                .map(|(_, v)| value.as_ref().map(|want| v == want).unwrap_or(true))
                .unwrap_or(false);
            decide(hit, *negate)
        }
        Require::Expr { negate, expr } => {
            let mut ctx = crate::expr::Context::new(req, env, peer, docroot);
            let hit = expr.eval(&mut ctx).map(|v| v.truthy()).unwrap_or(false);
            decide(hit, *negate)
        }
        Require::Unsupported(_) => PolicyResult::Denied,
    }
}

fn same_method(configured: &str, request: &str) -> bool {
    // Apache maps HEAD onto GET's method number.
    let configured = if configured == "HEAD" {
        "GET"
    } else {
        configured
    };
    let request = if request == "HEAD" { "GET" } else { request };
    configured == request
}

pub fn ip_in_net(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => ipv4_in_net(u32::from(a), u32::from(n), bits),
        (IpAddr::V6(a), IpAddr::V6(n)) => ipv6_in_net(u128::from(a), u128::from(n), bits),
        _ => false,
    }
}

fn reverse_dns_matches(ip: IpAddr, names: &[String]) -> bool {
    // Forward-confirmed reverse DNS (FCrDNS), matching Apache's behavior:
    // a PTR result is only accepted if it resolves back to the peer address.
    let Ok(host) = reverse_dns(ip) else {
        return false;
    };
    let host_l = host.to_ascii_lowercase();
    let name_ok = names.iter().any(|n| {
        let n = n.to_ascii_lowercase();
        if let Some(suffix) = n.strip_prefix('.') {
            host_l == suffix || host_l.ends_with(&format!(".{suffix}"))
        } else if let Some(suffix) = n.strip_prefix("*.") {
            host_l.ends_with(&format!(".{suffix}"))
        } else {
            host_l == n
        }
    });
    if !name_ok {
        return false;
    }
    // Confirm forward resolution.
    use std::net::ToSocketAddrs;
    match (host.as_str(), 0).to_socket_addrs() {
        Ok(addrs) => addrs.into_iter().any(|a| a.ip() == ip),
        Err(_) => false,
    }
}

fn reverse_dns(ip: IpAddr) -> Result<String, std::io::Error> {
    let sa = std::net::SocketAddr::new(ip, 0);
    let (storage, len) = socket_addr_to_storage(&sa);
    let mut host = [0i8; libc::NI_MAXHOST as usize];
    let rc = unsafe {
        libc::getnameinfo(
            &storage as *const _ as *const libc::sockaddr,
            len,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let c = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) };
    Ok(c.to_string_lossy().into_owned())
}

fn socket_addr_to_storage(sa: &std::net::SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match sa {
        std::net::SocketAddr::V4(v4) => {
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
        std::net::SocketAddr::V6(v6) => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthPolicy, RequireEntry};

    fn reqs(v: Vec<Require>) -> Option<AuthPolicy> {
        Some(AuthPolicy::List(
            v.into_iter()
                .map(|r| RequireEntry {
                    node: RequireNode::Provider(r),
                    limit: None,
                })
                .collect(),
        ))
    }

    fn nodes(v: Vec<RequireNode>) -> Option<AuthPolicy> {
        Some(AuthPolicy::List(
            v.into_iter()
                .map(|node| RequireEntry { node, limit: None })
                .collect(),
        ))
    }

    fn req(method: &str) -> Request {
        Request {
            method: method.into(),
            target: b"/".to_vec(),
            raw_path: b"/".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: Default::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    #[test]
    fn cidr() {
        assert!(ip_in_net(
            "10.1.2.3".parse().unwrap(),
            "10.0.0.0".parse().unwrap(),
            8
        ));
        assert!(!ip_in_net(
            "11.1.2.3".parse().unwrap(),
            "10.0.0.0".parse().unwrap(),
            8
        ));
        assert!(ip_in_net(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::".parse().unwrap(),
            32
        ));
    }

    #[test]
    fn require_ip_and_negation() {
        let mut s = Scope::default();
        s.authorization.requires = reqs(vec![Require::Ip {
            negate: false,
            nets: vec![("10.0.0.0".parse().unwrap(), 8)],
        }]);
        assert_eq!(
            check(&s, &req("GET"), "10.1.2.3".parse().unwrap(), None),
            Access::Allowed
        );
        assert_eq!(
            check(&s, &req("GET"), "11.1.2.3".parse().unwrap(), None),
            Access::Denied
        );

        s.authorization.requires = nodes(vec![RequireNode::All(vec![
            RequireNode::Provider(Require::AllGranted),
            RequireNode::Provider(Require::Ip {
                negate: true,
                nets: vec![("10.0.0.0".parse().unwrap(), 8)],
            }),
        ])]);
        assert_eq!(
            check(&s, &req("GET"), "10.1.2.3".parse().unwrap(), None),
            Access::Denied
        );
        assert_eq!(
            check(&s, &req("GET"), "11.1.2.3".parse().unwrap(), None),
            Access::Allowed
        );
    }

    #[test]
    fn access_grant_is_only_created_for_allowed() {
        assert!(grant_if_allowed(
            Access::Allowed,
            ResourceKey::request(None, &req("GET"), "/", None, None)
        )
        .is_some());
        assert!(grant_if_allowed(
            Access::Denied,
            ResourceKey::request(None, &req("GET"), "/", None, None)
        )
        .is_none());
        assert!(grant_if_allowed(
            Access::AuthRequired,
            ResourceKey::request(None, &req("GET"), "/", None, None)
        )
        .is_none());
    }

    #[test]
    fn access_grants_are_bound_to_the_authorized_resource() {
        let req = req("GET");
        let peer = "127.0.0.1".parse().unwrap();
        let scope = Scope::default();
        let a = ResourceKey::request(None, &req, "/public/a", None, None);
        let b = ResourceKey::request(None, &req, "/private/b", None, None);
        let grant = check_grant(&scope, &req, peer, None, a.clone()).expect("allowed");
        assert!(grant.require(&a));
        assert!(!grant.require(&b));
    }

    #[test]
    fn file_binding_records_the_opened_inode() {
        let req = req("GET");
        let peer = "127.0.0.1".parse().unwrap();
        let scope = Scope::default();
        let key = ResourceKey::request(None, &req, "/file", None, None);
        let grant = check_grant(&scope, &req, peer, None, key.clone()).expect("allowed");
        let meta = std::fs::metadata("/proc/self/exe").expect("self metadata");
        let bound = grant.bind_file(&key, &meta).expect("file bound");
        assert_eq!(bound.key().file_dev, Some(meta.dev()));
        assert_eq!(bound.key().file_ino, Some(meta.ino()));
        assert!(!bound.require(&key));
    }

    #[test]
    fn negated_valid_user_carries_its_negation() {
        let r = req("GET");
        let peer = "127.0.0.1".parse().unwrap();
        let docroot = Path::new("/");
        let identity = Identity {
            user: "alice".into(),
            groups: Vec::new(),
        };
        assert_eq!(
            eval_require(
                &Require::ValidUser { negate: false },
                &r,
                peer,
                Some(&identity),
                &[],
                docroot,
            ),
            PolicyResult::Granted
        );
        assert_eq!(
            eval_require(
                &Require::ValidUser { negate: true },
                &r,
                peer,
                Some(&identity),
                &[],
                docroot,
            ),
            PolicyResult::Denied
        );
        assert_eq!(
            eval_require(
                &Require::ValidUser { negate: true },
                &r,
                peer,
                None,
                &[],
                docroot,
            ),
            PolicyResult::Neutral
        );
    }

    #[test]
    fn require_local() {
        let mut s = Scope::default();
        s.authorization.requires = reqs(vec![Require::Local { negate: false }]);
        assert_eq!(
            check(&s, &req("GET"), "127.0.0.1".parse().unwrap(), None),
            Access::Allowed
        );
        assert_eq!(
            check(&s, &req("GET"), "10.0.0.1".parse().unwrap(), None),
            Access::Denied
        );
        s.authorization.requires = nodes(vec![RequireNode::All(vec![
            RequireNode::Provider(Require::AllGranted),
            RequireNode::Provider(Require::Local { negate: true }),
        ])]);
        assert_eq!(
            check(&s, &req("GET"), "127.0.0.1".parse().unwrap(), None),
            Access::Denied
        );
        assert_eq!(
            check(&s, &req("GET"), "10.0.0.1".parse().unwrap(), None),
            Access::Allowed
        );
    }

    #[test]
    fn multiple_requires_are_an_implicit_any() {
        let mut s = Scope::default();
        s.authorization.requires = reqs(vec![
            Require::Ip {
                negate: false,
                nets: vec![("10.0.0.0".parse().unwrap(), 8)],
            },
            Require::Local { negate: false },
        ]);
        // Localhost is not in 10/8, but the second provider is enough.
        assert_eq!(
            check(&s, &req("GET"), "127.0.0.1".parse().unwrap(), None),
            Access::Allowed
        );
        assert_eq!(
            check(&s, &req("GET"), "192.0.2.1".parse().unwrap(), None),
            Access::Denied
        );
        // A single matching provider among deny-all siblings still wins.
        s.authorization.requires = reqs(vec![Require::AllDenied, Require::AllGranted]);
        assert_eq!(
            check(&s, &req("GET"), "192.0.2.1".parse().unwrap(), None),
            Access::Allowed
        );
    }

    #[test]
    fn legacy_order_allow_deny() {
        use crate::config::{HostSpec, LegacyAccess, MethodScoped};
        let mut s = Scope::default();
        s.authorization.legacy = Some(LegacyAccess {
            order: vec![MethodScoped {
                limit: None,
                value: Order::AllowDeny,
            }],
            allow: vec![MethodScoped {
                limit: None,
                value: HostSpec::All,
            }],
            deny: vec![MethodScoped {
                limit: None,
                value: HostSpec::Net("10.0.0.0".parse().unwrap(), 8),
            }],
            ..LegacyAccess::default()
        });
        assert_eq!(
            check(&s, &req("GET"), "10.1.2.3".parse().unwrap(), None),
            Access::Denied
        );
        assert_eq!(
            check(&s, &req("GET"), "192.0.2.1".parse().unwrap(), None),
            Access::Allowed
        );
    }

    #[test]
    fn legacy_order_deny_allow() {
        use crate::config::{HostSpec, LegacyAccess, MethodScoped};
        let mut s = Scope::default();
        s.authorization.legacy = Some(LegacyAccess {
            order: vec![MethodScoped {
                limit: None,
                value: Order::DenyAllow,
            }],
            allow: vec![MethodScoped {
                limit: None,
                value: HostSpec::Net("10.0.0.0".parse().unwrap(), 8),
            }],
            deny: vec![MethodScoped {
                limit: None,
                value: HostSpec::All,
            }],
            ..LegacyAccess::default()
        });
        assert_eq!(
            check(&s, &req("GET"), "10.1.2.3".parse().unwrap(), None),
            Access::Allowed
        );
        assert_eq!(
            check(&s, &req("GET"), "192.0.2.1".parse().unwrap(), None),
            Access::Denied
        );
    }

    #[test]
    fn empty_scope_allows() {
        let s = Scope::default();
        assert_eq!(
            check(&s, &req("GET"), "127.0.0.1".parse().unwrap(), None),
            Access::Allowed
        );
    }

    #[test]
    fn all_granted_and_denied() {
        let mut s = Scope::default();
        s.authorization.requires = reqs(vec![Require::AllGranted]);
        assert_eq!(
            check(&s, &req("GET"), "127.0.0.1".parse().unwrap(), None),
            Access::Allowed
        );
        s.authorization.requires = reqs(vec![Require::AllDenied]);
        assert_eq!(
            check(&s, &req("GET"), "127.0.0.1".parse().unwrap(), None),
            Access::Denied
        );
    }

    #[test]
    fn unsupported_denies() {
        let mut s = Scope::default();
        s.authorization.requires = reqs(vec![Require::Unsupported("x".into())]);
        assert_eq!(
            check(&s, &req("GET"), "127.0.0.1".parse().unwrap(), None),
            Access::Denied
        );
    }

    #[test]
    fn nested_require_groups() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let mut s = Scope::default();
        s.authorization.requires = nodes(vec![RequireNode::All(vec![
            RequireNode::Provider(Require::AllGranted),
            RequireNode::Provider(Require::Local { negate: false }),
        ])]);
        assert_eq!(check(&s, &req("GET"), peer, None), Access::Allowed);
        s.authorization.requires = nodes(vec![RequireNode::All(vec![
            RequireNode::Provider(Require::AllGranted),
            RequireNode::Provider(Require::AllDenied),
        ])]);
        assert_eq!(check(&s, &req("GET"), peer, None), Access::Denied);

        s.authorization.requires = nodes(vec![RequireNode::Any(vec![
            RequireNode::Provider(Require::AllDenied),
            RequireNode::Provider(Require::Local { negate: false }),
        ])]);
        assert_eq!(check(&s, &req("GET"), peer, None), Access::Allowed);

        s.authorization.requires = nodes(vec![RequireNode::None(vec![RequireNode::Provider(
            Require::AllGranted,
        )])]);
        assert_eq!(check(&s, &req("GET"), peer, None), Access::Denied);
        s.authorization.requires = nodes(vec![RequireNode::None(vec![RequireNode::Provider(
            Require::AllDenied,
        )])]);
        // A negated-only group is neutral; at the root Apache denies.
        assert_eq!(check(&s, &req("GET"), peer, None), Access::Denied);
    }

    #[test]
    fn require_method() {
        let mut s = Scope::default();
        s.authorization.requires = reqs(vec![Require::Method {
            negate: false,
            methods: vec!["POST".into()],
        }]);
        assert_eq!(
            check(&s, &req("POST"), "127.0.0.1".parse().unwrap(), None),
            Access::Allowed
        );
        assert_eq!(
            check(&s, &req("GET"), "127.0.0.1".parse().unwrap(), None),
            Access::Denied
        );
        assert_eq!(
            check(&s, &req("HEAD"), "127.0.0.1".parse().unwrap(), None),
            Access::Denied
        );

        s.authorization.requires = reqs(vec![Require::Method {
            negate: false,
            methods: vec!["GET".into()],
        }]);
        assert_eq!(
            check(&s, &req("HEAD"), "127.0.0.1".parse().unwrap(), None),
            Access::Allowed
        );
    }

    #[test]
    fn method_limited_requires_are_skipped_for_other_methods() {
        use crate::config::MethodSet;
        let mut s = Scope::default();
        s.authorization.requires = Some(AuthPolicy::List(vec![RequireEntry {
            node: RequireNode::Provider(Require::AllDenied),
            limit: Some(MethodSet::Only(vec!["POST".into()])),
        }]));
        // Only POST has an applicable authorization rule.
        assert_eq!(
            check(&s, &req("POST"), "127.0.0.1".parse().unwrap(), None),
            Access::Denied
        );
        assert_eq!(
            check(&s, &req("GET"), "127.0.0.1".parse().unwrap(), None),
            Access::Allowed
        );
        // GET and HEAD share a method number, matching Apache.
        s.authorization.requires = Some(AuthPolicy::List(vec![RequireEntry {
            node: RequireNode::Provider(Require::AllDenied),
            limit: Some(MethodSet::Only(vec!["GET".into()])),
        }]));
        assert_eq!(
            check(&s, &req("HEAD"), "127.0.0.1".parse().unwrap(), None),
            Access::Denied
        );
        assert_eq!(
            check(&s, &req("POST"), "127.0.0.1".parse().unwrap(), None),
            Access::Allowed
        );
    }

    #[test]
    fn auth_merging_and_or_combine_policies() {
        use crate::config::AuthMerging;
        let peer_inside: IpAddr = "10.1.2.3".parse().unwrap();
        let peer_outside: IpAddr = "192.0.2.1".parse().unwrap();
        let alice = Identity {
            user: "alice".into(),
            groups: Vec::new(),
        };
        let req = req("GET");

        let mut parent = Scope::default();
        parent.authorization.requires = reqs(vec![Require::Ip {
            negate: false,
            nets: vec![("10.0.0.0".parse().unwrap(), 8)],
        }]);
        let mut child = Scope::default();
        child.authorization.auth_merging = Some(AuthMerging::And);
        child.authorization.requires = reqs(vec![Require::User {
            negate: false,
            names: vec!["alice".into()],
        }]);
        let mut merged = parent.clone();
        merged.merge(&child);
        assert_eq!(
            check(&merged, &req, peer_inside, Some(&alice)),
            Access::Allowed
        );
        assert_eq!(
            check(&merged, &req, peer_outside, Some(&alice)),
            Access::Denied
        );
        assert_eq!(
            check(&merged, &req, peer_inside, None),
            Access::AuthRequired
        );

        let mut child = Scope::default();
        child.authorization.auth_merging = Some(AuthMerging::Or);
        child.authorization.requires = reqs(vec![Require::User {
            negate: false,
            names: vec!["alice".into()],
        }]);
        let mut merged = parent.clone();
        merged.merge(&child);
        assert_eq!(
            check(&merged, &req, peer_outside, Some(&alice)),
            Access::Allowed
        );
        assert_eq!(check(&merged, &req, peer_inside, None), Access::Allowed);
        assert_eq!(
            check(&merged, &req, peer_outside, None),
            Access::AuthRequired
        );

        // Off (the default) keeps the child-only replacement semantics.
        let mut merged = parent.clone();
        let mut child = Scope::default();
        child.authorization.requires = reqs(vec![Require::User {
            negate: false,
            names: vec!["alice".into()],
        }]);
        merged.merge(&child);
        assert_eq!(
            check(&merged, &req, peer_inside, None),
            Access::AuthRequired
        );
    }

    #[test]
    fn satisfied_any_and_all_combine_host_and_auth() {
        use crate::config::{HostSpec, LegacyAccess, MethodScoped};
        let peer: IpAddr = "192.0.2.1".parse().unwrap();
        let mut s = Scope::default();
        s.authorization.requires = reqs(vec![Require::AllDenied]);
        s.authorization.legacy = Some(LegacyAccess {
            satisfy: vec![MethodScoped {
                limit: None,
                value: Satisfy::Any,
            }],
            allow: vec![MethodScoped {
                limit: None,
                value: HostSpec::All,
            }],
            ..LegacyAccess::default()
        });
        // Host access grants access, so the failing Require is bypassed.
        assert_eq!(check(&s, &req("GET"), peer, None), Access::Allowed);

        s.authorization.legacy.as_mut().unwrap().satisfy[0].value = Satisfy::All;
        s.authorization.legacy.as_mut().unwrap().allow.clear();
        // Default Order Deny,Allow allows the host; Satisfy All still needs
        // the authorization provider to pass.
        assert_eq!(check(&s, &req("GET"), peer, None), Access::Denied);

        s.authorization.requires = reqs(vec![Require::AllGranted]);
        assert_eq!(check(&s, &req("GET"), peer, None), Access::Allowed);

        // A host denial wins under Satisfy All even when Require passes.
        s.authorization
            .legacy
            .as_mut()
            .unwrap()
            .deny
            .push(MethodScoped {
                limit: None,
                value: HostSpec::All,
            });
        assert_eq!(check(&s, &req("GET"), peer, None), Access::Denied);
    }
}
