//! TLS (mod_ssl-compatible subset) using Rustls.
//!
//! Certificates are loaded while the process is still privileged and then
//! shared immutably.  TLS is fail-closed: enabling `SSLEngine` without a
//! usable certificate/key pair is a startup error, and only TLS 1.2/1.3 are
//! offered even if an old configuration mentions SSLv3/TLSv1.0.

use crate::config::{vhost_port, Config, SslConfig, VHost};
use rustls::crypto::{ring, CryptoProvider};
use rustls::pki_types::pem::{Error as PemError, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig, SupportedProtocolVersion};
use std::collections::HashMap;
use std::net::IpAddr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, Instant};

type SharedKey = Arc<RwLock<Arc<CertifiedKey>>>;

#[derive(Debug)]
struct SniResolver {
    default: SharedKey,
    names: HashMap<String, SharedKey>,
    wildcards: Vec<(String, SharedKey)>,
}

fn current_key(key: &SharedKey) -> Arc<CertifiedKey> {
    key.read().unwrap_or_else(|e| e.into_inner()).clone()
}

struct OcspRefresh {
    chain: Vec<CertificateDer<'static>>,
    force_url: Option<String>,
    timeout: Duration,
    interval: Duration,
    cache_path: PathBuf,
    // A refresher must not keep a retired TLS generation alive forever.
    key: Weak<RwLock<Arc<CertifiedKey>>>,
}

fn normalize_name(name: &str) -> String {
    let name = name.trim();
    let name = if let Some(rest) = name.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else if name.matches(':').count() == 1 {
        name.split(':').next().unwrap_or(name)
    } else {
        name
    };
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn wildcard_name_matches(name: &str, suffix: &str) -> bool {
    name.strip_suffix(&format!(".{suffix}"))
        .is_some_and(|prefix| !prefix.is_empty() && !prefix.contains('.'))
}

impl SniResolver {
    fn select_key(&self, name: Option<&str>) -> Arc<CertifiedKey> {
        let Some(name) = name else {
            return current_key(&self.default);
        };
        let name = normalize_name(name);
        if let Some(key) = self.names.get(&name) {
            return current_key(key);
        }
        for (suffix, key) in &self.wildcards {
            if wildcard_name_matches(&name, suffix) {
                return current_key(key);
            }
        }
        current_key(&self.default)
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.select_key(hello.server_name()))
    }
}

fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    crate::fault::hit("tls.cert.read")
        .map_err(|e| format!("cannot open certificate {}: {e}", path.display()))?;
    let data = std::fs::read(path)
        .map_err(|e| format!("cannot open certificate {}: {e}", path.display()))?;
    let certs = CertificateDer::pem_slice_iter(&data)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse certificate {}: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("no PEM certificates found in {}", path.display()));
    }
    Ok(certs)
}

fn read_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    crate::fault::hit("tls.key.read")
        .map_err(|e| format!("cannot open private key {}: {e}", path.display()))?;
    let data = std::fs::read(path)
        .map_err(|e| format!("cannot open private key {}: {e}", path.display()))?;
    PrivateKeyDer::from_pem_slice(&data).map_err(|e| match e {
        PemError::NoItemsFound => format!("no PEM private key found in {}", path.display()),
        _ => format!("cannot parse private key {}: {e}", path.display()),
    })
}

fn load_key(
    ssl: &SslConfig,
    provider: &CryptoProvider,
    cache_dir: Option<&Path>,
) -> Result<(Arc<CertifiedKey>, Option<OcspRefresh>), String> {
    let cert_file = ssl
        .cert_file
        .as_ref()
        .ok_or_else(|| "SSLEngine is on but SSLCertificateFile is missing".to_string())?;
    let mut chain = read_certs(cert_file)?;
    if let Some(chain_file) = &ssl.chain_file {
        chain.extend(read_certs(chain_file)?);
    }
    // Apache permits the private key to be concatenated into the certificate
    // file; fall back to that when SSLCertificateKeyFile is absent.
    let key_file = ssl.key_file.as_ref().unwrap_or(cert_file);
    let key = read_key(key_file)?;
    let mut refresh = None;
    let ocsp = if ssl.stapling {
        let timeout = if ssl.stapling_responder_timeout.is_zero() {
            Duration::from_secs(5)
        } else {
            ssl.stapling_responder_timeout
        };
        let dir = cache_dir
            .map(Path::to_path_buf)
            .unwrap_or_else(|| std::env::temp_dir().join("vapache-ocsp-cache"));
        let cache_path = crate::ocsp::cache_path(&dir, &chain, ssl.stapling_force_url.as_deref());
        let cached = crate::ocsp::load_cached(&cache_path);
        let fetched =
            crate::ocsp::staple_response(&chain, ssl.stapling_force_url.as_deref(), timeout);
        let response = if let Some(fresh) = fetched {
            crate::ocsp::save_cached(&cache_path, &fresh);
            Some(fresh)
        } else {
            cached
        };
        if response.is_none() {
            eprintln!(
                "vapache: OCSP stapling requested but no response could be fetched for {}",
                cert_file.display()
            );
        }
        let interval = if ssl.stapling_standard_cache_timeout.is_zero() {
            Duration::from_secs(3600)
        } else {
            ssl.stapling_standard_cache_timeout
        };
        refresh = Some((chain.clone(), cache_path, interval, timeout));
        response
    } else {
        None
    };
    let mut certified = CertifiedKey::from_der(chain, key, provider)
        .map_err(|e| format!("invalid TLS certificate/key pair: {e}"))?;
    certified.ocsp = ocsp;
    let certified = Arc::new(certified);
    let refresh = refresh.map(|(chain, cache_path, interval, timeout)| OcspRefresh {
        chain,
        force_url: ssl.stapling_force_url.clone(),
        timeout,
        interval,
        cache_path,
        key: Weak::new(),
    });
    Ok((certified, refresh))
}

fn apply_ocsp_response(refresh: &OcspRefresh, response: Vec<u8>) -> bool {
    let Some(shared) = refresh.key.upgrade() else {
        return false;
    };
    crate::ocsp::save_cached(&refresh.cache_path, &response);
    let mut guard = shared.write().unwrap_or_else(|e| e.into_inner());
    let mut key = (**guard).clone();
    key.ocsp = Some(response);
    *guard = Arc::new(key);
    true
}

fn wait_for_refresh(refresh: &OcspRefresh) -> bool {
    let deadline = Instant::now() + refresh.interval;
    loop {
        if refresh.key.upgrade().is_none() {
            return false;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return true;
        }
        // Poll generation liveness so reloads do not leave hour-long sleeper
        // threads behind.  This is not a network polling interval.
        std::thread::sleep(remaining.min(Duration::from_secs(1)));
    }
}

fn ocsp_refresh_loop<F, G>(refresh: OcspRefresh, mut fetch: F, mut keep_going: G)
where
    F: FnMut(&OcspRefresh) -> Option<Vec<u8>>,
    G: FnMut(&OcspRefresh) -> bool,
{
    while keep_going(&refresh) {
        if let Some(response) = fetch(&refresh) {
            if !apply_ocsp_response(&refresh, response) {
                break;
            }
        }
    }
}

fn spawn_ocsp_refresh(refresh: OcspRefresh) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        ocsp_refresh_loop(
            refresh,
            |refresh| {
                crate::ocsp::fetch_fresh(
                    &refresh.chain,
                    refresh.force_url.as_deref(),
                    refresh.timeout,
                )
            },
            wait_for_refresh,
        )
    })
}

fn protocol_versions(spec: Option<&str>) -> Result<Vec<&'static SupportedProtocolVersion>, String> {
    let mut tls12 = true;
    let mut tls13 = true;
    let mut replaced = false;
    if let Some(spec) = spec {
        for raw in spec.split_whitespace() {
            let (enable, bare, name) = match raw.as_bytes().first() {
                Some(b'+') => (true, false, &raw[1..]),
                Some(b'-') => (false, false, &raw[1..]),
                _ => (true, true, raw),
            };
            // Apache: a bare protocol list replaces the default; + and -
            // modify it.  We only implement TLS 1.2/1.3.
            if bare && !replaced {
                tls12 = false;
                tls13 = false;
                replaced = true;
            }
            match name.to_ascii_lowercase().as_str() {
                "all" => {
                    tls12 = enable;
                    tls13 = enable;
                }
                "tlsv1.2" => tls12 = enable,
                "tlsv1.3" => tls13 = enable,
                // SSLv2/3 and TLS 1.0/1.1 are intentionally unsupported.
                "sslv2" | "sslv3" | "tlsv1" | "tlsv1.1" => {}
                other => {
                    return Err(format!("unsupported SSLProtocol token '{other}'"));
                }
            }
        }
    }
    if !tls12 && !tls13 {
        return Err("SSLProtocol disables both TLS 1.2 and TLS 1.3".into());
    }
    let mut out = Vec::new();
    if tls12 {
        out.push(&rustls::version::TLS12);
    }
    if tls13 {
        out.push(&rustls::version::TLS13);
    }
    Ok(out)
}

/// Exercise the vapache-owned SNI normalization/wildcard and TLS protocol
/// policy parsers.  rustls itself has separate cryptographic fuzzing; this
/// target covers the configuration-to-resolver boundary specific to vapache.
#[cfg(feature = "fuzzing")]
pub fn fuzz_tls_policy(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let normalized = normalize_name(text);
    let _ = protocol_versions(Some(text));
    for raw_suffix in text.split(|ch: char| ch.is_ascii_whitespace() || ch == ',') {
        let suffix = normalize_name(raw_suffix.trim_start_matches("*."));
        let _ = wildcard_name_matches(&normalized, &suffix);
    }
}

fn vhost_applies(v: &VHost, port: u16, local_ip: Option<IpAddr>) -> bool {
    match local_ip {
        Some(ip) => Config::vhost_address_applies(v, ip, port),
        None => v.addrs.iter().any(|a| vhost_port(a) == port),
    }
}

/// The client-certificate policy that Rustls applies to a listener.  A single
/// `ServerConfig` has one client-certificate verifier, so vhosts that disagree
/// cannot safely share a listener: doing so would either demand a certificate
/// from a public vhost or accept one on a vhost that requires it.
fn client_policy_mode(ssl: &SslConfig) -> u8 {
    match ssl.verify_client {
        None => 0,
        Some(crate::config::ClientVerify::None) => 1,
        Some(crate::config::ClientVerify::Optional) => 2,
        Some(crate::config::ClientVerify::Require) => 3,
    }
}

fn client_policy_key(ssl: &SslConfig) -> (u8, Option<Vec<u8>>) {
    (
        client_policy_mode(ssl),
        ssl.ca_file
            .as_ref()
            .map(|path| path.as_os_str().as_bytes().to_vec()),
    )
}

fn client_policy_equal(a: &(u8, Option<Vec<u8>>), b: &(u8, Option<Vec<u8>>)) -> bool {
    let (a_mode, a_ca) = a;
    let (b_mode, b_ca) = b;
    vapache_verified::tls_client_policy_equal(
        *a_mode,
        a_ca.is_some(),
        a_ca.as_deref().unwrap_or(&[]),
        *b_mode,
        b_ca.is_some(),
        b_ca.as_deref().unwrap_or(&[]),
    )
}

fn ensure_uniform_client_policy(policies: &[&SslConfig], port: u16) -> Result<(), String> {
    let Some(first) = policies.first() else {
        return Ok(());
    };
    let expected = client_policy_key(first);
    for ssl in policies.iter().skip(1) {
        if !client_policy_equal(&expected, &client_policy_key(ssl)) {
            return Err(format!(
                "TLS port {port} has virtual hosts with different client-certificate policies;                  use separate Listen directives so SSLVerifyClient/SSLCACertificateFile cannot                  be applied across vhosts"
            ));
        }
    }
    Ok(())
}

/// Build the TLS configuration for a listening port, if any virtual host on
/// that port has `SSLEngine on` (or a global SSLEngine is configured).
/// `local_ip` filters address-bound vhosts when the listener itself is bound
/// to a specific destination address.
pub fn server_config(
    cfg: &Config,
    port: u16,
    local_ip: Option<IpAddr>,
) -> Result<Option<Arc<ServerConfig>>, String> {
    let provider = Arc::new(ring::default_provider());
    let mut vhosts: Vec<&VHost> = cfg
        .vhosts
        .iter()
        .filter(|v| v.ssl.engine && vhost_applies(v, port, local_ip))
        .collect();
    if let Some(ip) = local_ip {
        let exact_available = vhosts
            .iter()
            .any(|v| Config::vhost_address_is_specific(v, ip, port));
        vhosts.retain(|v| !exact_available || Config::vhost_address_is_specific(v, ip, port));
    }
    let global_only = cfg.ssl.engine && vhosts.is_empty();
    if vhosts.is_empty() && !global_only {
        return Ok(None);
    }
    let policies: Vec<&SslConfig> = vhosts.iter().map(|v| &v.ssl).collect();
    ensure_uniform_client_policy(&policies, port)?;

    // Apache's first matching virtual host is the default server.
    let default_ssl = if global_only {
        &cfg.ssl
    } else {
        &vhosts[0].ssl
    };
    // Keep privileged stapling state directly below the root-owned ServerRoot,
    // not below a legacy logs directory that older releases handed to the
    // service account.
    let ocsp_cache_dir = cfg.server_root.join(".vapache-ocsp-cache");
    let (default_cert, default_refresh) = load_key(default_ssl, &provider, Some(&ocsp_cache_dir))?;
    let default_key: SharedKey = Arc::new(RwLock::new(default_cert));
    if let Some(mut refresh) = default_refresh {
        refresh.key = Arc::downgrade(&default_key);
        let _ = spawn_ocsp_refresh(refresh);
    }
    let mut resolver = SniResolver {
        default: default_key.clone(),
        names: HashMap::new(),
        wildcards: Vec::new(),
    };
    if global_only {
        // No SNI names are known; the global certificate is the only key.
    } else {
        // The default vhost may be repeated; insert names for every TLS vhost.
        for v in vhosts.drain(..) {
            let key = if std::ptr::eq(&v.ssl, default_ssl) {
                default_key.clone()
            } else {
                let (cert, refresh) = load_key(&v.ssl, &provider, Some(&ocsp_cache_dir))?;
                let shared = Arc::new(RwLock::new(cert));
                if let Some(mut refresh) = refresh {
                    refresh.key = Arc::downgrade(&shared);
                    let _ = spawn_ocsp_refresh(refresh);
                }
                shared
            };
            let mut names = Vec::new();
            if let Some(n) = &v.server_name {
                names.push(n.clone());
            }
            names.extend(v.aliases.iter().cloned());
            for raw in names {
                let name = normalize_name(&raw);
                if name.is_empty() || name == "*" || name.starts_with('_') {
                    continue;
                }
                if let Some(suffix) = name.strip_prefix("*.") {
                    if !suffix.is_empty() {
                        resolver.wildcards.push((suffix.to_string(), key.clone()));
                    }
                } else if let Some(suffix) = name.strip_prefix('.') {
                    if !suffix.is_empty() {
                        resolver.wildcards.push((suffix.to_string(), key.clone()));
                    }
                } else {
                    resolver.names.insert(name, key.clone());
                }
            }
        }
    }

    let versions = protocol_versions(default_ssl.protocols.as_deref())?;
    let verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> = match default_ssl
        .verify_client
        .unwrap_or(crate::config::ClientVerify::None)
    {
        crate::config::ClientVerify::None => Arc::new(rustls::server::NoClientAuth),
        mode => {
            let ca = default_ssl
                .ca_file
                .as_ref()
                .ok_or_else(|| "SSLVerifyClient requires SSLCACertificateFile".to_string())?;
            let mut roots = RootCertStore::empty();
            for cert in read_certs(ca)? {
                roots
                    .add(cert)
                    .map_err(|e| format!("invalid client CA certificate: {e}"))?;
            }
            let builder = WebPkiClientVerifier::builder(Arc::new(roots));
            let builder = if mode == crate::config::ClientVerify::Optional {
                builder.allow_unauthenticated()
            } else {
                builder
            };
            builder
                .build()
                .map_err(|e| format!("invalid client certificate verifier: {e}"))?
        }
    };
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|e| format!("invalid TLS protocol configuration: {e}"))?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(resolver));
    // Prefer HTTP/2; clients that do not offer h2 fall back to HTTP/1.1.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Some(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_selection_is_safe() {
        assert_eq!(protocol_versions(None).unwrap().len(), 2);
        assert_eq!(protocol_versions(Some("TLSv1.2")).unwrap().len(), 1);
        assert_eq!(protocol_versions(Some("-TLSv1.3")).unwrap().len(), 1);
        assert_eq!(protocol_versions(Some("+TLSv1.2")).unwrap().len(), 2);
        assert!(protocol_versions(Some("-TLSv1.2 -TLSv1.3")).is_err());
        assert!(
            protocol_versions(Some("all -SSLv3 -TLSv1 -TLSv1.1"))
                .unwrap()
                .len()
                == 2
        );
        assert!(protocol_versions(Some("bogus")).is_err());
    }

    #[test]
    fn missing_certificate_is_an_error() {
        let provider = ring::default_provider();
        assert!(load_key(&SslConfig::default(), &provider, None).is_err());
        let ssl = SslConfig {
            engine: true,
            cert_file: Some("/does/not/exist.pem".into()),
            ..SslConfig::default()
        };
        assert!(load_key(&ssl, &provider, None).is_err());
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn injected_certificate_and_key_reads_fail_closed() {
        let dir = tempdir("read-failpoints");
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, b"not reached").unwrap();
        std::fs::write(&key, b"not reached").unwrap();

        crate::fault::configure("tls.cert.read", 0, std::io::ErrorKind::PermissionDenied);
        assert!(read_certs(&cert)
            .unwrap_err()
            .contains("injected failure at tls.cert.read"));

        crate::fault::configure("tls.key.read", 0, std::io::ErrorKind::PermissionDenied);
        assert!(read_key(&key)
            .unwrap_err()
            .contains("injected failure at tls.key.read"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn vhosts_cannot_share_a_listener_with_different_client_auth_policy() {
        let none = SslConfig::default();
        let require = SslConfig {
            verify_client: Some(crate::config::ClientVerify::Require),
            ca_file: Some("/etc/client-ca.pem".into()),
            ..SslConfig::default()
        };
        assert!(ensure_uniform_client_policy(&[&none, &none], 443).is_ok());
        assert!(ensure_uniform_client_policy(&[&none, &require], 443).is_err());
        let require2 = SslConfig {
            verify_client: Some(crate::config::ClientVerify::Require),
            ca_file: Some("/etc/client-ca.pem".into()),
            ..SslConfig::default()
        };
        assert!(ensure_uniform_client_policy(&[&require, &require2], 443).is_ok());
        let require3 = SslConfig {
            verify_client: Some(crate::config::ClientVerify::Require),
            ca_file: Some("/etc/other-ca.pem".into()),
            ..SslConfig::default()
        };
        assert!(ensure_uniform_client_policy(&[&require, &require3], 443).is_err());
    }

    #[test]
    fn sni_names_are_normalized() {
        assert_eq!(normalize_name("Example.COM:443"), "example.com");
        assert_eq!(normalize_name("[::1]:443"), "::1");
        assert_eq!(normalize_name("host.example."), "host.example");
    }

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vapache-tls-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_cert(dir: &Path) -> (PathBuf, PathBuf) {
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,DNS:*.example.test,IP:127.0.0.1",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-keyout",
                key.to_str().unwrap(),
                "-out",
                cert.to_str().unwrap(),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("openssl");
        assert!(status.success());
        (cert, key)
    }

    fn test_config(dir: &Path, text: &str) -> Config {
        let path = dir.join("httpd.conf");
        std::fs::write(&path, text).unwrap();
        Config::load(&path, dir, &Default::default(), &Default::default(), false).unwrap()
    }

    #[test]
    fn certificate_and_key_parsing_errors_are_closed() {
        let dir = tempdir("parse");
        let empty = dir.join("empty.pem");
        std::fs::write(&empty, "").unwrap();
        assert!(read_certs(&empty)
            .unwrap_err()
            .contains("no PEM certificates"));
        assert!(read_key(&empty).unwrap_err().contains("no PEM private key"));

        let garbage = dir.join("garbage.pem");
        std::fs::write(&garbage, "not a pem file\n").unwrap();
        assert!(read_certs(&garbage).is_err());
        assert!(read_key(&garbage).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_key_uses_cached_ocsp_and_zero_timeout_defaults() {
        let dir = tempdir("ocsp");
        let (cert, key) = make_cert(&dir);
        let chain = read_certs(&cert).unwrap();
        let force_url = Some("http://127.0.0.1:1/");
        let cache_dir = dir.join("cache");
        let cache_path = crate::ocsp::cache_path(&cache_dir, &chain, force_url);
        crate::ocsp::save_cached(&cache_path, &crate::ocsp::test_successful_response());
        let ssl = SslConfig {
            engine: true,
            cert_file: Some(cert.clone()),
            key_file: Some(key),
            chain_file: Some(cert),
            stapling: true,
            stapling_force_url: force_url.map(str::to_string),
            stapling_responder_timeout: Duration::ZERO,
            stapling_standard_cache_timeout: Duration::ZERO,
            ..SslConfig::default()
        };
        let provider = ring::default_provider();
        let (certified, refresh) = load_key(&ssl, &provider, Some(&cache_dir)).unwrap();
        assert!(certified.ocsp.is_some());
        assert!(refresh.is_some());

        // Non-zero responder timeout with no cached response exercises the
        // warning path and returns a refresh handle with no initial staple.
        let no_cache = dir.join("no-cache");
        let ssl = SslConfig {
            engine: true,
            cert_file: Some(dir.join("cert.pem")),
            key_file: Some(dir.join("key.pem")),
            stapling: true,
            stapling_force_url: force_url.map(str::to_string),
            stapling_responder_timeout: Duration::from_millis(1),
            stapling_standard_cache_timeout: Duration::from_millis(1),
            ..SslConfig::default()
        };
        let (certified, refresh) = load_key(&ssl, &provider, Some(&no_cache)).unwrap();
        assert!(certified.ocsp.is_none());
        assert!(refresh.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ocsp_refresh_loop_applies_a_response_and_spawn_is_bounded() {
        let dir = tempdir("ocsp-loop");
        let (cert, key) = make_cert(&dir);
        let ssl = SslConfig {
            engine: true,
            cert_file: Some(cert),
            key_file: Some(key),
            stapling: true,
            stapling_responder_timeout: Duration::from_millis(1),
            stapling_standard_cache_timeout: Duration::from_millis(1),
            ..SslConfig::default()
        };
        let provider = ring::default_provider();
        let (certified, refresh) = load_key(&ssl, &provider, Some(&dir)).unwrap();
        let mut refresh = refresh.expect("refresh handle");
        let shared = Arc::new(RwLock::new(certified));
        refresh.key = Arc::downgrade(&shared);
        refresh.interval = Duration::ZERO;
        let mut iterations = 0;
        ocsp_refresh_loop(
            refresh,
            |_| Some(crate::ocsp::test_successful_response()),
            |_| {
                iterations += 1;
                iterations == 1
            },
        );
        assert_eq!(iterations, 2);

        // The production spawn wrapper is covered; the thread sleeps on the
        // default interval and is reclaimed when the test process exits.
        let (cert, key) = make_cert(&dir);
        let ssl = SslConfig {
            engine: true,
            cert_file: Some(cert),
            key_file: Some(key),
            stapling: true,
            stapling_standard_cache_timeout: Duration::from_secs(3600),
            ..SslConfig::default()
        };
        let (_certified, refresh) = load_key(&ssl, &provider, Some(&dir)).unwrap();
        if let Some(mut refresh) = refresh {
            let shared = Arc::new(RwLock::new(_certified));
            refresh.key = Arc::downgrade(&shared);
            let thread = spawn_ocsp_refresh(refresh);
            drop(shared);
            thread.join().unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sni_selection_and_client_policy_modes_are_explicit() {
        let dir = tempdir("sni");
        let (cert, key) = make_cert(&dir);
        let provider = ring::default_provider();
        let ssl = SslConfig {
            engine: true,
            cert_file: Some(cert),
            key_file: Some(key),
            ..SslConfig::default()
        };
        let (first, _) = load_key(&ssl, &provider, None).unwrap();
        let (second, _) = load_key(&ssl, &provider, None).unwrap();
        let first = Arc::new(RwLock::new(first));
        let second = Arc::new(RwLock::new(second));
        let resolver = SniResolver {
            default: first.clone(),
            names: HashMap::from([("exact.test".to_string(), second.clone())]),
            wildcards: vec![("example.test".to_string(), second.clone())],
        };
        let default_key = current_key(&first);
        let second_key = current_key(&second);
        assert!(Arc::ptr_eq(&resolver.select_key(None), &default_key));
        assert!(Arc::ptr_eq(
            &resolver.select_key(Some("exact.test")),
            &second_key
        ));
        assert!(Arc::ptr_eq(
            &resolver.select_key(Some("single.example.test")),
            &second_key
        ));
        assert!(Arc::ptr_eq(
            &resolver.select_key(Some("multi.label.example.test")),
            &default_key
        ));
        assert!(Arc::ptr_eq(
            &resolver.select_key(Some("unknown.test")),
            &default_key
        ));

        assert_eq!(client_policy_mode(&SslConfig::default()), 0);
        assert_eq!(
            client_policy_mode(&SslConfig {
                verify_client: Some(crate::config::ClientVerify::None),
                ..SslConfig::default()
            }),
            1
        );
        assert_eq!(
            client_policy_mode(&SslConfig {
                verify_client: Some(crate::config::ClientVerify::Optional),
                ..SslConfig::default()
            }),
            2
        );
        assert_eq!(
            client_policy_mode(&SslConfig {
                verify_client: Some(crate::config::ClientVerify::Require),
                ..SslConfig::default()
            }),
            3
        );
        assert!(ensure_uniform_client_policy(&[], 443).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn server_config_covers_global_vhost_sni_and_optional_client_auth() {
        let dir = tempdir("server-config");
        let (cert, key) = make_cert(&dir);
        let cert_s = cert.display();
        let key_s = key.display();

        let none = test_config(&dir, "Listen 127.0.0.1:444\n");
        assert!(server_config(&none, 444, None).unwrap().is_none());

        let global = test_config(
            &dir,
            &format!(
                "Listen 127.0.0.1:443\nSSLEngine on\nSSLCertificateFile \"{cert_s}\"\nSSLCertificateKeyFile \"{key_s}\"\n"
            ),
        );
        assert!(server_config(&global, 443, None).unwrap().is_some());

        let vhosts = test_config(
            &dir,
            &format!(
                "Listen 127.0.0.1:443\n\
                 <VirtualHost *:443>\n\
                     ServerName a.test\n\
                     ServerAlias *.example.test .example.test _default_ *\n\
                     SSLEngine on\n\
                     SSLCertificateFile \"{cert_s}\"\n\
                     SSLCertificateKeyFile \"{key_s}\"\n\
                 </VirtualHost>\n\
                 <VirtualHost *:443>\n\
                     ServerName b.test\n\
                     SSLEngine on\n\
                     SSLUseStapling on\n\
                     SSLStaplingStandardCacheTimeout 3600\n\
                     SSLCertificateFile \"{cert_s}\"\n\
                     SSLCertificateKeyFile \"{key_s}\"\n\
                 </VirtualHost>\n"
            ),
        );
        assert!(server_config(&vhosts, 443, None).unwrap().is_some());

        let address_bound = test_config(
            &dir,
            &format!(
                "Listen 0.0.0.0:443\n\
                 <VirtualHost 127.0.0.1:443>\n\
                     ServerName admin.test\n\
                     SSLEngine on\n\
                     SSLCertificateFile \"{cert_s}\"\n\
                     SSLCertificateKeyFile \"{key_s}\"\n\
                 </VirtualHost>\n\
                 <VirtualHost *:443>\n\
                     ServerName public.test\n\
                     SSLEngine on\n\
                     SSLCertificateFile \"{cert_s}\"\n\
                     SSLCertificateKeyFile \"{key_s}\"\n\
                 </VirtualHost>\n"
            ),
        );
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let other: IpAddr = "127.0.0.2".parse().unwrap();
        assert!(vhost_applies(&address_bound.vhosts[0], 443, Some(loopback)));
        assert!(!vhost_applies(&address_bound.vhosts[0], 443, Some(other)));
        assert!(vhost_applies(&address_bound.vhosts[1], 443, Some(other)));
        assert!(server_config(&address_bound, 443, Some(loopback))
            .unwrap()
            .is_some());
        assert!(server_config(&address_bound, 443, Some(other))
            .unwrap()
            .is_some());

        for mode in ["optional", "require"] {
            let cfg = test_config(
                &dir,
                &format!(
                    "Listen 127.0.0.1:443\n\
                     SSLEngine on\n\
                     SSLCertificateFile \"{cert_s}\"\n\
                     SSLCertificateKeyFile \"{key_s}\"\n\
                     SSLVerifyClient {mode}\n\
                     SSLCACertificateFile \"{cert_s}\"\n"
                ),
            );
            assert!(server_config(&cfg, 443, None).unwrap().is_some(), "{mode}");
        }

        let missing_ca = test_config(
            &dir,
            &format!(
                "Listen 127.0.0.1:443\n\
                 SSLEngine on\n\
                 SSLCertificateFile \"{cert_s}\"\n\
                 SSLCertificateKeyFile \"{key_s}\"\n\
                 SSLVerifyClient require\n"
            ),
        );
        assert!(server_config(&missing_ca, 443, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
