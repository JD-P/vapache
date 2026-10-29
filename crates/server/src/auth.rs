//! HTTP Basic authentication (`mod_auth_basic` + `mod_authn_file`).
//!
//! Only password *verification* is implemented; plaintext passwords are
//! never accepted.  Supported htpasswd encodings are Apache MD5 (`$apr1$`),
//! Unix MD5 (`$1$`), bcrypt (`$2*$`), `{SHA}` and salted `{SSHA}`.
//! Anything else fails closed.

use crate::access::Identity;
use crate::config::Scope;
use crate::http::Request;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use md5::Md5;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

const MAX_PASSWORD_FILE: u64 = 4 * 1024 * 1024;
const MAX_AUTH_CACHE_BYTES: usize = 16 * 1024 * 1024;
const MAX_AUTH_CACHE_ENTRIES: usize = 128;

const CRYPT_ALPHABET: &[u8; 64] =
    b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Verify the request's Basic credentials against `AuthUserFile`.  Returns
/// `None` for missing, malformed, unsupported or non-matching credentials.
pub fn authenticate(scope: &Scope, req: &Request) -> Option<Identity> {
    if !scope
        .authorization
        .auth_type
        .as_deref()
        .map(|t| t.eq_ignore_ascii_case("basic"))
        .unwrap_or(false)
    {
        return None;
    }
    let header = req.header_str("authorization")?.trim();
    let mut parts = header.splitn(2, char::is_whitespace);
    let scheme = parts.next()?;
    let token = parts.next()?.trim();
    if !scheme.eq_ignore_ascii_case("basic") || token.is_empty() {
        return None;
    }
    let decoded = STANDARD
        .decode(token)
        .or_else(|_| STANDARD_NO_PAD.decode(token))
        .ok()?;
    let colon = decoded.iter().position(|b| *b == b':')?;
    let user = std::str::from_utf8(&decoded[..colon]).ok()?;
    let password = &decoded[colon + 1..];
    if user.is_empty()
        || user.chars().any(|c| c.is_control())
        || user.contains(':')
        || password.len() > 4096
    {
        return None;
    }
    let file = scope.authorization.auth_user_file.as_ref()?;
    let stored = lookup_user(file, user)?;
    if !verify_password(password, &stored) {
        return None;
    }
    let groups = scope
        .authorization
        .auth_group_file
        .as_ref()
        .map(|p| groups_for(p, user))
        .unwrap_or_default();
    Some(Identity {
        user: user.to_string(),
        groups,
    })
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct AuthFileKey {
    path: PathBuf,
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[derive(Default)]
struct AuthFileCache {
    entries: HashMap<AuthFileKey, (Arc<String>, usize)>,
    bytes: usize,
}

fn auth_file_cache() -> &'static Mutex<AuthFileCache> {
    static CACHE: OnceLock<Mutex<AuthFileCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(AuthFileCache::default()))
}

fn auth_key(path: &Path, meta: &std::fs::Metadata) -> AuthFileKey {
    AuthFileKey {
        path: path.to_path_buf(),
        dev: meta.dev(),
        ino: meta.ino(),
        size: meta.len(),
        mtime: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
        ctime: meta.ctime(),
        ctime_nsec: meta.ctime_nsec(),
    }
}

fn read_small(path: &Path) -> Option<Arc<String>> {
    let file = File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_PASSWORD_FILE {
        return None;
    }
    let key = auth_key(path, &meta);
    if let Some(data) = auth_file_cache()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .entries
        .get(&key)
        .map(|(data, _)| Arc::clone(data))
    {
        return Some(data);
    }
    let data = Arc::new(read_bounded(&file)?);
    let after = file.metadata().ok()?;
    if auth_key(path, &after) != key {
        return None;
    }
    let weight = data
        .len()
        .saturating_add(path.as_os_str().as_encoded_bytes().len())
        .saturating_add(128);
    if weight <= MAX_AUTH_CACHE_BYTES {
        let mut cache = auth_file_cache()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let stale: Vec<AuthFileKey> = cache
            .entries
            .keys()
            .filter(|candidate| candidate.path == path && *candidate != &key)
            .cloned()
            .collect();
        for stale_key in stale {
            if let Some((_, old_weight)) = cache.entries.remove(&stale_key) {
                cache.bytes = cache.bytes.saturating_sub(old_weight);
            }
        }
        while cache.entries.len() >= MAX_AUTH_CACHE_ENTRIES
            || cache.bytes.saturating_add(weight) > MAX_AUTH_CACHE_BYTES
        {
            let Some(victim) = cache.entries.keys().next().cloned() else {
                break;
            };
            if let Some((_, old_weight)) = cache.entries.remove(&victim) {
                cache.bytes = cache.bytes.saturating_sub(old_weight);
            }
        }
        cache.bytes = cache.bytes.saturating_add(weight);
        cache.entries.insert(key, (Arc::clone(&data), weight));
    }
    Some(data)
}

fn read_bounded(reader: impl Read) -> Option<String> {
    let mut data = Vec::new();
    reader
        .take(MAX_PASSWORD_FILE + 1)
        .read_to_end(&mut data)
        .ok()?;
    if data.len() as u64 > MAX_PASSWORD_FILE {
        return None;
    }
    Some(String::from_utf8_lossy(&data).into_owned())
}

fn lookup_user(path: &Path, user: &str) -> Option<String> {
    let data = read_small(path)?;
    let mut found = None;
    for line in data.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, hash)) = line.split_once(':') else {
            continue;
        };
        if name == user {
            if found.is_some() {
                // Ambiguous duplicate entry: fail rather than pick one.
                return None;
            }
            found = Some(hash.trim_end_matches('\r').to_string());
        }
    }
    found
}

fn groups_for(path: &Path, user: &str) -> Vec<String> {
    let Some(data) = read_small(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in data.lines() {
        let Some((group, members)) = line.split_once(':') else {
            continue;
        };
        if members.split_whitespace().any(|m| m == user) {
            out.push(group.trim().to_string());
        }
    }
    out
}

fn verify_password(password: &[u8], stored: &str) -> bool {
    let stored = stored.trim();
    if let Some(encoded) = stored.strip_prefix("{SHA}") {
        let Ok(expected) = STANDARD
            .decode(encoded)
            .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        else {
            return false;
        };
        return Sha1::digest(password).as_slice() == expected.as_slice();
    }
    if let Some(encoded) = stored.strip_prefix("{SSHA}") {
        let Ok(decoded) = STANDARD
            .decode(encoded)
            .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        else {
            return false;
        };
        if decoded.len() < 20 {
            return false;
        }
        let mut h = Sha1::new();
        h.update(password);
        h.update(&decoded[20..]);
        return h.finalize().as_slice() == &decoded[..20];
    }
    if stored.starts_with("$apr1$") {
        let Some(_expensive) = crate::resource::try_expensive() else {
            return false;
        };
        return md5_crypt_matches(password, stored, "$apr1$");
    }
    if stored.starts_with("$1$") {
        let Some(_expensive) = crate::resource::try_expensive() else {
            return false;
        };
        return md5_crypt_matches(password, stored, "$1$");
    }
    if stored.starts_with("$2a$")
        || stored.starts_with("$2b$")
        || stored.starts_with("$2x$")
        || stored.starts_with("$2y$")
    {
        let cost = stored
            .split('$')
            .nth(2)
            .and_then(|cost| cost.parse::<u32>().ok())
            .unwrap_or(u32::MAX);
        if !vapache_verified::bcrypt_cost_admit(cost) {
            return false;
        }
        let Some(_expensive) = crate::resource::try_expensive() else {
            return false;
        };
        let Ok(password) = std::str::from_utf8(password) else {
            return false;
        };
        return bcrypt::verify(password, stored).unwrap_or(false);
    }
    false
}

fn md5_crypt_matches(password: &[u8], stored: &str, magic: &str) -> bool {
    let Some(rest) = stored.strip_prefix(magic) else {
        return false;
    };
    let Some((salt, _)) = rest.split_once('$') else {
        return false;
    };
    let salt = salt.as_bytes();
    if salt.len() > 8 {
        return false;
    }
    let computed = md5_crypt(password, salt, magic);
    computed == stored
}

fn md5_crypt(password: &[u8], salt: &[u8], magic: &str) -> String {
    let mut ctx = Md5::new();
    ctx.update(password);
    ctx.update(salt);
    ctx.update(password);
    let mut digest = ctx.finalize();

    let mut ctx = Md5::new();
    ctx.update(password);
    ctx.update(magic.as_bytes());
    ctx.update(salt);
    let mut left = password.len();
    while left > 0 {
        let n = left.min(16);
        ctx.update(&digest[..n]);
        left -= n;
    }
    let mut i = password.len();
    while i > 0 {
        if i & 1 != 0 {
            ctx.update([0u8]);
        } else {
            ctx.update(&password[..1]);
        }
        i >>= 1;
    }
    digest = ctx.finalize();

    for i in 0..1000 {
        let mut ctx = Md5::new();
        if i & 1 != 0 {
            ctx.update(password);
        } else {
            ctx.update(digest.as_slice());
        }
        if i % 3 != 0 {
            ctx.update(salt);
        }
        if i % 7 != 0 {
            ctx.update(password);
        }
        if i & 1 != 0 {
            ctx.update(digest.as_slice());
        } else {
            ctx.update(password);
        }
        digest = ctx.finalize();
    }

    let mut out = String::with_capacity(magic.len() + salt.len() + 24);
    out.push_str(magic);
    out.push_str(std::str::from_utf8(salt).unwrap_or(""));
    out.push('$');
    b64_from_24(&mut out, digest[0], digest[6], digest[12], 4);
    b64_from_24(&mut out, digest[1], digest[7], digest[13], 4);
    b64_from_24(&mut out, digest[2], digest[8], digest[14], 4);
    b64_from_24(&mut out, digest[3], digest[9], digest[15], 4);
    b64_from_24(&mut out, digest[4], digest[10], digest[5], 4);
    b64_from_24(&mut out, 0, 0, digest[11], 2);
    out
}

fn b64_from_24(out: &mut String, a: u8, b: u8, c: u8, n: usize) {
    let mut w = ((a as u32) << 16) | ((b as u32) << 8) | c as u32;
    for _ in 0..n {
        out.push(CRYPT_ALPHABET[(w & 0x3f) as usize] as char);
        w >>= 6;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{BodyFraming, Headers, Version};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "vapache-auth-{label}-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn request(authorization: Option<Vec<u8>>) -> Request {
        let mut headers = Headers::default();
        if let Some(value) = authorization {
            headers.insert("Authorization", value);
        }
        Request {
            method: "GET".into(),
            target: b"/".to_vec(),
            raw_path: b"/".to_vec(),
            query: Vec::new(),
            version: Version::Http11,
            headers,
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: BodyFraming::None,
        }
    }

    fn basic(value: &[u8]) -> Vec<u8> {
        format!("Basic {}", STANDARD.encode(value)).into_bytes()
    }

    #[test]
    fn authenticate_rejects_malformed_and_unsafe_credentials() {
        let mut scope = Scope::default();
        assert!(authenticate(&scope, &request(None)).is_none());
        scope.authorization.auth_type = Some("basic".into());
        for header in [
            b"Bearer abc".to_vec(),
            b"Basic ".to_vec(),
            b"Basic %%%".to_vec(),
            basic(b"missing-colon"),
            basic(b"\xff:secret"),
            basic(b":secret"),
            basic(b"bad\nname:secret"),
        ] {
            assert!(authenticate(&scope, &request(Some(header))).is_none());
        }
        let mut oversized = b"alice:".to_vec();
        oversized.extend(std::iter::repeat_n(b'x', 4097));
        assert!(authenticate(&scope, &request(Some(basic(&oversized)))).is_none());
        assert!(authenticate(&scope, &request(Some(basic(b"alice:secret")))).is_none());
    }

    #[test]
    fn authenticate_reads_unique_user_and_groups() {
        let users = temp_path("users");
        let groups = temp_path("groups");
        std::fs::write(
            &users,
            "# comment\nmalformed\nalice:$apr1$gqijKP2Z$nBjZURLWP3/zSfPLTfhVM0\r\n",
        )
        .unwrap();
        std::fs::write(&groups, "malformed\n admins: alice bob\nother: bob\n").unwrap();
        let mut scope = Scope::default();
        scope.authorization.auth_type = Some("BASIC".into());
        scope.authorization.auth_user_file = Some(users.clone());
        scope.authorization.auth_group_file = Some(groups.clone());

        let identity = authenticate(&scope, &request(Some(basic(b"alice:secret")))).unwrap();
        assert_eq!(identity.user, "alice");
        assert_eq!(identity.groups, ["admins"]);
        assert!(authenticate(&scope, &request(Some(basic(b"alice:wrong")))).is_none());
        assert!(authenticate(&scope, &request(Some(basic(b"nobody:secret")))).is_none());

        std::fs::write(
            &users,
            "alice:$apr1$gqijKP2Z$nBjZURLWP3/zSfPLTfhVM0\nalice:duplicate\n",
        )
        .unwrap();
        assert!(authenticate(&scope, &request(Some(basic(b"alice:secret")))).is_none());
        std::fs::remove_file(users).unwrap();
        std::fs::remove_file(groups).unwrap();
    }

    #[test]
    fn password_file_and_hash_error_edges_fail_closed() {
        let directory = temp_path("directory");
        std::fs::create_dir(&directory).unwrap();
        assert!(read_small(&directory).is_none());
        assert!(groups_for(&directory.join("missing"), "alice").is_empty());
        std::fs::remove_dir(directory).unwrap();
        assert!(read_bounded(std::io::Cursor::new(vec![
            b'x';
            MAX_PASSWORD_FILE as usize + 1
        ]))
        .is_none());

        assert!(!verify_password(b"x", "{SHA}%%%"));
        assert!(!verify_password(b"x", "{SSHA}%%%"));
        assert!(!verify_password(b"x", "{SSHA}eA=="));
        assert!(!verify_password(
            b"\xff",
            "$2y$05$lFdvgVrS6ROEENEOjKS5h.y4SA05OvKSOFRPC1BcjARNhNt.DQ8jC"
        ));
        assert!(!verify_password(b"x", "$1$x$bad"));
        assert!(!md5_crypt_matches(b"x", "$1$x$bad", "$apr1$"));
        assert!(!md5_crypt_matches(b"x", "$apr1$missing", "$apr1$"));
        assert!(!md5_crypt_matches(b"x", "$apr1$123456789$bad", "$apr1$"));
    }

    #[test]
    fn apr1_matches_apache_htpasswd() {
        // Generated with `htpasswd -nb alice secret`.
        assert!(verify_password(
            b"secret",
            "$apr1$gqijKP2Z$nBjZURLWP3/zSfPLTfhVM0"
        ));
        assert!(!verify_password(
            b"wrong",
            "$apr1$gqijKP2Z$nBjZURLWP3/zSfPLTfhVM0"
        ));
    }

    #[test]
    fn sha_and_ssha() {
        // echo -n password | openssl dgst -sha1 -binary | base64
        assert!(verify_password(
            b"password",
            "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
        ));
        // Salted SHA variant: 20-byte digest followed by "salt".
        let mut raw = Sha1::digest(b"passwordsalt").to_vec();
        raw.extend_from_slice(b"salt");
        let encoded = STANDARD.encode(raw);
        assert!(verify_password(b"password", &format!("{{SSHA}}{encoded}")));
        assert!(!verify_password(b"nope", &format!("{{SSHA}}{encoded}")));
    }

    #[test]
    fn bcrypt_matches_apache_htpasswd() {
        // Generated with `htpasswd -nbB alice secret`.
        assert!(verify_password(
            b"secret",
            "$2y$05$lFdvgVrS6ROEENEOjKS5h.y4SA05OvKSOFRPC1BcjARNhNt.DQ8jC"
        ));
        assert!(!verify_password(
            b"wrong",
            "$2y$05$lFdvgVrS6ROEENEOjKS5h.y4SA05OvKSOFRPC1BcjARNhNt.DQ8jC"
        ));
        assert!(!verify_password(
            b"secret",
            "$2y$31$lFdvgVrS6ROEENEOjKS5h.y4SA05OvKSOFRPC1BcjARNhNt.DQ8jC"
        ));
    }

    #[test]
    fn unsupported_hashes_fail_closed() {
        assert!(!verify_password(b"password", "password"));
        assert!(!verify_password(b"password", "{PLAIN}password"));
        assert!(!verify_password(b"password", "{CRYPT}xyz"));
    }
}
