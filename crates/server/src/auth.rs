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
use std::fs::File;
use std::io::Read;
use std::path::Path;

const MAX_PASSWORD_FILE: u64 = 4 * 1024 * 1024;

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

fn read_small(path: &Path) -> Option<String> {
    let file = File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_PASSWORD_FILE {
        return None;
    }
    let mut data = Vec::new();
    file.take(MAX_PASSWORD_FILE + 1)
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
        return md5_crypt_matches(password, stored, "$apr1$");
    }
    if stored.starts_with("$1$") {
        return md5_crypt_matches(password, stored, "$1$");
    }
    if stored.starts_with("$2a$")
        || stored.starts_with("$2b$")
        || stored.starts_with("$2x$")
        || stored.starts_with("$2y$")
    {
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
    }

    #[test]
    fn unsupported_hashes_fail_closed() {
        assert!(!verify_password(b"password", "password"));
        assert!(!verify_password(b"password", "{PLAIN}password"));
        assert!(!verify_password(b"password", "{CRYPT}xyz"));
    }
}
