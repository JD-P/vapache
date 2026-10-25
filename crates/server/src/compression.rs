//! Apache-compatible gzip/brotli response filtering.
//!
//! The implementation supports the common `mod_deflate`/`mod_brotli` subset:
//! `SetOutputFilter`, `AddOutputFilterByType`, `AddOutputFilter`,
//! `DeflateCompressionLevel`, `BrotliCompressionQuality` and the ETag-alter
//! settings.  Compression is deliberately skipped for ranges, already encoded
//! bodies, `no-transform` responses and bodies larger than the in-memory cap;
//! `Vary: Accept-Encoding` is still emitted for negotiable representations.

use crate::config::{AlterEtag, CompressionKind, CompressionRule, Scope};
use crate::http::{Body, Request, Response};
use std::borrow::Cow;
use std::io::{Read, Seek, SeekFrom, Write};

const MAX_COMPRESS_BODY: u64 = 8 * 1024 * 1024;
const DEFAULT_DEFLATE_LEVEL: u32 = 6;
const DEFAULT_BROTLI_QUALITY: u32 = 5;

fn header<'a>(resp: &'a Response, name: &str) -> Option<&'a [u8]> {
    resp.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

fn header_str(resp: &Response, name: &str) -> Option<String> {
    header(resp, name).map(|v| String::from_utf8_lossy(v).into_owned())
}

fn remove_header(resp: &mut Response, name: &str) {
    resp.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
}

fn set_header(resp: &mut Response, name: &'static str, value: Vec<u8>) {
    remove_header(resp, name);
    resp.headers.push((Cow::Borrowed(name), value));
}

fn add_vary_value(resp: &mut Response, value: &str) {
    for (name, existing) in &mut resp.headers {
        if name.eq_ignore_ascii_case("vary") {
            let text = String::from_utf8_lossy(existing);
            if text.trim() == "*"
                || text
                    .split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case(value))
            {
                return;
            }
            let mut text = text.into_owned();
            if !text.is_empty() {
                text.push_str(", ");
            }
            text.push_str(value);
            *existing = text.into_bytes();
            return;
        }
    }
    resp.headers
        .push((Cow::Borrowed("Vary"), value.as_bytes().to_vec()));
}

fn add_vary_accept_encoding(resp: &mut Response) {
    for (name, value) in &resp.headers {
        if name.eq_ignore_ascii_case("vary") {
            let text = String::from_utf8_lossy(value);
            if text.trim() == "*"
                || text
                    .split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case("accept-encoding"))
            {
                return;
            }
        }
    }
    for (name, value) in &mut resp.headers {
        if name.eq_ignore_ascii_case("vary") {
            let mut text = String::from_utf8_lossy(value).into_owned();
            if !text.is_empty() {
                text.push_str(", ");
            }
            text.push_str("Accept-Encoding");
            *value = text.into_bytes();
            return;
        }
    }
    resp.headers
        .push((Cow::Borrowed("Vary"), b"Accept-Encoding".to_vec()));
}

fn media_type(resp: &Response) -> Option<String> {
    header_str(resp, "content-type").map(|s| {
        s.split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
    })
}

fn configured_kinds(scope: &Scope, media: Option<&str>, path: &[u8]) -> Vec<CompressionKind> {
    let mut kinds: Vec<CompressionKind> = Vec::new();
    let ext = path
        .rsplit(|b| *b == b'/')
        .next()
        .and_then(|name| {
            name.iter()
                .rposition(|b| *b == b'.')
                .map(|p| &name[p + 1..])
        })
        .map(|e| String::from_utf8_lossy(e).to_ascii_lowercase())
        .unwrap_or_default();

    for rule in &scope.compression_policy.compression_rules {
        match rule {
            CompressionRule::Set(list) => kinds = list.clone(),
            CompressionRule::ByType(kind, types) => {
                let Some(media) = media else { continue };
                if types.iter().any(|t| {
                    let t = t.trim();
                    t == "*" || t.eq_ignore_ascii_case(media)
                }) {
                    kinds.push(*kind);
                }
            }
            CompressionRule::ByExt(kind, exts) => {
                if exts.iter().any(|e| {
                    let e = e.trim().trim_start_matches('.');
                    !e.is_empty() && e.eq_ignore_ascii_case(&ext)
                }) {
                    kinds.push(*kind);
                }
            }
        }
    }
    // Stable de-duplication, preserving configured preference.
    let mut out = Vec::new();
    for k in kinds {
        if !out.contains(&k) {
            out.push(k);
        }
    }
    out
}

fn q_value(value: &str) -> f32 {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix("q=") {
        rest.trim().parse::<f32>().unwrap_or(0.0)
    } else if let Some(rest) = value.strip_prefix("Q=") {
        rest.trim().parse::<f32>().unwrap_or(0.0)
    } else {
        0.0
    }
}

fn accepts_encoding(req: &Request, kind: CompressionKind) -> bool {
    let Some(value) = req.header("accept-encoding") else {
        return false;
    };
    let text = String::from_utf8_lossy(value);
    let wanted = kind.encoding();
    let mut wildcard = 0.0f32;
    let mut explicit: Option<f32> = None;
    for item in text.split(',') {
        let mut parts = item.split(';');
        let name = parts.next().unwrap_or("").trim();
        let q = parts
            .find_map(|p| {
                let p = p.trim();
                if p.to_ascii_lowercase().starts_with('q') {
                    Some(q_value(p))
                } else {
                    None
                }
            })
            .unwrap_or(1.0);
        if name == "*" {
            wildcard = q.max(wildcard);
        } else if name.eq_ignore_ascii_case(wanted)
            || (wanted == "gzip" && name.eq_ignore_ascii_case("x-gzip"))
        {
            explicit = Some(q);
        }
    }
    explicit.unwrap_or(wildcard) > 0.0
}

fn alter_etag(resp: &mut Response, kind: CompressionKind, scope: &Scope) {
    let setting = match kind {
        CompressionKind::Gzip => scope.compression_policy.deflate_alter_etag,
        CompressionKind::Brotli => scope.compression_policy.brotli_alter_etag,
    }
    .unwrap_or(AlterEtag::AddSuffix);
    match setting {
        AlterEtag::NoChange => {}
        AlterEtag::Remove => remove_header(resp, "etag"),
        AlterEtag::AddSuffix => {
            let suffix = format!("-{}", kind.encoding());
            for (name, value) in &mut resp.headers {
                if !name.eq_ignore_ascii_case("etag") {
                    continue;
                }
                let mut text = String::from_utf8_lossy(value).into_owned();
                if text.ends_with(&suffix) || text.ends_with(&format!("{suffix}\"")) {
                    return;
                }
                if let Some(pos) = text.rfind('"') {
                    text.insert_str(pos, &suffix);
                } else {
                    text.push_str(&suffix);
                }
                *value = text.into_bytes();
                return;
            }
        }
    }
}

fn read_body(body: Body) -> Result<(Vec<u8>, Option<Body>), Body> {
    match body {
        Body::Empty => Ok((Vec::new(), None)),
        Body::Bytes(bytes) => Ok((bytes, None)),
        Body::Stream { reader, len } => Err(Body::Stream { reader, len }),
        Body::File {
            mut file,
            offset,
            len,
        } => {
            if !vapache_verified::compression_body_admit(len, MAX_COMPRESS_BODY) {
                return Err(Body::File { file, offset, len });
            }
            if file.seek(SeekFrom::Start(offset)).is_err() {
                return Err(Body::File { file, offset, len });
            }
            let mut bytes = vec![0u8; len as usize];
            if file.read_exact(&mut bytes).is_err() {
                return Err(Body::File { file, offset, len });
            }
            Ok((bytes, None))
        }
    }
}

fn gzip(data: &[u8], level: u32) -> std::io::Result<Vec<u8>> {
    let mut encoder =
        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(level.min(9)));
    encoder.write_all(data)?;
    encoder.finish()
}

fn brotli(data: &[u8], quality: u32) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    {
        let mut encoder = brotli::CompressorWriter::new(&mut out, 4096, quality.min(11), 22);
        encoder.write_all(data)?;
        encoder.flush()?;
        encoder.into_inner();
    }
    Ok(out)
}

/// Apply the configured output filter to a response.
///
/// `path` is the request path used for extension-based `AddOutputFilter`
/// rules.  The function is idempotent: responses already carrying a
/// `Content-Encoding` are left alone.
pub fn finalize(scope: &Scope, req: &Request, resp: &mut Response, path: &[u8]) {
    for value in &scope.header_policy.vary {
        add_vary_value(resp, value);
    }
    for cookie in &scope.header_policy.cookies {
        if !resp.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("set-cookie") && value.as_slice() == cookie.as_bytes()
        }) {
            resp.headers
                .push((Cow::Borrowed("Set-Cookie"), cookie.as_bytes().to_vec()));
        }
    }
    crate::expires::apply(scope, resp);
    if resp.status == 204 || (100..200).contains(&resp.status) {
        return;
    }
    let media = media_type(resp);
    let kinds = configured_kinds(scope, media.as_deref(), path);
    if kinds.is_empty() {
        return;
    }
    add_vary_accept_encoding(resp);

    // Compression changes the representation, so byte ranges and conditional
    // range validators continue to use the identity representation.
    if req.header("range").is_some() || req.header("if-range").is_some() {
        return;
    }
    if header(resp, "content-encoding").is_some() {
        return;
    }
    if let Some(cc) = header_str(resp, "cache-control") {
        if cc
            .split(',')
            .any(|v| v.trim().eq_ignore_ascii_case("no-transform"))
        {
            return;
        }
    }
    let kind = [CompressionKind::Brotli, CompressionKind::Gzip]
        .into_iter()
        .find(|k| kinds.contains(k) && accepts_encoding(req, *k));
    let Some(kind) = kind else {
        return;
    };

    if resp.status == 304 {
        alter_etag(resp, kind, scope);
        set_header(
            resp,
            "Content-Encoding",
            kind.encoding().as_bytes().to_vec(),
        );
        return;
    }
    // HEAD has no body to compress; keep the identity headers/length rather
    // than advertising an encoded representation whose length we cannot know.
    if req.is_head() {
        return;
    }

    let body = std::mem::replace(&mut resp.body, Body::Empty);
    let (raw, restore) = match read_body(body) {
        Ok(v) => v,
        Err(body) => {
            resp.body = body;
            return;
        }
    };
    if raw.is_empty() {
        resp.body = Body::Bytes(raw);
        return;
    }
    let encoded = match kind {
        CompressionKind::Gzip => gzip(
            &raw,
            scope
                .compression_policy
                .deflate_level
                .unwrap_or(DEFAULT_DEFLATE_LEVEL),
        ),
        CompressionKind::Brotli => brotli(
            &raw,
            scope
                .compression_policy
                .brotli_quality
                .unwrap_or(DEFAULT_BROTLI_QUALITY),
        ),
    };
    let encoded = match encoded {
        Ok(v) => v,
        Err(_) => {
            resp.body = restore.unwrap_or(Body::Bytes(raw));
            return;
        }
    };
    let len = encoded.len();
    resp.body = Body::Bytes(encoded);
    set_header(
        resp,
        "Content-Encoding",
        kind.encoding().as_bytes().to_vec(),
    );
    set_header(resp, "Content-Length", len.to_string().into_bytes());
    set_header(resp, "Accept-Ranges", b"none".to_vec());
    alter_etag(resp, kind, scope);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CompressionKind, CompressionRule, Scope};
    use crate::http::{Body, Headers, Request, Response, Version};

    fn request(accept: &str) -> Request {
        let mut headers = Headers::default();
        headers.insert("accept-encoding", accept.as_bytes().to_vec());
        Request {
            method: "GET".into(),
            target: b"/index.html".to_vec(),
            raw_path: b"/index.html".to_vec(),
            query: Vec::new(),
            version: Version::Http11,
            headers,
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    fn response(body: &[u8], content_type: &str) -> Response {
        let mut r = Response::new(200);
        r.headers.push((
            Cow::Borrowed("Content-Type"),
            content_type.as_bytes().to_vec(),
        ));
        r.headers.push((Cow::Borrowed("ETag"), b"\"abc\"".to_vec()));
        r.body = Body::Bytes(body.to_vec());
        r
    }

    #[test]
    fn gzip_and_brotli_are_negotiated_and_vary_is_added() {
        let mut scope = Scope::default();
        scope
            .compression_policy
            .compression_rules
            .push(CompressionRule::ByType(
                CompressionKind::Gzip,
                vec!["text/html".into()],
            ));
        scope
            .compression_policy
            .compression_rules
            .push(CompressionRule::ByType(
                CompressionKind::Brotli,
                vec!["text/html".into()],
            ));

        let mut r = response(b"hello hello hello", "text/html; charset=utf-8");
        finalize(&scope, &request("gzip, br"), &mut r, b"/index.html");
        assert_eq!(header_str(&r, "content-encoding").as_deref(), Some("br"));
        assert_eq!(header_str(&r, "vary").as_deref(), Some("Accept-Encoding"));
        assert_eq!(
            header_str(&r, "content-length").unwrap(),
            r.body_len().to_string()
        );
        assert!(header_str(&r, "etag").unwrap().ends_with("-br\""));

        let mut r = response(b"hello hello hello", "text/html");
        finalize(&scope, &request("gzip"), &mut r, b"/index.html");
        assert_eq!(header_str(&r, "content-encoding").as_deref(), Some("gzip"));
        assert!(header_str(&r, "etag").unwrap().ends_with("-gzip\""));
    }

    #[test]
    fn q_zero_and_unlisted_types_are_not_compressed() {
        let mut scope = Scope::default();
        scope
            .compression_policy
            .compression_rules
            .push(CompressionRule::ByType(
                CompressionKind::Gzip,
                vec!["text/html".into()],
            ));
        let mut r = response(b"hello", "application/octet-stream");
        finalize(&scope, &request("gzip"), &mut r, b"/x.bin");
        assert!(header(&r, "content-encoding").is_none());

        let mut r = response(b"hello", "text/html");
        finalize(&scope, &request("gzip;q=0"), &mut r, b"/x.html");
        assert!(header(&r, "content-encoding").is_none());
        assert_eq!(header_str(&r, "vary").as_deref(), Some("Accept-Encoding"));
    }

    #[test]
    fn ranges_and_no_transform_bypass_compression() {
        let mut scope = Scope::default();
        scope
            .compression_policy
            .compression_rules
            .push(CompressionRule::Set(vec![CompressionKind::Gzip]));
        let mut req = request("gzip");
        req.headers.insert("range", b"bytes=0-3".to_vec());
        let mut r = response(b"hello", "text/html");
        finalize(&scope, &req, &mut r, b"/x.html");
        assert!(header(&r, "content-encoding").is_none());

        let mut r = response(b"hello", "text/html");
        r.headers
            .push((Cow::Borrowed("Cache-Control"), b"no-transform".to_vec()));
        finalize(&scope, &request("gzip"), &mut r, b"/x.html");
        assert!(header(&r, "content-encoding").is_none());
    }

    #[test]
    fn extension_rules_and_set_filter_work() {
        let mut scope = Scope::default();
        scope
            .compression_policy
            .compression_rules
            .push(CompressionRule::ByExt(
                CompressionKind::Gzip,
                vec![".css".into()],
            ));
        let mut r = response(b"body{}", "text/css");
        finalize(&scope, &request("gzip"), &mut r, b"/style.css");
        assert_eq!(header_str(&r, "content-encoding").as_deref(), Some("gzip"));

        scope.compression_policy.compression_rules.clear();
        scope
            .compression_policy
            .compression_rules
            .push(CompressionRule::Set(vec![CompressionKind::Gzip]));
        let mut r = response(b"body", "application/octet-stream");
        finalize(&scope, &request("gzip"), &mut r, b"/x.bin");
        assert_eq!(header_str(&r, "content-encoding").as_deref(), Some("gzip"));
    }
}
