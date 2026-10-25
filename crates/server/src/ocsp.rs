//! OCSP stapling support for the Rustls certificate resolver.
//!
//! `SSLUseStapling On` fetches an OCSP response for the leaf certificate from
//! the responder advertised in its Authority Information Access extension and
//! attaches it to the `CertifiedKey`.  This intentionally implements the
//! common HTTP responder case synchronously at startup; failures are soft
//! (the certificate is still served) unless the caller decides otherwise.

use rustls::pki_types::CertificateDer;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

const MAX_OCSP_HTTP_LINE: usize = 16 * 1024;
const MAX_OCSP_HTTP_HEAD: usize = 64 * 1024;

#[derive(Clone, Copy)]
struct Tlv {
    tag: u8,
    start: usize,
    content_start: usize,
    content_end: usize,
    end: usize,
}

fn parse_tlv(data: &[u8], pos: usize) -> Option<Tlv> {
    if pos + 2 > data.len() {
        return None;
    }
    let tag = data[pos];
    let first = data[pos + 1];
    let (len, content_start) = if first & 0x80 == 0 {
        (first as usize, pos + 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 8 || pos + 2 + n > data.len() {
            return None;
        }
        let mut len = 0usize;
        for &b in &data[pos + 2..pos + 2 + n] {
            len = len.checked_mul(256)?.checked_add(b as usize)?;
        }
        (len, pos + 2 + n)
    };
    let content_end = content_start.checked_add(len)?;
    if content_end > data.len() {
        return None;
    }
    Some(Tlv {
        tag,
        start: pos,
        content_start,
        content_end,
        end: content_end,
    })
}

fn raw<'a>(data: &'a [u8], t: Tlv) -> &'a [u8] {
    &data[t.start..t.end]
}

fn der_len(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else {
        let mut bytes = Vec::new();
        let mut n = len;
        while n > 0 {
            bytes.push((n & 0xff) as u8);
            n >>= 8;
        }
        bytes.reverse();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 8);
    out.push(tag);
    der_len(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

struct CertInfo {
    serial: Vec<u8>,
    subject_name: Vec<u8>,
    issuer_key: Vec<u8>,
    ocsp_url: Option<String>,
}

fn parse_spki(data: &[u8], spki: Tlv) -> Option<Vec<u8>> {
    let mut p = spki.content_start;
    while p < spki.content_end {
        let t = parse_tlv(data, p)?;
        p = t.end;
        if t.tag == 0x03 {
            if t.content_start >= t.content_end {
                return None;
            }
            // The first octet is the number of unused bits.
            let unused = data[t.content_start];
            if unused > 7 {
                return None;
            }
            return Some(data[t.content_start + 1..t.content_end].to_vec());
        }
    }
    None
}

fn parse_aia_value(data: &[u8], value: Tlv) -> Option<String> {
    let seq = parse_tlv(data, value.content_start)?;
    if seq.tag != 0x30 {
        return None;
    }
    let mut p = seq.content_start;
    while p < seq.content_end {
        let ad = parse_tlv(data, p)?;
        p = ad.end;
        if ad.tag != 0x30 {
            continue;
        }
        let oid = parse_tlv(data, ad.content_start)?;
        let mut q = oid.end;
        let Some(gn) = parse_tlv(data, q) else {
            continue;
        };
        q = gn.end;
        let _ = q;
        // 1.3.6.1.5.5.7.48.1 (id-ad-ocsp)
        if oid.tag == 0x06
            && raw(data, oid) == [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]
            && gn.tag == 0x86
        {
            return std::str::from_utf8(&data[gn.content_start..gn.content_end])
                .ok()
                .map(|s| s.to_string());
        }
    }
    None
}

fn parse_aia(data: &[u8], wrapper: Tlv) -> Option<String> {
    // [3] EXPLICIT Extensions
    let extensions = parse_tlv(data, wrapper.content_start)?;
    if extensions.tag != 0x30 {
        return None;
    }
    let aia_oid = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
    let mut p = extensions.content_start;
    while p < extensions.content_end {
        let ext = parse_tlv(data, p)?;
        p = ext.end;
        if ext.tag != 0x30 {
            continue;
        }
        let oid = parse_tlv(data, ext.content_start)?;
        if oid.tag != 0x06 || &data[oid.content_start..oid.content_end] != aia_oid {
            continue;
        }
        let mut q = oid.end;
        let mut value = None;
        while q < ext.content_end {
            let t = parse_tlv(data, q)?;
            q = t.end;
            if t.tag == 0x04 {
                value = Some(t);
            }
        }
        if let Some(value) = value {
            if let Some(url) = parse_aia_value(data, value) {
                return Some(url);
            }
        }
    }
    None
}

fn parse_cert(der_bytes: &[u8]) -> Option<CertInfo> {
    let outer = parse_tlv(der_bytes, 0)?;
    if outer.tag != 0x30 {
        return None;
    }
    let tbs = parse_tlv(der_bytes, outer.content_start)?;
    if tbs.tag != 0x30 {
        return None;
    }
    let mut p = tbs.content_start;
    let mut stage = 0u8;
    let mut serial = None;
    let mut subject_name = None;
    let mut issuer_key = None;
    let mut ocsp_url = None;
    while p < tbs.content_end {
        let t = parse_tlv(der_bytes, p)?;
        p = t.end;
        match stage {
            0 => {
                if t.tag == 0x02 {
                    serial = Some(raw(der_bytes, t).to_vec());
                    stage = 1;
                }
            }
            1 => {
                if t.tag == 0x30 {
                    stage = 2;
                }
            }
            2 => {
                if t.tag == 0x30 {
                    stage = 3;
                }
            }
            3 => {
                if t.tag == 0x30 {
                    stage = 4;
                }
            }
            4 => {
                if t.tag == 0x30 {
                    subject_name = Some(raw(der_bytes, t).to_vec());
                    stage = 5;
                }
            }
            5 => {
                if t.tag == 0x30 {
                    issuer_key = parse_spki(der_bytes, t);
                    stage = 6;
                }
            }
            6 => {
                if t.tag == 0xa3 {
                    ocsp_url = parse_aia(der_bytes, t);
                }
            }
            _ => {}
        }
    }
    Some(CertInfo {
        serial: serial?,
        subject_name: subject_name?,
        issuer_key: issuer_key?,
        ocsp_url,
    })
}

fn build_request(leaf: &CertInfo, issuer: &CertInfo) -> Option<Vec<u8>> {
    let mut name_hasher = Sha1::new();
    name_hasher.update(&issuer.subject_name);
    let name_hash = name_hasher.finalize();
    let mut key_hasher = Sha1::new();
    key_hasher.update(&issuer.issuer_key);
    let key_hash = key_hasher.finalize();
    let sha1_oid = [0x2b, 0x0e, 0x03, 0x02, 0x1a];
    let alg = der(0x30, &[der(0x06, &sha1_oid), der(0x05, &[])].concat());
    let cert_id = der(
        0x30,
        &[
            alg,
            der(0x04, &name_hash),
            der(0x04, &key_hash),
            leaf.serial.clone(),
        ]
        .concat(),
    );
    let request = der(0x30, &cert_id);
    let request_list = der(0x30, &request);
    let tbs_request = der(0x30, &request_list);
    Some(der(0x30, &tbs_request))
}

fn parse_http_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.trim().strip_prefix("http://")?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path))
}

fn read_http_line(reader: &mut impl BufRead) -> Option<String> {
    let mut line = Vec::new();
    let n = reader.read_until(b'\n', &mut line).ok()?;
    if n == 0 || line.len() > MAX_OCSP_HTTP_LINE {
        return None;
    }
    while line.last() == Some(&b'\n') || line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line).ok()
}

fn fetch_response(url: &str, request: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    let (host, port, path) = parse_http_url(url)?;
    let mut stream = None;
    for candidate in (host.as_str(), port).to_socket_addrs().ok()? {
        if let Ok(s) = TcpStream::connect_timeout(&candidate, timeout) {
            stream = Some(s);
            break;
        }
    }
    let mut stream = stream?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/ocsp-request\r\nAccept: application/ocsp-response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        request.len()
    );
    stream.write_all(head.as_bytes()).ok()?;
    stream.write_all(request).ok()?;
    let mut reader = BufReader::new(stream);
    let status = read_http_line(&mut reader)?;
    if !status.split_whitespace().nth(1)?.starts_with("200") {
        return None;
    }
    let mut content_length = None;
    let mut head_bytes = status.len() + 2;
    loop {
        let line = read_http_line(&mut reader)?;
        head_bytes = head_bytes.saturating_add(line.len() + 2);
        if head_bytes > MAX_OCSP_HTTP_HEAD {
            return None;
        }
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse::<usize>().ok();
            }
        }
    }
    let mut body = Vec::new();
    if let Some(n) = content_length {
        if n > 2 * 1024 * 1024 {
            return None;
        }
        body.resize(n, 0);
        reader.read_exact(&mut body).ok()?;
    } else {
        reader
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut body)
            .ok()?;
        if body.len() > 2 * 1024 * 1024 {
            return None;
        }
    }
    Some(body)
}

fn successful_response(data: &[u8]) -> bool {
    let Some(outer) = parse_tlv(data, 0) else {
        return false;
    };
    if outer.tag != 0x30 {
        return false;
    }
    let Some(status) = parse_tlv(data, outer.content_start) else {
        return false;
    };
    status.tag == 0x0a
        && status.content_end - status.content_start == 1
        && data[status.content_start] == 0
}

fn cache() -> &'static Mutex<HashMap<Vec<u8>, Vec<u8>>> {
    static CACHE: OnceLock<Mutex<HashMap<Vec<u8>, Vec<u8>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn response_key(chain: &[CertificateDer<'static>], force_url: Option<&str>) -> Vec<u8> {
    let mut key = chain
        .first()
        .map(|c| c.as_ref().to_vec())
        .unwrap_or_default();
    key.push(0);
    if let Some(url) = force_url {
        key.extend_from_slice(url.as_bytes());
    }
    key
}

pub fn cache_path(
    dir: &std::path::Path,
    chain: &[CertificateDer<'static>],
    force_url: Option<&str>,
) -> std::path::PathBuf {
    let key = response_key(chain, force_url);
    let mut hasher = Sha1::new();
    hasher.update(&key);
    dir.join(format!("{:x}.ocsp", hasher.finalize()))
}

pub fn load_cached(path: &std::path::Path) -> Option<Vec<u8>> {
    let data = std::fs::read(path).ok()?;
    if successful_response(&data) {
        Some(data)
    } else {
        None
    }
}

pub fn save_cached(path: &std::path::Path, response: &[u8]) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, response).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// Fetch a fresh response, bypassing the in-memory cache.  Used by the
/// periodic refresher so a valid startup staple is replaced with current
/// revocation information.
pub fn fetch_fresh(
    chain: &[CertificateDer<'static>],
    force_url: Option<&str>,
    timeout: Duration,
) -> Option<Vec<u8>> {
    if chain.len() < 2 {
        return None;
    }
    let leaf = parse_cert(chain[0].as_ref())?;
    let issuer = parse_cert(chain[1].as_ref())?;
    let url = force_url.map(str::to_string).or(leaf.ocsp_url.clone())?;
    let request = build_request(&leaf, &issuer)?;
    let response = fetch_response(&url, &request, timeout)?;
    if successful_response(&response) {
        Some(response)
    } else {
        None
    }
}

/// Fetch and return a DER-encoded OCSPResponse to staple for `chain[0]`.
/// `chain[1]` must be the issuer certificate.  `force_url` overrides the AIA
/// URL when `SSLStaplingForceURL` is configured.
pub fn staple_response(
    chain: &[CertificateDer<'static>],
    force_url: Option<&str>,
    timeout: Duration,
) -> Option<Vec<u8>> {
    if chain.len() < 2 {
        return None;
    }
    let leaf = parse_cert(chain[0].as_ref())?;
    let issuer = parse_cert(chain[1].as_ref())?;
    let url = force_url.map(str::to_string).or(leaf.ocsp_url.clone())?;
    let request = build_request(&leaf, &issuer)?;
    let mut key = chain[0].as_ref().to_vec();
    key.extend_from_slice(url.as_bytes());
    if let Some(cached) = cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .cloned()
    {
        return Some(cached);
    }
    let response = fetch_response(&url, &request, timeout)?;
    if !successful_response(&response) {
        return None;
    }
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, response.clone());
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_responses_must_be_successful() {
        let dir = std::env::temp_dir().join(format!("vapache-ocsp-cache-{}", std::process::id()));
        let path = dir.join("response.ocsp");
        let good = [0x30, 0x03, 0x0a, 0x01, 0x00];
        save_cached(&path, &good);
        assert_eq!(load_cached(&path).as_deref(), Some(good.as_slice()));
        let bad = [0x30, 0x03, 0x0a, 0x01, 0x01];
        save_cached(&path, &bad);
        assert!(load_cached(&path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ocsp_http_lines_are_bounded() {
        let mut short = &b"HTTP/1.1 200 OK\r\n"[..];
        assert_eq!(
            read_http_line(&mut short).as_deref(),
            Some("HTTP/1.1 200 OK")
        );
        let mut long = vec![b'A'; MAX_OCSP_HTTP_LINE + 1];
        long.push(b'\n');
        let mut long = &long[..];
        assert!(read_http_line(&mut long).is_none());
    }

    #[test]
    fn der_length_round_trip() {
        let mut out = Vec::new();
        der_len(300, &mut out);
        assert_eq!(out, vec![0x82, 0x01, 0x2c]);
        let encoded = der(0x04, b"abc");
        let t = parse_tlv(&encoded, 0).unwrap();
        assert_eq!(t.tag, 0x04);
        assert_eq!(&encoded[t.content_start..t.content_end], b"abc");
    }
}
