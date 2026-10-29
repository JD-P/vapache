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
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

const MAX_OCSP_HTTP_LINE: usize = 16 * 1024;
const MAX_OCSP_HTTP_HEAD: usize = 64 * 1024;
const MAX_OCSP_RESPONSE: u64 = 2 * 1024 * 1024;

pub fn prepare_cache_dir(path: &std::path::Path) -> std::io::Result<()> {
    let dir = crate::files::ensure_admin_dir(path, 0o750)?;
    crate::files::make_admin_dir_root_owned(&dir, 0o750)
}

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
            // `stage` is initialized at zero and is only advanced through
            // six; no parser transition can construct another value.
            _ => {} // coverage:ignore-line
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
            return None; // coverage:ignore-line -- socket regression is transport-timing dependent
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
    if status.tag != 0x0a
        || status.content_end - status.content_start != 1
        || data[status.content_start] != 0
    {
        return false;
    }
    // A successful status without ResponseBytes is not a staple. Require an
    // id-pkix-ocsp-basic payload with the complete BasicOCSPResponse signed
    // shape so a five-byte `successful` status injected on the plaintext AIA
    // transport cannot replace a working staple with malformed bytes. TLS
    // clients still perform the cryptographic certificate/status validation.
    let Some(wrapper) = parse_tlv(data, status.end) else {
        return false;
    };
    if outer.end != data.len() || wrapper.tag != 0xa0 || wrapper.end != outer.content_end {
        return false;
    }
    let Some(response_bytes) = parse_tlv(data, wrapper.content_start) else {
        return false;
    };
    if response_bytes.tag != 0x30 || response_bytes.end != wrapper.content_end {
        return false;
    }
    let Some(kind) = parse_tlv(data, response_bytes.content_start) else {
        return false;
    };
    const BASIC_OCSP_OID: &[u8] = &[
        0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01,
    ];
    if raw(data, kind) != BASIC_OCSP_OID {
        return false;
    }
    let Some(encoded) = parse_tlv(data, kind.end) else {
        return false;
    };
    if encoded.tag != 0x04 || encoded.end != response_bytes.content_end {
        return false;
    }
    let basic_bytes = &data[encoded.content_start..encoded.content_end];
    let Some(basic) = parse_tlv(basic_bytes, 0) else {
        return false;
    };
    if basic.tag != 0x30 || basic.end != basic_bytes.len() {
        return false;
    }
    let Some(tbs) = parse_tlv(basic_bytes, basic.content_start) else {
        return false;
    };
    let Some(algorithm) = parse_tlv(basic_bytes, tbs.end) else {
        return false;
    };
    let Some(signature) = parse_tlv(basic_bytes, algorithm.end) else {
        return false;
    };
    tbs.tag == 0x30
        && algorithm.tag == 0x30
        && signature.tag == 0x03
        && signature.content_end > signature.content_start + 1
        && basic_bytes[signature.content_start] == 0
}

#[cfg(test)]
pub(crate) fn test_successful_response() -> Vec<u8> {
    let basic = der(
        0x30,
        &[der(0x30, &[]), der(0x30, &[]), der(0x03, &[0, 1])].concat(),
    );
    let response_bytes = der(
        0x30,
        &[
            vec![
                0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01,
            ],
            der(0x04, &basic),
        ]
        .concat(),
    );
    der(
        0x30,
        &[der(0x0a, &[0]), der(0xa0, &response_bytes)].concat(),
    )
}

/// Bound the handwritten DER and HTTP-URL parsers with arbitrary certificate
/// and responder material.  No network access occurs in this entry point.
#[cfg(feature = "fuzzing")]
pub fn fuzz_ocsp_parsers(data: &[u8]) {
    let _ = parse_cert(data);
    let _ = successful_response(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_http_url(text);
    }
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
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    dir.join(format!("{digest}.ocsp"))
}

pub fn load_cached(path: &std::path::Path) -> Option<Vec<u8>> {
    let mut file =
        crate::files::open_admin_path(path, libc::O_RDONLY | libc::O_NONBLOCK, 0).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_OCSP_RESPONSE {
        return None;
    }
    let mut data = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(MAX_OCSP_RESPONSE + 1)
        .read_to_end(&mut data)
        .ok()?;
    if data.len() as u64 > MAX_OCSP_RESPONSE {
        return None;
    }
    if successful_response(&data) {
        Some(data)
    } else {
        None
    }
}

pub fn save_cached(path: &std::path::Path, response: &[u8]) {
    if response.len() as u64 > MAX_OCSP_RESPONSE || !successful_response(response) {
        return;
    }
    let Some(parent) = path.parent() else {
        return;
    };
    if crate::files::ensure_admin_dir(parent, 0o770).is_err() {
        return;
    }
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return;
    };
    for _ in 0..16 {
        let nonce = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let tmp = parent.join(format!(".{name}.{}.{nonce}.tmp", std::process::id()));
        let Ok(mut file) = crate::files::open_admin_path(
            &tmp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NONBLOCK,
            0o600,
        ) else {
            continue;
        };
        let identity = file
            .metadata()
            .ok()
            .map(|metadata| (metadata.dev(), metadata.ino()));
        if file.write_all(response).is_ok()
            && file.sync_data().is_ok()
            && identity.is_some()
            && crate::files::open_admin_path(&tmp, libc::O_RDONLY | libc::O_NONBLOCK, 0)
                .ok()
                .and_then(|candidate| candidate.metadata().ok())
                .is_some_and(|metadata| {
                    metadata.is_file() && Some((metadata.dev(), metadata.ino())) == identity
                })
            && std::fs::rename(&tmp, path).is_ok()
        {
            return;
        }
        let _ = std::fs::remove_file(&tmp);
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

    fn minimal_cert(url: Option<&str>) -> Vec<u8> {
        let mut fields = vec![
            der(0x02, &[1]),
            der(0x30, &[]),
            der(0x30, &[]),
            der(0x30, &[]),
            der(0x30, &[0x05, 0x00]),
            der(0x30, &der(0x03, &[0, 1, 2, 3])),
        ];
        if let Some(url) = url {
            let access = der(
                0x30,
                &[
                    der(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]),
                    der(0x86, url.as_bytes()),
                ]
                .concat(),
            );
            let aia_value = der(0x04, &der(0x30, &access));
            let extension = der(
                0x30,
                &[
                    der(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01]),
                    aia_value,
                ]
                .concat(),
            );
            fields.push(der(0xa3, &der(0x30, &extension)));
        }
        der(0x30, &der(0x30, &fields.concat()))
    }

    fn serve(response: Vec<u8>) -> Option<Vec<u8>> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Drain the complete request before replying. Closing a socket
            // with unread request bytes can emit a TCP RST and make the
            // response-body assertion timing-dependent under a full suite.
            let mut request = Vec::new();
            let mut chunk = [0u8; 512];
            while !request.ends_with(b"\r\n\r\nrequest") {
                let n = stream.read(&mut chunk).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..n]);
            }
            let _ = stream.write_all(&response);
        });
        let result = fetch_response(
            &format!("http://{addr}/ocsp"),
            b"request",
            Duration::from_secs(2),
        );
        handle.join().unwrap();
        result
    }

    #[test]
    fn cached_responses_must_be_successful() {
        let dir = std::env::temp_dir().join(format!("vapache-ocsp-cache-{}", std::process::id()));
        let path = dir.join("response.ocsp");
        let good = test_successful_response();
        save_cached(&path, &good);
        assert_eq!(load_cached(&path).as_deref(), Some(good.as_slice()));
        let bad = [0x30, 0x03, 0x0a, 0x01, 0x01];
        save_cached(&path, &bad);
        assert_eq!(load_cached(&path).as_deref(), Some(good.as_slice()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_rejects_links_fifos_and_oversized_files() {
        use std::os::unix::fs::symlink;

        let dir =
            std::env::temp_dir().join(format!("vapache-ocsp-cache-objects-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, b"unchanged").unwrap();
        let path = dir.join("response.ocsp");
        symlink(&victim, &path).unwrap();
        assert!(load_cached(&path).is_none());
        save_cached(&path, &test_successful_response());
        assert_eq!(std::fs::read(&victim).unwrap(), b"unchanged");
        assert!(load_cached(&path).is_some());

        let fifo = dir.join("fifo.ocsp");
        crate::files::make_test_fifo(&fifo).unwrap();
        assert!(load_cached(&fifo).is_none());

        let oversized = dir.join("oversized.ocsp");
        std::fs::write(&oversized, vec![0u8; MAX_OCSP_RESPONSE as usize + 1]).unwrap();
        assert!(load_cached(&oversized).is_none());
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

    #[test]
    fn der_certificate_and_url_parsers_cover_malformed_edges() {
        assert!(parse_tlv(&[], 0).is_none());
        assert!(parse_tlv(&[0x04, 0x80], 0).is_none());
        assert!(parse_tlv(&[0x04, 0x89], 0).is_none());
        assert!(parse_tlv(&[0x04, 0x82, 0x01], 0).is_none());
        assert!(parse_tlv(&[0x04, 3, 1], 0).is_none());

        let empty_spki = der(0x30, &[]);
        assert!(parse_spki(&empty_spki, parse_tlv(&empty_spki, 0).unwrap()).is_none());
        for content in [&[][..], &[8, 1][..]] {
            let spki = der(0x30, &der(0x03, content));
            assert!(parse_spki(&spki, parse_tlv(&spki, 0).unwrap()).is_none());
        }

        let not_a_sequence = der(0x04, &der(0x04, b"x"));
        assert!(parse_aia_value(&not_a_sequence, parse_tlv(&not_a_sequence, 0).unwrap()).is_none());
        let skipped_ad = der(0x04, &der(0x30, &der(0x04, b"x")));
        assert!(parse_aia_value(&skipped_ad, parse_tlv(&skipped_ad, 0).unwrap()).is_none());
        let missing_general_name = der(0x04, &der(0x30, &der(0x30, &der(0x06, &[0x2b]))));
        assert!(parse_aia_value(
            &missing_general_name,
            parse_tlv(&missing_general_name, 0).unwrap()
        )
        .is_none());
        let bad_wrapper = der(0xa3, &der(0x04, b"x"));
        assert!(parse_aia(&bad_wrapper, parse_tlv(&bad_wrapper, 0).unwrap()).is_none());
        let skipped_extension = der(0xa3, &der(0x30, &der(0x04, b"x")));
        assert!(parse_aia(
            &skipped_extension,
            parse_tlv(&skipped_extension, 0).unwrap()
        )
        .is_none());

        let cert = minimal_cert(Some("http://ocsp.example.test/check"));
        let info = parse_cert(&cert).unwrap();
        assert_eq!(
            info.ocsp_url.as_deref(),
            Some("http://ocsp.example.test/check")
        );
        assert!(!build_request(&info, &info).unwrap().is_empty());
        assert!(parse_cert(&der(0x04, b"bad")).is_none());
        assert!(parse_cert(&der(0x30, &der(0x04, b"bad"))).is_none());

        assert_eq!(
            parse_http_url("http://example.test:8080/path"),
            Some(("example.test".into(), 8080, "/path".into()))
        );
        assert_eq!(
            parse_http_url("http://example.test"),
            Some(("example.test".into(), 80, "/".into()))
        );
        assert!(parse_http_url("https://example.test/").is_none());
        assert!(parse_http_url("http:///path").is_none());
        assert!(parse_http_url("http://host:bad/").is_none());

        assert!(!successful_response(&[]));
        assert!(!successful_response(&der(0x04, b"bad")));
        assert!(!successful_response(&der(0x30, &[])));
        assert!(fetch_fresh(&[], None, Duration::ZERO).is_none());
        assert!(staple_response(&[], None, Duration::ZERO).is_none());
        let chain = [
            CertificateDer::from(cert),
            CertificateDer::from(minimal_cert(None)),
        ];
        assert!(response_key(&chain, Some("http://forced/")).ends_with(b"http://forced/"));
        assert!(cache_path(std::path::Path::new("/tmp"), &chain, None)
            .extension()
            .is_some_and(|ext| ext == "ocsp"));
    }

    #[test]
    fn ocsp_http_fetch_handles_length_eof_status_and_header_limits() {
        assert_eq!(
            serve(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec()),
            Some(b"hello".to_vec())
        );
        assert_eq!(
            serve(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody".to_vec()),
            Some(b"body".to_vec())
        );
        assert!(serve(b"HTTP/1.1 500 Error\r\n\r\n".to_vec()).is_none());
        assert!(serve(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nno".to_vec()).is_none());
        assert!(serve(b"HTTP/1.1 200 OK\r\nContent-Length: 2097153\r\n\r\n".to_vec()).is_none());
        let mut oversized_body = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        oversized_body.resize(oversized_body.len() + 2 * 1024 * 1024 + 1, b'x');
        assert!(serve(oversized_body).is_none());

        let mut oversized_head = b"HTTP/1.1 200 OK\r\n".to_vec();
        for _ in 0..8 {
            oversized_head.extend_from_slice(b"X-Fill: ");
            oversized_head.extend(std::iter::repeat_n(b'x', 9000));
            oversized_head.extend_from_slice(b"\r\n");
        }
        oversized_head.extend_from_slice(b"\r\n");
        assert!(serve(oversized_head).is_none());

        let mut eof = &b""[..];
        assert!(read_http_line(&mut eof).is_none());
        assert!(fetch_response("not-a-url", b"x", Duration::ZERO).is_none());
    }

    #[test]
    fn fresh_and_stapled_responses_cover_failure_and_cache_paths() {
        fn responder(body: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let handle = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request);
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            });
            (format!("http://{addr}/ocsp"), handle)
        }

        let cert = minimal_cert(None);
        let chain = [
            CertificateDer::from(cert.clone()),
            CertificateDer::from(cert),
        ];
        let (bad_url, bad_thread) = responder(der(0x30, &der(0x0a, &[1])));
        assert!(fetch_fresh(&chain, Some(&bad_url), Duration::from_secs(2)).is_none());
        bad_thread.join().unwrap();

        let (bad_staple_url, bad_staple_thread) = responder(der(0x30, &der(0x0a, &[1])));
        assert!(staple_response(&chain, Some(&bad_staple_url), Duration::from_secs(2)).is_none());
        bad_staple_thread.join().unwrap();

        let good = test_successful_response();
        let (fresh_url, fresh_thread) = responder(good.clone());
        assert_eq!(
            fetch_fresh(&chain, Some(&fresh_url), Duration::from_secs(2)),
            Some(good.clone())
        );
        fresh_thread.join().unwrap();
        let (good_url, good_thread) = responder(good.clone());
        assert_eq!(
            staple_response(&chain, Some(&good_url), Duration::from_secs(2)),
            Some(good.clone())
        );
        good_thread.join().unwrap();
        // No responder is listening now: success proves the cache-return arm.
        assert_eq!(
            staple_response(&chain, Some(&good_url), Duration::from_millis(10)),
            Some(good)
        );
    }
}
