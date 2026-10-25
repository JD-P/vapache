//! Static file serving: secure path opening, conditional requests, byte
//! ranges, directory indexes and autoindex, and Apache-compatible errors.
//!
//! Every filesystem access goes through `openat2(root, ..., RESOLVE_BENEATH)`
//! (with `RESOLVE_NO_SYMLINKS` when `Options -FollowSymLinks`).  This makes
//! path traversal impossible even if URI normalization has a bug: the kernel
//! refuses to resolve outside the document root.

use crate::config::{Config, ErrorDoc, Scope, ServerSignature, VHost, ETAG_ALL};
use crate::http::{reason_phrase, Body, Request, Response};
use crate::util::{html_escape, http_date, parse_http_date, url_encode_path};
use crate::verified::{parse_byte_range, RangeDecision};
use std::borrow::Cow;
use std::cell::RefCell;
use std::ffi::CString;
use std::fmt::Write as _;
use std::fs::{File, Metadata};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

pub enum Target {
    File { file: File, meta: Metadata },
    Directory { file: File, meta: Metadata },
    NotFound,
    Forbidden,
}

/// Resolve the absolute path of an already-opened descriptor.  Used to bind
/// authorization to the object actually opened rather than only to the URL
/// path that selected it.
pub fn fd_path(file: &File) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()
}

/// Open `root/rel` without ever escaping `root`.
pub fn resolve_target(root: &Path, rel: &Path, follow_symlinks: bool) -> Target {
    let mut flags = (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK) as u64;
    if rel.as_os_str().is_empty() {
        flags |= libc::O_DIRECTORY as u64;
    }
    let opened = if rel.as_os_str().is_empty() {
        File::open(root)
    } else {
        open_beneath(root, rel, flags, follow_symlinks)
    };
    let file = match opened {
        Ok(f) => f,
        Err(e) => {
            return match e.raw_os_error() {
                Some(libc::ENOENT) | Some(libc::ENOTDIR) => Target::NotFound,
                Some(libc::EACCES) | Some(libc::ELOOP) | Some(libc::EXDEV) | Some(libc::EPERM) => {
                    Target::Forbidden
                }
                _ => Target::NotFound,
            }
        }
    };
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(_) => return Target::Forbidden,
    };
    if meta.is_dir() {
        Target::Directory { file, meta }
    } else if meta.is_file() {
        Target::File { file, meta }
    } else {
        // FIFOs, devices and sockets are never served.
        Target::Forbidden
    }
}

type OpenResult = Result<File, io::Error>;

thread_local! {
    /// Opening the document root on every request is an avoidable syscall.
    /// A document root is normally stable for the life of the process, and
    /// each connection thread serves a small set of roots (vhosts/aliases).
    static ROOT_FDS: RefCell<Vec<(PathBuf, Arc<File>)>> =
        const { RefCell::new(Vec::new()) };
}

fn root_file(root: &Path) -> io::Result<Arc<File>> {
    ROOT_FDS.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some((_, f)) = cache.iter().find(|(p, _)| p == root) {
            return Ok(f.clone());
        }
        let f = Arc::new(File::open(root)?);
        if cache.len() >= 16 {
            cache.remove(0);
        }
        cache.push((root.to_path_buf(), f.clone()));
        Ok(f)
    })
}

fn open_beneath(root: &Path, rel: &Path, flags: u64, follow: bool) -> OpenResult {
    let root_file = root_file(root)?;
    let rel_c = CString::new(rel.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let mut how = OpenHow {
        flags,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    };
    if !follow {
        how.resolve |= RESOLVE_NO_SYMLINKS;
    }
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_file.as_raw_fd(),
            rel_c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd >= 0 {
        return Ok(unsafe { File::from_raw_fd(fd as i32) });
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() != Some(libc::ENOSYS) && e.raw_os_error() != Some(libc::EINVAL) {
        return Err(e);
    }
    // Fallback for kernels without openat2.  Canonicalize and verify the
    // prefix; this is TOCTOU-prone, so openat2 is strongly preferred.
    let candidate = root.join(rel);
    let canon_root = root.canonicalize()?;
    let canon = candidate.canonicalize()?;
    if !canon.starts_with(&canon_root) {
        return Err(io::Error::from_raw_os_error(libc::EXDEV));
    }
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    if flags & libc::O_DIRECTORY as u64 != 0 {
        if !canon.is_dir() {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }
    }
    o.open(canon)
}

fn open_at(dir: &File, name: &[u8], follow: bool) -> OpenResult {
    let c = CString::new(name).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let mut how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    };
    if !follow {
        how.resolve |= RESOLVE_NO_SYMLINKS;
    }
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd >= 0 {
        return Ok(unsafe { File::from_raw_fd(fd as i32) });
    }
    Err(io::Error::last_os_error())
}

pub fn mime_type(cfg: &Config, scope: &Scope, name: &[u8]) -> Option<String> {
    if let Some(ft) = &scope.content_policy.force_type {
        return Some(ft.clone());
    }
    // The overwhelmingly common case is a plain TypesConfig lookup with no
    // per-directory AddType/RemoveType overrides.  Avoid scanning and
    // lowercasing the extension when both override lists are empty.
    if scope.content_policy.remove_types.is_empty() && scope.content_policy.add_types.is_empty() {
        let mut t = cfg.mime.content_type(name)?;
        if let Some(cs) = &scope.content_policy.default_charset {
            if t.starts_with("text/") && !t.contains("charset") {
                t.push_str("; charset=");
                t.push_str(cs);
            }
        }
        return Some(t);
    }
    let base = name.rsplit(|b| *b == b'/').next().unwrap_or(name);
    let ext = base
        .rsplit(|b| *b == b'.')
        .next()
        .and_then(|e| std::str::from_utf8(e).ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let removed = scope
        .content_policy
        .remove_types
        .iter()
        .any(|e| e.trim_start_matches('.').eq_ignore_ascii_case(&ext));
    if !removed {
        for (ty, exts) in scope.content_policy.add_types.iter().rev() {
            if exts
                .split_ascii_whitespace()
                .any(|e| e.trim_start_matches('.').eq_ignore_ascii_case(&ext))
            {
                let mut t = ty.clone();
                if let Some(cs) = &scope.content_policy.default_charset {
                    if t.starts_with("text/") && !t.contains("charset") {
                        t.push_str("; charset=");
                        t.push_str(cs);
                    }
                }
                return Some(t);
            }
        }
    }
    if removed {
        return None;
    }
    let mut t = cfg.mime.content_type(name)?;
    if let Some(cs) = &scope.content_policy.default_charset {
        if t.starts_with("text/") && !t.contains("charset") {
            t.push_str("; charset=");
            t.push_str(cs);
        }
    }
    Some(t)
}

fn etag(meta: &Metadata, bits: u32) -> String {
    let bits = if bits == 0 { ETAG_ALL } else { bits };
    let mut s = String::with_capacity(48);
    s.push('"');
    if bits & crate::config::ETAG_INODE != 0 {
        let _ = write!(s, "{:x}", meta.ino());
    }
    if bits & crate::config::ETAG_SIZE != 0 {
        let _ = write!(s, "-{:x}", meta.size());
    }
    if bits & crate::config::ETAG_MTIME != 0 {
        let _ = write!(s, "-{:x}", meta.mtime());
    }
    s.push('"');
    s
}

fn etag_opaque(etag: &str) -> String {
    let s = etag.trim().strip_prefix("W/").unwrap_or(etag.trim());
    let s = s.strip_prefix('"').unwrap_or(s);
    let s = s.strip_suffix('"').unwrap_or(s);
    s.strip_suffix("-gzip")
        .or_else(|| s.strip_suffix("-br"))
        .unwrap_or(s)
        .to_string()
}

fn header_etag_list_matches(value: &[u8], etag: &str, weak: bool) -> bool {
    let v = std::str::from_utf8(value).unwrap_or("");
    for part in v.split(',') {
        let p = part.trim();
        if p == "*" {
            return true;
        }
        let (pw, pt) = if let Some(rest) = p.strip_prefix("W/") {
            (true, rest)
        } else {
            (false, p)
        };
        let (ew, et) = if let Some(rest) = etag.strip_prefix("W/") {
            (true, rest)
        } else {
            (false, etag)
        };
        let pt = etag_opaque(pt);
        let et = etag_opaque(et);
        if weak {
            if pt == et {
                return true;
            }
        } else if !pw && !ew && pt == et {
            return true;
        }
    }
    false
}

/// Serve an opened regular file, applying HTTP conditional and range rules.
fn serve_file_inner(
    cfg: &Config,
    scope: &Scope,
    req: &Request,
    file: File,
    meta: &Metadata,
    mime_name: &[u8],
    peer: std::net::IpAddr,
    local_ip: &str,
) -> Response {
    let size = meta.size();
    let mtime = meta.mtime();
    let tag = etag(meta, scope.content_policy.file_etag.unwrap_or(ETAG_ALL));
    let last_mod = http_date(mtime);
    let mime = mime_type(cfg, scope, mime_name);

    let is_get = req.method == "GET";
    let is_head = req.method == "HEAD";

    // RFC 9110 §13.2.2 evaluation order.
    if let Some(v) = req.header("if-match") {
        if !header_etag_list_matches(v, &tag, false) {
            return error_response(cfg, None, scope, 412, req, "", 0, "", peer, local_ip);
        }
    } else if let Some(v) = req.header("if-unmodified-since") {
        if let Some(t) = parse_http_date(v) {
            if mtime > t {
                return error_response(cfg, None, scope, 412, req, "", 0, "", peer, local_ip);
            }
        }
    }
    if let Some(v) = req.header("if-none-match") {
        if header_etag_list_matches(v, &tag, true) {
            if is_get || is_head {
                let mut r = Response::new(304);
                r.headers.push(("ETag".into(), tag.into_bytes()));
                r.headers
                    .push(("Last-Modified".into(), last_mod.into_bytes()));
                if let Some(mime) = &mime {
                    r.headers
                        .push(("Content-Type".into(), mime.as_bytes().to_vec()));
                }
                return r;
            }
            return error_response(cfg, None, scope, 412, req, "", 0, "", peer, local_ip);
        }
    } else if is_get || is_head {
        if let Some(v) = req.header("if-modified-since") {
            if let Some(t) = parse_http_date(v) {
                if mtime <= t {
                    let mut r = Response::new(304);
                    r.headers.push(("ETag".into(), tag.into_bytes()));
                    r.headers
                        .push(("Last-Modified".into(), last_mod.into_bytes()));
                    if let Some(mime) = &mime {
                        r.headers
                            .push(("Content-Type".into(), mime.as_bytes().to_vec()));
                    }
                    return r;
                }
            }
        }
    }

    let mut status = 200u16;
    let mut start = 0u64;
    let mut len = size;
    let mut content_range: Option<String> = None;

    if (is_get || is_head) && size > 0 {
        if let Some(range) = req.header("range") {
            let use_range = match req.header("if-range") {
                None => true,
                Some(ir) => {
                    if ir.first() == Some(&b'"') || ir.starts_with(b"W/") {
                        header_etag_list_matches(ir, &tag, true)
                    } else {
                        parse_http_date(ir).map(|t| t == mtime).unwrap_or(false)
                    }
                }
            };
            if use_range {
                match parse_byte_range(range, size) {
                    RangeDecision::Satisfiable { start: s, end: e } => {
                        status = 206;
                        start = s;
                        len = e - s + 1;
                        content_range = Some(format!("bytes {s}-{e}/{size}"));
                    }
                    RangeDecision::Unsatisfiable => {
                        let mut r =
                            error_response(cfg, None, scope, 416, req, "", 0, "", peer, local_ip);
                        r.headers.push((
                            "Content-Range".into(),
                            format!("bytes */{size}").into_bytes(),
                        ));
                        return r;
                    }
                    RangeDecision::Ignore => {}
                }
            }
        }
    }

    if !(is_get || is_head) {
        // Apache answers unsupported methods on static resources with 405.
        let mut r = error_response(cfg, None, scope, 405, req, "", 0, "", peer, local_ip);
        r.headers
            .push(("Allow".into(), b"GET, HEAD, OPTIONS".to_vec()));
        return r;
    }

    let mut r = Response::new(status);
    if let Some(mime) = mime {
        r.headers.push(("Content-Type".into(), mime.into_bytes()));
    }
    r.headers
        .push(("Last-Modified".into(), last_mod.into_bytes()));
    r.headers.push(("ETag".into(), tag.into_bytes()));
    r.headers.push(("Accept-Ranges".into(), b"bytes".to_vec()));
    if let Some(cr) = content_range {
        r.headers.push(("Content-Range".into(), cr.into_bytes()));
    }
    for (n, v) in &scope.header_policy.set_headers {
        r.headers
            .push((Cow::Owned(n.clone()), v.as_bytes().to_vec()));
    }
    for (n, v) in &scope.header_policy.add_headers {
        r.headers
            .push((Cow::Owned(n.clone()), v.as_bytes().to_vec()));
    }
    if req.is_head() {
        r.headers
            .push(("Content-Length".into(), len.to_string().into_bytes()));
        r.body = Body::Empty;
    } else {
        r.body = Body::File {
            file,
            offset: start,
            len,
        };
    }
    r
}

pub fn serve_file(
    cfg: &Config,
    scope: &Scope,
    req: &Request,
    file: File,
    meta: &Metadata,
    fs_path: &std::path::Path,
    mime_name: &[u8],
    peer: std::net::IpAddr,
    local_ip: &str,
    grant: &crate::access::AccessGrant,
    resource: &crate::access::ResourceKey,
) -> Response {
    if !grant.require(resource) || resource.fs_path.as_deref() != Some(fs_path) {
        return error_response(cfg, None, scope, 500, req, "", 0, "", peer, local_ip);
    }
    let mut r = serve_file_inner(cfg, scope, req, file, meta, mime_name, peer, local_ip);
    crate::compression::finalize(scope, req, &mut r, mime_name);
    r
}

enum DirAction {
    Redirect(String),
    Index(File, Metadata, Vec<u8>),
    List(Vec<(Vec<u8>, bool, u64)>),
    Forbidden,
}

fn directory_action(
    cfg: &Config,
    scope: &Scope,
    req: &Request,
    dir: &File,
    url_path: &str,
    raw_path: &[u8],
    follow: bool,
) -> DirAction {
    let has_slash = url_path.ends_with('/');
    let slash_enabled = scope.content_policy.directory_slash.unwrap_or(true);
    if !has_slash && slash_enabled {
        let mut loc = raw_path.to_vec();
        loc.push(b'/');
        if !req.query.is_empty() {
            loc.push(b'?');
            loc.extend_from_slice(&req.query);
        }
        return DirAction::Redirect(String::from_utf8_lossy(&loc).into_owned());
    }
    for name in cfg.directory_index_for(scope) {
        if name.contains('/') || name == ".." || name == "." || name.is_empty() {
            continue;
        }
        if let Ok(f) = open_at(dir, name.as_bytes(), follow) {
            if let Ok(m) = f.metadata() {
                if m.is_file() {
                    return DirAction::Index(f, m, name.into_bytes());
                }
            }
        }
    }
    if scope
        .effective_options()
        .contains(crate::config::Options::INDEXES)
    {
        let path = format!("/proc/self/fd/{}", dir.as_raw_fd());
        let mut entries: Vec<(Vec<u8>, bool, u64)> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(path) {
            for ent in rd.flatten() {
                let name = ent.file_name().as_encoded_bytes().to_vec();
                if name.starts_with(b".") {
                    continue;
                }
                if name.ends_with(b"~") || name.starts_with(b"#") {
                    continue;
                }
                let meta = ent.metadata().ok();
                let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let size = meta.as_ref().map(|m| m.size()).unwrap_or(0);
                entries.push((name, is_dir, size));
            }
        }
        entries.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| a.0.to_ascii_lowercase().cmp(&b.0.to_ascii_lowercase()))
        });
        return DirAction::List(entries);
    }
    DirAction::Forbidden
}

/// Return the configured directory index filename when the directory should
/// serve one.  The caller is expected to perform an internal subrequest so
/// handlers (CGI, FastCGI, filters) run exactly as for a direct request.
pub fn directory_index_name(
    cfg: &Config,
    scope: &Scope,
    req: &Request,
    dir: &File,
    url_path: &str,
    raw_path: &[u8],
) -> Option<Vec<u8>> {
    let follow = scope
        .effective_options()
        .contains(crate::config::Options::FOLLOW_SYMLINKS)
        || scope
            .effective_options()
            .contains(crate::config::Options::SYMLINKS_IF_OWNER_MATCH);
    match directory_action(cfg, scope, req, dir, url_path, raw_path, follow) {
        DirAction::Index(_, _, name) => Some(name),
        _ => None,
    }
}

/// Serve a directory target (index file, autoindex or redirect).
fn serve_directory_inner(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    req: &Request,
    dir: File,
    url_path: &str,
    raw_path: &[u8],
    host: &str,
    port: u16,
    peer: std::net::IpAddr,
    local_ip: &str,
) -> Response {
    let follow = scope
        .effective_options()
        .contains(crate::config::Options::FOLLOW_SYMLINKS)
        || scope
            .effective_options()
            .contains(crate::config::Options::SYMLINKS_IF_OWNER_MATCH);
    match directory_action(cfg, scope, req, &dir, url_path, raw_path, follow) {
        DirAction::Redirect(loc) => {
            let authority = req
                .header_str("host")
                .map(str::trim)
                .filter(|h| !h.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| {
                    if port == 80 {
                        host.to_string()
                    } else {
                        format!("{host}:{port}")
                    }
                });
            let loc = if loc.starts_with('/') {
                format!("http://{authority}{loc}")
            } else {
                loc
            };
            let mut r = Response::new(301);
            r.headers
                .push(("Location".into(), loc.clone().into_bytes()));
            r.headers.push((
                "Content-Type".into(),
                b"text/html; charset=iso-8859-1".to_vec(),
            ));
            let body = format!(
                "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>301 Moved Permanently</title>\n</head><body>\n<h1>Moved Permanently</h1>\n<p>The document has moved <a href=\"{}\">here</a>.</p>\n</body></html>\n",
                html_escape(loc.as_bytes())
            );
            r.body = Body::Bytes(body.into_bytes());
            r
        }
        DirAction::Index(_, _, name) => {
            let index_url = format!(
                "{}/{}",
                url_path.trim_end_matches('/'),
                String::from_utf8_lossy(&name)
            );
            crate::server::internal_dispatch(
                cfg,
                req,
                &index_url,
                std::net::SocketAddr::new(peer, 0),
                local_ip,
                port,
            )
        }
        DirAction::List(entries) => autoindex(cfg, scope, url_path, &entries, host, port),
        DirAction::Forbidden => error_response(
            cfg, vhost, scope, 403, req, url_path, port, host, peer, local_ip,
        ),
    }
}

pub fn serve_directory(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    req: &Request,
    dir: File,
    meta: &Metadata,
    fs_path: &std::path::Path,
    url_path: &str,
    raw_path: &[u8],
    host: &str,
    port: u16,
    peer: std::net::IpAddr,
    local_ip: &str,
    grant: &crate::access::AccessGrant,
    resource: &crate::access::ResourceKey,
) -> Response {
    if !grant.require(resource) || resource.fs_path.as_deref() != Some(fs_path) {
        return error_response(
            cfg, vhost, scope, 500, req, url_path, port, host, peer, local_ip,
        );
    }
    let mut r = serve_directory_inner(
        cfg, vhost, scope, req, dir, url_path, raw_path, host, port, peer, local_ip,
    );
    crate::compression::finalize(scope, req, &mut r, url_path.as_bytes());
    r
}

fn autoindex(
    cfg: &Config,
    scope: &Scope,
    url_path: &str,
    entries: &[(Vec<u8>, bool, u64)],
    host: &str,
    port: u16,
) -> Response {
    let title = format!("Index of {}", html_escape(url_path.as_bytes()));
    let mut body = String::new();
    body.push_str(
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n<html>\n <head>\n  <title>",
    );
    body.push_str(&title);
    body.push_str("</title>\n </head>\n <body>\n<h1>");
    body.push_str(&title);
    body.push_str("</h1>\n  <table>\n");
    if url_path != "/" {
        body.push_str("   <tr><td><a href=\"../\">Parent Directory</a></td></tr>\n");
    }
    for (name, is_dir, size) in entries {
        let mut href = url_encode_path(name);
        if *is_dir {
            href.push('/');
        }
        body.push_str("   <tr><td><a href=\"");
        body.push_str(&href);
        body.push_str("\">");
        body.push_str(&html_escape(name));
        if *is_dir {
            body.push('/');
        }
        body.push_str("</a></td><td>");
        if *is_dir {
            body.push_str("-");
        } else {
            body.push_str(&size.to_string());
        }
        body.push_str("</td></tr>\n");
    }
    body.push_str("  </table>\n");
    add_signature(&mut body, cfg, host, port);
    body.push_str(" </body>\n</html>\n");
    let mut r = Response::bytes(200, "text/html; charset=UTF-8", body.into_bytes());
    for (n, v) in &scope.header_policy.set_headers {
        r.headers
            .push((Cow::Owned(n.clone()), v.as_bytes().to_vec()));
    }
    r
}

fn add_signature(body: &mut String, cfg: &Config, host: &str, port: u16) {
    if cfg.server_signature == ServerSignature::Off {
        return;
    }
    body.push_str("<hr>\n<address>");
    body.push_str(&html_escape(cfg.server_header().as_bytes()));
    if cfg.server_signature == ServerSignature::Email {
        body.push_str(" Server at ");
        body.push_str(&html_escape(host.as_bytes()));
        body.push_str(" Port ");
        body.push_str(&port.to_string());
    } else {
        body.push_str(" Server at ");
        body.push_str(&html_escape(host.as_bytes()));
        body.push_str(" Port ");
        body.push_str(&port.to_string());
    }
    body.push_str("</address>\n");
}

fn error_response_inner(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    status: u16,
    req: &Request,
    url_path: &str,
    port: u16,
    host: &str,
    peer: std::net::IpAddr,
    local_ip: &str,
) -> Response {
    if let Some(doc) = scope.error_document(status) {
        match doc {
            ErrorDoc::Text(t) => {
                return Response::bytes(
                    status,
                    "text/html; charset=iso-8859-1",
                    t.as_bytes().to_vec(),
                )
            }
            ErrorDoc::External(url) => {
                let mut r = Response::bytes(
                    302,
                    "text/html; charset=iso-8859-1",
                    format!(
                        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>302 Found</title>\n</head><body>\n<h1>Found</h1>\n<p>The document has moved <a href=\"{}\">here</a>.</p>\n</body></html>\n",
                        html_escape(url.as_bytes())
                    )
                    .into_bytes(),
                );
                r.headers.push(("Location".into(), url.as_bytes().to_vec()));
                return r;
            }
            ErrorDoc::Local(path) => {
                if let Some(r) =
                    serve_error_document(cfg, vhost, req, path, status, peer, local_ip, port)
                {
                    return r;
                }
            }
        }
    }
    let reason = reason_phrase(status);
    let mut body = String::new();
    body.push_str("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>");
    body.push_str(&format!("{status} {reason}"));
    body.push_str("</title>\n</head><body>\n<h1>");
    body.push_str(reason);
    body.push_str("</h1>\n<p>");
    body.push_str(&error_message(status, url_path));
    body.push_str("</p>\n");
    add_signature(&mut body, cfg, host, port);
    body.push_str("</body></html>\n");
    let mut r = Response::bytes(status, "text/html; charset=iso-8859-1", body.into_bytes());
    r.headers.push((
        "Cache-Control".into(),
        if status >= 400 {
            b"no-store".to_vec()
        } else {
            b"no-cache".to_vec()
        },
    ));
    r
}

pub fn error_response(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    status: u16,
    req: &Request,
    url_path: &str,
    port: u16,
    host: &str,
    peer: std::net::IpAddr,
    local_ip: &str,
) -> Response {
    let mut r = error_response_inner(
        cfg, vhost, scope, status, req, url_path, port, host, peer, local_ip,
    );
    crate::compression::finalize(scope, req, &mut r, url_path.as_bytes());
    r
}

fn error_message(status: u16, url: &str) -> String {
    let url = html_escape(url.as_bytes());
    match status {
        400 => "Your browser sent a request that this server could not understand.".into(),
        401 => "This server could not verify that you are authorized to access the document requested.".into(),
        403 => format!("You don't have permission to access this resource."),
        404 => format!("The requested URL {url} was not found on this server."),
        405 => "The requested method is not allowed for this URL.".into(),
        408 => "The server closed the network connection because the browser didn't finish the request within the specified time.".into(),
        412 => "The precondition on the request for the URL failed positive evaluation.".into(),
        413 => "The requested resource does not allow request data with the requested method.".into(),
        414 => "The requested URL's length exceeds the capacity limit for this server.".into(),
        416 => "The requested range is not satisfiable.".into(),
        431 => "The server is unwilling to process the request because its header fields are too large.".into(),
        500 => "The server encountered an internal error or misconfiguration and was unable to complete your request.".into(),
        501 => "The server does not support the action requested by the browser.".into(),
        503 => "The server is temporarily unable to service your request due to maintenance downtime or capacity problems.".into(),
        505 => "The server does not support the HTTP protocol version used in the request.".into(),
        _ => "An unexpected error occurred.".into(),
    }
}

thread_local! {
    static IN_ERROR_DOCUMENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn serve_error_document(
    cfg: &Config,
    _vhost: Option<&VHost>,
    req: &Request,
    path: &str,
    status: u16,
    peer: std::net::IpAddr,
    local_ip: &str,
    local_port: u16,
) -> Option<Response> {
    // Avoid recursion when an error document itself fails (for example a
    // missing ErrorDocument target).
    if IN_ERROR_DOCUMENT.with(|active| active.replace(true)) {
        return None;
    }
    let response = crate::server::internal_dispatch(
        cfg,
        req,
        path,
        std::net::SocketAddr::new(peer, 0),
        local_ip,
        local_port,
    );
    IN_ERROR_DOCUMENT.with(|active| active.set(false));
    if response.status >= 300 {
        return None;
    }
    let mut response = response;
    response.status = status;
    Some(response)
}

/// Build a small `text/html` response used for OPTIONS and redirects.
pub fn simple_html(status: u16, message: &str, location: Option<&str>) -> Response {
    let reason = reason_phrase(status);
    let mut r = Response::bytes(
        status,
        "text/html; charset=iso-8859-1",
        format!(
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>{status} {reason}</title>\n</head><body>\n<h1>{reason}</h1>\n<p>{}</p>\n</body></html>\n",
            html_escape(message.as_bytes())
        )
        .into_bytes(),
    );
    if let Some(l) = location {
        r.headers.push(("Location".into(), l.as_bytes().to_vec()));
    }
    r
}
