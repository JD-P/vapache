//! HTTP/1.1 parsing and response serialization.
//!
//! The parser is intentionally strict and linear: no request smuggling via
//! conflicting `Content-Length`/`Transfer-Encoding`, no obs-fold, no
//! whitespace before the colon, bounded header counts and sizes, and an
//! allow-list token check for methods and header names.  These are the
//! parsing rules that httpd's own security advisories keep returning to.

use crate::util::{trim_ascii, with_http_date_now};
use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use vapache_verified::{parse_request_head, HeadError, HttpVersion, ParsedHead};

pub use vapache_verified::BodyFraming;

pub const DEFAULT_LIMIT_REQUEST_LINE: usize = 8190;
pub const DEFAULT_LIMIT_REQUEST_FIELDS: usize = 100;
pub const DEFAULT_LIMIT_REQUEST_FIELD_SIZE: usize = 8190;
pub const MAX_HEAD_TOTAL: usize = 131_072;
pub const MAX_BODY_BUFFERED: u64 = 32 * 1024 * 1024;
/// Request bodies above this size are spooled to an unlinked temporary file
/// instead of occupying heap memory for the whole request.
pub const MAX_REQUEST_BODY_IN_MEMORY: u64 = 1024 * 1024;
/// Bound request trailers the same way the proxy reader does.
const MAX_REQUEST_TRAILERS: usize = 64;
const MAX_REQUEST_TRAILER_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Version {
    Http10,
    Http11,
    Http2,
}

impl Version {
    pub fn as_str(self) -> &'static str {
        match self {
            Version::Http10 => "HTTP/1.0",
            Version::Http11 => "HTTP/1.1",
            Version::Http2 => "HTTP/2.0",
        }
    }
}

impl From<HttpVersion> for Version {
    fn from(v: HttpVersion) -> Self {
        match v {
            HttpVersion::Http10 => Version::Http10,
            HttpVersion::Http11 => Version::Http11,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Headers {
    entries: Vec<(String, Vec<u8>)>,
}

impl Headers {
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
    }

    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.entries
            .iter()
            .filter(move |(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.entries.iter().any(|(n, _)| n == name)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.entries.iter().map(|(n, v)| (n.as_str(), v.as_slice()))
    }

    pub fn insert(&mut self, name: &str, value: impl Into<Vec<u8>>) {
        let lname = name.to_ascii_lowercase();
        self.entries.retain(|(n, _)| *n != lname);
        self.entries.push((lname, value.into()));
    }

    pub fn remove(&mut self, name: &str) {
        let lname = name.to_ascii_lowercase();
        self.entries.retain(|(n, _)| *n != lname);
    }

    pub fn push(&mut self, name: &str, value: impl Into<Vec<u8>>) {
        self.entries.push((name.to_ascii_lowercase(), value.into()));
    }
}

#[derive(Debug)]
pub struct SpooledBody {
    file: std::sync::Mutex<File>,
    pub len: u64,
}

impl SpooledBody {
    pub fn reader(&self) -> io::Result<File> {
        let file = self.file.lock().unwrap_or_else(|e| e.into_inner());
        let mut clone = file.try_clone()?;
        clone.seek(SeekFrom::Start(0))?;
        Ok(clone)
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    pub target: Vec<u8>,
    /// Raw path bytes (still percent-encoded), without the query string.
    pub raw_path: Vec<u8>,
    pub query: Vec<u8>,
    pub version: Version,
    pub headers: Headers,
    pub body: Vec<u8>,
    /// Bodies above the in-memory threshold are spooled here.  The file is
    /// unlinked immediately and shared by clones of the request.
    pub body_spool: Option<std::sync::Arc<SpooledBody>>,
    pub keep_alive: bool,
    pub expect_continue: bool,
    /// Body framing proved by the verified request-head parser.
    pub framing: BodyFraming,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers.get(name)
    }

    pub fn header_str(&self, name: &str) -> Option<&str> {
        self.header(name).and_then(|v| std::str::from_utf8(v).ok())
    }

    pub fn is_head(&self) -> bool {
        self.method == "HEAD"
    }

    pub fn body_len(&self) -> u64 {
        self.body_spool
            .as_ref()
            .map(|b| b.len)
            .unwrap_or(self.body.len() as u64)
    }

    pub fn body_reader(&self) -> Option<io::Result<File>> {
        self.body_spool.as_ref().map(|b| b.reader())
    }
}

#[derive(Debug)]
pub enum ParseError {
    BadRequest(&'static str),
    UriTooLong,
    HeadersTooLarge,
    TooManyHeaders,
    VersionNotSupported,
    PayloadTooLarge,
    LengthRequired,
    NotImplemented(&'static str),
}

impl ParseError {
    pub fn status(&self) -> u16 {
        match self {
            ParseError::BadRequest(_) => 400,
            ParseError::UriTooLong => 414,
            ParseError::HeadersTooLarge | ParseError::TooManyHeaders => 431,
            ParseError::VersionNotSupported => 505,
            ParseError::PayloadTooLarge => 413,
            ParseError::LengthRequired => 411,
            ParseError::NotImplemented(_) => 501,
        }
    }

    pub fn message(&self) -> String {
        match self {
            ParseError::BadRequest(m) => format!("Bad request: {m}"),
            ParseError::UriTooLong => "Request-URI Too Long".into(),
            ParseError::HeadersTooLarge => "Request Header Fields Too Large".into(),
            ParseError::TooManyHeaders => "Too Many Request Header Fields".into(),
            ParseError::VersionNotSupported => "HTTP Version Not Supported".into(),
            ParseError::PayloadTooLarge => "Request Entity Too Large".into(),
            ParseError::LengthRequired => "Length Required".into(),
            ParseError::NotImplemented(m) => format!("Not implemented: {m}"),
        }
    }
}

#[derive(Debug)]
pub enum ReadError {
    Io(io::Error),
    Parse(ParseError),
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        ReadError::Io(e)
    }
}

impl From<ParseError> for ReadError {
    fn from(e: ParseError) -> Self {
        ReadError::Parse(e)
    }
}

pub struct Limits {
    pub request_line: usize,
    pub fields: usize,
    pub field_size: usize,
    pub body: u64,
    pub header_timeout: Duration,
    pub body_timeout: Duration,
    pub header_min_rate: u64,
    pub body_min_rate: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            request_line: DEFAULT_LIMIT_REQUEST_LINE,
            fields: DEFAULT_LIMIT_REQUEST_FIELDS,
            field_size: DEFAULT_LIMIT_REQUEST_FIELD_SIZE,
            body: MAX_BODY_BUFFERED,
            header_timeout: Duration::from_secs(20),
            body_timeout: Duration::from_secs(30),
            header_min_rate: 0,
            body_min_rate: 0,
        }
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    // Strict CRLF CRLF.  Bare-LF tolerance is intentionally not provided:
    // split-parser differentials are a recurring smuggling vector.
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Read one complete request from a keep-alive connection.
///
/// `buf` is a per-connection buffer; any bytes belonging to the next pipelined
/// request remain in it.  Returns `Ok(None)` on a clean EOF between requests.
pub fn read_request<R: Read + Write>(
    stream: &mut R,
    buf: &mut Vec<u8>,
    limits: &Limits,
    on_headers: impl FnOnce(&mut R),
) -> Result<Option<Request>, ReadError> {
    let header_started = Instant::now();
    let head_end = loop {
        if let Some(end) = find_head_end(buf) {
            break end;
        }
        if buf.len() > MAX_HEAD_TOTAL {
            return Err(ReadError::Parse(ParseError::HeadersTooLarge));
        }
        let elapsed = header_started.elapsed();
        let allowed = if limits.header_min_rate == 0 {
            limits.header_timeout
        } else {
            limits.header_timeout.max(Duration::from_millis(
                (buf.len() as u64 * 1000) / limits.header_min_rate,
            ))
        };
        if elapsed > allowed {
            return Err(ReadError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "request header timeout",
            )));
        }
        let mut chunk = [0u8; 8192];
        match stream.read(&mut chunk) {
            Ok(0) => {
                if buf.is_empty() {
                    return Ok(None);
                }
                return Err(ReadError::Parse(ParseError::BadRequest(
                    "unexpected EOF in request headers",
                )));
            }
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ReadError::Io(e)),
        }
        if buf.len() > MAX_HEAD_TOTAL {
            return Err(ReadError::Parse(ParseError::HeadersTooLarge));
        }
    };

    // Parse directly from the connection buffer; the verified parser returns
    // owned request fields and does not retain a borrow of the head.
    let mut req = parse_head(&buf[..head_end], limits)?;
    buf.drain(..head_end);

    let framing = req.framing;
    on_headers(stream);

    if req.expect_continue && framing != BodyFraming::None {
        // The client is waiting for this before sending the body.
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
        stream.flush()?;
    }

    match framing {
        BodyFraming::None => {}
        BodyFraming::Length(n) => {
            if n > limits.body {
                return Err(ReadError::Parse(ParseError::PayloadTooLarge));
            }
            let body_deadline = Instant::now()
                + if limits.body_min_rate == 0 {
                    limits.body_timeout
                } else {
                    limits.body_timeout.max(Duration::from_millis(
                        n.saturating_mul(1000) / limits.body_min_rate,
                    ))
                };
            if n > MAX_REQUEST_BODY_IN_MEMORY {
                let file = spool_file()?;
                let mut file = file;
                let take = (n as usize).min(buf.len());
                file.write_all(&buf[..take])?;
                buf.drain(..take);
                let mut remaining = n - take as u64;
                let mut chunk = vec![0u8; 64 * 1024];
                while remaining > 0 {
                    if Instant::now() > body_deadline {
                        return Err(ReadError::Io(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "request body timeout",
                        )));
                    }
                    let want = remaining.min(chunk.len() as u64) as usize;
                    let got = stream.read(&mut chunk[..want])?;
                    if got == 0 {
                        return Err(ReadError::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "EOF in request body",
                        )));
                    }
                    file.write_all(&chunk[..got])?;
                    remaining -= got as u64;
                }
                req.body_spool = Some(std::sync::Arc::new(SpooledBody {
                    file: std::sync::Mutex::new(file),
                    len: n,
                }));
            } else {
                read_exact_into(
                    stream,
                    buf,
                    &mut req.body,
                    n,
                    body_deadline,
                    limits.body_min_rate,
                )?;
            }
        }
        BodyFraming::Chunked => {
            let mut file = spool_file()?;
            let chunk_deadline = Instant::now()
                + if limits.body_min_rate == 0 {
                    limits.body_timeout
                } else {
                    limits.body_timeout.max(Duration::from_millis(
                        limits.body.saturating_mul(1000) / limits.body_min_rate,
                    ))
                };
            let len = read_chunked_to_file(stream, buf, &mut file, limits.body, chunk_deadline)?;
            req.body_spool = Some(std::sync::Arc::new(SpooledBody {
                file: std::sync::Mutex::new(file),
                len,
            }));
        }
    }
    Ok(Some(req))
}

const SPOOL_ATTEMPTS: u64 = 16;

fn spool_path(dir: &Path, counter: u64) -> PathBuf {
    dir.join(format!(
        "vapache-request-{}-{}.body",
        std::process::id(),
        counter
    ))
}

/// Create an unlinked, private spool file.  `O_EXCL` matters: a predictable
/// name in a shared temporary directory must never follow a pre-created
/// symlink (which could truncate or expose a file the server can reach).  A
/// colliding name is skipped rather than followed, and a bounded number of
/// collisions fails closed.
fn spool_file_named(dir: &Path, counter: &std::sync::atomic::AtomicU64) -> io::Result<File> {
    use std::sync::atomic::Ordering;
    for _ in 0..SPOOL_ATTEMPTS {
        let n = counter.fetch_add(1, Ordering::Relaxed);
        let path = spool_path(dir, n);
        match OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => {
                let _ = std::fs::remove_file(&path);
                return Ok(file);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "cannot create a private request spool file",
    ))
}

pub(crate) fn spool_file() -> io::Result<File> {
    use std::sync::atomic::AtomicU64;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    spool_file_named(&std::env::temp_dir(), &COUNTER)
}

fn read_exact_into<R: Read>(
    stream: &mut R,
    buf: &mut Vec<u8>,
    out: &mut Vec<u8>,
    n: u64,
    deadline: Instant,
    min_rate: u64,
) -> io::Result<()> {
    let n = n as usize;
    out.reserve(n.min(1 << 20));
    let take = n.min(buf.len());
    out.extend_from_slice(&buf[..take]);
    buf.drain(..take);
    let mut remaining = n - take;
    let mut chunk = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let elapsed = deadline.saturating_duration_since(Instant::now());
        if elapsed.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request body timeout",
            ));
        }
        let want = remaining.min(chunk.len());
        let got = stream.read(&mut chunk[..want])?;
        if got == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF in request body",
            ));
        }
        out.extend_from_slice(&chunk[..got]);
        remaining -= got;
    }
    Ok(())
}

fn read_chunked_to_file<R: Read>(
    stream: &mut R,
    buf: &mut Vec<u8>,
    file: &mut File,
    max: u64,
    deadline: Instant,
) -> io::Result<u64> {
    let mut total = 0u64;
    loop {
        if Instant::now() > deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request body timeout",
            ));
        }
        let line = read_line(stream, buf, 1024)?;
        let size_part = line.split(|b| *b == b';').next().unwrap_or(&line);
        let size = crate::util::parse_hex_u64(trim_ascii(size_part))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
        if size == 0 {
            // Trailer fields are part of the request body deadline.  Without
            // an explicit check a client can send a zero-size chunk and then
            // keep one worker busy with trailer lines indefinitely.
            let mut trailer_count = 0usize;
            let mut trailer_bytes = 0usize;
            loop {
                if Instant::now() > deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "request body timeout",
                    ));
                }
                let t = read_line(stream, buf, 8190)?;
                if t.is_empty() {
                    return Ok(total);
                }
                trailer_count += 1;
                trailer_bytes = trailer_bytes.saturating_add(t.len() + 2);
                if trailer_count > MAX_REQUEST_TRAILERS || trailer_bytes > MAX_REQUEST_TRAILER_BYTES
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "request trailers too large",
                    ));
                }
            }
        }
        if total.saturating_add(size) > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked body too large",
            ));
        }
        let size_usize = usize::try_from(size)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk too large"))?;
        let mut remaining = size_usize;
        while remaining > 0 {
            if Instant::now() > deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "request body timeout",
                ));
            }
            if !buf.is_empty() {
                let take = remaining.min(buf.len());
                file.write_all(&buf[..take])?;
                buf.drain(..take);
                remaining -= take;
                total += take as u64;
            } else {
                let mut chunk = [0u8; 8192];
                let want = remaining.min(chunk.len());
                let got = stream.read(&mut chunk[..want])?;
                if got == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "EOF in chunked body",
                    ));
                }
                file.write_all(&chunk[..got])?;
                remaining -= got;
                total += got as u64;
            }
        }
        let mut crlf = [0u8; 2];
        if buf.len() >= 2 {
            crlf.copy_from_slice(&buf[..2]);
            buf.drain(..2);
        } else {
            stream.read_exact(&mut crlf)?;
        }
        if crlf != *b"\r\n" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad chunk crlf"));
        }
    }
}

fn read_line<R: Read>(stream: &mut R, buf: &mut Vec<u8>, max: usize) -> io::Result<Vec<u8>> {
    loop {
        if let Some(p) = buf.windows(2).position(|w| w == b"\r\n") {
            if p > max {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
            }
            let line = buf[..p].to_vec();
            buf.drain(..p + 2);
            return Ok(line);
        }
        if buf.len() > max + 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        let mut chunk = [0u8; 8192];
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF in chunked body",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn parse_head(head: &[u8], limits: &Limits) -> Result<Request, ParseError> {
    let parsed = parse_request_head(head, limits.request_line, limits.fields, limits.field_size)
        .map_err(head_error)?;
    let ParsedHead {
        method,
        target,
        raw_path,
        query,
        version,
        headers,
        framing,
        keep_alive,
        expect_continue,
    } = parsed;

    let method =
        String::from_utf8(method).map_err(|_| ParseError::BadRequest("non-ASCII method"))?;
    let mut entries = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        let name =
            String::from_utf8(name).map_err(|_| ParseError::BadRequest("non-ASCII header name"))?;
        entries.push((name, value));
    }

    Ok(Request {
        method,
        target,
        raw_path,
        query,
        version: version.into(),
        headers: Headers { entries },
        body: Vec::new(),
        body_spool: None,
        keep_alive,
        expect_continue,
        framing,
    })
}

/// Map a rejection from the verified request-head parser to the wire-level
/// `ParseError` that the HTTP/1.1 layer has always used.
fn head_error(e: HeadError) -> ParseError {
    match e {
        HeadError::NulByte => ParseError::BadRequest("NUL in request"),
        HeadError::TooManyEmptyLines => ParseError::BadRequest("too many empty lines"),
        HeadError::UnterminatedRequestLine => ParseError::BadRequest("unterminated request line"),
        HeadError::RequestLineTooLong => ParseError::UriTooLong,
        HeadError::MissingMethod => ParseError::BadRequest("missing method"),
        HeadError::MissingTarget => ParseError::BadRequest("missing request target"),
        HeadError::MissingVersion => ParseError::BadRequest("missing HTTP version"),
        HeadError::WhitespaceInRequestLine => ParseError::BadRequest("whitespace in request line"),
        HeadError::InvalidMethod => ParseError::BadRequest("invalid method"),
        HeadError::InvalidTargetByte => ParseError::BadRequest("invalid byte in request target"),
        HeadError::InvalidVersion => ParseError::BadRequest("invalid HTTP version"),
        HeadError::VersionNotSupported => ParseError::VersionNotSupported,
        HeadError::UnterminatedHeaders => ParseError::BadRequest("unterminated headers"),
        HeadError::UnterminatedHeader => ParseError::BadRequest("unterminated header"),
        HeadError::HeaderLineTooLong => ParseError::HeadersTooLarge,
        HeadError::ObsoleteFolding => ParseError::BadRequest("obsolete line folding"),
        HeadError::MissingColon => ParseError::BadRequest("header without colon"),
        HeadError::InvalidHeaderName => ParseError::BadRequest("invalid header name"),
        HeadError::InvalidHeaderValue => ParseError::BadRequest("invalid header value"),
        HeadError::TooManyHeaders => ParseError::TooManyHeaders,
        HeadError::DuplicateHost => ParseError::BadRequest("duplicate Host header"),
        HeadError::MissingHost => ParseError::BadRequest("missing Host header"),
        HeadError::InvalidHost => ParseError::BadRequest("invalid Host header"),
        HeadError::InvalidAuthority => ParseError::BadRequest("invalid absolute URI authority"),
        HeadError::NotOriginForm => ParseError::BadRequest("request target is not origin-form"),
        HeadError::FragmentInTarget => ParseError::BadRequest("fragment in request target"),
        HeadError::BothTransferEncodingAndContentLength => {
            ParseError::BadRequest("both Transfer-Encoding and Content-Length")
        }
        HeadError::TransferEncodingInHttp10 => {
            ParseError::BadRequest("Transfer-Encoding in HTTP/1.0 request")
        }
        HeadError::UnsupportedTransferCoding => {
            ParseError::NotImplemented("unsupported transfer coding")
        }
        HeadError::InvalidContentLength => ParseError::BadRequest("invalid Content-Length"),
        HeadError::ConflictingContentLength => {
            ParseError::BadRequest("conflicting Content-Length values")
        }
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

pub enum Body {
    Empty,
    Bytes(Vec<u8>),
    File {
        file: File,
        offset: u64,
        len: u64,
    },
    Stream {
        reader: Box<dyn Read + Send>,
        len: u64,
    },
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(Cow<'static, str>, Vec<u8>)>,
    pub body: Body,
}

impl Response {
    pub fn new(status: u16) -> Self {
        Response {
            status,
            headers: Vec::new(),
            body: Body::Empty,
        }
    }

    pub fn bytes(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        let mut r = Response::new(status);
        r.headers.push((
            Cow::Borrowed("Content-Type"),
            content_type.as_bytes().to_vec(),
        ));
        r.body = Body::Bytes(body);
        r
    }

    pub fn header(mut self, name: &str, value: impl Into<Vec<u8>>) -> Self {
        self.headers
            .push((Cow::Owned(name.to_string()), value.into()));
        self
    }

    pub fn body_len(&self) -> u64 {
        match &self.body {
            Body::Empty => 0,
            Body::Bytes(b) => b.len() as u64,
            Body::File { len, .. } => *len,
            Body::Stream { len, .. } => *len,
        }
    }
}

#[inline]
fn push_decimal(out: &mut Vec<u8>, mut n: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&buf[i..]);
}

pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Requested Range Not Satisfiable",
        417 => "Expectation Failed",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

/// A response destination.  Raw file descriptors are used only for plain TCP
/// sockets; TLS and other wrappers must copy file bodies through `Write` so
/// that bytes are encrypted.
pub trait ResponseWrite: Write {
    fn raw_fd(&self) -> Option<RawFd> {
        None
    }
}

impl ResponseWrite for TcpStream {
    fn raw_fd(&self) -> Option<RawFd> {
        Some(self.as_raw_fd())
    }
}

pub struct ResponseOptions<'a> {
    pub server_header: &'a str,
    pub keep_alive: bool,
    pub head_only: bool,
    pub protocol: Version,
    pub request_keep_alive: bool,
}

/// Serialize a response and send its body.  Returns the number of body bytes
/// actually sent (used for `%O` accounting).
pub fn write_response<W: ResponseWrite>(
    stream: &mut W,
    resp: &mut Response,
    opts: &ResponseOptions,
) -> io::Result<u64> {
    let body_len = resp.body_len();
    let status = resp.status;
    let mut have_date = false;
    let mut have_server = false;
    for (n, _) in &resp.headers {
        if n.eq_ignore_ascii_case("date") {
            have_date = true;
        } else if n.eq_ignore_ascii_case("server") {
            have_server = true;
        }
    }
    let no_body_status = status == 204 || status == 304 || (100..200).contains(&status);
    // For a HEAD response there is no body to frame, and a 204/304/1xx status
    // has no body by definition.  Preserve an explicitly supplied
    // Content-Length there (HEAD mirrors the GET representation); for every
    // body-bearing response the writer computes it from the bytes it will send.
    let preserve_content_length = (opts.head_only || no_body_status)
        && resp
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("content-length"));

    // Coalesce the response head with small bodies into one write.  For static
    // files this avoids a separate header packet/syscall; larger files still
    // use sendfile.  The limits keep CGI/error bodies from being double-buffered
    // without bound.
    const INLINE_BYTES_LIMIT: u64 = 64 * 1024;
    const INLINE_FILE_LIMIT: u64 = 16 * 1024;
    let inline_body = !opts.head_only
        && !no_body_status
        && match &resp.body {
            Body::Bytes(_) => body_len <= INLINE_BYTES_LIMIT,
            Body::File { len, .. } => *len > 0 && *len <= INLINE_FILE_LIMIT,
            Body::Empty | Body::Stream { .. } => false,
        };
    let mut head = Vec::with_capacity(512 + if inline_body { body_len as usize } else { 0 });
    head.extend_from_slice(b"HTTP/1.1 ");
    push_decimal(&mut head, status as u64);
    head.push(b' ');
    head.extend_from_slice(reason_phrase(status).as_bytes());
    head.extend_from_slice(b"\r\n");
    if !have_date {
        head.extend_from_slice(b"Date: ");
        with_http_date_now(|date| head.extend_from_slice(date.as_bytes()));
        head.extend_from_slice(b"\r\n");
    }
    if !have_server {
        head.extend_from_slice(b"Server: ");
        head.extend_from_slice(opts.server_header.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    for (name, value) in &resp.headers {
        // The writer owns the message framing.  A caller-supplied
        // Content-Length/Transfer-Encoding that disagreed with the bytes sent
        // would desynchronize a keep-alive connection (request/response
        // smuggling for the next request on the socket).
        if name.eq_ignore_ascii_case("content-length") {
            if !preserve_content_length {
                continue;
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            continue;
        }
        // Never let an upstream/CGI/filename-derived header split the response.
        if crate::verified::sanitize_header_value(value).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CR/LF/NUL in response header",
            ));
        }
        if !crate::verified::valid_token(name.as_bytes()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid response header name",
            ));
        }
        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value);
        head.extend_from_slice(b"\r\n");
    }
    if !preserve_content_length && !no_body_status {
        head.extend_from_slice(b"Content-Length: ");
        push_decimal(&mut head, body_len);
        head.extend_from_slice(b"\r\n");
    }
    let close = !opts.keep_alive || !opts.request_keep_alive;
    if close {
        head.extend_from_slice(b"Connection: close\r\n");
    } else if opts.protocol == Version::Http10 {
        head.extend_from_slice(b"Connection: keep-alive\r\n");
    }
    head.extend_from_slice(b"\r\n");

    if inline_body {
        let mut sent = 0u64;
        if let Body::Bytes(b) = &mut resp.body {
            head.extend_from_slice(b);
            sent = b.len() as u64;
        }
        if let Body::File { file, offset, len } = &mut resp.body {
            file.seek(SeekFrom::Start(*offset))?;
            let start = head.len();
            head.resize(start + *len as usize, 0);
            file.read_exact(&mut head[start..])?;
            sent = *len;
        }
        stream.write_all(&head)?;
        stream.flush()?;
        return Ok(sent);
    }

    stream.write_all(&head)?;
    let mut sent = 0u64;
    if opts.head_only || no_body_status {
        return Ok(0);
    }
    match &mut resp.body {
        Body::Empty => {}
        Body::Bytes(b) => {
            stream.write_all(b)?;
            sent = b.len() as u64;
        }
        Body::Stream { reader, len } => {
            let mut tmp = vec![0u8; 64 * 1024];
            let mut remaining = *len;
            while remaining > 0 {
                let want = remaining.min(tmp.len() as u64) as usize;
                let got = reader.read(&mut tmp[..want])?;
                if got == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "short streamed response body",
                    ));
                }
                stream.write_all(&tmp[..got])?;
                sent += got as u64;
                remaining -= got as u64;
            }
        }
        Body::File { file, offset, len } => {
            if *len == 0 {
                return Ok(0);
            }
            // `sendfile` uses the explicit offset below, so the plain-TCP path
            // does not need an lseek first.  The TLS fallback seeks its own
            // cloned handle.
            let mut off = *offset as i64;
            let mut remaining = *len;
            if let Some(fd) = stream.raw_fd() {
                while remaining > 0 {
                    let chunk = remaining.min(i32::MAX as u64) as usize;
                    let n = unsafe {
                        libc::sendfile(fd, file.as_raw_fd(), &mut off as *mut i64, chunk)
                    };
                    if n < 0 {
                        // Fall through to the bounded copy path.  Never spin
                        // here on a non-blocking destination (EAGAIN): a full
                        // socket buffer is not a truncated response budget.
                        break;
                    }
                    if n == 0 {
                        break;
                    }
                    sent += n as u64;
                    remaining -= n as u64;
                }
            }
            // TLS and other non-socket destinations: copy through `Write`.
            if remaining > 0 {
                let mut f = file.try_clone()?;
                f.seek(SeekFrom::Start(off.max(0) as u64))?;
                let mut tmp = vec![0u8; 64 * 1024];
                while remaining > 0 {
                    let want = remaining.min(tmp.len() as u64) as usize;
                    let got = f.read(&mut tmp[..want])?;
                    if got == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "short file response body",
                        ));
                    }
                    stream.write_all(&tmp[..got])?;
                    sent += got as u64;
                    remaining -= got as u64;
                }
            }
        }
    }
    stream.flush()?;
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits::default()
    }

    #[test]
    fn parse_basic() {
        let raw = b"GET /index.html?x=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let req = parse_head(raw, &limits()).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.raw_path, b"/index.html");
        assert_eq!(req.query, b"x=1");
        assert_eq!(req.version, Version::Http11);
        assert!(req.keep_alive);
    }

    #[test]
    fn framing_is_decided_by_verified_parser() {
        let raw = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n";
        let req = parse_head(raw, &limits()).unwrap();
        assert_eq!(req.framing, BodyFraming::Length(5));

        let raw = b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";
        let req = parse_head(raw, &limits()).unwrap();
        assert_eq!(req.framing, BodyFraming::Chunked);

        let raw = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";
        let req = parse_head(raw, &limits()).unwrap();
        assert_eq!(req.framing, BodyFraming::None);

        let raw = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n";
        let req = parse_head(raw, &limits()).unwrap();
        assert_eq!(req.framing, BodyFraming::Length(5));

        for raw in [
            &b"POST /x HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
            b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: nope\r\n\r\n",
            b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
        ] {
            assert!(
                parse_head(raw, &limits()).is_err(),
                "{:?}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    #[test]
    fn header_names_are_canonicalized_and_values_trimmed() {
        let raw = b"GET / HTTP/1.1\r\nHost: Example.COM\r\nX-Mixed-Case:  value  \r\n\r\n";
        let req = parse_head(raw, &limits()).unwrap();
        assert_eq!(req.header("host"), Some(&b"Example.COM"[..]));
        assert_eq!(req.header("x-mixed-case"), Some(&b"value"[..]));
    }

    #[test]
    fn absolute_form_and_asterisk_targets() {
        let req = parse_head(
            b"GET http://example.com/a?b HTTP/1.1\r\nHost: example.com\r\n\r\n",
            &limits(),
        )
        .unwrap();
        assert_eq!(req.raw_path, b"/a");
        assert_eq!(req.query, b"b");

        let req = parse_head(b"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n", &limits()).unwrap();
        assert_eq!(req.raw_path, b"*");
        assert!(req.query.is_empty());
    }

    #[test]
    fn rejects_smuggling_vectors() {
        let cases: &[&[u8]] = &[
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost : x\r\n\r\n",
            b"GET / HTTP/1.1\r\n Host: x\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: x\r\nX: a\r\n folded\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: x\r\nBad\x01Name: v\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: x\r\nX: a\x00b\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            b"GET / HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n",
        ];
        for c in cases {
            assert!(
                parse_head(c, &limits()).is_err(),
                "{:?}",
                String::from_utf8_lossy(c)
            );
        }
    }

    #[test]
    fn rejects_bad_targets() {
        for t in [
            &b"GET http:/x HTTP/1.1\r\nHost: x\r\n\r\n"[..],
            b"GET /a b HTTP/1.1\r\nHost: x\r\n\r\n",
            b"GET /a#frag HTTP/1.1\r\nHost: x\r\n\r\n",
        ] {
            assert!(parse_head(t, &limits()).is_err());
        }
    }

    #[test]
    fn http10_keepalive_opt_in() {
        let req = parse_head(b"GET / HTTP/1.0\r\n\r\n", &limits()).unwrap();
        assert!(!req.keep_alive);
        let req = parse_head(
            b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
            &limits(),
        )
        .unwrap();
        assert!(req.keep_alive);
        let req = parse_head(
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            &limits(),
        )
        .unwrap();
        assert!(!req.keep_alive);
    }

    #[test]
    fn large_request_bodies_are_spooled() {
        let body = vec![b'x'; 2 * 1024 * 1024];
        let mut wire = format!(
            "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        wire.extend_from_slice(&body);
        let mut cursor = std::io::Cursor::new(wire);
        let mut buf = Vec::new();
        let req = read_request(&mut cursor, &mut buf, &limits(), |_| {})
            .unwrap()
            .unwrap();
        assert!(req.body.is_empty());
        assert_eq!(req.body_len(), body.len() as u64);
        let mut reader = req.body_reader().unwrap().unwrap();
        let mut read = Vec::new();
        reader.read_to_end(&mut read).unwrap();
        assert_eq!(read, body);
    }

    #[test]
    fn request_trailers_are_bounded() {
        let mut wire =
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".to_vec();
        for i in 0..(MAX_REQUEST_TRAILERS + 1) {
            wire.extend_from_slice(format!("X-Trailer-{i}: x\r\n").as_bytes());
        }
        wire.extend_from_slice(b"\r\n");
        let mut cursor = std::io::Cursor::new(wire);
        let mut buf = Vec::new();
        assert!(read_request(&mut cursor, &mut buf, &limits(), |_| {}).is_err());
    }

    #[test]
    fn head_limits() {
        let long = format!("GET /{} HTTP/1.1\r\nHost: x\r\n\r\n", "a".repeat(9000));
        assert!(matches!(
            parse_head(long.as_bytes(), &limits()),
            Err(ParseError::UriTooLong)
        ));
    }

    #[test]
    fn parse_error_and_reason_phrase_tables_are_complete() {
        let errors = [
            ParseError::BadRequest("x"),
            ParseError::UriTooLong,
            ParseError::HeadersTooLarge,
            ParseError::TooManyHeaders,
            ParseError::VersionNotSupported,
            ParseError::PayloadTooLarge,
            ParseError::LengthRequired,
            ParseError::NotImplemented("x"),
        ];
        for error in errors {
            assert!(error.status() >= 400);
            assert!(!error.message().is_empty());
        }
        for status in [
            100u16, 201, 202, 204, 303, 307, 308, 408, 409, 411, 413, 415, 417, 429, 431, 503, 504,
        ] {
            assert_ne!(reason_phrase(status), "Unknown", "status {status}");
        }
    }

    #[test]
    fn head_error_maps_every_parser_rejection() {
        use vapache_verified::HeadError::*;
        let errors = [
            NulByte,
            TooManyEmptyLines,
            UnterminatedRequestLine,
            RequestLineTooLong,
            MissingMethod,
            MissingTarget,
            MissingVersion,
            WhitespaceInRequestLine,
            InvalidMethod,
            InvalidTargetByte,
            InvalidVersion,
            VersionNotSupported,
            UnterminatedHeaders,
            UnterminatedHeader,
            HeaderLineTooLong,
            ObsoleteFolding,
            MissingColon,
            InvalidHeaderName,
            InvalidHeaderValue,
            TooManyHeaders,
            DuplicateHost,
            MissingHost,
            InvalidHost,
            InvalidAuthority,
            NotOriginForm,
            FragmentInTarget,
            BothTransferEncodingAndContentLength,
            TransferEncodingInHttp10,
            UnsupportedTransferCoding,
            InvalidContentLength,
            ConflictingContentLength,
        ];
        for error in errors {
            let mapped = head_error(error);
            assert!(mapped.status() >= 400);
            assert!(!mapped.message().is_empty());
        }
    }

    fn header_and_empty_body_helpers() {
        let response = Response::new(204).header("X-Test", "yes");
        assert_eq!(response.status, 204);
        assert_eq!(response.body_len(), 0);
        assert_eq!(response.headers[0].0, "X-Test");
        let stream = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::Stream {
                reader: Box::new(std::io::Cursor::new(Vec::<u8>::new())),
                len: 7,
            },
        };
        assert_eq!(stream.body_len(), 7);
    }

    #[test]
    fn response_builders_and_body_lengths() {
        header_and_empty_body_helpers();
    }

    struct TestWriter {
        data: Vec<u8>,
        fd: Option<RawFd>,
    }

    impl Write for TestWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.data.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ResponseWrite for TestWriter {
        fn raw_fd(&self) -> Option<RawFd> {
            self.fd
        }
    }

    struct SocketWriter(std::os::unix::net::UnixStream);

    impl Write for SocketWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    impl ResponseWrite for SocketWriter {
        fn raw_fd(&self) -> Option<RawFd> {
            Some(self.0.as_raw_fd())
        }
    }

    fn response_options() -> ResponseOptions<'static> {
        ResponseOptions {
            server_header: "test",
            keep_alive: true,
            head_only: false,
            protocol: Version::Http11,
            request_keep_alive: true,
        }
    }

    fn temp_file(data: &[u8]) -> File {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vapache-http-test-{}-{}.body",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, data).unwrap();
        let file = File::open(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        file
    }

    #[test]
    fn response_writer_covers_inline_stream_file_and_error_paths() {
        // Inline bytes.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response::bytes(200, "text/plain", b"hello".to_vec());
        let sent = write_response(&mut writer, &mut response, &response_options()).unwrap();
        assert_eq!(sent, 5);
        assert!(writer.data.windows(5).any(|w| w == b"hello"));

        // Inline small file.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::File {
                file: temp_file(b"file-body"),
                offset: 0,
                len: 9,
            },
        };
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            9
        );
        assert!(writer.data.windows(9).any(|w| w == b"file-body"));

        // Empty body, HEAD and no-body statuses.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response::new(200);
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            0
        );
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response::bytes(200, "text/plain", b"abc".to_vec());
        let mut opts = response_options();
        opts.head_only = true;
        assert_eq!(
            write_response(&mut writer, &mut response, &opts).unwrap(),
            0
        );
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response::bytes(204, "text/plain", b"abc".to_vec());
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            0
        );

        // Large bytes use the non-inline path.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response::bytes(200, "text/plain", vec![b'b'; 70 * 1024]);
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            70 * 1024
        );

        // Stream body success and premature EOF.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::Stream {
                reader: Box::new(std::io::Cursor::new(vec![b's'; 10])),
                len: 10,
            },
        };
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            10
        );
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::Stream {
                reader: Box::new(std::io::Cursor::new(Vec::<u8>::new())),
                len: 10,
            },
        };
        assert!(write_response(&mut writer, &mut response, &response_options()).is_err());

        // Non-socket file copy fallback.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::File {
                file: temp_file(&vec![b'f'; 32 * 1024]),
                offset: 0,
                len: 32 * 1024,
            },
        };
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            32 * 1024
        );

        // sendfile failure falls back to the copy path.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: Some(-1),
        };
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::File {
                file: temp_file(&vec![b'g'; 32 * 1024]),
                offset: 0,
                len: 32 * 1024,
            },
        };
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            32 * 1024
        );

        // Short file: sendfile ends at EOF and the fallback sees no bytes.
        // The response must fail closed rather than advertise more body bytes
        // than were sent on a reusable connection.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: Some(-1),
        };
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::File {
                file: temp_file(b"short"),
                offset: 0,
                len: 32 * 1024,
            },
        };
        assert!(write_response(&mut writer, &mut response, &response_options()).is_err());

        // Zero-length file body after the head.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::File {
                file: temp_file(b""),
                offset: 0,
                len: 0,
            },
        };
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            0
        );

        // Header serialization failures.
        for bad in [
            ("X-Test", b"bad\r\nvalue".to_vec()),
            ("bad name", b"value".to_vec()),
        ] {
            let mut writer = TestWriter {
                data: Vec::new(),
                fd: None,
            };
            let mut response = Response::new(200);
            response
                .headers
                .push((Cow::Owned(bad.0.to_string()), bad.1));
            assert!(write_response(&mut writer, &mut response, &response_options()).is_err());
        }

        // Connection-header variants.
        for (opts, expected) in [
            (
                ResponseOptions {
                    keep_alive: false,
                    ..response_options()
                },
                "Connection: close\r\n",
            ),
            (
                ResponseOptions {
                    protocol: Version::Http10,
                    ..response_options()
                },
                "Connection: keep-alive\r\n",
            ),
        ] {
            let mut writer = TestWriter {
                data: Vec::new(),
                fd: None,
            };
            let mut response = Response::new(200);
            write_response(&mut writer, &mut response, &opts).unwrap();
            assert!(writer
                .data
                .windows(expected.len())
                .any(|w| w == expected.as_bytes()));
        }

        // sendfile success through a real socket.
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut writer = SocketWriter(a);
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::File {
                file: temp_file(&vec![b'h'; 32 * 1024]),
                offset: 0,
                len: 32 * 1024,
            },
        };
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            32 * 1024
        );
        drop(writer);
        assert!(b.take(32 * 1024).bytes().count() > 0);

        // TcpStream implements raw_fd for the sendfile path.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let _ = listener.accept();
        });
        let stream = std::net::TcpStream::connect(addr).unwrap();
        assert!(stream.raw_fd().is_some());
        drop(stream);
        handle.join().unwrap();
    }

    struct SlowReader {
        delay: Duration,
        data: Vec<u8>,
        pos: usize,
    }

    impl Read for SlowReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            std::thread::sleep(self.delay);
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    #[test]
    fn chunked_and_line_readers_cover_limits_timeouts_and_eof() {
        use std::io::Cursor;

        let mut file = spool_file().unwrap();
        let mut buf = Vec::new();
        let mut stream = Cursor::new(b"1\r\na\r\n0\r\n\r\n".to_vec());
        let now = Instant::now();
        assert_eq!(
            read_chunked_to_file(
                &mut stream,
                &mut buf,
                &mut file,
                10,
                now + Duration::from_secs(5)
            )
            .unwrap(),
            1
        );

        let mut file = spool_file().unwrap();
        let mut buf = b"1\r\na\r\n0\r\n\r\n".to_vec();
        let mut empty = Cursor::new(Vec::<u8>::new());
        assert_eq!(
            read_chunked_to_file(
                &mut empty,
                &mut buf,
                &mut file,
                10,
                now + Duration::from_secs(5)
            )
            .unwrap(),
            1
        );

        let mut file = spool_file().unwrap();
        let mut buf = Vec::new();
        let mut too_big = Cursor::new(b"2\r\nxx\r\n0\r\n\r\n".to_vec());
        assert!(read_chunked_to_file(
            &mut too_big,
            &mut buf,
            &mut file,
            1,
            now + Duration::from_secs(5)
        )
        .is_err());

        let mut file = spool_file().unwrap();
        let mut buf = Vec::new();
        let mut eof = Cursor::new(b"5\r\n".to_vec());
        assert!(read_chunked_to_file(
            &mut eof,
            &mut buf,
            &mut file,
            10,
            now + Duration::from_secs(5)
        )
        .is_err());

        let mut file = spool_file().unwrap();
        let mut buf = Vec::new();
        let mut bad_crlf = Cursor::new(b"1\r\naXX".to_vec());
        assert!(read_chunked_to_file(
            &mut bad_crlf,
            &mut buf,
            &mut file,
            10,
            now + Duration::from_secs(5)
        )
        .is_err());

        let mut file = spool_file().unwrap();
        let mut buf = b"0\r\n".to_vec();
        let mut slow = SlowReader {
            delay: Duration::from_millis(10),
            data: b"X-Test: x\r\n\r\n".to_vec(),
            pos: 0,
        };
        assert!(read_chunked_to_file(
            &mut slow,
            &mut buf,
            &mut file,
            10,
            Instant::now() + Duration::from_millis(1)
        )
        .is_err());

        let mut file = spool_file().unwrap();
        let mut buf = b"5\r\n".to_vec();
        let mut slow = SlowReader {
            delay: Duration::from_millis(10),
            data: b"abc".to_vec(),
            pos: 0,
        };
        assert!(read_chunked_to_file(
            &mut slow,
            &mut buf,
            &mut file,
            10,
            Instant::now() + Duration::from_millis(1)
        )
        .is_err());

        let mut line = Cursor::new(b"abc\r\n".to_vec());
        let mut buf = Vec::new();
        assert!(read_line(&mut line, &mut buf, 1).is_err());
        let mut long = Cursor::new(vec![b'a'; 8]);
        let mut buf = Vec::new();
        assert!(read_line(&mut long, &mut buf, 2).is_err());
        let mut eof = Cursor::new(Vec::<u8>::new());
        let mut buf = Vec::new();
        assert!(read_line(&mut eof, &mut buf, 10).is_err());
    }

    #[test]
    fn read_request_covers_header_and_body_error_branches() {
        use std::io::Cursor;

        // Clean EOF between requests.
        let mut empty = Cursor::new(Vec::<u8>::new());
        let mut buf = Vec::new();
        assert!(read_request(&mut empty, &mut buf, &limits(), |_| {})
            .unwrap()
            .is_none());

        // Partial header EOF.
        let mut partial = Cursor::new(b"GET / HTTP/1.1\r\nHost: x".to_vec());
        let mut buf = Vec::new();
        assert!(read_request(&mut partial, &mut buf, &limits(), |_| {}).is_err());

        // Header total limit before and after a read.
        let mut empty = Cursor::new(Vec::<u8>::new());
        let mut buf = vec![b'a'; MAX_HEAD_TOTAL + 1];
        assert!(matches!(
            read_request(&mut empty, &mut buf, &limits(), |_| {}),
            Err(ReadError::Parse(ParseError::HeadersTooLarge))
        ));
        let mut data = Cursor::new(vec![b'a'; 8192]);
        let mut buf = vec![b'a'; MAX_HEAD_TOTAL];
        assert!(matches!(
            read_request(&mut data, &mut buf, &limits(), |_| {}),
            Err(ReadError::Parse(ParseError::HeadersTooLarge))
        ));

        // Header timeout and rate-based allowance.
        let mut timeout_limits = limits();
        timeout_limits.header_timeout = Duration::ZERO;
        timeout_limits.header_min_rate = 1;
        let mut empty = Cursor::new(Vec::<u8>::new());
        let mut buf = Vec::new();
        assert!(matches!(
            read_request(&mut empty, &mut buf, &timeout_limits, |_| {}),
            Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::TimedOut
        ));

        // Content-Length over the configured limit.
        let wire = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\n\r\n".to_vec();
        let mut cursor = Cursor::new(wire);
        let mut buf = Vec::new();
        let mut small = limits();
        small.body = 5;
        assert!(matches!(
            read_request(&mut cursor, &mut buf, &small, |_| {}),
            Err(ReadError::Parse(ParseError::PayloadTooLarge))
        ));

        // Spooled body timeout and EOF.
        let wire = format!(
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            MAX_REQUEST_BODY_IN_MEMORY + 1
        )
        .into_bytes();
        let mut cursor = Cursor::new(wire.clone());
        let mut buf = Vec::new();
        let mut zero_timeout = limits();
        zero_timeout.body_timeout = Duration::ZERO;
        assert!(matches!(
            read_request(&mut cursor, &mut buf, &zero_timeout, |_| {}),
            Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::TimedOut
        ));
        let mut cursor = Cursor::new(wire);
        let mut buf = Vec::new();
        assert!(matches!(
            read_request(&mut cursor, &mut buf, &limits(), |_| {}),
            Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof
        ));

        // In-memory body timeout and EOF.
        let wire = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n".to_vec();
        let mut cursor = Cursor::new(wire.clone());
        let mut buf = Vec::new();
        let mut zero_timeout = limits();
        zero_timeout.body_timeout = Duration::ZERO;
        assert!(matches!(
            read_request(&mut cursor, &mut buf, &zero_timeout, |_| {}),
            Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::TimedOut
        ));
        let mut cursor = Cursor::new(wire);
        let mut buf = Vec::new();
        assert!(matches!(
            read_request(&mut cursor, &mut buf, &limits(), |_| {}),
            Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof
        ));

        // Chunked body deadline and success.
        let wire = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        let mut cursor = Cursor::new(wire.clone());
        let mut buf = Vec::new();
        let mut zero_timeout = limits();
        zero_timeout.body_timeout = Duration::ZERO;
        assert!(matches!(
            read_request(&mut cursor, &mut buf, &zero_timeout, |_| {}),
            Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::TimedOut
        ));
        let mut wire = wire;
        wire.extend_from_slice(b"4\r\nbody\r\n0\r\n\r\n");
        let mut cursor = Cursor::new(wire);
        let mut buf = Vec::new();
        let req = read_request(&mut cursor, &mut buf, &limits(), |_| {})
            .unwrap()
            .unwrap();
        assert_eq!(req.body_len(), 4);
    }

    #[test]
    fn body_rate_limits_are_applied_to_fixed_and_chunked_bodies() {
        use std::io::Cursor;

        let mut rate_limited = limits();
        rate_limited.body_min_rate = 1;

        let wire = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nbody".to_vec();
        let mut cursor = Cursor::new(wire);
        let mut buf = Vec::new();
        let req = read_request(&mut cursor, &mut buf, &rate_limited, |_| {})
            .unwrap()
            .unwrap();
        assert_eq!(req.body, b"body");

        let wire =
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n"
                .to_vec();
        let mut cursor = Cursor::new(wire);
        let mut buf = Vec::new();
        let req = read_request(&mut cursor, &mut buf, &rate_limited, |_| {})
            .unwrap()
            .unwrap();
        assert_eq!(req.body_len(), 4);
        let mut body = req.body_reader().unwrap().unwrap();
        let mut read = Vec::new();
        body.read_to_end(&mut read).unwrap();
        assert_eq!(read, b"body");
    }

    struct ShortReads {
        data: Vec<u8>,
        pos: usize,
        max: usize,
    }

    impl Read for ShortReads {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.max).min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    #[test]
    fn chunk_terminator_can_span_two_reads() {
        let mut file = spool_file().unwrap();
        let mut buf = Vec::new();
        let mut stream = ShortReads {
            data: b"1\r\na\r\n0\r\n\r\n".to_vec(),
            pos: 0,
            max: 4,
        };
        let total = read_chunked_to_file(
            &mut stream,
            &mut buf,
            &mut file,
            10,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(total, 1);
    }

    struct PlainWriter {
        data: Vec<u8>,
    }

    impl Write for PlainWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.data.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ResponseWrite for PlainWriter {}

    #[test]
    fn response_write_default_destination_has_no_sendfile_fd() {
        let writer = PlainWriter { data: Vec::new() };
        assert_eq!(writer.raw_fd(), None);

        // The default implementation also selects the encrypted/copy path for
        // file bodies rather than sendfile.
        let mut writer = writer;
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::File {
                file: temp_file(&vec![b'p'; 32 * 1024]),
                offset: 0,
                len: 32 * 1024,
            },
        };
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            32 * 1024
        );
    }

    #[test]
    fn short_file_body_fails_closed_on_a_socket_destination() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut writer = SocketWriter(a);
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::File {
                file: temp_file(b"short"),
                offset: 0,
                len: 32 * 1024,
            },
        };
        assert!(write_response(&mut writer, &mut response, &response_options()).is_err());
        drop(writer);
        drop(b);
    }

    #[test]
    fn response_writer_owns_framing_headers() {
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response::bytes(200, "text/plain", b"abc".to_vec());
        response
            .headers
            .push((Cow::Borrowed("Content-Length"), b"999".to_vec()));
        response
            .headers
            .push((Cow::Borrowed("Transfer-Encoding"), b"chunked".to_vec()));
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            3
        );
        let head = String::from_utf8_lossy(&writer.data[..writer.data.len() - 3]);
        assert!(head.contains("Content-Length: 3\r\n"), "{head}");
        assert!(!head.contains("999"), "{head}");
        assert!(!head.contains("Transfer-Encoding"), "{head}");

        // HEAD has no body to frame; the selected representation length is
        // preserved instead of being replaced with zero.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response::bytes(200, "text/plain", b"abc".to_vec());
        response
            .headers
            .push((Cow::Borrowed("Content-Length"), b"12".to_vec()));
        let mut opts = response_options();
        opts.head_only = true;
        assert_eq!(
            write_response(&mut writer, &mut response, &opts).unwrap(),
            0
        );
        let head = String::from_utf8_lossy(&writer.data);
        assert!(head.contains("Content-Length: 12\r\n"), "{head}");
        assert!(!head.contains("Content-Length: 3\r\n"), "{head}");
    }

    #[test]
    fn spool_files_are_private_and_do_not_follow_existing_names() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::sync::atomic::AtomicU64;

        let dir = std::env::temp_dir().join(format!("vapache-spool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        symlink(&victim, spool_path(&dir, 0)).unwrap();

        let counter = AtomicU64::new(0);
        let file = spool_file_named(&dir, &counter).unwrap();
        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert!(spool_path(&dir, 0)
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn spool_name_collisions_fail_closed() {
        use std::sync::atomic::AtomicU64;

        let dir = std::env::temp_dir().join(format!("vapache-spool-full-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for n in 0..SPOOL_ATTEMPTS {
            std::fs::write(spool_path(&dir, n), b"occupied").unwrap();
        }
        let counter = AtomicU64::new(0);
        assert!(spool_file_named(&dir, &counter).is_err());
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::Relaxed),
            SPOOL_ATTEMPTS
        );

        // A missing/unusable directory is a hard error, not an unbounded retry.
        assert!(spool_file_named(&dir.join("missing"), &AtomicU64::new(0)).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
