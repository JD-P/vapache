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
use std::os::unix::io::{AsRawFd, RawFd};
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

fn spool_file() -> io::Result<File> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("vapache-request-{}-{}.body", std::process::id(), n));
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&path)?;
    let _ = std::fs::remove_file(&path);
    Ok(file)
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
            loop {
                let t = read_line(stream, buf, 8190)?;
                if t.is_empty() {
                    return Ok(total);
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
    let mut have_cl = false;
    for (n, _) in &resp.headers {
        if n.eq_ignore_ascii_case("date") {
            have_date = true;
        } else if n.eq_ignore_ascii_case("server") {
            have_server = true;
        } else if n.eq_ignore_ascii_case("content-length") {
            have_cl = true;
        }
    }
    let no_body_status = status == 204 || status == 304 || (100..200).contains(&status);

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
    if !have_cl && !no_body_status {
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
        match &mut resp.body {
            Body::Empty => {}
            Body::Bytes(b) => {
                head.extend_from_slice(b);
                sent = b.len() as u64;
            }
            Body::File { file, offset, len } => {
                file.seek(SeekFrom::Start(*offset))?;
                let start = head.len();
                head.resize(start + *len as usize, 0);
                file.read_exact(&mut head[start..])?;
                sent = *len;
            }
            Body::Stream { .. } => {}
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
                        let e = io::Error::last_os_error();
                        if e.kind() == io::ErrorKind::Interrupted
                            || e.kind() == io::ErrorKind::WouldBlock
                        {
                            continue;
                        }
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
                        break;
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
    fn head_limits() {
        let long = format!("GET /{} HTTP/1.1\r\nHost: x\r\n\r\n", "a".repeat(9000));
        assert!(matches!(
            parse_head(long.as_bytes(), &limits()),
            Err(ParseError::UriTooLong)
        ));
    }
}
