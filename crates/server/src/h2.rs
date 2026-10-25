//! HTTP/2 over TLS (RFC 9113) using the `h2` state machine.
//!
//! HTTP/2 has no request line, chunked framing, or Connection headers.  We
//! translate each stream into the same internal `Request` used by the strict
//! HTTP/1 parser and reuse the central dispatcher, so access control, path
//! canonicalisation, file serving and CGI policy are identical on both
//! protocols.

use crate::config::Config;
use crate::http::{Body, Request, Response, Version};
use crate::log::{AccessEntry, Logger};
use crate::util::http_date_now;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, StatusCode};
use std::io::{self, Read, Seek, SeekFrom};
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::server::TlsStream;

const H2_RESET_RECLAIM: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Clone, Copy)]
enum H2TaskEvent {
    Ended { stream_id: u64, reset: bool },
    Reclaimed { stream_id: u64 },
}

/// Adapter-side stream identity ledger.  This is the runtime projection of
/// the verified idempotent purge set: a stream may be ended and scheduled for
/// reset cleanup at most once, even if the same early-RST/completion path is
/// observed more than once.
#[derive(Default)]
struct H2StreamIds {
    active: Vec<u64>,
    pending_resets: Vec<u64>,
}

impl H2StreamIds {
    fn begin(&mut self, stream_id: u64) -> bool {
        if !vapache_verified::h2_stream_admit(&self.active, &self.pending_resets, stream_id) {
            false
        } else {
            self.active.push(stream_id);
            true
        }
    }

    fn end(&mut self, stream_id: u64) -> bool {
        if let Some(i) = self.active.iter().position(|id| *id == stream_id) {
            self.active.swap_remove(i);
            true
        } else {
            false
        }
    }

    fn schedule_purge(&mut self, stream_id: u64) -> bool {
        if vapache_verified::h2_purge_contains_exec(&self.pending_resets, stream_id) {
            false
        } else {
            self.pending_resets.push(stream_id);
            true
        }
    }

    fn reclaim(&mut self, stream_id: u64) -> bool {
        if let Some(i) = self.pending_resets.iter().position(|id| *id == stream_id) {
            self.pending_resets.swap_remove(i);
            true
        } else {
            false
        }
    }
}

/// Releases an active slot even if the stream task panics or is cancelled.
/// The normal path overwrites `reset` with the observed result; unwinding
/// conservatively reports a reset so the connection fails closed rather than
/// leaking capacity.
struct H2TaskEventGuard {
    tx: mpsc::UnboundedSender<H2TaskEvent>,
    stream_id: u64,
    reset: bool,
}

impl Drop for H2TaskEventGuard {
    fn drop(&mut self) {
        let _ = self.tx.send(H2TaskEvent::Ended {
            stream_id: self.stream_id,
            reset: self.reset,
        });
    }
}

enum H2ReadFailure {
    /// The peer sent RST_STREAM.  Do not attempt a response; report the
    /// observed reset to the connection-level budget.
    Reset,
    Response(Response),
}

/// A read-only mmap kept alive by `Bytes` for zero-copy HTTP/2 file bodies.
struct MmapBytes {
    ptr: *mut libc::c_void,
    len: usize,
}

unsafe impl Send for MmapBytes {}
unsafe impl Sync for MmapBytes {}

impl MmapBytes {
    fn new(file: &std::fs::File, len: usize) -> io::Result<Self> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { ptr, len })
    }
}

impl AsRef<[u8]> for MmapBytes {
    fn as_ref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}

impl Drop for MmapBytes {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr, self.len);
        }
    }
}

fn bad(status: u16, message: &str) -> Response {
    let body = format!(
        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head><title>{status} {}</title></head><body><h1>{}</h1><p>{}</p></body></html>\n",
        crate::http::reason_phrase(status),
        crate::http::reason_phrase(status),
        crate::util::html_escape(message.as_bytes())
    );
    Response::bytes(status, "text/html; charset=iso-8859-1", body.into_bytes())
}

async fn read_body(
    mut recv: h2::RecvStream,
    limit: u64,
    timeout: std::time::Duration,
) -> Result<Vec<u8>, H2ReadFailure> {
    let mut body = Vec::new();
    let mut budget = vapache_verified::h2_body_init(limit);
    loop {
        let next = match tokio::time::timeout(timeout, recv.data()).await {
            Ok(next) => next,
            Err(_) => return Err(H2ReadFailure::Response(bad(408, "request body timeout"))),
        };
        let Some(chunk) = next else {
            break;
        };
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(e) if e.is_reset() => return Err(H2ReadFailure::Reset),
            Err(_) => {
                return Err(H2ReadFailure::Response(bad(
                    400,
                    "malformed HTTP/2 request body",
                )))
            }
        };
        let Some(next_budget) = vapache_verified::h2_body_append(budget, chunk.len() as u64) else {
            return Err(H2ReadFailure::Response(bad(413, "request body too large")));
        };
        budget = next_budget;
        body.extend_from_slice(&chunk);
        debug_assert_eq!(body.len() as u64, budget.len);
    }
    Ok(body)
}

fn send_io_error(e: h2::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}

async fn send_capacity(
    send: &mut h2::SendStream<Bytes>,
    remaining: usize,
    deadline: Instant,
) -> io::Result<usize> {
    send.reserve_capacity(remaining);
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP/2 send window timeout",
            ));
        }
        let wait = deadline.saturating_duration_since(now);
        match tokio::time::timeout(wait, std::future::poll_fn(|cx| send.poll_capacity(cx))).await {
            Ok(Some(Ok(n))) if n > 0 => return Ok(n),
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(e))) => return Err(send_io_error(e)),
            Ok(None) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "HTTP/2 send stream closed",
                ))
            }
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTP/2 send window timeout",
                ))
            }
        }
    }
}

/// Send DATA only after the h2 crate has assigned capacity.  Without this,
/// `send_data` queues an unbounded amount of response bytes when a client
/// advertises a zero/small flow-control window.  Each chunk is split to the
/// assigned capacity, so pending bytes are bounded by the window.
async fn send_data_bounded(
    send: &mut h2::SendStream<Bytes>,
    data: Bytes,
    end: bool,
    timeout: std::time::Duration,
) -> io::Result<()> {
    if data.is_empty() {
        return send.send_data(data, end).map_err(send_io_error);
    }
    let deadline = Instant::now() + timeout;
    let mut offset = 0usize;
    while offset < data.len() {
        let remaining = data.len() - offset;
        let capacity = send_capacity(send, remaining, deadline).await?;
        let n = capacity.min(remaining);
        let last = end && offset + n == data.len();
        send.send_data(data.slice(offset..offset + n), last)
            .map_err(send_io_error)?;
        offset += n;
    }
    Ok(())
}

async fn send_response(
    mut respond: h2::server::SendResponse<Bytes>,
    cfg: &Config,
    mut resp: Response,
    head_only: bool,
) -> io::Result<u64> {
    let status = StatusCode::from_u16(resp.status)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid response status"))?;
    let no_body = status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
        || head_only;
    let body_len = resp.body_len();

    let mut out = http::Response::builder().status(status);
    {
        let headers = out.headers_mut().expect("response builder");
        let mut have_date = false;
        let mut have_server = false;
        let mut declared_len = None;
        for (name, value) in resp.headers.drain(..) {
            let lname = name.to_ascii_lowercase();
            match lname.as_str() {
                "date" => have_date = true,
                "server" => have_server = true,
                "content-length" => {
                    declared_len = std::str::from_utf8(&value)
                        .ok()
                        .and_then(|v| v.trim().parse::<u64>().ok());
                    continue;
                }
                // Connection-specific header fields are forbidden in HTTP/2.
                "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding"
                | "upgrade" => continue,
                "te" if !value.eq_ignore_ascii_case(b"trailers") => continue,
                _ => {}
            }
            let Ok(name) = HeaderName::from_bytes(lname.as_bytes()) else {
                continue;
            };
            let Ok(value) = HeaderValue::from_bytes(&value) else {
                continue;
            };
            headers.append(name, value);
        }
        if !have_date {
            headers.append(
                HeaderName::from_static("date"),
                HeaderValue::from_str(&http_date_now())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad date"))?,
            );
        }
        if !have_server {
            headers.append(
                HeaderName::from_static("server"),
                HeaderValue::from_bytes(cfg.server_header().as_bytes())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad server"))?,
            );
        }
        if !no_body || status == StatusCode::OK {
            // HEAD has no body but must advertise the selected
            // representation's length, which the file layer already supplied.
            let cl = if head_only {
                declared_len.unwrap_or(body_len)
            } else {
                body_len
            };
            headers.append(
                HeaderName::from_static("content-length"),
                HeaderValue::from_str(&cl.to_string())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad length"))?,
            );
        }
    }
    let response = out
        .body(())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid response headers"))?;

    let end = no_body || body_len == 0;
    let mut send = respond
        .send_response(response, end)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    if end {
        return Ok(0);
    }
    let send_timeout = cfg.timeout.max(std::time::Duration::from_secs(5));

    let mut sent = 0u64;
    match resp.body {
        Body::Empty => {
            send_data_bounded(&mut send, Bytes::new(), true, send_timeout).await?;
        }
        Body::Bytes(data) => {
            sent = data.len() as u64;
            send_data_bounded(&mut send, Bytes::from(data), true, send_timeout).await?;
        }
        Body::Stream { mut reader, len } => {
            let mut left = len;
            let mut buf = vec![0u8; 64 * 1024];
            while left > 0 {
                let want = left.min(buf.len() as u64) as usize;
                let n = reader
                    .read(&mut buf[..want])
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                if n == 0 {
                    send_data_bounded(&mut send, Bytes::new(), true, send_timeout).await?;
                    return Ok(sent);
                }
                left -= n as u64;
                sent += n as u64;
                send_data_bounded(
                    &mut send,
                    Bytes::copy_from_slice(&buf[..n]),
                    left == 0,
                    send_timeout,
                )
                .await?;
            }
        }
        Body::File {
            mut file,
            offset,
            len,
        } => {
            // A synchronous read on this connection's current-thread runtime
            // blocks every other stream on the same HTTP/2 connection.  For
            // the common large-file case, read the representation on the
            // blocking pool so multiplexed streams keep making progress.
            const OFFLOAD_MIN: u64 = 256 * 1024;
            const OFFLOAD_MAX: u64 = 8 * 1024 * 1024;
            if len >= OFFLOAD_MIN && len <= OFFLOAD_MAX {
                let data = tokio::task::spawn_blocking(move || -> io::Result<Bytes> {
                    // Range responses can start mid-file; only the common
                    // full-file case can be mapped from offset zero.  Mapping
                    // a file the server itself may write is avoided: a
                    // concurrent truncate would turn into SIGBUS.
                    if offset == 0 {
                        if let Ok(meta) = file.metadata() {
                            let euid = unsafe { libc::geteuid() } as u32;
                            if vapache_verified::mmap_read_allowed(
                                meta.len(),
                                len,
                                meta.uid(),
                                euid,
                                meta.mode(),
                            ) {
                                if let Ok(map) = MmapBytes::new(&file, len as usize) {
                                    return Ok(Bytes::from_owner(map));
                                }
                            }
                        }
                    }
                    file.seek(SeekFrom::Start(offset))?;
                    let mut buf = vec![0u8; len as usize];
                    file.read_exact(&mut buf)?;
                    Ok(Bytes::from(buf))
                })
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))??;
                sent = data.len() as u64;
                send_data_bounded(&mut send, data, true, send_timeout).await?;
            } else if len < OFFLOAD_MIN {
                file.seek(SeekFrom::Start(offset))?;
                let mut buf = vec![0u8; len as usize];
                file.read_exact(&mut buf)?;
                sent = buf.len() as u64;
                send_data_bounded(&mut send, Bytes::from(buf), true, send_timeout).await?;
            } else {
                file.seek(SeekFrom::Start(offset))?;
                const BATCH: u64 = 1024 * 1024;
                let mut left = len;
                while left > 0 {
                    let want =
                        vapache_verified::h2_batch_len(left, BATCH).min(usize::MAX as u64) as usize;
                    let mut buf = vec![0u8; want];
                    let mut filled = 0usize;
                    while filled < want {
                        match file.read(&mut buf[filled..]) {
                            Ok(0) => break,
                            Ok(n) => filled += n,
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(e) => return Err(e),
                        }
                    }
                    if filled == 0 {
                        break;
                    }
                    left -= filled as u64;
                    sent += filled as u64;
                    buf.truncate(filled);
                    send_data_bounded(&mut send, Bytes::from(buf), left == 0, send_timeout).await?;
                }
                if sent == 0 {
                    send_data_bounded(&mut send, Bytes::new(), true, send_timeout).await?;
                }
            }
        }
    }
    Ok(sent)
}

async fn handle_stream(
    cfg: Arc<Config>,
    logger: Arc<Logger>,
    peer: SocketAddr,
    local_ip: String,
    local_port: u16,
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
) -> bool {
    // The return value is true when the stream was reset (including a
    // timeout that drops the response future).  `serve` projects that event
    // into the verified connection budget.
    let started = Instant::now();
    let (parts, recv) = request.into_parts();
    let method = parts.method.as_str().to_string();
    let uri = parts.uri.clone();
    let mut target = uri
        .path_and_query()
        .map(|p| p.as_str().as_bytes().to_vec())
        .unwrap_or_else(|| b"/".to_vec());
    if target.is_empty() {
        target = b"/".to_vec();
    }
    let (raw_path, query) = match target.iter().position(|b| *b == b'?') {
        Some(i) => (target[..i].to_vec(), target[i + 1..].to_vec()),
        None => (target.clone(), Vec::new()),
    };

    let mut headers = crate::http::Headers::default();
    for (name, value) in parts.headers.iter() {
        // :authority is authoritative in HTTP/2.  Ignore any legacy Host
        // header so a conflicting pair cannot select a different vhost than
        // the one used for TLS SNI/absolute redirects.
        if name.as_str() == "host" {
            continue;
        }
        headers.push(name.as_str(), value.as_bytes().to_vec());
    }
    // HTTP/2 carries the authority in :authority (exposed through the URI),
    // not in a Host header.  Apache exposes it as Host to modules/CGI.
    if let Some(authority) = uri.authority() {
        headers.push("host", authority.as_str().as_bytes().to_vec());
    }

    // Apply the same request bounds as the HTTP/1 parser.  HTTP/2's HPACK
    // decoder has its own table limits, but that does not replace Apache's
    // LimitRequestLine/Fields/FieldSize policy.  The whole head is admitted by
    // one verified decision function so rejection precedence cannot drift
    // between the h2 and HTTP/1 paths.
    let mut header_budget =
        vapache_verified::h2_header_init(vapache_verified::h2_settings().max_header_list as u64);
    for (name, value) in headers.iter() {
        let Some(next) = vapache_verified::h2_header_add(
            header_budget,
            name.len().saturating_add(value.len()) as u64,
        ) else {
            let _ = send_response(
                respond,
                &cfg,
                bad(431, "request header list too large"),
                false,
            )
            .await;
            return true;
        };
        header_budget = next;
    }
    let largest_field = headers
        .iter()
        .map(|(n, v)| n.len().saturating_add(v.len()) as u64)
        .max()
        .unwrap_or(0);
    let head_error = match vapache_verified::h2_head_admit(
        method.as_bytes(),
        target.len() as u64,
        cfg.limit_request_line as u64,
        headers.iter().count() as u64,
        cfg.limit_request_fields as u64,
        largest_field,
        cfg.limit_request_field_size as u64,
    ) {
        vapache_verified::H2HeadDecision::Accept => None,
        vapache_verified::H2HeadDecision::InvalidMethod => Some(bad(400, "invalid HTTP/2 method")),
        vapache_verified::H2HeadDecision::TargetTooLong => {
            Some(bad(414, "request target too long"))
        }
        vapache_verified::H2HeadDecision::TooManyHeaders => {
            Some(bad(431, "too many request headers"))
        }
        vapache_verified::H2HeadDecision::HeaderFieldTooLarge => {
            Some(bad(431, "request header field too large"))
        }
    };
    if let Some(resp) = head_error {
        return send_response(respond, &cfg, resp, false).await.is_err();
    }

    let mut declared: Option<u64> = None;
    let mut bad_length = false;
    for value in headers.get_all("content-length") {
        match std::str::from_utf8(value)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
        {
            None => bad_length = true,
            Some(n) => {
                if declared.map(|prev| prev != n).unwrap_or(false) {
                    bad_length = true;
                }
                declared = Some(n);
            }
        }
    }
    if bad_length {
        return send_response(respond, &cfg, bad(400, "invalid Content-Length"), false)
            .await
            .is_err();
    }
    let max_body = cfg.limit_request_body.min(crate::http::MAX_BODY_BUFFERED);
    let body_timeout = cfg
        .request_body_timeout
        .max(std::time::Duration::from_secs(1));
    let body_future = read_body(recv, max_body, body_timeout);
    tokio::pin!(body_future);
    let body_result = {
        // `SendResponse::poll_reset` is the h2 API for a client RST_STREAM
        // before response headers.  Race it against body consumption so a
        // reset that arrives while the body is still open is projected into
        // the connection budget even if no DATA error is surfaced.
        let mut reset_watch = std::future::poll_fn(|cx| respond.poll_reset(cx));
        tokio::select! {
            biased;
            _ = &mut reset_watch => return true,
            result = &mut body_future => result,
        }
    };
    let (body, early) = match body_result {
        Ok(body) => (body, None),
        Err(H2ReadFailure::Reset) => return true,
        Err(H2ReadFailure::Response(resp)) => (Vec::new(), Some(resp)),
    };
    if let Some(declared) = declared {
        if declared != body.len() as u64 && early.is_none() {
            return send_response(respond, &cfg, bad(400, "Content-Length mismatch"), false)
                .await
                .is_err();
        }
    }

    let req = Request {
        method,
        target,
        raw_path,
        query,
        version: Version::Http2,
        headers,
        body,
        body_spool: None,
        keep_alive: true,
        expect_continue: false,
        // HTTP/2 framing is handled by the h2 crate before a `Request` exists.
        framing: crate::verified::BodyFraming::None,
    };
    let peer = cfg.client_addr(peer, &req);
    let resp = match early {
        Some(resp) => resp,
        None => crate::server::dispatch(&cfg, &req, peer, &local_ip, local_port),
    };
    let head_only = req.is_head();
    let status = resp.status;
    let bytes_in = req.target.len() as u64 + req.body_len();
    let body_sent = match send_response(respond, &cfg, resp, head_only).await {
        Ok(n) => n,
        Err(e) => {
            logger.error(&format!("HTTP/2 stream failed: {e}"));
            return true;
        }
    };
    crate::status::hit(body_sent);

    let host = req.header_str("host").unwrap_or("");
    let server_name = crate::server::server_name_for_public(&cfg, &req, local_port);
    let vhost_idx = cfg
        .select_vhost(local_port, if host.is_empty() { None } else { Some(host) })
        .and_then(|v| cfg.vhosts.iter().position(|x| std::ptr::eq(x, v)));
    let uri_text = String::from_utf8_lossy(&req.target).into_owned();
    logger.access(&AccessEntry {
        remote_ip: &peer.ip().to_string(),
        remote_port: peer.port(),
        local_ip: &local_ip,
        local_port,
        server_name: &server_name,
        method: &req.method,
        uri: &uri_text,
        protocol: req.version.as_str(),
        status,
        bytes_sent: body_sent,
        bytes_in,
        referer: req.header_str("referer").unwrap_or(""),
        user_agent: req.header_str("user-agent").unwrap_or(""),
        host,
        vhost_index: vhost_idx,
        started,
    });
    false
}

/// Compose the two H2Budget transitions for a task completion.  A normal
/// completion releases the active slot; a reset releases it and consumes one
/// pending-reset slot.  `None` means the connection should fail closed.
fn h2_task_end(
    budget: vapache_verified::H2Budget,
    reset: bool,
) -> Option<vapache_verified::H2Budget> {
    let finished =
        vapache_verified::h2_budget_step(budget, vapache_verified::H2BudgetEvent::Finish)?;
    if reset {
        vapache_verified::h2_budget_step(finished, vapache_verified::H2BudgetEvent::Reset)
    } else {
        Some(finished)
    }
}

pub async fn serve(
    cfg: Arc<Config>,
    logger: Arc<Logger>,
    tls: TlsStream<TcpStream>,
    peer: SocketAddr,
    local_ip: String,
    local_port: u16,
) -> io::Result<()> {
    let settings = vapache_verified::h2_settings();
    let mut builder = h2::server::Builder::new();
    builder
        // Bound compressed/decoded header memory before HPACK allocates.
        .max_header_list_size(settings.max_header_list)
        .max_concurrent_streams(settings.max_concurrent_streams)
        // Bound stream/window and reset amplification.  The h2 crate owns
        // frame parsing; these limits control what the adapter will accept.
        .initial_window_size(settings.initial_window)
        .initial_connection_window_size(settings.initial_connection_window)
        .max_frame_size(settings.max_frame)
        .max_concurrent_reset_streams(settings.max_reset_streams as usize)
        .max_pending_accept_reset_streams(settings.max_reset_streams as usize)
        .reset_stream_duration(H2_RESET_RECLAIM)
        .max_send_buffer_size(settings.max_send_buffer as usize);
    let mut conn = builder
        .handshake(tls)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // The same verified budget is used for every accepted stream.  The h2
    // crate still owns frame parsing and its own reset counters; this loop
    // projects the adapter's task lifecycle and observed reset errors into
    // the H2Budget state machine.  Events are prioritized so a completed
    // task releases its slot before another request is accepted.
    let mut budget = vapache_verified::h2_budget_new(
        settings.max_concurrent_streams as u64,
        settings.max_reset_streams as u64,
    );
    let mut stream_ids = H2StreamIds::default();
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let idle_timeout = cfg
        .timeout
        .max(cfg.keep_alive_timeout)
        .max(std::time::Duration::from_secs(30));
    loop {
        tokio::select! {
            biased;
            Some(event) = events_rx.recv() => {
                match event {
                    H2TaskEvent::Ended { stream_id, reset } => {
                        // Idempotent cleanup: a duplicate early-reset or close
                        // notification for the same stream is ignored instead
                        // of decrementing the budget twice.
                        if !stream_ids.end(stream_id) {
                            logger.error("HTTP/2 duplicate stream completion ignored");
                            continue;
                        }
                        let Some(next) = h2_task_end(budget, reset) else {
                            // Either the accounting state was lost, or the
                            // reset budget is exhausted.  Do not let queued
                            // reset wakeups grow without bound.
                            logger.error("HTTP/2 stream/reset budget exhausted; closing connection");
                            conn.abrupt_shutdown(h2::Reason::ENHANCE_YOUR_CALM);
                            break;
                        };
                        budget = next;
                        if reset && stream_ids.schedule_purge(stream_id) {
                            let tx = events_tx.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(H2_RESET_RECLAIM).await;
                                let _ = tx.send(H2TaskEvent::Reclaimed { stream_id });
                            });
                        }
                    }
                    H2TaskEvent::Reclaimed { stream_id } => {
                        if !stream_ids.reclaim(stream_id) {
                            continue;
                        }
                        if let Some(next) = vapache_verified::h2_budget_step(
                            budget,
                            vapache_verified::H2BudgetEvent::Reclaim,
                        ) {
                            budget = next;
                        }
                    }
                }
            }
            _ = tokio::time::sleep(idle_timeout) => {
                logger.error("HTTP/2 connection idle timeout");
                conn.abrupt_shutdown(h2::Reason::NO_ERROR);
                break;
            }
            accepted = conn.accept() => {
                let Some(result) = accepted else {
                    break;
                };
                let (request, respond) =
                    result.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                let stream_id = respond.stream_id().as_u32() as u64;
                let Some(next) = vapache_verified::h2_budget_step(
                    budget,
                    vapache_verified::H2BudgetEvent::Begin,
                ) else {
                    // This should be unreachable while h2's own max-stream
                    // setting is at least as strict; refuse rather than
                    // spawning an untracked task if it ever is not.
                    logger.error("HTTP/2 active-stream budget rejected a stream");
                    let mut respond = respond;
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                    continue;
                };
                budget = next;
                if !stream_ids.begin(stream_id) {
                    logger.error("HTTP/2 duplicate stream identifier; closing connection");
                    conn.abrupt_shutdown(h2::Reason::PROTOCOL_ERROR);
                    break;
                }
                let cfg = cfg.clone();
                let logger = logger.clone();
                let local_ip = local_ip.clone();
                let stream_timeout = cfg.timeout.max(std::time::Duration::from_secs(5));
                let tx = events_tx.clone();
                tokio::spawn(async move {
                    let mut done = H2TaskEventGuard {
                        tx,
                        stream_id,
                        reset: true,
                    };
                    done.reset = match tokio::time::timeout(
                        stream_timeout,
                        handle_stream(cfg, logger, peer, local_ip, local_port, request, respond),
                    )
                    .await
                    {
                        Ok(reset) => reset,
                        // Dropping the response future resets the h2 stream.
                        Err(_) => true,
                    };
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};

    #[test]
    fn mmap_policy_rejects_server_writable_and_short_files() {
        // Root-owned 0644 served by an unprivileged uid: safe to map.
        assert!(vapache_verified::mmap_read_allowed(10, 10, 0, 33, 0o644));
        assert!(vapache_verified::mmap_read_allowed(10, 10, 0, 33, 0o444));

        // Owner-writable, group-writable and world-writable files are copied.
        assert!(!vapache_verified::mmap_read_allowed(10, 10, 33, 33, 0o644));
        assert!(!vapache_verified::mmap_read_allowed(10, 10, 0, 33, 0o664));
        assert!(!vapache_verified::mmap_read_allowed(10, 10, 0, 33, 0o646));

        // Never map beyond the representation length.
        assert!(!vapache_verified::mmap_read_allowed(9, 10, 0, 33, 0o644));
        assert!(vapache_verified::mmap_read_allowed(10, 0, 0, 33, 0o644));
    }

    #[test]
    fn h2_admission_bounds_are_checked_without_overflow() {
        assert!(vapache_verified::h2_body_admit(0, 10, 10));
        assert!(!vapache_verified::h2_body_admit(10, 1, 10));
        assert!(!vapache_verified::h2_body_admit(u64::MAX, 1, 10));
        assert!(vapache_verified::h2_target_admit(10, 10));
        assert!(!vapache_verified::h2_target_admit(11, 10));
        assert!(vapache_verified::h2_header_admit(3, 10, 3, 10));
        assert!(!vapache_verified::h2_header_admit(4, 10, 3, 10));
        assert!(vapache_verified::h2_header_total_admit(10, 10));
        assert!(!vapache_verified::h2_header_total_admit(11, 10));
        let hs = vapache_verified::h2_header_init(10);
        let hs = vapache_verified::h2_header_add(hs, 7).unwrap();
        assert!(vapache_verified::h2_header_add(hs, 4).is_none());
        assert_eq!(vapache_verified::h2_header_add(hs, 3).unwrap().total, 10);
    }

    #[test]
    fn h2_head_admission_reports_the_first_failed_bound() {
        use vapache_verified::H2HeadDecision::{
            Accept, HeaderFieldTooLarge, InvalidMethod, TargetTooLong, TooManyHeaders,
        };
        assert!(vapache_verified::h2_method_ok(b"GET"));
        assert!(!vapache_verified::h2_method_ok(b""));
        assert!(!vapache_verified::h2_method_ok(b"GET SPACE"));
        let too_long = [b'A'; 65];
        assert!(!vapache_verified::h2_method_ok(&too_long));
        assert_eq!(
            vapache_verified::h2_head_admit(b"GET", 10, 10, 3, 3, 10, 10),
            Accept
        );
        assert_eq!(
            vapache_verified::h2_head_admit(b"BAD\x00METHOD", 1, 10, 1, 3, 1, 10),
            InvalidMethod
        );
        assert_eq!(
            vapache_verified::h2_head_admit(b"GET", 11, 10, 1, 3, 1, 10),
            TargetTooLong
        );
        assert_eq!(
            vapache_verified::h2_head_admit(b"GET", 10, 10, 4, 3, 1, 10),
            TooManyHeaders
        );
        assert_eq!(
            vapache_verified::h2_head_admit(b"GET", 10, 10, 3, 3, 11, 10),
            HeaderFieldTooLarge
        );
    }

    #[test]
    fn h2_body_state_never_accepts_more_than_the_limit() {
        let state = vapache_verified::h2_body_init(10);
        let state = vapache_verified::h2_body_append(state, 7).unwrap();
        assert_eq!(state.len, 7);
        assert!(vapache_verified::h2_body_append(state, 4).is_none());
        let state = vapache_verified::h2_body_append(state, 3).unwrap();
        assert_eq!(state.len, 10);
        assert!(vapache_verified::h2_body_append(state, 1).is_none());
    }

    #[test]
    fn h2_flow_model_bounds_windows_and_send_buffer() {
        let flow = vapache_verified::h2_flow_new(1024, 256, 512);
        let flow = vapache_verified::h2_flow_charge(flow, 200).unwrap();
        assert_eq!(flow.conn_window, 824);
        assert_eq!(flow.stream_window, 56);
        assert!(vapache_verified::h2_flow_charge(flow, 57).is_none());
        let flow = vapache_verified::h2_flow_enqueue(flow, 512).unwrap();
        assert!(vapache_verified::h2_flow_enqueue(flow, 1).is_none());
        let flow = vapache_verified::h2_flow_dequeue(flow, 512).unwrap();
        let flow = vapache_verified::h2_flow_credit(flow, u64::MAX);
        assert_eq!(flow.conn_window, 1024);
        assert_eq!(flow.stream_window, 256);
    }

    #[test]
    fn h2_budget_transitions_preserve_limits() {
        let budget = vapache_verified::h2_budget_new(2, 1);
        let budget = vapache_verified::h2_budget_begin(budget).unwrap();
        let budget = vapache_verified::h2_budget_begin(budget).unwrap();
        assert!(vapache_verified::h2_budget_begin(budget).is_none());
        let budget = vapache_verified::h2_budget_reset(budget).unwrap();
        assert!(vapache_verified::h2_budget_reset(budget).is_none());
        let budget = vapache_verified::h2_budget_reclaim(budget).unwrap();
        assert!(vapache_verified::h2_budget_reclaim(budget).is_none());
        let budget = vapache_verified::h2_budget_finish(budget).unwrap();
        let budget = vapache_verified::h2_budget_finish(budget).unwrap();
        assert!(vapache_verified::h2_budget_finish(budget).is_none());

        let budget =
            vapache_verified::h2_budget_step(budget, vapache_verified::H2BudgetEvent::Begin)
                .unwrap();
        assert_eq!(budget.active, 1);
        let budget =
            vapache_verified::h2_budget_step(budget, vapache_verified::H2BudgetEvent::Finish)
                .unwrap();
        assert_eq!(budget.active, 0);

        let budget = vapache_verified::h2_budget_step(
            vapache_verified::h2_budget_new(1, 1),
            vapache_verified::H2BudgetEvent::Begin,
        )
        .unwrap();
        let budget = h2_task_end(budget, true).unwrap();
        assert_eq!(budget.active, 0);
        assert_eq!(budget.pending_resets, 1);
        let budget =
            vapache_verified::h2_budget_step(budget, vapache_verified::H2BudgetEvent::Reclaim)
                .unwrap();
        assert_eq!(budget.pending_resets, 0);
        let budget =
            vapache_verified::h2_budget_step(budget, vapache_verified::H2BudgetEvent::Begin)
                .unwrap();
        assert!(h2_task_end(budget, false).is_some());

        let (tx, mut rx) = mpsc::unbounded_channel();
        {
            let _guard = H2TaskEventGuard {
                tx,
                stream_id: 1,
                reset: true,
            };
        }
        assert!(matches!(
            rx.try_recv(),
            Ok(H2TaskEvent::Ended {
                stream_id: 1,
                reset: true
            })
        ));
    }

    #[test]
    fn h2_stream_admission_rejects_active_or_pending_ids() {
        let active = [1u64, 3];
        let pending = [2u64, 5];
        assert!(vapache_verified::h2_stream_admit(&active, &pending, 4));
        assert!(!vapache_verified::h2_stream_admit(&active, &pending, 1));
        assert!(!vapache_verified::h2_stream_admit(&active, &pending, 3));
        assert!(!vapache_verified::h2_stream_admit(&active, &pending, 2));
        assert!(!vapache_verified::h2_stream_admit(&active, &pending, 5));
    }

    #[test]
    fn h2_stream_cleanup_is_idempotent() {
        let mut ids = H2StreamIds::default();
        assert!(ids.begin(1));
        assert!(!ids.begin(1));
        assert!(ids.end(1));
        assert!(!ids.end(1));
        assert!(ids.schedule_purge(1));
        assert!(!ids.schedule_purge(1));
        assert!(ids.reclaim(1));
        assert!(!ids.reclaim(1));
        assert!(ids.begin(1));
    }

    #[test]
    fn batch_length_makes_progress_and_is_bounded() {
        assert_eq!(vapache_verified::h2_batch_len(0, 1024), 0);
        assert_eq!(vapache_verified::h2_batch_len(512, 1024), 512);
        assert_eq!(vapache_verified::h2_batch_len(2048, 1024), 1024);
        assert!(vapache_verified::h2_batch_len(1, 1) > 0);
    }

    #[test]
    fn mmap_owner_exposes_file_bytes() {
        let dir = std::env::temp_dir().join(format!("vapache-h2-mmap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("body.bin");
        let bytes = vec![0x5au8; 300 * 1024];
        fs::write(&path, &bytes).unwrap();
        let file = File::open(&path).unwrap();
        let map = MmapBytes::new(&file, bytes.len()).unwrap();
        assert_eq!(map.as_ref(), &bytes[..]);
        drop(map);
        fs::remove_dir_all(&dir).unwrap();
    }
}
