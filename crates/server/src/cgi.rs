//! CGI/1.1 execution.
//!
//! Scripts are executed directly with `execve` (never through a shell), with a
//! minimal, explicitly constructed environment, `PR_SET_NO_NEW_PRIVS`, a new
//! session, resource limits, a watchdog that kills the process group on
//! timeout, and bounded output.  Response headers emitted by the script are
//! parsed and re-serialized through the same validated header path as native
//! responses, preventing response splitting.

use crate::config::{Config, VHost};
use crate::http::{Headers, Request, Response, Version};
use crate::util::trim_ascii;
use crate::verified::valid_token;
use std::ffi::OsString;
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

const MAX_OUTPUT: usize = 64 * 1024 * 1024;
const MAX_HEADER: usize = 64 * 1024;
const MAX_STDERR: usize = 64 * 1024;

pub struct ScriptTarget {
    pub rel_script: PathBuf,
    pub file: File,
    pub meta: Metadata,
    pub path_info: String,
}

/// Find the executable prefix of a mapped path, splitting `PATH_INFO` the way
/// Apache's mod_cgi does when the trailing path does not exist.
pub fn find_script(root: &Path, rel: &Path, follow: bool) -> Option<ScriptTarget> {
    let comps: Vec<&std::ffi::OsStr> = rel.iter().collect();
    for n in (1..=comps.len()).rev() {
        let mut prefix = PathBuf::new();
        for c in &comps[..n] {
            prefix.push(c);
        }
        if let crate::files::Target::File { file, meta, .. } =
            crate::files::resolve_target(root, &prefix, follow)
        {
            let info = comps[n..]
                .iter()
                .map(|c| c.to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            return Some(ScriptTarget {
                rel_script: prefix,
                file,
                meta,
                path_info: if info.is_empty() {
                    String::new()
                } else {
                    format!("/{info}")
                },
            });
        }
    }
    None
}

pub struct CgiContext<'a> {
    pub cfg: &'a Config,
    pub vhost: Option<&'a VHost>,
    pub req: &'a Request,
    pub root: &'a Path,
    pub script_rel: &'a Path,
    pub script_name: &'a str,
    pub path_info: &'a str,
    pub docroot: &'a Path,
    pub remote_ip: &'a str,
    pub remote_port: u16,
    pub local_ip: &'a str,
    pub local_port: u16,
    pub server_name: &'a str,
    pub host: &'a str,
    pub follow_symlinks: bool,
    pub env: &'a [(String, String)],
    /// Opened script descriptor, when the caller already authorized a
    /// specific inode.  Execution uses `/proc/self/fd` so the path cannot be
    /// swapped between authorization and exec.
    pub script_file: Option<&'a File>,
}

fn sanitize_env_value(v: &[u8]) -> String {
    // NUL cannot appear in an environment variable; replace other non-UTF8
    // bytes lossily.  CR/LF in headers are rejected by the HTTP parser.
    String::from_utf8_lossy(v).replace('\0', "")
}

/// Names whose values are calculated from the request, connection or
/// authenticated identity.  A `SetEnv`/rewrite environment entry must not
/// replace them: that is the CVE-2025-65082 boundary.  `HTTP_*` covers all
/// request-derived CGI header variables.
fn reserved_cgi_env(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    matches!(
        name.as_str(),
        "GATEWAY_INTERFACE"
            | "SERVER_SOFTWARE"
            | "SERVER_PROTOCOL"
            | "SERVER_NAME"
            | "SERVER_ADDR"
            | "SERVER_PORT"
            | "SERVER_ADMIN"
            | "DOCUMENT_ROOT"
            | "REQUEST_METHOD"
            | "REQUEST_URI"
            | "REQUEST_SCHEME"
            | "QUERY_STRING"
            | "SCRIPT_NAME"
            | "SCRIPT_FILENAME"
            | "PATH_INFO"
            | "PATH_TRANSLATED"
            | "REMOTE_ADDR"
            | "REMOTE_PORT"
            | "REMOTE_HOST"
            | "REMOTE_USER"
            | "AUTH_TYPE"
            | "CONTENT_TYPE"
            | "CONTENT_LENGTH"
            | "REDIRECT_STATUS"
            | "HTTPS"
    ) || name.starts_with("HTTP_")
}

pub(crate) fn build_env(ctx: &CgiContext) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = Vec::new();
    let mut put = |k: &str, v: String| env.push((OsString::from(k), OsString::from(v)));
    put("GATEWAY_INTERFACE", "CGI/1.1".into());
    put("SERVER_SOFTWARE", ctx.cfg.server_header());
    put("SERVER_PROTOCOL", ctx.req.version.as_str().to_string());
    put("SERVER_NAME", ctx.server_name.to_string());
    put("SERVER_ADDR", ctx.local_ip.to_string());
    put("SERVER_PORT", ctx.local_port.to_string());
    put("SERVER_ADMIN", ctx.cfg.server_admin.clone());
    put("DOCUMENT_ROOT", ctx.docroot.to_string_lossy().into_owned());
    put("REQUEST_METHOD", ctx.req.method.clone());
    put(
        "REQUEST_URI",
        String::from_utf8_lossy(&ctx.req.target).into_owned(),
    );
    put(
        "QUERY_STRING",
        String::from_utf8_lossy(&ctx.req.query).into_owned(),
    );
    put("SCRIPT_NAME", ctx.script_name.to_string());
    put(
        "SCRIPT_FILENAME",
        ctx.root.join(ctx.script_rel).to_string_lossy().into_owned(),
    );
    if !ctx.path_info.is_empty() {
        put("PATH_INFO", ctx.path_info.to_string());
        let pi = ctx.path_info.trim_start_matches('/');
        put(
            "PATH_TRANSLATED",
            ctx.docroot.join(pi).to_string_lossy().into_owned(),
        );
    }
    put("REMOTE_ADDR", ctx.remote_ip.to_string());
    put("REMOTE_PORT", ctx.remote_port.to_string());
    put("REMOTE_HOST", ctx.remote_ip.to_string());
    put("REQUEST_SCHEME", "http".into());
    put("REDIRECT_STATUS", "200".into());
    put("PATH", "/usr/local/bin:/usr/bin:/bin".into());
    put("LANG", "C".into());
    put("TZ", "UTC".into());

    if let Some(ct) = ctx.req.header("content-type") {
        put("CONTENT_TYPE", sanitize_env_value(ct));
    }
    if let Some(cl) = ctx.req.header("content-length") {
        put("CONTENT_LENGTH", sanitize_env_value(cl));
    } else if ctx.req.body_len() > 0 {
        put("CONTENT_LENGTH", ctx.req.body_len().to_string());
    }
    for (name, value) in ctx.req.headers.iter() {
        if matches!(
            name,
            "content-type" | "content-length" | "connection" | "proxy"
        ) {
            continue;
        }
        // httpoxy: a request header named Proxy must never become HTTP_PROXY.
        let env_name = format!("HTTP_{}", name.to_ascii_uppercase().replace('-', "_"));
        if valid_token(env_name.as_bytes()) {
            put(&env_name, sanitize_env_value(value));
        }
    }
    if let Some(auth) = ctx.req.header("authorization") {
        // Never expose credentials as HTTP_AUTHORIZATION to CGI; Apache uses
        // AUTH_TYPE/REMOTE_USER after authentication.
        env.retain(|(k, _)| k != "HTTP_AUTHORIZATION");
        let _ = auth;
    }
    for (k, v) in ctx.env {
        // Do not let a configured/rewrite environment entry shadow values
        // computed from the request.  Custom non-CGI variables remain
        // available to the application.
        let key_valid = !k.is_empty() && !k.contains('=') && !k.as_bytes().contains(&0);
        if !vapache_verified::cgi_env_entry_admit(key_valid, reserved_cgi_env(k)) {
            continue;
        }
        env.retain(|(n, _)| n != k.as_str());
        env.push((OsString::from(k), OsString::from(v)));
    }
    env
}

pub fn execute(ctx: &CgiContext) -> Response {
    let original_path = ctx.root.join(ctx.script_rel);
    let cwd = original_path
        .parent()
        .unwrap_or(Path::new("/"))
        .to_path_buf();
    // If the caller authorized an already-opened script, execute that exact
    // inode rather than reopening a path that could have been swapped.
    let mut script_fd = None;
    let path = if let Some(file) = ctx.script_file {
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 0) };
        if fd < 0 {
            return cgi_error(ctx);
        }
        script_fd = Some(unsafe { File::from_raw_fd(fd) });
        PathBuf::from(format!("/proc/self/fd/{fd}"))
    } else {
        original_path.clone()
    };
    let env = build_env(ctx);
    // Local CGI still expects a contiguous stdin buffer; proxy and FastCGI
    // stream spooled bodies directly.  Reads above the request threshold are
    // already on disk, so this is the remaining memory copy for CGI only.
    let spooled_body = ctx.req.body_reader().and_then(|r| {
        let mut file = r.ok()?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).ok()?;
        Some(data)
    });
    let body = spooled_body.as_deref().unwrap_or(&ctx.req.body);

    // The worker pool is created on the first CGI request.  Static-only
    // deployments therefore pay nothing, and CGI no longer forks from the
    // large, multi-threaded server process (which caused an expensive COW/TLB
    // storm for every request).
    // Execute bound scripts in the worker too.  The worker reopens the path
    // and verifies the authorized dev/inode before exec, so the grant remains
    // inode-bound without forking the large main process (and copying its page
    // tables) for every CGI request.
    let worker_identity = ctx
        .script_file
        .and_then(|file| file.metadata().ok().map(|meta| (meta.dev(), meta.ino())));
    let worker_path = if script_fd.is_some() {
        original_path.as_path()
    } else {
        path.as_path()
    };
    if let Some(pool) = POOL.get() {
        if let Some(mut worker) = pool.take() {
            match exchange(
                &mut worker.stream,
                worker_path,
                &cwd,
                &env,
                body,
                ctx.cfg.timeout,
                worker_identity,
            ) {
                Ok((out, stderr)) => {
                    pool.put(worker);
                    if !stderr.trim().is_empty() {
                        eprintln!("CGI stderr: {}", stderr.trim());
                    }
                    return match parse_cgi_response(&out, ctx.req.version) {
                        Ok(r) => r,
                        Err(()) => cgi_error(ctx),
                    };
                }
                Err(e) => {
                    // Do not retry locally: the script may already have run.
                    eprintln!("vapached: CGI worker failed: {e}");
                    return cgi_error(ctx);
                }
            }
        }
    }

    match run_local(&path, &cwd, &env, body, ctx.cfg.timeout, false, None) {
        Ok((out, stderr)) => {
            if !stderr.trim().is_empty() {
                eprintln!("CGI stderr: {}", stderr.trim());
            }
            match parse_cgi_response(&out, ctx.req.version) {
                Ok(r) => r,
                Err(()) => cgi_error(ctx),
            }
        }
        Err(e) => {
            let _ = std::fs::write(
                "/tmp/vapache-cgi-debug",
                format!("run_local {path:?}: {e}\n"),
            );
            eprintln!("vapached: CGI failed: {e}");
            cgi_error(ctx)
        }
    }
}

fn cgi_error(ctx: &CgiContext) -> Response {
    crate::files::error_response(
        ctx.cfg,
        ctx.vhost,
        &crate::config::Scope::default(),
        500,
        ctx.req,
        ctx.script_name,
        ctx.local_port,
        ctx.host,
        ctx.remote_ip
            .parse()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        ctx.local_ip,
    )
}

const WORKER_FD: i32 = 3;
const MAX_WORKER_BODY: u64 = 2 * 1024 * 1024 * 1024;
const MAX_WORKER_ENV: u32 = 4096;
const MAX_WORKER_PATH: u32 = 64 * 1024;

struct CgiWorker {
    stream: UnixStream,
    child: Child,
}

struct CgiPool {
    workers: Mutex<Vec<CgiWorker>>,
    ready: Condvar,
    closed: AtomicBool,
}

static POOL: OnceLock<CgiPool> = OnceLock::new();

impl CgiPool {
    fn take(&self) -> Option<CgiWorker> {
        let mut guard = self.workers.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.load(Ordering::Relaxed) {
            return None;
        }
        if guard.is_empty() {
            let (next, _) = self
                .ready
                .wait_timeout(guard, Duration::from_millis(500))
                .unwrap_or_else(|e| e.into_inner());
            guard = next;
        }
        guard.pop()
    }

    fn put(&self, worker: CgiWorker) {
        let mut guard = self.workers.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.load(Ordering::Relaxed) {
            drop(guard);
            drop(worker);
            return;
        }
        guard.push(worker);
        self.ready.notify_one();
    }
}

/// Ask idle CGI workers to exit and wait briefly for their coverage/output
/// streams to close cleanly.  Called during server shutdown so a SIGTERM does
/// not truncate a worker's LLVM profile or leave children behind.
pub fn shutdown_pool() {
    let Some(pool) = POOL.get() else {
        return;
    };
    pool.closed.store(true, Ordering::SeqCst);
    pool.ready.notify_all();
    let workers = {
        let mut guard = pool.workers.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *guard)
    };
    for mut worker in workers {
        drop(worker.stream);
        for _ in 0..100 {
            match worker.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => break,
            }
        }
        let _ = worker.child.kill();
        let _ = worker.child.wait();
    }
}

/// Create the CGI worker pool.  Called from the main process before it drops
/// privileges, so workers can exec a binary that lives in a root-only
/// directory and then drop to the configured user themselves.
pub fn init_pool(cfg: &Config) -> Result<(), String> {
    if POOL.get().is_some() {
        return Ok(());
    }
    let (uid, gid) = worker_ids(&cfg.user, &cfg.group)?;
    let pool = start_pool(uid, gid, &cfg.user)?;
    POOL.set(pool)
        .map_err(|_| "CGI worker pool already initialized".to_string())
}

fn worker_ids(user: &str, group: &str) -> Result<(u32, u32), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok((unsafe { libc::geteuid() }, unsafe { libc::getegid() }));
    }
    let uid = if let Ok(n) = user.parse::<u32>() {
        n
    } else {
        let cuser = std::ffi::CString::new(user).map_err(|_| "invalid CGI user".to_string())?;
        let pw = unsafe { libc::getpwnam(cuser.as_ptr()) };
        if pw.is_null() {
            return Err(format!("CGI user '{user}' not found"));
        }
        unsafe { (*pw).pw_uid }
    };
    let gid = if let Ok(n) = group.parse::<u32>() {
        n
    } else {
        let cgroup = std::ffi::CString::new(group).map_err(|_| "invalid CGI group".to_string())?;
        let gr = unsafe { libc::getgrnam(cgroup.as_ptr()) };
        if gr.is_null() {
            return Err(format!("CGI group '{group}' not found"));
        }
        unsafe { (*gr).gr_gid }
    };
    Ok((uid, gid))
}

fn start_pool(uid: u32, gid: u32, user: &str) -> Result<CgiPool, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find own executable: {e}"))?;
    // Start enough workers for the common concurrent CGI fan-out.  Each one is
    // a tiny single-threaded process that waits on a socket when idle.
    let count = std::thread::available_parallelism()
        .map(|n| n.get() * 4)
        .unwrap_or(8)
        .clamp(8, 64);
    let mut workers = Vec::with_capacity(count);
    for _ in 0..count {
        let (mut parent, child) =
            UnixStream::pair().map_err(|e| format!("cannot create CGI worker socket: {e}"))?;
        parent
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| e.to_string())?;
        parent
            .set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| e.to_string())?;
        let child_fd = child.as_raw_fd();
        let mut cmd = Command::new(&exe);
        cmd.arg("--cgi-worker")
            .arg(uid.to_string())
            .arg(gid.to_string())
            .arg(user)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_clear();
        // Keep coverage collection working in the isolated worker.  This is
        // the only environment variable inherited, and only when the operator
        // explicitly set a profile path.
        if let Ok(profile) = std::env::var("LLVM_PROFILE_FILE") {
            cmd.env("LLVM_PROFILE_FILE", profile);
        }
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(child_fd, WORKER_FD) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let proc = cmd
            .spawn()
            .map_err(|e| format!("cannot spawn CGI worker: {e}"))?;
        drop(child);
        // The worker signals readiness after dropping privileges.  This also
        // catches a bad configured user before the first request.
        let mut ready = [0u8; 1];
        parent
            .read_exact(&mut ready)
            .map_err(|e| format!("CGI worker did not start: {e}"))?;
        if ready[0] != 1 {
            return Err("CGI worker failed privilege drop".into());
        }
        workers.push(CgiWorker {
            stream: parent,
            child: proc,
        });
    }
    Ok(CgiPool {
        workers: Mutex::new(workers),
        ready: Condvar::new(),
        closed: AtomicBool::new(false),
    })
}

fn drop_worker_privileges(uid: u32, gid: u32, user: &str) -> bool {
    if unsafe { libc::geteuid() } != 0 {
        return unsafe { libc::geteuid() } == uid && unsafe { libc::getegid() } == gid;
    }
    if let Ok(cuser) = std::ffi::CString::new(user) {
        let pw = unsafe { libc::getpwnam(cuser.as_ptr()) };
        if !pw.is_null() {
            unsafe {
                libc::initgroups(cuser.as_ptr(), gid as libc::gid_t);
            }
        }
    }
    unsafe {
        if libc::setgid(gid as libc::gid_t) != 0 || libc::setuid(uid as libc::uid_t) != 0 {
            return false;
        }
    }
    true
}

/// CGI worker process entry point.  It is spawned once per pool slot and is
/// deliberately tiny and single-threaded until it has completed a request, so
/// fork/exec avoids copying the main server's address space and TLB entries.
pub fn worker_main(fd: i32, uid: u32, gid: u32, user: &str) {
    unsafe {
        libc::setsid();
        libc::umask(0o022);
    }
    if !drop_worker_privileges(uid, gid, user) {
        std::process::exit(1);
    }
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0);
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        let cpu = libc::rlimit {
            rlim_cur: 3600,
            rlim_max: 3600,
        };
        libc::setrlimit(libc::RLIMIT_CPU, &cpu);
        let fsize = libc::rlimit {
            rlim_cur: MAX_OUTPUT as libc::rlim_t,
            rlim_max: MAX_OUTPUT as libc::rlim_t,
        };
        libc::setrlimit(libc::RLIMIT_FSIZE, &fsize);
    }
    let mut stream = unsafe { UnixStream::from_raw_fd(fd) };
    if stream.write_all(&[1]).is_err() {
        return;
    }
    loop {
        match worker_request(&mut stream) {
            Ok(true) => {}
            Ok(false) => break,
            Err(_) => break,
        }
    }
}

fn worker_request(stream: &mut UnixStream) -> Result<bool, String> {
    let script = match read_bytes(stream, MAX_WORKER_PATH, true)? {
        Some(v) => PathBuf::from(OsString::from_vec(v)),
        None => return Ok(false),
    };
    let has_identity = read_u8(stream)? != 0;
    let expected = if has_identity {
        Some((read_u64(stream)?, read_u64(stream)?))
    } else {
        None
    };
    let cwd = PathBuf::from(OsString::from_vec(
        read_bytes(stream, MAX_WORKER_PATH, false)?.unwrap_or_default(),
    ));
    let env_count = read_u32(stream)?;
    if env_count > MAX_WORKER_ENV {
        return Err("too many CGI environment entries".into());
    }
    let mut env = Vec::with_capacity(env_count as usize);
    for _ in 0..env_count {
        let k = read_bytes(stream, MAX_WORKER_PATH, false)?.unwrap_or_default();
        let v = read_bytes(stream, MAX_WORKER_PATH, false)?.unwrap_or_default();
        env.push((OsString::from_vec(k), OsString::from_vec(v)));
    }
    let body_len = read_u64(stream)?;
    if body_len > MAX_WORKER_BODY {
        return Err("CGI request body too large".into());
    }
    let mut body = vec![0u8; body_len as usize];
    stream
        .read_exact(&mut body)
        .map_err(|e| format!("short CGI body: {e}"))?;
    let timeout = Duration::from_secs(read_u64(stream)?.clamp(1, 3600));

    let result = run_local(&script, &cwd, &env, &body, timeout, true, expected);
    match result {
        Ok((out, stderr)) => {
            write_u8(stream, 1)?;
            write_bytes(stream, &out)?;
            write_bytes(stream, stderr.as_bytes())?;
        }
        Err(e) => {
            write_u8(stream, 0)?;
            write_bytes(stream, &[])?;
            write_bytes(stream, e.as_bytes())?;
        }
    }
    stream.flush().map_err(|e| e.to_string())?;
    Ok(true)
}

fn exchange(
    stream: &mut UnixStream,
    path: &Path,
    cwd: &Path,
    env: &[(OsString, OsString)],
    body: &[u8],
    timeout: Duration,
    expected: Option<(u64, u64)>,
) -> Result<(Vec<u8>, String), String> {
    write_bytes(stream, path.as_os_str().as_bytes())?;
    match expected {
        Some((dev, ino)) => {
            write_u8(stream, 1)?;
            write_u64(stream, dev)?;
            write_u64(stream, ino)?;
        }
        None => write_u8(stream, 0)?,
    }
    write_bytes(stream, cwd.as_os_str().as_bytes())?;
    write_u32(stream, env.len() as u32)?;
    for (k, v) in env {
        write_bytes(stream, k.as_os_str().as_bytes())?;
        write_bytes(stream, v.as_os_str().as_bytes())?;
    }
    write_u64(stream, body.len() as u64)?;
    stream.write_all(body).map_err(|e| e.to_string())?;
    write_u64(stream, timeout.as_secs().max(1))?;
    stream.flush().map_err(|e| e.to_string())?;

    let ok = read_u8(stream)?;
    let out = read_bytes(stream, MAX_OUTPUT as u32, false)?.unwrap_or_default();
    let err = read_bytes(stream, MAX_STDERR as u32, false)?.unwrap_or_default();
    let err = String::from_utf8_lossy(&err).into_owned();
    if ok == 0 {
        return Err(if err.is_empty() {
            "CGI worker reported failure".into()
        } else {
            err
        });
    }
    Ok((out, err))
}

fn write_u8(w: &mut impl Write, v: u8) -> Result<(), String> {
    w.write_all(&[v]).map_err(|e| e.to_string())
}

fn write_u32(w: &mut impl Write, v: u32) -> Result<(), String> {
    w.write_all(&v.to_le_bytes()).map_err(|e| e.to_string())
}

fn write_u64(w: &mut impl Write, v: u64) -> Result<(), String> {
    w.write_all(&v.to_le_bytes()).map_err(|e| e.to_string())
}

fn read_u8(r: &mut impl Read) -> Result<u8, String> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(b[0])
}

fn read_u32(r: &mut impl Read) -> Result<u32, String> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64(r: &mut impl Read) -> Result<u64, String> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(u64::from_le_bytes(b))
}

fn write_bytes(w: &mut impl Write, data: &[u8]) -> Result<(), String> {
    write_u32(w, data.len() as u32)?;
    w.write_all(data).map_err(|e| e.to_string())
}

fn read_bytes(r: &mut impl Read, limit: u32, eof_ok: bool) -> Result<Option<Vec<u8>>, String> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if eof_ok && e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.to_string()),
    }
    let len = u32::from_le_bytes(len);
    if !vapache_verified::cgi_field_len_ok(len, limit) {
        return Err("CGI worker message field too large".into());
    }
    let mut data = vec![0u8; len as usize];
    r.read_exact(&mut data).map_err(|e| e.to_string())?;
    Ok(Some(data))
}

fn run_local(
    path: &Path,
    cwd: &Path,
    env: &[(OsString, OsString)],
    body: &[u8],
    timeout: Duration,
    worker_prepared: bool,
    expected: Option<(u64, u64)>,
) -> Result<(Vec<u8>, String), String> {
    // In the worker path, set the child's cwd in the worker before spawning
    // instead of asking `Command` for a per-child chdir.  This keeps the spawn
    // path free of `pre_exec`/`current_dir`, allowing the standard library to
    // use posix_spawn (vfork-based) instead of copying the worker's page tables
    // for every CGI request.  The worker handles one request at a time, so the
    // cwd change is safely restored before it reads the response.
    let previous_cwd = if worker_prepared {
        let previous = std::env::current_dir().map_err(|e| format!("cannot read CGI cwd: {e}"))?;
        std::env::set_current_dir(cwd)
            .map_err(|e| format!("cannot enter CGI cwd {}: {e}", cwd.display()))?;
        Some(previous)
    } else {
        None
    };
    let mut verified_script: Option<File> = None;
    let exec_path: PathBuf = if let Some((dev, ino)) = expected {
        let file = File::open(path)
            .map_err(|e| format!("cannot reopen CGI script {}: {e}", path.display()))?;
        let meta = file
            .metadata()
            .map_err(|e| format!("cannot stat reopened CGI script: {e}"))?;
        if meta.dev() != dev || meta.ino() != ino {
            return Err("CGI script inode changed after authorization".into());
        }
        let fd = file.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
            return Err("cannot make CGI script descriptor inheritable".into());
        }
        verified_script = Some(file);
        PathBuf::from(format!("/proc/self/fd/{fd}"))
    } else {
        path.to_path_buf()
    };
    let mut cmd = Command::new(&exec_path);
    if !worker_prepared {
        cmd.current_dir(cwd);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }
    if !worker_prepared {
        unsafe {
            cmd.pre_exec(move || {
                libc::setsid();
                libc::umask(0o022);
                let _ = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                let lim = libc::rlimit {
                    rlim_cur: timeout.as_secs().max(1) as libc::rlim_t,
                    rlim_max: timeout.as_secs().max(1) as libc::rlim_t,
                };
                libc::setrlimit(libc::RLIMIT_CPU, &lim);
                let fsize = libc::rlimit {
                    rlim_cur: MAX_OUTPUT as libc::rlim_t,
                    rlim_max: MAX_OUTPUT as libc::rlim_t,
                };
                libc::setrlimit(libc::RLIMIT_FSIZE, &fsize);
                Ok(())
            });
        }
    }
    let spawn_result = cmd.spawn();
    if let Some(previous) = previous_cwd {
        let _ = std::env::set_current_dir(previous);
    }
    let mut child = spawn_result.map_err(|e| format!("cannot execute {}: {e}", path.display()))?;
    let pid = child.id() as i32;
    let deadline = Instant::now() + timeout;

    // Feed stdin.  Empty GET bodies just close the pipe.  Only larger bodies
    // need a writer thread; it is joined before this worker forks again.
    let stdin_thread = child.stdin.take().and_then(|mut stdin| {
        if body.is_empty() {
            drop(stdin);
            None
        } else if body.len() <= 16 * 1024 {
            let _ = stdin.write_all(body);
            drop(stdin);
            None
        } else {
            let body = body.to_vec();
            Some(std::thread::spawn(move || {
                let _ = stdin.write_all(&body);
            }))
        }
    });
    let stderr_thread = child.stderr.take().map(|e| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = e.take(MAX_STDERR as u64).read_to_end(&mut buf);
            buf
        })
    });

    let mut out = Vec::new();
    let read_result = child
        .stdout
        .take()
        .ok_or_else(|| "CGI stdout unavailable".to_string())
        .and_then(|stdout| read_with_deadline(stdout, deadline, &mut out));
    let waited = if read_result.is_ok() {
        wait_with_deadline(&mut child, pid, deadline)
    } else {
        kill_group(pid);
        let _ = child.wait();
        Err("CGI timed out or wrote too much output".to_string())
    };
    if let Some(t) = stdin_thread {
        let _ = t.join();
    }
    let stderr = stderr_thread
        .and_then(|h| h.join().ok())
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    match (read_result, waited) {
        (Ok(()), Ok(())) => Ok((out, stderr)),
        (Err(e), _) => Err(e),
        (_, Err(e)) => Err(e),
    }
}

fn kill_group(pid: i32) {
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
        libc::kill(pid, libc::SIGKILL);
    }
}

fn wait_with_deadline(child: &mut Child, pid: i32, deadline: Instant) -> Result<(), String> {
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(e) => return Err(e.to_string()),
        }
        if Instant::now() >= deadline {
            kill_group(pid);
            let _ = child.wait();
            return Err("CGI timeout".into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn read_with_deadline(
    mut reader: impl Read + AsRawFd,
    deadline: Instant,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    let fd = reader.as_raw_fd();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("CGI timeout".into());
        }
        let remaining = deadline.saturating_duration_since(now);
        let wait_ms = remaining.as_millis().min(100) as i32;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, wait_ms) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.to_string());
        }
        if rc == 0 {
            continue;
        }
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                out.extend_from_slice(&chunk[..n]);
                if out.len() > MAX_OUTPUT {
                    return Err("CGI output too large".into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
}

pub(crate) fn parse_cgi_response(data: &[u8], version: Version) -> Result<Response, ()> {
    let (head, body) = split_cgi_head(data).ok_or(())?;
    let mut status = 200u16;
    let mut headers = Headers::default();
    let mut location: Option<Vec<u8>> = None;
    let mut saw_status = false;
    for line in head.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let colon = line.iter().position(|&b| b == b':').ok_or(())?;
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(());
        }
        let value = trim_ascii(&line[colon + 1..]);
        if value.iter().any(|&b| b == b'\r' || b == b'\n' || b == 0) {
            return Err(());
        }
        let lname = std::str::from_utf8(name)
            .map_err(|_| ())?
            .to_ascii_lowercase();
        if lname == "status" {
            let s = std::str::from_utf8(value).map_err(|_| ())?;
            let code = s.split_whitespace().next().ok_or(())?;
            status = code.parse().map_err(|_| ())?;
            if !(100..=599).contains(&status) {
                return Err(());
            }
            saw_status = true;
            continue;
        }
        if lname == "content-length" || lname == "transfer-encoding" {
            // Recompute; never trust the script's framing.
            continue;
        }
        if lname == "location" {
            location = Some(value.to_vec());
        }
        if lname == "connection" || lname == "keep-alive" || lname == "proxy-authenticate" {
            continue;
        }
        headers.push(&lname, value.to_vec());
    }
    if let Some(loc) = location {
        if !saw_status {
            status = 302;
        }
        headers.insert("location", loc);
    }
    if !headers.contains("content-type") && status != 204 && status != 304 {
        headers.insert("content-type", b"text/html".to_vec());
    }
    let body = if status == 204 || status == 304 {
        Vec::new()
    } else {
        body.to_vec()
    };
    let mut r = Response::new(status);
    r.headers = headers
        .iter()
        .map(|(n, v)| {
            (
                std::borrow::Cow::Owned(canonical_header_name(n)),
                v.to_vec(),
            )
        })
        .collect();
    r.body = crate::http::Body::Bytes(body);
    let _ = version;
    Ok(r)
}

fn canonical_header_name(lname: &str) -> String {
    lname
        .split('-')
        .map(|p| {
            let mut c = p.chars();
            match c.next() {
                Some(f) => f.to_ascii_uppercase().to_string() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

fn split_cgi_head(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if let Some(p) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        if p > MAX_HEADER {
            return None;
        }
        return Some((&data[..p], &data[p + 4..]));
    }
    if let Some(p) = data.windows(2).position(|w| w == b"\n\n") {
        if p > MAX_HEADER {
            return None;
        }
        return Some((&data[..p], &data[p + 2..]));
    }
    None
}

/// Decide whether a filename should be handled by CGI given the scopes and
/// handler map.  ScriptAlias directories always execute.
pub fn is_cgi(cfg: &Config, scope: &crate::config::Scope, name: &[u8], script_alias: bool) -> bool {
    if script_alias {
        return true;
    }
    let options = scope.effective_options();
    if !options.contains(crate::config::Options::EXEC_CGI) {
        return false;
    }
    let _ = cfg;
    crate::config::effective_handler(scope, name)
        .map(|handler| handler.eq_ignore_ascii_case("cgi-script"))
        .unwrap_or(false)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Body, Headers};
    use std::collections::HashMap;
    use std::fs;
    use std::io::Cursor;

    fn tempdir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("vapache-cgi-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn config(root: &Path) -> Config {
        let path = root.join("httpd.conf");
        fs::write(&path, "Listen 127.0.0.1:0\n").unwrap();
        Config::load(&path, root, &HashMap::new(), &HashMap::new(), false).unwrap()
    }

    fn request(path: &str, body: Vec<u8>) -> Request {
        Request {
            method: "GET".into(),
            target: path.as_bytes().to_vec(),
            raw_path: path.as_bytes().to_vec(),
            query: Vec::new(),
            version: Version::Http11,
            headers: Headers::default(),
            body,
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        p
    }

    #[test]
    fn execute_falls_back_without_pool_and_parses_cgi_output() {
        let dir = tempdir("fallback");
        let cfg = config(&dir);
        script(
            &dir,
            "hello.sh",
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\nhello\\n'\n",
        );
        let req = request("/hello.sh", Vec::new());
        let ctx = CgiContext {
            cfg: &cfg,
            vhost: None,
            req: &req,
            root: &dir,
            script_rel: Path::new("hello.sh"),
            script_name: "/hello.sh",
            path_info: "",
            docroot: &dir,
            remote_ip: "127.0.0.1",
            remote_port: 12345,
            local_ip: "127.0.0.1",
            local_port: 8080,
            server_name: "localhost",
            host: "localhost",
            follow_symlinks: false,
            env: &[],
            script_file: None,
        };
        let resp = execute(&ctx);
        assert_eq!(resp.status, 200);
        match resp.body {
            Body::Bytes(b) => assert_eq!(b, b"hello\n"),
            _ => panic!("expected an in-memory CGI body"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn execute_with_opened_script_fd() {
        let dir = tempdir("opened");
        let cfg = config(&dir);
        let path = script(
            &dir,
            "opened.sh",
            "#!/bin/sh\nprintf 'Content-Type: text/plain\r\n\r\nopened\n'\n",
        );
        let file = File::open(&path).unwrap();
        let req = request("/opened.sh", Vec::new());
        let ctx = CgiContext {
            cfg: &cfg,
            vhost: None,
            req: &req,
            root: &dir,
            script_rel: Path::new("opened.sh"),
            script_name: "/opened.sh",
            path_info: "",
            docroot: &dir,
            remote_ip: "127.0.0.1",
            remote_port: 12345,
            local_ip: "127.0.0.1",
            local_port: 8080,
            server_name: "localhost",
            host: "localhost",
            follow_symlinks: false,
            env: &[],
            script_file: Some(&file),
        };
        let resp = execute(&ctx);
        assert_eq!(resp.status, 200);
        match resp.body {
            Body::Bytes(b) => assert_eq!(b, b"opened\n"),
            _ => panic!("expected an in-memory CGI body"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn configured_environment_cannot_override_calculated_cgi_variables() {
        let dir = tempdir("env-reserved");
        let cfg = config(&dir);
        let mut req = request("/cgi-bin/env.sh?x=1", Vec::new());
        req.query = b"x=1".to_vec();
        let extra = vec![
            ("REQUEST_METHOD".into(), "POST".into()),
            ("HTTP_HOST".into(), "evil.test".into()),
            ("SCRIPT_FILENAME".into(), "/etc/passwd".into()),
            ("CUSTOM_VALUE".into(), "ok".into()),
        ];
        let ctx = CgiContext {
            cfg: &cfg,
            vhost: None,
            req: &req,
            root: &dir,
            script_rel: Path::new("cgi-bin/env.sh"),
            script_name: "/cgi-bin/env.sh",
            path_info: "",
            docroot: &dir,
            remote_ip: "127.0.0.1",
            remote_port: 12345,
            local_ip: "127.0.0.1",
            local_port: 8080,
            server_name: "localhost",
            host: "localhost",
            follow_symlinks: false,
            env: &extra,
            script_file: None,
        };
        let env = build_env(&ctx);
        let get = |name: &str| {
            env.iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.to_string_lossy().into_owned())
                .unwrap()
        };
        assert_eq!(get("REQUEST_METHOD"), "GET");
        assert_eq!(
            get("SCRIPT_FILENAME"),
            dir.join("cgi-bin/env.sh").to_string_lossy()
        );
        assert_eq!(get("CUSTOM_VALUE"), "ok");
        assert_eq!(get("QUERY_STRING"), "x=1");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_cgi_headers_are_rejected() {
        let mut data = b"X-Test: ".to_vec();
        data.extend(std::iter::repeat(b'a').take(MAX_HEADER + 1));
        data.extend_from_slice(b"\r\n\r\n");
        assert!(parse_cgi_response(&data, Version::Http11).is_err());
    }

    #[test]
    fn malformed_cgi_output_becomes_500() {
        let dir = tempdir("malformed");
        let cfg = config(&dir);
        script(
            &dir,
            "bad.sh",
            "#!/bin/sh\nprintf 'not a cgi response\\n'\n",
        );
        let req = request("/bad.sh", Vec::new());
        let ctx = CgiContext {
            cfg: &cfg,
            vhost: None,
            req: &req,
            root: &dir,
            script_rel: Path::new("bad.sh"),
            script_name: "/bad.sh",
            path_info: "",
            docroot: &dir,
            remote_ip: "127.0.0.1",
            remote_port: 12345,
            local_ip: "127.0.0.1",
            local_port: 8080,
            server_name: "localhost",
            host: "localhost",
            follow_symlinks: false,
            env: &[],
            script_file: None,
        };
        assert_eq!(execute(&ctx).status, 500);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn local_timeout_kills_the_process_group() {
        let dir = tempdir("timeout");
        let p = script(&dir, "slow.sh", "#!/bin/sh\nsleep 5\n");
        let start = Instant::now();
        let result = run_local(&p, &dir, &[], b"", Duration::from_millis(50), false, None);
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn protocol_lengths_are_bounded() {
        let mut oversize = Cursor::new(vec![5u8, 0, 0, 0, 0]);
        assert!(read_bytes(&mut oversize, 4, false).is_err());

        let mut eof = Cursor::new(Vec::<u8>::new());
        assert_eq!(read_bytes(&mut eof, 4, true).unwrap(), None);
        assert!(read_bytes(&mut eof, 4, false).is_err());
    }

    #[test]
    fn exchange_propagates_worker_success_and_failure() {
        let (mut parent, child) = UnixStream::pair().unwrap();
        let fake = std::thread::spawn(move || {
            let mut child = child;
            write_u8(&mut child, 1).unwrap();
            write_bytes(&mut child, b"out").unwrap();
            write_bytes(&mut child, b"").unwrap();
            child.flush().unwrap();
        });
        let (out, err) = exchange(
            &mut parent,
            Path::new("/bin/true"),
            Path::new("/"),
            &[],
            b"",
            Duration::from_secs(1),
            None,
        )
        .unwrap();
        assert_eq!(out, b"out");
        assert_eq!(err, "");
        fake.join().unwrap();

        let (mut parent, child) = UnixStream::pair().unwrap();
        let fake = std::thread::spawn(move || {
            let mut child = child;
            write_u8(&mut child, 0).unwrap();
            write_bytes(&mut child, b"").unwrap();
            write_bytes(&mut child, b"boom").unwrap();
            child.flush().unwrap();
        });
        let err = exchange(
            &mut parent,
            Path::new("/bin/true"),
            Path::new("/"),
            &[],
            b"",
            Duration::from_secs(1),
            None,
        )
        .unwrap_err();
        assert_eq!(err, "boom");
        fake.join().unwrap();
    }

    #[test]
    fn worker_request_handles_eof_and_bad_counts() {
        let (mut parent, child) = UnixStream::pair().unwrap();
        drop(child);
        assert!(matches!(worker_request(&mut parent), Ok(false)));

        let (mut parent, mut child) = UnixStream::pair().unwrap();
        write_bytes(&mut child, b"/bin/true").unwrap();
        write_u8(&mut child, 0).unwrap();
        write_bytes(&mut child, b"/").unwrap();
        write_u32(&mut child, MAX_WORKER_ENV + 1).unwrap();
        child.flush().unwrap();
        assert!(worker_request(&mut parent).is_err());
        drop(child);
    }

    #[test]
    fn worker_ids_reject_unknown_names() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        assert!(worker_ids("no-such-vapache-user-xyz", "www-data").is_err());
        assert!(worker_ids("www-data", "no-such-vapache-group-xyz").is_err());
        assert!(worker_ids("www-data", "www-data").is_ok());
        assert!(worker_ids("33", "33").is_ok());
    }
}
