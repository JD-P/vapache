//! Access and error logging with Apache `LogFormat` compatibility.
//!
//! Log values derived from the request are escaped so that a hostile
//! `User-Agent` or URL cannot inject forged log lines (CWE-117).

use crate::config::{Config, CustomLog};
use crate::util::{http_date, unix_now};
use std::cell::RefCell;
use std::fmt::Write as _;
use std::io::Write;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Emerg = 0,
    Alert = 1,
    Crit = 2,
    Error = 3,
    Warn = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl Level {
    pub fn parse(s: &str) -> Level {
        match s.to_ascii_lowercase().as_str() {
            "emerg" => Level::Emerg,
            "alert" => Level::Alert,
            "crit" => Level::Crit,
            "error" => Level::Error,
            "warn" => Level::Warn,
            "notice" => Level::Notice,
            "info" => Level::Info,
            "debug" | "trace1" | "trace2" | "trace3" | "trace4" | "trace5" | "trace6"
            | "trace7" | "trace8" => Level::Debug,
            _ => Level::Warn,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Level::Emerg => "emerg",
            Level::Alert => "alert",
            Level::Crit => "crit",
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Notice => "notice",
            Level::Info => "info",
            Level::Debug => "debug",
        }
    }
}

pub struct Logger {
    error: Mutex<Box<dyn Write + Send>>,
    error_path: String,
    root: PathBuf,
    level: Level,
    access: Vec<AccessLog>,
    pub errors: Mutex<Vec<String>>,
}

struct AccessLog {
    path: String,
    format: String,
    vhost: Option<usize>,
    writer: Mutex<Box<dyn Write + Send>>,
    discard: bool,
}

pub struct AccessEntry<'a> {
    pub remote_ip: &'a str,
    pub remote_port: u16,
    pub local_ip: &'a str,
    pub local_port: u16,
    pub server_name: &'a str,
    pub method: &'a str,
    pub uri: &'a str,
    pub protocol: &'a str,
    pub status: u16,
    pub bytes_sent: u64,
    pub bytes_in: u64,
    pub referer: &'a str,
    pub user_agent: &'a str,
    pub host: &'a str,
    pub vhost_index: Option<usize>,
    pub started: Instant,
}

fn open_log(path: &str, server_root: &Path) -> std::io::Result<Box<dyn Write + Send>> {
    if let Some(rest) = path.strip_prefix("syslog:") {
        let _ = rest;
        // Syslog is not implemented; write to stderr rather than silently drop.
        return Ok(Box::new(std::io::stderr()));
    }
    let p = PathBuf::from(path);
    let relative = !p.is_absolute();
    let full = if !relative { p } else { server_root.join(p) };
    if let Some(parent) = full.parent() {
        // The service account must be able to traverse the root-owned parent
        // when reopening an already-owned log after privilege drop, but it
        // must not be able to replace directory entries.
        crate::files::ensure_admin_dir(parent, 0o755)?;
        if relative {
            let below_root = parent.strip_prefix(server_root).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "relative log target escaped ServerRoot",
                )
            })?;
            let mut current = server_root.to_path_buf();
            for component in below_root.components() {
                let std::path::Component::Normal(component) = component else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid relative log directory",
                    ));
                };
                current.push(component);
                let directory = crate::files::ensure_admin_dir(&current, 0o755)?;
                crate::files::make_admin_dir_root_owned(&directory, 0o755)?;
            }
        }
    }
    let f = crate::files::open_admin_path(
        &full,
        libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND | libc::O_NONBLOCK,
        0o640,
    )?;
    let metadata = f.metadata()?;
    let explicit_null = full == Path::new("/dev/null") && metadata.file_type().is_char_device();
    if !metadata.is_file() && !explicit_null {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "log target is not a regular file",
        ));
    }
    Ok(Box::new(std::io::BufWriter::new(f)))
}

impl Logger {
    pub fn new(cfg: &Config) -> std::io::Result<Logger> {
        let error = open_log(&cfg.error_log, &cfg.server_root)?;
        let mut access = Vec::new();
        let mut add = |cl: &CustomLog, vhost: Option<usize>| -> std::io::Result<()> {
            let w = open_log(&cl.path, &cfg.server_root)?;
            let fmt = if cl.format.starts_with('"') && cl.format.ends_with('"') {
                cl.format[1..cl.format.len() - 1].to_string()
            } else {
                cfg.log_formats
                    .get(&cl.format)
                    .cloned()
                    .unwrap_or_else(|| cl.format.clone())
            };
            access.push(AccessLog {
                path: cl.path.clone(),
                format: fmt,
                vhost,
                writer: Mutex::new(w),
                discard: cl.path == "/dev/null",
            });
            Ok(())
        };
        for cl in &cfg.custom_logs {
            add(cl, None)?;
        }
        for (i, v) in cfg.vhosts.iter().enumerate() {
            for cl in &v.custom_logs {
                add(cl, Some(i))?;
            }
        }
        Ok(Logger {
            error: Mutex::new(error),
            error_path: cfg.error_log.clone(),
            root: cfg.server_root.clone(),
            level: Level::parse(&cfg.log_level),
            access,
            errors: Mutex::new(Vec::new()),
        })
    }

    /// Hand configured log files/directories to the account the daemon will
    /// drop to.  Called while still root, so reloads and SIGUSR1 can reopen
    /// logs after privilege dropping.
    pub fn prepare_permissions(&self, cfg: &Config) {
        #[cfg(unix)]
        {
            use std::ffi::CString;
            if unsafe { libc::geteuid() } != 0 {
                return;
            }
            let user = CString::new(cfg.user.as_str()).ok(); // coverage:ignore-start - root-only ownership handoff
            let group = CString::new(cfg.group.as_str()).ok();
            let uid = user.as_ref().and_then(|u| unsafe {
                let pw = libc::getpwnam(u.as_ptr());
                (!pw.is_null()).then(|| (*pw).pw_uid)
            });
            let gid = group.as_ref().and_then(|g| unsafe {
                let gr = libc::getgrnam(g.as_ptr());
                (!gr.is_null()).then(|| (*gr).gr_gid)
            });
            let Some(uid) = uid else { return };
            let full = |path: &str| {
                let p = PathBuf::from(path);
                if p.is_absolute() {
                    p
                } else {
                    self.root.join(p)
                }
            };
            let mut paths = vec![full(&self.error_path)];
            paths.extend(self.access.iter().map(|a| full(&a.path)));
            for path in paths {
                let Ok(file) = crate::files::open_admin_path(
                    &path,
                    libc::O_WRONLY | libc::O_APPEND | libc::O_NONBLOCK,
                    0,
                ) else {
                    continue;
                };
                if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
                    continue;
                }
                let gid = gid.unwrap_or(u32::MAX);
                unsafe {
                    let _ = libc::fchown(file.as_raw_fd(), uid, gid);
                    let _ = libc::fchmod(file.as_raw_fd(), 0o640); // coverage:ignore-stop
                }
            }
        }
    }

    /// Reopen error/access logs after log rotation (`SIGUSR1`).
    pub fn reopen(&self) -> std::io::Result<()> {
        let error = open_log(&self.error_path, &self.root)?;
        let mut access_writers = Vec::new();
        for entry in &self.access {
            access_writers.push(open_log(&entry.path, &self.root)?);
        }
        *self.error.lock().unwrap_or_else(|e| e.into_inner()) = error;
        for (entry, writer) in self.access.iter().zip(access_writers) {
            *entry.writer.lock().unwrap_or_else(|e| e.into_inner()) = writer;
        }
        Ok(())
    }

    pub fn log(&self, level: Level, module: &str, msg: &str) {
        if level > self.level {
            return;
        }
        // Error-log messages can contain request-derived text.  Escape terminal
        // controls so a hostile request cannot inject escape sequences into a
        // terminal viewing the error log (CVE-2003-0020).
        let escaped = vapache_verified::escape_log_bytes(msg.as_bytes());
        let msg = String::from_utf8_lossy(&escaped);
        let line = format!(
            "[{} {}] [{}:{}] [pid {}] {}\n",
            http_date(unix_now()),
            format_args!("{:?}", std::time::SystemTime::now()),
            module,
            level.name(),
            std::process::id(),
            msg
        );
        if let Ok(mut w) = self.error.lock() {
            let _ = w.write_all(line.as_bytes());
            let _ = w.flush();
        }
    }

    pub fn error(&self, msg: &str) {
        self.log(Level::Error, "core", msg);
    }

    pub fn warn(&self, msg: &str) {
        self.log(Level::Warn, "core", msg);
    }

    pub fn info(&self, msg: &str) {
        self.log(Level::Info, "core", msg);
    }

    pub fn wants_access_log(&self) -> bool {
        self.access.iter().any(|log| !log.discard)
    }

    pub fn access(&self, e: &AccessEntry) {
        ACCESS_LINE.with(|buf| {
            let mut line = buf.borrow_mut();
            for log in &self.access {
                if log.discard {
                    continue;
                }
                if let Some(v) = log.vhost {
                    if Some(v) != e.vhost_index {
                        continue;
                    }
                }
                line.clear();
                format_access_into(&mut line, &log.format, e);
                if let Ok(mut w) = log.writer.lock() {
                    let _ = w.write_all(line.as_bytes());
                    let _ = w.write_all(b"\n");
                    let _ = w.flush();
                }
            }
        });
    }
}

#[cfg(test)]
fn escape_log(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    escape_log_into(&mut out, s);
    out
}

fn escape_log_into(out: &mut String, s: &str) {
    let escaped = vapache_verified::escape_log_bytes(s.as_bytes());
    out.push_str(&String::from_utf8_lossy(&escaped));
}
thread_local! {
    /// `%t` only changes once per second; format it once per connection thread.
    static LOG_TIME_CACHE: RefCell<(i64, String)> = const { RefCell::new((i64::MIN, String::new())) };
    /// Reuse the access-log line buffer on each connection thread.
    static ACCESS_LINE: RefCell<String> = const { RefCell::new(String::new()) };
}

fn request_start_secs(started: Instant) -> i64 {
    let now = std::time::SystemTime::now();
    let start = now
        .checked_sub(Duration::from_millis(started.elapsed().as_millis() as u64))
        .unwrap_or(now);
    crate::util::system_time_secs(start)
}

fn with_common_log_time<F: FnOnce(&str)>(started: Instant, f: F) {
    let secs = request_start_secs(started);
    LOG_TIME_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.0 != secs {
            cache.0 = secs;
            cache.1 = strftime_secs("%d/%b/%Y:%H:%M:%S +0000", secs);
        }
        f(&cache.1);
    });
}

#[cfg(test)]
fn format_access(fmt: &str, e: &AccessEntry) -> String {
    let mut out = String::with_capacity(fmt.len() + 128);
    format_access_into(&mut out, fmt, e);
    out
}

fn format_access_into(out: &mut String, fmt: &str, e: &AccessEntry) {
    let b = fmt.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'%' {
            out.push(b[i] as char);
            i += 1;
            continue;
        }
        i += 1;
        if i >= b.len() {
            out.push('%');
            break;
        }
        if b[i] == b'{' {
            let end = match fmt[i..].find('}') {
                Some(x) => i + x,
                None => {
                    out.push('%');
                    break;
                }
            };
            let arg = &fmt[i + 1..end];
            i = end + 1;
            if i >= b.len() {
                break;
            }
            let conv = b[i] as char;
            i += 1;
            match conv {
                'i' => {
                    let v = match arg.to_ascii_lowercase().as_str() {
                        "referer" => e.referer,
                        "user-agent" => e.user_agent,
                        "host" => e.host,
                        _ => "",
                    };
                    if v.is_empty() {
                        out.push('-');
                    } else {
                        escape_log_into(out, v);
                    }
                }
                'o' => out.push('-'),
                't' => format_time_into(out, arg, e.started),
                'e' => out.push('-'),
                _ => {}
            }
            continue;
        }
        // Optional status modifier.
        let mut conv = b[i] as char;
        if conv == '>' || conv == '<' {
            i += 1;
            if i < b.len() {
                conv = b[i] as char;
            }
        }
        i += 1;
        match conv {
            'h' | 'a' => out.push_str(e.remote_ip),
            'l' => out.push('-'),
            'u' => out.push('-'),
            't' => {
                out.push('[');
                format_time_into(out, "%d/%b/%Y:%H:%M:%S +0000", e.started);
                out.push(']');
            }
            'r' => {
                if e.uri.is_empty() {
                    out.push('-');
                } else {
                    escape_log_into(out, e.method);
                    out.push(' ');
                    escape_log_into(out, e.uri);
                    out.push(' ');
                    out.push_str(e.protocol);
                }
            }
            's' => {
                let _ = write!(out, "{}", e.status);
            }
            'b' => {
                if e.bytes_sent == 0 {
                    out.push('-');
                } else {
                    let _ = write!(out, "{}", e.bytes_sent);
                }
            }
            'O' => {
                let _ = write!(out, "{}", e.bytes_sent);
            }
            'I' => {
                let _ = write!(out, "{}", e.bytes_in);
            }
            'B' => {
                let _ = write!(out, "{}", e.bytes_sent);
            }
            'v' => escape_log_into(out, e.server_name),
            'p' => {
                let _ = write!(out, "{}", e.local_port);
            }
            'U' => escape_log_into(out, e.uri.split('?').next().unwrap_or("/")),
            'q' => {
                if let Some(q) = e.uri.split_once('?').map(|(_, q)| q) {
                    out.push('?');
                    escape_log_into(out, q);
                }
            }
            'm' => out.push_str(e.method),
            'H' => out.push_str(e.protocol),
            'A' => out.push_str(e.local_ip),
            'D' => {
                let _ = write!(out, "{}", e.started.elapsed().as_micros());
            }
            'T' => {
                let _ = write!(out, "{}", e.started.elapsed().as_secs());
            }
            'P' => {
                let _ = write!(out, "{}", std::process::id());
            }
            '%' => out.push('%'),
            _ => {
                out.push('%');
                out.push(conv);
            }
        }
    }
}

fn format_time_into(out: &mut String, arg: &str, started: Instant) {
    match arg {
        "msec" | "msec_frac" => {
            let _ = write!(out, "{}", started.elapsed().as_millis());
        }
        "usec" => {
            let _ = write!(out, "{}", started.elapsed().as_micros());
        }
        "sec" => {
            let _ = write!(out, "{}", started.elapsed().as_secs());
        }
        "%d/%b/%Y:%H:%M:%S +0000" => with_common_log_time(started, |s| out.push_str(s)),
        _ => strftime_common_into(out, arg, started),
    }
}

fn strftime_secs(fmt: &str, secs: i64) -> String {
    let mut out = String::new();
    strftime_secs_into(&mut out, fmt, secs);
    out
}

fn strftime_common_into(out: &mut String, fmt: &str, started: Instant) {
    // Convert Instant to wall clock approximately: the only fields used by
    // standard formats are date/time, so use the current time adjusted by
    // elapsed milliseconds (adequate for sub-second request logging).
    strftime_secs_into(out, fmt, request_start_secs(started));
}

fn strftime_secs_into(out: &mut String, fmt: &str, secs: i64) {
    let (y, m, d) = crate::util::civil_from_days(secs.div_euclid(86_400));
    let sod = secs.rem_euclid(86_400);
    let hh = sod / 3600;
    let mm = (sod % 3600) / 60;
    let ss = sod % 60;
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let b = fmt.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 1 < b.len() {
            i += 1;
            match b[i] as char {
                'Y' => {
                    let _ = write!(out, "{y:04}");
                }
                'm' => {
                    let _ = write!(out, "{m:02}");
                }
                'd' => {
                    let _ = write!(out, "{d:02}");
                }
                'H' => {
                    let _ = write!(out, "{hh:02}");
                }
                'M' => {
                    let _ = write!(out, "{mm:02}");
                }
                'S' => {
                    let _ = write!(out, "{ss:02}");
                }
                'b' => out.push_str(months[(m as usize - 1) % 12]),
                'a' => out.push_str(
                    ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"]
                        [(secs.div_euclid(86_400)).rem_euclid(7) as usize],
                ),
                'z' => out.push_str("+0000"),
                'Z' => out.push_str("GMT"),
                '%' => out.push('%'),
                c => {
                    out.push('%');
                    out.push(c);
                }
            }
            i += 1;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
}

impl Logger {
    pub fn access_log_count(&self) -> usize {
        self.access.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn escape_control() {
        assert_eq!(escape_log("a\"\n\x01b"), "a\\\"\\x0a\\x01b");
    }

    #[test]
    fn format_conversions() {
        let e = AccessEntry {
            remote_ip: "192.0.2.1",
            remote_port: 1234,
            local_ip: "127.0.0.1",
            local_port: 8080,
            server_name: "example.com",
            method: "GET",
            uri: "/a?b=1",
            protocol: "HTTP/1.1",
            status: 200,
            bytes_sent: 0,
            bytes_in: 7,
            referer: "",
            user_agent: "ua\"x",
            host: "example.com",
            vhost_index: None,
            started: Instant::now(),
        };
        let s = format_access(
            "%h %a %l %u %{Referer}i %{User-Agent}i %{Host}i %{Other}i %b %B %I %v %p %U %q %m %H %A %r %% %Z",
            &e,
        );
        assert!(s.starts_with("192.0.2.1 192.0.2.1 - - - "));
        assert!(s.contains(
            "ua\\\"x example.com - - 0 7 example.com 8080 /a ?b=1 GET HTTP/1.1 127.0.0.1"
        ));
        assert!(s.ends_with("% %Z"));

        let empty = AccessEntry { uri: "", ..e };
        assert!(format_access("%r %q", &empty).starts_with("- "));
        assert_eq!(format_access("trailing%", &empty), "trailing%");
        assert_eq!(format_access("%{unclosed", &empty), "%");
        assert_eq!(format_access("%{Referer", &empty), "%");
        assert_eq!(format_access("%{Referer}i", &empty), "-");
        assert_eq!(format_access("%{Anything}o %{Anything}e", &empty), "- -");
        assert_eq!(format_access("%{Anything}Z", &empty), "");
        assert_eq!(format_access("%{Referer}", &empty), "");
        assert_eq!(format_access("%<s", &empty), "200");
        assert!(format_access("%D %T %P", &empty).split_whitespace().count() == 3);
    }

    #[test]
    fn time_formats() {
        let e = AccessEntry {
            remote_ip: "127.0.0.1",
            remote_port: 1,
            local_ip: "127.0.0.1",
            local_port: 80,
            server_name: "x",
            method: "GET",
            uri: "/",
            protocol: "HTTP/1.1",
            status: 200,
            bytes_sent: 0,
            bytes_in: 0,
            referer: "",
            user_agent: "",
            host: "",
            vhost_index: None,
            started: Instant::now(),
        };
        for conv in ["%{msec}t", "%{msec_frac}t", "%{usec}t", "%{sec}t"] {
            assert!(!format_access(conv, &e).is_empty());
        }
        let t = format_access("%{%Y-%m-%d %H:%M:%S %b %a %z %Z %% %Q}t", &e);
        assert!(t.len() > 20);
        assert!(t.contains("+0000 GMT"));
        assert!(t.ends_with("%Q"));
    }

    #[test]
    fn log_format() {
        let started = Instant::now();
        let e = AccessEntry {
            remote_ip: "127.0.0.1",
            remote_port: 1234,
            local_ip: "127.0.0.1",
            local_port: 80,
            server_name: "example.com",
            method: "GET",
            uri: "/a?b=1",
            protocol: "HTTP/1.1",
            status: 200,
            bytes_sent: 42,
            bytes_in: 100,
            referer: "-",
            user_agent: "test",
            host: "example.com",
            vhost_index: None,
            started,
        };
        let s = format_access(
            "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"",
            &e,
        );
        assert!(s.starts_with("127.0.0.1 - - ["));
        assert!(s.ends_with(" \"-\" \"test\""));
        assert!(s.contains("\"GET /a?b=1 HTTP/1.1\" 200 42"));
    }

    #[test]
    fn logger_opens_writes_filters_and_reopens_configured_logs() {
        for (name, expected) in [
            ("emerg", Level::Emerg),
            ("alert", Level::Alert),
            ("crit", Level::Crit),
            ("error", Level::Error),
            ("warn", Level::Warn),
            ("notice", Level::Notice),
            ("info", Level::Info),
            ("trace8", Level::Debug),
            ("unknown", Level::Warn),
        ] {
            assert!(Level::parse(name) == expected);
            assert!(!expected.name().is_empty());
        }

        let dir = std::env::temp_dir().join(format!("vapache-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        std::fs::write(
            &conf,
            format!(
                "ServerRoot \"{}\"\n\
                 Listen 127.0.0.1:0\n\
                 ErrorLog logs/error.log\n\
                 LogLevel info\n\
                 LogFormat \"%h %>s %b\" common\n\
                 CustomLog logs/access.log common\n\
                 CustomLog /dev/null \"%h\"\n\
                 <VirtualHost 127.0.0.1:0>\n\
                 CustomLog logs/vhost.log common\n\
                 </VirtualHost>\n",
                dir.display()
            ),
        )
        .unwrap();
        let mut cfg = Config::load(&conf, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        cfg.custom_logs.push(CustomLog {
            path: "logs/quoted.log".into(),
            format: "\"%h %s\"".into(),
            condition: None,
        });
        let logger = Logger::new(&cfg).unwrap();
        assert_eq!(logger.access_log_count(), 4);
        assert!(logger.wants_access_log());
        logger.prepare_permissions(&cfg);
        logger.log(Level::Debug, "test", "filtered");
        logger.error("error\nline");
        logger.warn("warning");
        logger.info("information");

        let entry = AccessEntry {
            remote_ip: "192.0.2.1",
            remote_port: 1234,
            local_ip: "127.0.0.1",
            local_port: 80,
            server_name: "example.test",
            method: "GET",
            uri: "/",
            protocol: "HTTP/1.1",
            status: 200,
            bytes_sent: 5,
            bytes_in: 0,
            referer: "",
            user_agent: "",
            host: "example.test",
            vhost_index: None,
            started: Instant::now(),
        };
        logger.access(&entry);
        logger.access(&AccessEntry {
            vhost_index: Some(0),
            ..entry
        });
        logger.reopen().unwrap();
        drop(logger);
        assert!(std::fs::read_to_string(dir.join("logs/error.log"))
            .unwrap()
            .contains("error\\x0aline"));
        assert!(std::fs::read_to_string(dir.join("logs/access.log"))
            .unwrap()
            .contains("192.0.2.1 200 5"));
        assert!(std::fs::read_to_string(dir.join("logs/vhost.log"))
            .unwrap()
            .contains("192.0.2.1 200 5"));

        assert!(open_log("syslog:local0", &dir).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
