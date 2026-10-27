//! Apache `ap_expr` subset used by `Require expr` and `<If>`.
//!
//! The parser is intentionally independent of the HTTP server; the evaluator
//! receives a small context with the request, environment, peer address and
//! filesystem root.  Unsupported syntax is a parse error (config fails closed).

use crate::http::Request;
use regex::Regex;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone)]
pub enum Expr {
    Bool(bool),
    Str(String),
    Int(i64),
    Var(String),
    Func(String, Vec<Expr>),
    Concat(Vec<Expr>),
    Not(Box<Expr>),
    Neg(Box<Expr>),
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Compare(Box<Expr>, String, Box<Expr>),
    Regex(Box<Expr>, String, bool, bool),
    In(Box<Expr>, Vec<Expr>),
    FileTest(String, Box<Expr>),
    /// `<IfFile path>` from the main configuration.  Unlike per-directory
    /// expression file tests this argument is an operator-supplied path and is
    /// not confined to DocumentRoot.
    IfFile(String),
    StrTest(Box<Expr>, bool),
    IpMatch(Box<Expr>, Box<Expr>, bool),
    StrMatch(Box<Expr>, Box<Expr>, bool, bool),
    Capture(usize),
}

#[derive(Debug, Clone)]
pub enum Value {
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<Value>),
}

impl Value {
    pub fn truthy(&self) -> bool {
        match self {
            Value::Bool(b) => {
                vapache_verified::expr_value_truthy(vapache_verified::ExprValueKind::Bool, *b, 0, 0)
            }
            Value::Int(i) => vapache_verified::expr_value_truthy(
                vapache_verified::ExprValueKind::Int,
                false,
                *i,
                0,
            ),
            Value::Str(s) => vapache_verified::expr_value_truthy(
                vapache_verified::ExprValueKind::Str,
                false,
                0,
                s.len() as u64,
            ),
            Value::List(v) => vapache_verified::expr_value_truthy(
                vapache_verified::ExprValueKind::List,
                false,
                0,
                v.len() as u64,
            ),
        }
    }

    fn string(&self) -> String {
        match self {
            Value::Bool(b) => if *b { "true" } else { "false" }.into(),
            Value::Int(i) => i.to_string(),
            Value::Str(s) => s.clone(),
            Value::List(v) => v.iter().map(Value::string).collect::<Vec<_>>().join(","),
        }
    }

    fn int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Str(s) => s.trim().parse().ok(),
            Value::Bool(b) => Some(if *b { 1 } else { 0 }),
            Value::List(_) => None,
        }
    }
}

thread_local! {
    /// The listener scheme/port for the request currently being dispatched.
    /// These are set by the connection layer, never derived from a client
    /// header such as `X-Forwarded-Proto`.
    static REQUEST_HTTPS: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    static REQUEST_PORT: std::cell::Cell<Option<u16>> = const { std::cell::Cell::new(None) };
    static REQUEST_SERVER_NAME: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

pub(crate) struct ServerNameGuard(Option<String>);

impl Drop for ServerNameGuard {
    fn drop(&mut self) {
        REQUEST_SERVER_NAME.with(|v| *v.borrow_mut() = self.0.take());
    }
}

/// Install the dispatcher-selected canonical name for expression evaluation.
/// The guard restores the previous value when the request finishes.
pub(crate) fn set_server_name(name: &str) -> ServerNameGuard {
    let previous = REQUEST_SERVER_NAME.with(|v| v.borrow_mut().replace(name.to_string()));
    ServerNameGuard(previous)
}

fn request_server_name() -> Option<String> {
    REQUEST_SERVER_NAME.with(|v| v.borrow().clone())
}

/// Run `f` with the real listener TLS state and port visible to expression
/// evaluation.
pub(crate) fn with_connection<T>(https: bool, port: u16, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<bool>, Option<u16>);
    impl Drop for Restore {
        fn drop(&mut self) {
            REQUEST_HTTPS.with(|v| v.set(self.0));
            REQUEST_PORT.with(|v| v.set(self.1));
        }
    }
    let previous = (
        REQUEST_HTTPS.with(|v| v.get()),
        REQUEST_PORT.with(|v| v.get()),
    );
    REQUEST_HTTPS.with(|v| v.set(Some(https)));
    REQUEST_PORT.with(|v| v.set(Some(port)));
    let _restore = Restore(previous.0, previous.1);
    f()
}

pub(crate) fn request_is_https() -> bool {
    REQUEST_HTTPS.with(|v| v.get()).unwrap_or(false)
}

fn request_port() -> u16 {
    REQUEST_PORT.with(|v| v.get()).unwrap_or(80)
}

pub struct Context<'a> {
    pub req: &'a Request,
    pub env: &'a [(String, String)],
    pub peer: IpAddr,
    pub docroot: &'a Path,
    /// The dispatcher-selected canonical URL path: percent-decoded,
    /// query-free and free of dot segments.  `%{REQUEST_URI}` must be bound to
    /// this value, never to `Request::target` (F57/I57).
    pub url_path: &'a str,
    pub captures: Vec<String>,
}

impl<'a> Context<'a> {
    pub fn new(
        req: &'a Request,
        env: &'a [(String, String)],
        peer: IpAddr,
        docroot: &'a Path,
        url_path: &'a str,
    ) -> Self {
        // The constructor is the single place where expression evaluation
        // binds REQUEST_URI.  The runtime supplies the dispatcher's canonical
        // path; a raw target or query-bearing value is never accepted.
        debug_assert!(vapache_verified::request_uri_identity_admit(
            true, false, false
        ));
        Self {
            req,
            env,
            peer,
            docroot,
            url_path,
            captures: Vec::new(),
        }
    }
}

fn function_arg(ctx: &Context<'_>, arg: &str) -> Result<String, String> {
    let upper = arg.to_ascii_uppercase();
    let is_var = arg.contains("%{")
        || arg.starts_with("req:")
        || arg.starts_with("http:")
        || arg.starts_with("env:")
        || arg.starts_with("HTTP_")
        || matches!(
            upper.as_str(),
            "TIME"
                | "TIME_YEAR"
                | "TIME_MON"
                | "TIME_DAY"
                | "TIME_HOUR"
                | "TIME_MIN"
                | "TIME_SEC"
                | "REQUEST_METHOD"
                | "QUERY_STRING"
                | "REQUEST_URI"
                | "REQUEST_SCHEME"
                | "HTTPS"
                | "REMOTE_ADDR"
                | "SERVER_NAME"
                | "SERVER_PORT"
                | "DOCUMENT_ROOT"
                | "API_VERSION"
        );
    if is_var {
        if arg.contains("%{") {
            expand(arg, ctx)
        } else {
            Ok(var(ctx, arg)?.string())
        }
    } else {
        Ok(arg.to_string())
    }
}

fn var(ctx: &Context<'_>, name: &str) -> Result<Value, String> {
    if let Some((func, arg)) = name.split_once(':') {
        if matches!(
            func.to_ascii_lowercase().as_str(),
            "toupper" | "tolower" | "escape" | "unescape"
        ) {
            let value = function_arg(ctx, arg)?;
            return Ok(Value::Str(match func.to_ascii_lowercase().as_str() {
                "toupper" => value.to_ascii_uppercase(),
                "tolower" => value.to_ascii_lowercase(),
                "escape" => percent_encode(&value),
                _ => percent_decode(&value),
            }));
        }
    }
    let lower = name.to_ascii_lowercase();
    if let Some(header) = lower.strip_prefix("req:") {
        return Ok(Value::Str(
            ctx.req.header_str(header).unwrap_or("").to_string(),
        ));
    }
    if let Some(header) = lower.strip_prefix("http:") {
        return Ok(Value::Str(
            ctx.req.header_str(header).unwrap_or("").to_string(),
        ));
    }
    if let Some(env_name) = lower.strip_prefix("env:") {
        return Ok(Value::Str(
            ctx.env
                .iter()
                .rev()
                .find(|(k, _)| k.eq_ignore_ascii_case(env_name))
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
        ));
    }
    if let Some(header) = lower.strip_prefix("http_") {
        let header = header.replace('_', "-");
        return Ok(Value::Str(
            ctx.req.header_str(&header).unwrap_or("").to_string(),
        ));
    }
    let empty = String::new();
    let now = crate::util::unix_now();
    let days = now.div_euclid(86_400);
    let sod = now.rem_euclid(86_400);
    let (year, month, day) = crate::util::civil_from_days(days);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    Ok(Value::Str(match lower.as_str() {
        "time" => format!("{year:04}{month:02}{day:02}{hh:02}{mm:02}{ss:02}"),
        "time_year" => format!("{year:04}"),
        "time_mon" => format!("{month:02}"),
        "time_day" => format!("{day:02}"),
        "time_hour" => format!("{hh:02}"),
        "time_min" => format!("{mm:02}"),
        "time_sec" => format!("{ss:02}"),
        "request_method" => ctx.req.method.clone(),
        // Raw request-target bytes may fail UTF-8; fail closed instead of
        // conflating distinct byte strings through the replacement character.
        "query_string" => String::from_utf8(ctx.req.query.clone())
            .map_err(|_| "QUERY_STRING is not valid UTF-8".to_string())?,
        "request_uri" => ctx.url_path.to_string(),
        "request_scheme" => if request_is_https() { "https" } else { "http" }.into(),
        // Never trust X-Forwarded-Proto here.  Forwarded headers are only a
        // separate, explicitly trusted-proxy input (mod_remoteip); they are
        // not evidence that the client connection itself used TLS.
        "https" => if request_is_https() { "on" } else { "off" }.into(),
        "remote_addr" => ctx.peer.to_string(),
        "server_name" => request_server_name().unwrap_or_else(|| {
            ctx.req
                .header_str("host")
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("")
                .to_string()
        }),
        "server_port" => request_port().to_string(),
        "document_root" => ctx.docroot.to_string_lossy().into_owned(),
        "api_version" => "20120211".into(),
        other => {
            if other.starts_with("http") {
                empty
            } else {
                return Err(format!("unknown expression variable '%{{{name}}}'"));
            }
        }
    }))
}

fn expand(text: &str, ctx: &Context<'_>) -> Result<String, String> {
    let mut out = String::new();
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 1 < b.len() && b[i + 1] == b'{' {
            let mut depth = 1;
            let mut j = i + 2;
            while j < b.len() && depth > 0 {
                if b[j] == b'{' {
                    depth += 1;
                } else if b[j] == b'}' {
                    depth -= 1;
                }
                j += 1;
            }
            if depth != 0 {
                return Err("unterminated %{...} expression".into());
            }
            let inner = &text[i + 2..j - 1];
            if let Some((func, arg)) = inner.split_once(':') {
                let value = Value::Str(function_arg(ctx, arg)?);
                out.push_str(&match func.to_ascii_lowercase().as_str() {
                    "toupper" => value.string().to_ascii_uppercase(),
                    "tolower" => value.string().to_ascii_lowercase(),
                    "escape" => percent_encode(&value.string()),
                    "unescape" => percent_decode(&value.string()),
                    _ => return Err(format!("unknown expression function '{func}'")),
                });
            } else {
                out.push_str(&var(ctx, inner)?.string());
            }
            i = j;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    Ok(out)
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02x}"));
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn glob(pattern: &str, value: &str, path_mode: bool) -> bool {
    vapache_verified::expr_glob_match(pattern.as_bytes(), value.as_bytes(), path_mode)
}

fn compare_op(op: &str) -> Option<vapache_verified::ExprCompareOp> {
    Some(match op {
        "=" | "==" | "-eq" => vapache_verified::ExprCompareOp::Eq,
        "!=" | "-ne" => vapache_verified::ExprCompareOp::Ne,
        "<" | "-lt" => vapache_verified::ExprCompareOp::Lt,
        "<=" | "-le" => vapache_verified::ExprCompareOp::Le,
        ">" | "-gt" => vapache_verified::ExprCompareOp::Gt,
        ">=" | "-ge" => vapache_verified::ExprCompareOp::Ge,
        _ => return None,
    })
}

fn cmp(left: &Value, op: &str, right: &Value) -> bool {
    let Some(kind) = compare_op(op) else {
        return false;
    };
    let numeric = matches!(op, "-eq" | "-ne" | "-lt" | "-le" | "-gt" | "-ge")
        && left.int().is_some()
        && right.int().is_some();
    if numeric {
        return vapache_verified::expr_compare_ints(
            kind,
            left.int().unwrap_or_default(),
            right.int().unwrap_or_default(),
        );
    }
    let a = left.string();
    let b = right.string();
    vapache_verified::expr_compare_strs(kind, a.as_bytes(), b.as_bytes())
}

/// Resolve an expression file argument beneath the document root.  `.htaccess`
/// authors can use `Require expr`/`RewriteCond expr`; allowing absolute or
/// parent-relative paths there would let a local author read files with the
/// httpd user's privileges (CVE-2026-24072 / CVE-2026-44119).  Existing paths
/// are canonicalized and must still be under the canonical document root.
fn confined_expr_path(ctx: &Context<'_>, raw: &str, must_exist: bool) -> Option<PathBuf> {
    let path = Path::new(raw);
    let absolute = path.is_absolute();
    let parent_relative = path.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    });
    if !vapache_verified::expr_file_test_admit(absolute, parent_relative, true) {
        return None;
    }
    let joined = ctx.docroot.join(path);
    if !must_exist {
        return Some(joined);
    }
    let root = std::fs::canonicalize(ctx.docroot).ok()?;
    let target = std::fs::canonicalize(&joined).ok()?;
    // Consume the same verified component-aware containment kernel as the
    // rewrite, alias and FastCGI paths instead of a local `starts_with`:
    // containment is one story (`path_under_base`) everywhere, and its
    // reflexivity/transitivity lemmas hold for this check too.
    if vapache_verified::path_under_base(
        target.as_os_str().as_encoded_bytes(),
        root.as_os_str().as_encoded_bytes(),
    ) {
        Some(target)
    } else {
        None
    }
}

impl Expr {
    pub fn eval(&self, ctx: &mut Context<'_>) -> Result<Value, String> {
        Ok(match self {
            Expr::Bool(b) => Value::Bool(*b),
            Expr::Str(s) => Value::Str(expand(s, ctx)?),
            Expr::Int(i) => Value::Int(*i),
            Expr::Var(v) => var(ctx, v)?,
            Expr::Capture(i) => Value::Str(ctx.captures.get(*i).cloned().unwrap_or_default()),
            Expr::Concat(parts) => Value::Str(
                parts
                    .iter()
                    .map(|p| p.eval(ctx).map(|v| v.string()))
                    .collect::<Result<Vec<_>, _>>()?
                    .join(""),
            ),
            Expr::Not(e) => Value::Bool(!e.eval(ctx)?.truthy()),
            Expr::Neg(e) => Value::Int(-e.eval(ctx)?.int().ok_or("unary - needs a number")?),
            Expr::And(es) => {
                for e in es {
                    if !e.eval(ctx)?.truthy() {
                        return Ok(Value::Bool(false));
                    }
                }
                Value::Bool(true)
            }
            Expr::Or(es) => {
                for e in es {
                    if e.eval(ctx)?.truthy() {
                        return Ok(Value::Bool(true));
                    }
                }
                Value::Bool(false)
            }
            Expr::Compare(l, op, r) => Value::Bool(cmp(&l.eval(ctx)?, op, &r.eval(ctx)?)),
            Expr::Regex(l, pattern, nocase, negate) => {
                let text = l.eval(ctx)?.string();
                if !vapache_verified::regex_dialect_admit(pattern.as_bytes()) {
                    return Err("unsupported expression regex dialect".into());
                }
                let re = regex::RegexBuilder::new(pattern)
                    .case_insensitive(*nocase)
                    .build()
                    .map_err(|e| format!("bad expression regex: {e}"))?;
                let caps = re.captures(&text);
                let matched = caps.is_some();
                ctx.captures = caps
                    .map(|c| {
                        (0..c.len())
                            .map(|i| c.get(i).map(|m| m.as_str().to_string()).unwrap_or_default())
                            .collect()
                    })
                    .unwrap_or_default();
                Value::Bool(matched != *negate)
            }
            Expr::In(l, list) => {
                let needle = l.eval(ctx)?.string();
                Value::Bool(
                    list.iter()
                        .any(|e| e.eval(ctx).map(|v| v.string() == needle).unwrap_or(false)),
                )
            }
            Expr::StrTest(e, nonempty) => {
                let s = e.eval(ctx)?.string();
                Value::Bool(if *nonempty {
                    !s.is_empty()
                } else {
                    s.is_empty()
                })
            }
            Expr::IfFile(path) => Value::Bool(
                crate::files::symlink_metadata_cached(std::path::Path::new(path)).is_ok(),
            ),
            Expr::FileTest(op, e) => {
                let raw = e.eval(ctx)?.string();
                // File tests are a metadata oracle too.  Use the same
                // canonical document-root confinement as file()/filesize();
                // an absolute path or a symlink leaving the root must not be
                // observable through `.htaccess` expressions (F45/I42).
                let p = confined_expr_path(ctx, &raw, true);
                let meta = p.as_deref().map(std::fs::symlink_metadata);
                Value::Bool(match op.as_str() {
                    "-f" => meta
                        .as_ref()
                        .and_then(|m| m.as_ref().ok())
                        .map(|m| m.is_file())
                        .unwrap_or(false),
                    "-d" => meta
                        .as_ref()
                        .and_then(|m| m.as_ref().ok())
                        .map(|m| m.is_dir())
                        .unwrap_or(false),
                    "-e" | "-F" | "-U" => meta.as_ref().map(|m| m.is_ok()).unwrap_or(false),
                    "-s" => meta
                        .as_ref()
                        .and_then(|m| m.as_ref().ok())
                        .map(|m| m.len() > 0)
                        .unwrap_or(false),
                    "-R" => {
                        let spec = e.eval(ctx)?.string();
                        crate::config::parse_ip_net(&spec)
                            .map(|(net, bits)| crate::access::ip_in_net(ctx.peer, net, bits))
                            .unwrap_or(false)
                    }
                    _ => false,
                })
            }
            Expr::IpMatch(l, r, negate) => {
                let ip: IpAddr = l
                    .eval(ctx)?
                    .string()
                    .parse()
                    .map_err(|_| "bad IP expression")?;
                let spec = r.eval(ctx)?.string();
                let matched = crate::config::parse_ip_net(&spec)
                    .map(|(net, bits)| crate::access::ip_in_net(ip, net, bits))
                    .unwrap_or(false);
                Value::Bool(matched != *negate)
            }
            Expr::StrMatch(l, r, nocase, path_mode) => {
                let mut a = l.eval(ctx)?.string();
                let mut b = r.eval(ctx)?.string();
                if *nocase {
                    a = a.to_ascii_lowercase();
                    b = b.to_ascii_lowercase();
                }
                Value::Bool(glob(&b, &a, *path_mode))
            }
            Expr::Func(name, args) => {
                let vals: Vec<Value> =
                    args.iter().map(|a| a.eval(ctx)).collect::<Result<_, _>>()?;
                let arg = |i: usize| vals.get(i).map(Value::string).unwrap_or_default();
                match name.to_ascii_lowercase().as_str() {
                    "req" | "http" => {
                        Value::Str(ctx.req.header_str(&arg(0)).unwrap_or("").to_string())
                    }
                    "env" => Value::Str(
                        ctx.env
                            .iter()
                            .rev()
                            .find(|(k, _)| k.eq_ignore_ascii_case(&arg(0)))
                            .map(|(_, v)| v.clone())
                            .unwrap_or_default(),
                    ),
                    "file" => {
                        let p = confined_expr_path(ctx, &arg(0), true).ok_or_else(|| {
                            "expression file path escapes DOCUMENT_ROOT".to_string()
                        })?;
                        Value::Str(std::fs::read_to_string(p).map_err(|e| e.to_string())?)
                    }
                    "filesize" => {
                        let p = confined_expr_path(ctx, &arg(0), true).ok_or_else(|| {
                            "expression file path escapes DOCUMENT_ROOT".to_string()
                        })?;
                        Value::Int(std::fs::metadata(p).map(|m| m.len() as i64).unwrap_or(0))
                    }
                    "toupper" => Value::Str(arg(0).to_ascii_uppercase()),
                    "tolower" => Value::Str(arg(0).to_ascii_lowercase()),
                    "escape" => Value::Str(percent_encode(&arg(0))),
                    "unescape" => Value::Str(percent_decode(&arg(0))),
                    "sha1" => Value::Str(sha1_hex(&arg(0))),
                    "md5" => Value::Str(md5_hex(&arg(0))),
                    "base64" => Value::Str(base64_encode(arg(0).as_bytes())),
                    "unbase64" => {
                        Value::Str(String::from_utf8_lossy(&base64_decode(&arg(0))).into_owned())
                    }
                    other => return Err(format!("unknown expression function '{other}'")),
                }
            }
        })
    }
}

fn sha1_hex(s: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn md5_hex(s: &str) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn base64_encode(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_default()
}

/// Cap on parser recursion depth (`!`, `-`, `(` nesting). `primary()` and
/// `unary()` recurse once per operator, so inputs nested deeper than this cap
/// return `Err` instead of overflowing the stack — the parser stays total.
/// `Expr::eval` needs no cap of its own because no expression tree deeper than
/// the cap can be parsed.
///
/// The value is calibrated against the parser's smallest execution stack: the
/// `primary → or → and → compare → concat → unary` descent chain costs several
/// hundred bytes to ~2 KiB per frame on 2 MiB default `std::thread` stacks
/// (request handlers spawn without `stack_size`), and a paren level costs
/// 8 such frames. 64 keeps the reachable worst case around 1 MiB with margin
/// while still accepting nesting far deeper than any real-world expression.
const MAX_EXPR_DEPTH: usize = 64;

struct Parser<'a> {
    input: &'a str,
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            pos: 0,
            depth: 0,
        }
    }

    fn skip(&mut self) {
        while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip();
        self.input.as_bytes().get(self.pos).copied()
    }

    fn take(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn word(&mut self) -> String {
        self.skip();
        let start = self.pos;
        while self.pos < self.input.len() {
            let b = self.input.as_bytes()[self.pos];
            if b.is_ascii_whitespace() || b"()[]{},.'\"=!<>&|".contains(&b) {
                break;
            }
            self.pos += 1;
        }
        self.input[start..self.pos].to_string()
    }

    fn string(&mut self) -> Result<String, String> {
        let quote = self.input.as_bytes()[self.pos];
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.input.len() {
            let b = self.input.as_bytes()[self.pos];
            self.pos += 1;
            if b == quote {
                return Ok(out);
            }
            if b == b'\\' && self.pos < self.input.len() {
                let n = self.input.as_bytes()[self.pos];
                self.pos += 1;
                out.push(match n {
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    other => other as char,
                });
            } else {
                out.push(b as char);
            }
        }
        Err("unterminated expression string".into())
    }

    fn variable(&mut self) -> Result<Expr, String> {
        self.pos += 2; // %{
        let start = self.pos;
        let mut depth = 1;
        while self.pos < self.input.len() {
            match self.input.as_bytes()[self.pos] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        let name = self.input[start..self.pos].to_string();
                        self.pos += 1;
                        return Ok(Expr::Var(name));
                    }
                }
                _ => {}
            }
            self.pos += 1;
        }
        Err("unterminated %{...}".into())
    }

    fn regex(&mut self) -> Result<(String, bool), String> {
        let Some(delim) = self.input.as_bytes().get(self.pos).copied() else {
            return Err("expected a regex after =~".into());
        };
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.input.len() {
            let b = self.input.as_bytes()[self.pos];
            self.pos += 1;
            if b == delim {
                let mut nocase = false;
                while self.pos < self.input.len()
                    && self.input.as_bytes()[self.pos].is_ascii_alphabetic()
                {
                    nocase |= self.input.as_bytes()[self.pos] == b'i';
                    self.pos += 1;
                }
                return Ok((out, nocase));
            }
            if b == b'\\' && self.pos < self.input.len() {
                out.push('\\');
                out.push(self.input.as_bytes()[self.pos] as char);
                self.pos += 1;
            } else {
                out.push(b as char);
            }
        }
        Err("unterminated expression regex".into())
    }

    fn primary(&mut self) -> Result<Expr, String> {
        self.depth += 1;
        if self.depth > MAX_EXPR_DEPTH {
            self.depth -= 1;
            return Err("expression exceeds maximum parse depth".into());
        }
        let r = self.primary_inner();
        self.depth -= 1;
        r
    }

    fn primary_inner(&mut self) -> Result<Expr, String> {
        self.skip();
        let Some(c) = self.peek() else {
            return Err("unexpected end of expression".into());
        };
        if c == b'(' {
            self.pos += 1;
            let e = self.or()?;
            if !self.take(b')') {
                return Err("missing ')'".into());
            }
            return Ok(e);
        }
        if c == b'\'' || c == b'"' {
            return Ok(Expr::Str(self.string()?));
        }
        if c == b'%' && self.input.as_bytes().get(self.pos + 1) == Some(&b'{') {
            return self.variable();
        }
        if c == b'$' {
            self.pos += 1;
            let start = self.pos;
            while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
            let idx = self.input[start..self.pos]
                .parse::<usize>()
                .map_err(|_| "bad capture".to_string())?;
            return Ok(Expr::Capture(idx));
        }
        if c == b'{' {
            self.pos += 1;
            let mut list = Vec::new();
            loop {
                self.skip();
                if self.take(b'}') {
                    break;
                }
                list.push(self.or()?);
                self.skip();
                if self.take(b',') {
                    continue;
                }
                if !self.take(b'}') {
                    return Err("expected ',' or '}' in list".into());
                }
                break;
            }
            return Ok(Expr::In(Box::new(Expr::Str(String::new())), list));
        }
        if c == b'-' {
            if let Some(rest) = self.input[self.pos..].strip_prefix("-in") {
                if rest.is_empty() || rest.starts_with(char::is_whitespace) {
                    self.pos += 3;
                    return Ok(Expr::Str("-in".into()));
                }
            }
            self.pos += 1;
            let start = self.pos;
            while self.pos < self.input.len()
                && self.input.as_bytes()[self.pos].is_ascii_alphabetic()
            {
                self.pos += 1;
            }
            let word = &self.input[start..self.pos];
            if !word.is_empty() {
                if matches!(word, "n" | "z" | "f" | "d" | "e" | "s" | "F" | "U" | "R") {
                    return Ok(Expr::Str(format!("-{word}")));
                }
            }
            return self.primary().map(|e| Expr::Neg(Box::new(e)));
        }
        if c.is_ascii_digit() {
            let start = self.pos;
            while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
            return Ok(Expr::Int(self.input[start..self.pos].parse().unwrap_or(0)));
        }
        let w = self.word();
        if w.is_empty() {
            return Err("expected expression".into());
        }
        if w.eq_ignore_ascii_case("true") {
            return Ok(Expr::Bool(true));
        }
        if w.eq_ignore_ascii_case("false") {
            return Ok(Expr::Bool(false));
        }
        if self.peek() == Some(b'(') {
            self.pos += 1;
            let mut args = Vec::new();
            loop {
                self.skip();
                if self.take(b')') {
                    break;
                }
                args.push(self.or()?);
                self.skip();
                if self.take(b',') {
                    continue;
                }
                if self.take(b')') {
                    break;
                }
                return Err("expected ',' or ')' in function".into());
            }
            return Ok(Expr::Func(w, args));
        }
        Err(format!("unknown expression token '{w}'"))
    }

    fn unary(&mut self) -> Result<Expr, String> {
        self.depth += 1;
        if self.depth > MAX_EXPR_DEPTH {
            self.depth -= 1;
            return Err("expression exceeds maximum parse depth".into());
        }
        let r = self.unary_inner();
        self.depth -= 1;
        r
    }

    fn unary_inner(&mut self) -> Result<Expr, String> {
        self.skip();
        if self.peek() == Some(b'!') && self.input.as_bytes().get(self.pos + 1) != Some(&b'=') {
            self.pos += 1;
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        if let Some(c) = self.peek() {
            if c == b'-' {
                let save = self.pos;
                self.pos += 1;
                let start = self.pos;
                while self.pos < self.input.len()
                    && self.input.as_bytes()[self.pos].is_ascii_alphabetic()
                {
                    self.pos += 1;
                }
                let op = &self.input[start..self.pos];
                if matches!(op, "f" | "d" | "e" | "s" | "F" | "U" | "R") {
                    return Ok(Expr::FileTest(format!("-{op}"), Box::new(self.primary()?)));
                }
                if op == "n" || op == "z" {
                    return Ok(Expr::StrTest(Box::new(self.primary()?), op == "n"));
                }
                self.pos = save;
            }
        }
        self.primary()
    }

    fn concat(&mut self) -> Result<Expr, String> {
        let mut parts = vec![self.unary()?];
        while self.peek() == Some(b'.') {
            self.pos += 1;
            parts.push(self.unary()?);
        }
        if parts.len() == 1 {
            Ok(parts.pop().unwrap())
        } else {
            Ok(Expr::Concat(parts))
        }
    }

    fn compare(&mut self) -> Result<Expr, String> {
        let left = self.concat()?;
        self.skip();
        let ops = [
            "==",
            "!=",
            "<=",
            ">=",
            "=~",
            "!~",
            "-eq",
            "-ne",
            "-lt",
            "-le",
            "-gt",
            "-ge",
            "-in",
            "-ipmatch",
            "-strmatch",
            "-strcmatch",
            "-fnmatch",
            "=",
            "<",
            ">",
        ];
        for op in ops {
            if self.input[self.pos..].starts_with(op) {
                self.pos += op.len();
                if op == "=~" || op == "!~" {
                    self.skip();
                    let (pat, nocase) = self.regex()?;
                    return Ok(Expr::Regex(Box::new(left), pat, nocase, op == "!~"));
                }
                if op == "-in" {
                    self.skip();
                    if !self.take(b'{') {
                        return Err("expected '{' after -in".into());
                    }
                    let mut list = Vec::new();
                    loop {
                        self.skip();
                        if self.take(b'}') {
                            break;
                        }
                        list.push(self.or()?);
                        if self.take(b',') {
                            continue;
                        }
                        if self.take(b'}') {
                            break;
                        }
                    }
                    return Ok(Expr::In(Box::new(left), list));
                }
                let right = self.concat()?;
                return Ok(match op {
                    "-ipmatch" => Expr::IpMatch(Box::new(left), Box::new(right), false),
                    "-strmatch" => Expr::StrMatch(Box::new(left), Box::new(right), false, false),
                    "-strcmatch" => Expr::StrMatch(Box::new(left), Box::new(right), true, false),
                    "-fnmatch" => Expr::StrMatch(Box::new(left), Box::new(right), false, true),
                    _ => Expr::Compare(Box::new(left), op.into(), Box::new(right)),
                });
            }
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut items = vec![self.compare()?];
        loop {
            self.skip();
            if self.input[self.pos..].starts_with("&&") {
                self.pos += 2;
                items.push(self.compare()?);
            } else {
                break;
            }
        }
        if items.len() == 1 {
            Ok(items.pop().unwrap())
        } else {
            Ok(Expr::And(items))
        }
    }

    fn or(&mut self) -> Result<Expr, String> {
        let mut items = vec![self.and()?];
        loop {
            self.skip();
            if self.input[self.pos..].starts_with("||") {
                self.pos += 2;
                items.push(self.and()?);
            } else {
                break;
            }
        }
        if items.len() == 1 {
            Ok(items.pop().unwrap())
        } else {
            Ok(Expr::Or(items))
        }
    }
}

pub fn parse(input: &str) -> Result<Expr, String> {
    let mut p = Parser::new(input);
    let e = p.or()?;
    p.skip();
    if p.pos != input.len() {
        return Err(format!("trailing expression input '{}'", &input[p.pos..]));
    }
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Headers, Request, Version};

    fn req() -> Request {
        Request {
            method: "GET".into(),
            target: b"/x".to_vec(),
            raw_path: b"/x".to_vec(),
            query: Vec::new(),
            version: Version::Http11,
            headers: Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    fn eval(s: &str) -> bool {
        let e = parse(s).unwrap();
        let r = req();
        let docroot = Path::new("/tmp");
        let mut c = Context::new(&r, &[], "127.0.0.1".parse().unwrap(), docroot, "/x");
        e.eval(&mut c).unwrap().truthy()
    }

    #[test]
    fn parser_cases_from_apache_suite() {
        let cases = [
            ("true", true),
            ("false", false),
            ("1 -eq 01", true),
            ("1 -ne 2", true),
            ("'aa' == 'aa'", true),
            ("'aa' < 'b'", true),
            ("'a' . 'b' . 'c' = 'abc'", true),
            ("'a1c' = 'a'. 1. 'c'", true),
            ("'a' -in { 'b', 'a' }", true),
            ("'abc' =~ /BC/i", true),
            ("'abc' =~ /(bc)/ && $1 == 'bc'", true),
            ("%{REQUEST_METHOD} == 'GET'", true),
            ("%{API_VERSION} -gt 20101001", true),
            ("toupper('abC12d') = 'ABC12D'", true),
            ("escape('?') = '%3f'", true),
            ("%{toupper:%{escape:?}} = '%3F'", true),
            ("-n '1'", true),
            ("-z ''", true),
            ("-R '127.0.0.1'", true),
            ("'127.0.0.1' -ipmatch '127.0.0.0/8'", true),
            ("'foo' -strmatch 'f*'", true),
            ("'a/b' -fnmatch 'a/*'", true),
            ("true && !false", true),
            ("false || true", true),
        ];
        for (expr, expected) in cases {
            assert_eq!(eval(expr), expected, "{expr}");
        }
    }

    #[test]
    fn query_string_variable_uses_the_current_request_query() {
        let mut r = req();
        r.query = b"a=1".to_vec();
        let e = parse("%{QUERY_STRING} == 'a=1'").unwrap();
        let docroot = Path::new("/tmp");
        let mut c = Context::new(&r, &[], "127.0.0.1".parse().unwrap(), docroot, "/x");
        assert!(e.eval(&mut c).unwrap().truthy());
    }

    #[test]
    fn query_string_variable_fails_closed_on_invalid_utf8() {
        // Raw request-target bytes may fail UTF-8; from_utf8_lossy would
        // conflate \xff and \xfe into one replacement character, so the
        // variable is an evaluation error instead.
        let mut r = req();
        r.query = b"\xff\xfe".to_vec();
        let mut c = Context::new(
            &r,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
        );
        let cond = parse("%{QUERY_STRING} == ''").unwrap();
        assert!(cond.eval(&mut c).is_err());
        assert!(expand("%{QUERY_STRING}", &c).is_err());
        assert!(expand("%{QUERY_STRING}|x", &c).is_err());
    }

    #[test]
    fn expression_file_access_is_confined_to_docroot() {
        let dir = std::env::temp_dir().join(format!("vp-expr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("inside.txt"), "inside").unwrap();
        let r = req();
        let mut c = Context::new(&r, &[], "127.0.0.1".parse().unwrap(), &dir, "/x");
        let inside = parse("file('inside.txt') = 'inside'").unwrap();
        assert!(inside.eval(&mut c).unwrap().truthy());
        let outside = parse("file('/etc/passwd') = ''").unwrap();
        assert!(outside.eval(&mut c).is_err());
        let traversal = parse("-f '../etc/passwd'").unwrap();
        assert!(!traversal.eval(&mut c).unwrap().truthy());
        // FileTest uses the same canonical confinement as file()/filesize().
        for expr in [
            "-f '/etc/passwd'",
            "-e '/etc/passwd'",
            "-s '/etc/passwd'",
            "-d '/etc'",
            "-F '/etc/passwd'",
            "-U '/etc/passwd'",
        ] {
            assert!(
                !parse(expr).unwrap().eval(&mut c).unwrap().truthy(),
                "{expr}"
            );
        }
        let outside_file = dir.with_file_name(format!("vp-expr-outside-{}", std::process::id()));
        std::fs::write(&outside_file, "outside").unwrap();
        std::os::unix::fs::symlink(&outside_file, dir.join("escape")).unwrap();
        assert!(!parse("-f 'escape'").unwrap().eval(&mut c).unwrap().truthy());
        let _ = std::fs::remove_file(&outside_file);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verified_expression_kernels_keep_comparison_and_glob_semantics() {
        use vapache_verified::ExprCompareOp::{Eq, Ge, Gt, Le, Ne};
        use vapache_verified::{expr_compare_ints, expr_compare_strs, expr_glob_match};
        assert!(expr_compare_ints(Eq, 1, 1));
        assert!(expr_compare_ints(Le, -1, 1));
        assert!(expr_compare_ints(Ge, 1, 1));
        assert!(expr_compare_ints(Ne, 1, 2));
        assert!(expr_compare_strs(Le, b"aa", b"b"));
        assert!(expr_compare_strs(Gt, b"b", b"aa"));
        assert!(expr_compare_strs(Eq, b"", b""));
        assert!(!expr_compare_strs(Gt, b"aa", b"aa"));
        assert!(expr_glob_match(b"a/*", b"a/b", true));
        assert!(!expr_glob_match(b"a/*", b"a/b/c", true));
        assert!(!expr_glob_match(b"a?b", b"a/b", false));
        assert!(expr_glob_match(b"a?b", b"a/b", true));
        assert!(expr_glob_match(b"*.php", b"index.php", true));
        assert!(!expr_glob_match(b"?.php", b"index.php", true));
        assert!(expr_glob_match(b"", b"", true));
        assert!(!expr_glob_match(b"", b"x", true));
        // The runtime evaluator consumes the verified kernels directly.
        assert!(!eval("'a/b/c' -fnmatch 'a/*'"));
        assert!(eval("'a/b' -fnmatch 'a/*'"));
        assert!(!eval("'a/b' -strmatch 'a?b'"));
        assert!(eval("'a/b' -fnmatch 'a?b'"));
        assert!(eval("'aa' < 'b'"));
        assert!(eval("'2' -lt '10'"));
    }

    #[test]
    fn parses_common_expressions() {
        assert!(eval("true"));
        assert!(!eval("false"));
        assert!(eval("1 -eq 01"));
        assert!(eval("'aa' == 'aa'"));
        assert!(eval("'a' . 'b' = 'ab'"));
        assert!(eval("'a' -in { 'b', 'a' }"));
        assert!(eval("'abc' =~ /bc/"));
        assert!(eval("'abc' =~ /BC/i"));
        assert!(eval("%{REQUEST_METHOD} == 'GET'"));
        assert!(eval("-R '127.0.0.1'"));
    }

    fn eval_result(s: &str) -> Result<Value, String> {
        let e = parse(s)?;
        let r = req();
        let mut c = Context::new(
            &r,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
        );
        e.eval(&mut c)
    }

    #[test]
    fn value_conversions_and_connection_context() {
        assert!(Value::Bool(true).truthy());
        assert!(Value::Int(1).truthy());
        assert!(!Value::Int(0).truthy());
        assert!(Value::Str("x".into()).truthy());
        assert!(!Value::Str(String::new()).truthy());
        assert!(Value::List(vec![Value::Int(1)]).truthy());
        assert!(!Value::List(Vec::new()).truthy());
        assert_eq!(Value::Bool(true).string(), "true");
        assert_eq!(Value::Bool(false).string(), "false");
        assert_eq!(
            Value::List(vec![Value::Int(1), Value::Str("x".into())]).string(),
            "1,x"
        );
        assert_eq!(Value::Bool(true).int(), Some(1));
        assert_eq!(Value::Bool(false).int(), Some(0));
        assert_eq!(Value::List(Vec::new()).int(), None);
        assert_eq!(Value::Str(" 42 ".into()).int(), Some(42));

        assert!(!request_is_https());
        assert_eq!(request_port(), 80);
        let guard = set_server_name("canonical.test");
        assert_eq!(request_server_name().as_deref(), Some("canonical.test"));
        drop(guard);
        assert_eq!(request_server_name(), None);
        with_connection(true, 8443, || {
            assert!(request_is_https());
            assert_eq!(request_port(), 8443);
        });
        assert!(!request_is_https());
        assert_eq!(request_port(), 80);

        let r = req();
        let c = Context::new(
            &r,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
        );
        assert_eq!(function_arg(&c, "literal").unwrap(), "literal");
        assert_eq!(function_arg(&c, "REQUEST_METHOD").unwrap(), "GET");
        assert_eq!(function_arg(&c, "%{REQUEST_METHOD}").unwrap(), "GET");
        assert_eq!(
            confined_expr_path(&c, "relative.txt", false),
            Some(PathBuf::from("/tmp/relative.txt"))
        );
    }

    #[test]
    fn var_expand_and_encoding_edge_paths() {
        let mut r = req();
        r.headers.push("X-Test", "Header");
        r.headers.push("Host", "example.test:8080");
        let env = vec![("FOO".to_string(), "bar".to_string())];
        let mut c = Context::new(
            &r,
            &env,
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
        );
        assert_eq!(var(&c, "req:x-test").unwrap().string(), "Header");
        assert_eq!(var(&c, "http:x-test").unwrap().string(), "Header");
        assert_eq!(var(&c, "env:foo").unwrap().string(), "bar");
        assert_eq!(var(&c, "http_x_test").unwrap().string(), "Header");
        assert_eq!(var(&c, "server_name").unwrap().string(), "example.test");
        assert_eq!(var(&c, "httpfoo").unwrap().string(), "");
        assert!(var(&c, "unknown_variable").is_err());
        assert_eq!(var(&c, "tolower:ABC").unwrap().string(), "abc");
        assert_eq!(var(&c, "escape:a b").unwrap().string(), "a%20b");
        assert_eq!(var(&c, "unescape:a%20b").unwrap().string(), "a b");
        assert_eq!(var(&c, "TIME_YEAR").unwrap().string().len(), 4);
        assert_eq!(var(&c, "REQUEST_SCHEME").unwrap().string(), "http");
        assert_eq!(var(&c, "HTTPS").unwrap().string(), "off");

        // F57/I57: REQUEST_URI is the canonical decoded, query-free path
        // supplied by the dispatcher, never the raw request-line target.
        let mut raw = req();
        raw.target = b"/%2eenv?x=1".to_vec();
        raw.raw_path = b"/%2eenv".to_vec();
        raw.query = b"x=1".to_vec();
        let raw_ctx = Context::new(
            &raw,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/.env",
        );
        assert_eq!(var(&raw_ctx, "REQUEST_URI").unwrap().string(), "/.env");
        assert_eq!(function_arg(&raw_ctx, "REQUEST_URI").unwrap(), "/.env");
        assert_eq!(
            expand("%{REQUEST_URI}|%{QUERY_STRING}", &raw_ctx).unwrap(),
            "/.env|x=1"
        );

        assert_eq!(expand("plain text", &c).unwrap(), "plain text");
        assert_eq!(expand("%{toupper:%{REQUEST_METHOD}}", &c).unwrap(), "GET");
        assert_eq!(expand("%{unescape:a%20b}", &c).unwrap(), "a b");
        assert!(expand("%{unknown:%{REQUEST_METHOD}}", &c).is_err());
        assert!(expand("%{REQUEST_METHOD", &c).is_err());
        assert_eq!(percent_encode("a b/?~"), "a%20b%2f%3f~");
        assert_eq!(percent_decode("a%20b%2f%3F%zz"), "a b/?%zz");
        assert_eq!(hex(b'0'), Some(0));
        assert_eq!(hex(b'a'), Some(10));
        assert_eq!(hex(b'F'), Some(15));
        assert_eq!(hex(b'z'), None);
        assert_eq!(sha1_hex("abc").len(), 40);
        assert_eq!(md5_hex("abc").len(), 32);
        assert_eq!(base64_encode(b"abc"), "YWJj");
        assert_eq!(base64_decode("YWJj"), b"abc");
        assert_eq!(base64_decode("!!!"), Vec::<u8>::new());
        assert_eq!(compare_op(">="), Some(vapache_verified::ExprCompareOp::Ge));
        assert!(compare_op("bogus").is_none());
        assert!(!cmp(&Value::Int(1), "bogus", &Value::Int(1)));
    }

    #[test]
    fn eval_branch_coverage() {
        assert_eq!(eval_result("-1 < 0").unwrap().string(), "true");
        assert!(!eval_result("false && true").unwrap().truthy());
        assert!(!eval_result("false || false").unwrap().truthy());
        assert!(eval_result("'ABC' -strcmatch 'abc'").unwrap().truthy());
        assert!(eval_result("req('x-test') == ''").unwrap().truthy());
        assert!(eval_result("env('FOO') == ''").unwrap().truthy());
        let dir = std::env::temp_dir().join(format!("vp-expr-branches-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("inside.txt"), "inside").unwrap();
        let r = req();
        let mut file_ctx = Context::new(&r, &[], "127.0.0.1".parse().unwrap(), &dir, "/x");
        let size = parse("filesize('inside.txt')").unwrap();
        assert_eq!(size.eval(&mut file_ctx).unwrap().int(), Some(6));
        let forbidden = parse("filesize('/etc/passwd')").unwrap();
        assert!(forbidden.eval(&mut file_ctx).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(eval_result("unescape('a%20b')").unwrap().string(), "a b");
        assert_eq!(
            eval_result("sha1('abc')").unwrap().string(),
            sha1_hex("abc")
        );
        assert_eq!(eval_result("md5('abc')").unwrap().string(), md5_hex("abc"));
        assert_eq!(eval_result("base64('abc')").unwrap().string(), "YWJj");
        assert_eq!(eval_result("unbase64('YWJj')").unwrap().string(), "abc");
        assert!(eval_result("bogus()").is_err());
        assert!(eval_result("'a' =~ /(a)\\1/").is_err());

        let r = req();
        let mut c = Context::new(
            &r,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
        );
        let bad_test = Expr::FileTest("-x".into(), Box::new(Expr::Str("x".into())));
        assert!(!bad_test.eval(&mut c).unwrap().truthy());
    }

    #[test]
    fn parser_error_and_escape_branches() {
        for text in [
            "'unterminated",
            "%{unterminated",
            "'a' =~ /unterminated",
            "(true",
            "true trailing",
            "?",
            "unknown_token",
            "req('x'",
            "req('x' 'y')",
            "'a' -in { 'b'",
            "'a' -in 'b'",
            "{ 'a' 'b' }",
            "=",
            "-inx",
            "-foo",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
        assert!(parse("'a\\nb\\rc\\td\\xe'").is_ok());
        assert!(parse("%{nested{brace}}").is_ok());
        assert!(parse("'a' -in { 'b', 'c' }").is_ok());
        assert!(parse("'a' -in { }").is_ok());
        assert!(parse("{ }").is_ok());
        assert!(parse("{ 'a', }").is_ok());
        assert!(parse("{ 'a', 'b' }").is_ok());
        assert!(parse("(true)").is_ok());
        assert!(parse("!true").is_ok());
        assert!(parse("-in").is_ok());
        let mut direct = Parser::new("-n");
        assert!(matches!(direct.primary().unwrap(), Expr::Str(ref s) if s == "-n"));
        assert!(parse("-1").is_ok());
        assert!(parse("req()").is_ok());
        assert!(parse("req('x',)").is_ok());
        assert!(eval("-in == '-in'"));
    }

    #[test]
    fn parser_is_total_at_regex_operator_boundary() {
        // An expression ending right at =~ / !~ used to index past the end of
        // the input and panic; reachable from main-config <If> and from
        // attacker-writable .htaccess, it must be an error, not an abort.
        assert!(parse("x =~").is_err());
        assert!(parse("'a' !~").is_err());
        assert!(parse("%{REQUEST_URI} =~").is_err());
        assert!(parse("x =~  ").is_err());
        // The delimiter still works normally at every position.
        assert!(eval("'abc' =~ /bc/"));
        // The unsupported-dialect case must stay a (parse-shaped) error.
        assert!(eval_result("'a' =~ /(a)\\1/").is_err());
    }

    #[test]
    fn parser_recursion_is_capped_not_a_stack_overflow() {
        // Recursion depth is capped instead of overflowing the stack, so the
        // deepest inputs Err cleanly even on small (2 MiB) request threads.
        // Depth accounting: a `!` or `-` costs one primary/unary frame; a
        // paren level costs two (unary + primary).
        let deep_not = format!("{}true", "!".repeat(MAX_EXPR_DEPTH + 1));
        assert!(parse(&deep_not).is_err());
        // Inputs just under the cap still parse; semantics unchanged.
        let ok_not = format!("{}true", "!".repeat(MAX_EXPR_DEPTH - 2));
        assert_eq!(eval(&ok_not), true);
        // Paren boundary: MAX_EXPR_DEPTH/2 - 1 levels sit exactly at the cap.
        let ok_parens = format!(
            "{}true{}",
            "(".repeat(MAX_EXPR_DEPTH / 2 - 1),
            ")".repeat(MAX_EXPR_DEPTH / 2 - 1)
        );
        assert!(parse(&ok_parens).is_ok());
        let deep_parens = format!(
            "{}true{}",
            "(".repeat(MAX_EXPR_DEPTH / 2 + 1),
            ")".repeat(MAX_EXPR_DEPTH / 2 + 1)
        );
        assert!(parse(&deep_parens).is_err());
        // Mixed operator nesting is also bounded and erroring.
        let deep_neg = format!("{}1", "-".repeat(MAX_EXPR_DEPTH + 1));
        assert!(parse(&deep_neg).is_err());
    }
}
