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
    pub captures: Vec<String>,
}

impl<'a> Context<'a> {
    pub fn new(
        req: &'a Request,
        env: &'a [(String, String)],
        peer: IpAddr,
        docroot: &'a Path,
    ) -> Self {
        Self {
            req,
            env,
            peer,
            docroot,
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
        "query_string" => String::from_utf8_lossy(&ctx.req.query).into_owned(),
        "request_uri" => String::from_utf8_lossy(&ctx.req.target).into_owned(),
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
            if let Some(rest) = other.strip_prefix("http_") {
                ctx.req.header_str(rest).unwrap_or("").to_string()
            } else if other.starts_with("http") {
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
    if path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return None;
    }
    let joined = ctx.docroot.join(path);
    if !must_exist {
        return Some(joined);
    }
    let root = std::fs::canonicalize(ctx.docroot).ok()?;
    let target = std::fs::canonicalize(&joined).ok()?;
    if target.starts_with(&root) {
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
            Expr::FileTest(op, e) => {
                let raw = e.eval(ctx)?.string();
                let p = PathBuf::from(&raw);
                let p = if p.is_absolute() {
                    p
                } else {
                    ctx.docroot.join(p)
                };
                let meta = std::fs::symlink_metadata(&p);
                Value::Bool(match op.as_str() {
                    "-f" => meta.map(|m| m.is_file()).unwrap_or(false),
                    "-d" => meta.map(|m| m.is_dir()).unwrap_or(false),
                    "-e" | "-F" => meta.is_ok(),
                    "-s" => meta.map(|m| m.len() > 0).unwrap_or(false),
                    "-U" => {
                        let raw = e.eval(ctx)?.string();
                        let p = raw.trim_start_matches('/').to_string();
                        std::fs::symlink_metadata(ctx.docroot.join(p)).is_ok()
                    }
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

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
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
        let delim = self.input.as_bytes()[self.pos];
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
                if self.take(b'}') {
                    break;
                }
                return Err("expected ',' or '}' in list".into());
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
        if c == b'!' {
            self.pos += 1;
            return self.primary().map(|e| Expr::Not(Box::new(e)));
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
        let mut c = Context::new(&r, &[], "127.0.0.1".parse().unwrap(), docroot);
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
        let mut c = Context::new(&r, &[], "127.0.0.1".parse().unwrap(), docroot);
        assert!(e.eval(&mut c).unwrap().truthy());
    }

    #[test]
    fn expression_file_access_is_confined_to_docroot() {
        let dir = std::env::temp_dir().join(format!("vp-expr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("inside.txt"), "inside").unwrap();
        let r = req();
        let mut c = Context::new(&r, &[], "127.0.0.1".parse().unwrap(), &dir);
        let inside = parse("file('inside.txt') = 'inside'").unwrap();
        assert!(inside.eval(&mut c).unwrap().truthy());
        let outside = parse("file('/etc/passwd') = ''").unwrap();
        assert!(outside.eval(&mut c).is_err());
        let traversal = parse("-f '../etc/passwd'").unwrap();
        assert!(!traversal.eval(&mut c).unwrap().truthy());
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
}
