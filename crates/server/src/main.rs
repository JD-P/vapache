//! `vapached` command line, daemon lifecycle and privilege handling.

use std::collections::HashMap;
use std::ffi::{CString, OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use vapached::config::{Config, EncodedSlashes};
use vapached::http::{BodyFraming, Headers, Request, Version};
use vapached::log::Logger;
use vapached::server::{self, Server};

static STOP: AtomicBool = AtomicBool::new(false);
static RELOAD: AtomicBool = AtomicBool::new(false);
static REOPEN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

extern "C" fn on_reload(_sig: libc::c_int) {
    RELOAD.store(true, Ordering::SeqCst);
}

extern "C" fn on_reopen(_sig: libc::c_int) {
    REOPEN.store(true, Ordering::SeqCst);
}

struct Args {
    server_root: PathBuf,
    config: Option<PathBuf>,
    defines: HashMap<String, String>,
    foreground: bool,
    test: bool,
    dump_modules: bool,
    dump_vhosts: bool,
    action: Option<String>,
    no_envvars: bool,
    strict: bool,
    show_version: bool,
    show_build: bool,
    show_modules_compiled: bool,
    explain: Option<String>,
    explain_method: Option<String>,
    explain_host: Option<String>,
    explain_port: Option<u16>,
    explain_headers: Vec<(String, String)>,
}

fn usage() -> ! {
    eprintln!(
        "Usage: vapached [-d serverroot] [-f config] [-D name] [-k start|stop|restart|graceful|status]\n\
         \x20                [-t] [-T] [-M] [-S] [-v] [-V] [-l] [-X] [--strict-config]\n\
         \x20                [--explain PATH [--explain-method M] [--explain-host H] [--explain-port P]\n\
         \x20                 [--explain-header 'Name: value']]"
    );
    std::process::exit(1)
}

fn parse_args() -> Args {
    let mut a = Args {
        server_root: std::env::var("VAPACHE_SERVER_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/etc/apache2")),
        config: None,
        defines: HashMap::new(),
        foreground: false,
        test: false,
        dump_modules: false,
        dump_vhosts: false,
        action: None,
        no_envvars: false,
        strict: false,
        show_version: false,
        show_build: false,
        show_modules_compiled: false,
        explain: None,
        explain_method: None,
        explain_host: None,
        explain_port: None,
        explain_headers: Vec::new(),
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "-d" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                a.server_root = PathBuf::from(&args[i]);
            }
            "-f" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                a.config = Some(PathBuf::from(&args[i]));
            }
            "-D" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                a.defines.insert(args[i].clone(), String::new());
                if args[i] == "FOREGROUND" {
                    a.foreground = true;
                }
            }
            "-k" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                a.action = Some(args[i].clone());
            }
            "-t" | "-T" => a.test = true,
            "-M" => a.dump_modules = true,
            "-S" => a.dump_vhosts = true,
            "-X" => a.foreground = true,
            "-v" => a.show_version = true,
            "-V" => a.show_build = true,
            "-l" => a.show_modules_compiled = true,
            "--strict-config" => a.strict = true,
            "--no-envvars" => a.no_envvars = true,
            "--explain" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                a.explain = Some(args[i].clone());
            }
            "--explain-method" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                a.explain_method = Some(args[i].clone());
            }
            "--explain-host" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                a.explain_host = Some(args[i].clone());
            }
            "--explain-port" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                a.explain_port = args[i].parse().ok();
            }
            "--explain-header" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                if let Some((name, value)) = args[i].split_once(':') {
                    a.explain_headers
                        .push((name.trim().to_string(), value.trim().to_string()));
                } else {
                    eprintln!("vapached: --explain-header requires 'Name: value'");
                    usage();
                }
            }
            other if other.starts_with("-D") && other.len() > 2 => {
                let name = other[2..].to_string();
                if name == "FOREGROUND" {
                    a.foreground = true;
                }
                a.defines.insert(name, String::new());
            }
            "-C" | "-c" => {
                // Accepted for apachectl compatibility; setting individual
                // directives on the command line is rarely used and will be
                // implemented with the config expression engine.
                i += 1;
                if i >= args.len() {
                    usage();
                }
                eprintln!("vapached: warning: {arg} is accepted but not applied");
            }
            "-e" | "-E" => {
                i += 1;
            }
            "-h" | "--help" => usage(),
            other => {
                eprintln!("vapached: unrecognized argument '{other}'");
                usage();
            }
        }
        i += 1;
    }
    a
}

fn expand_env(value: &str, vars: &HashMap<String, String>) -> String {
    let b = value.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'$' {
            if i + 1 < b.len() && b[i + 1] == b'{' {
                if let Some(end) = value[i + 2..].find('}') {
                    let name = &value[i + 2..i + 2 + end];
                    // Shell parameter-expansion operators are not evaluated;
                    // the default Debian envvars uses ${VAR##prefix} only in
                    // a diagnostic branch, so treating it as empty is safe.
                    let base = name.split("##").next().unwrap_or(name);
                    if let Some(v) = vars.get(base) {
                        out.push_str(v);
                    }
                    i += end + 3;
                    continue;
                }
            } else {
                let mut j = i + 1;
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                    j += 1;
                }
                if j > i + 1 {
                    let name = &value[i + 1..j];
                    if let Some(v) = vars.get(name) {
                        out.push_str(v);
                    }
                    i = j;
                    continue;
                }
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

fn load_envvars(path: &Path) -> HashMap<String, String> {
    let mut vars: HashMap<String, String> = std::env::vars().collect();
    let Ok(data) = std::fs::read_to_string(path) else {
        return vars;
    };
    for raw in data.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix("unset ") {
            vars.remove(name.trim());
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            continue;
        }
        let mut v = value.trim().to_string();
        if (v.starts_with('"') && v.ends_with('"') && v.len() >= 2)
            || (v.starts_with('\'') && v.ends_with('\'') && v.len() >= 2)
        {
            v = v[1..v.len() - 1].to_string();
        }
        let expanded = expand_env(&v, &vars);
        vars.insert(name.to_string(), expanded);
    }
    vars
}

fn user_ids(user: &str, group: &str) -> Result<(libc::uid_t, libc::gid_t, CString), String> {
    let cuser = CString::new(user).map_err(|_| "invalid User name".to_string())?;
    let cgroup = CString::new(group).map_err(|_| "invalid Group name".to_string())?;
    let uid = if let Ok(n) = user.parse::<u32>() {
        n
    } else {
        let pw = unsafe { libc::getpwnam(cuser.as_ptr()) };
        if pw.is_null() {
            return Err(format!("user '{user}' not found"));
        }
        unsafe { (*pw).pw_uid }
    };
    let gid = if let Ok(n) = group.parse::<u32>() {
        n
    } else {
        let gr = unsafe { libc::getgrnam(cgroup.as_ptr()) };
        if gr.is_null() {
            return Err(format!("group '{group}' not found"));
        }
        unsafe { (*gr).gr_gid }
    };
    Ok((uid, gid, cuser))
}

fn drop_privileges(user: &str, group: &str) -> Result<(), String> {
    let (uid, gid, cuser) = user_ids(user, group)?;
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        let cur = unsafe { libc::getuid() };
        if cur != uid {
            eprintln!(
                "vapached: warning: not running as root; cannot switch from uid {cur} to {uid}"
            );
        }
        return Ok(());
    }
    unsafe {
        if libc::initgroups(cuser.as_ptr(), gid as libc::gid_t) != 0 {
            return Err(format!(
                "initgroups failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if libc::setgid(gid) != 0 {
            return Err(format!(
                "setgid failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if libc::setuid(uid) != 0 {
            return Err(format!(
                "setuid failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

fn daemonize() -> Result<(), String> {
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return Err("fork failed".into());
        }
        if pid > 0 {
            std::process::exit(0);
        }
        if libc::setsid() < 0 {
            return Err("setsid failed".into());
        }
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        let pid2 = libc::fork();
        if pid2 < 0 {
            return Err("second fork failed".into());
        }
        if pid2 > 0 {
            std::process::exit(0);
        }
        let devnull = CString::new("/dev/null").unwrap();
        let fd = libc::open(devnull.as_ptr(), libc::O_RDWR);
        if fd >= 0 {
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
            if fd > 2 {
                libc::close(fd);
            }
        }
        let root = CString::new("/").unwrap();
        libc::chdir(root.as_ptr());
    }
    Ok(())
}

fn write_pid(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(path, format!("{}\n", std::process::id()))
        .map_err(|e| format!("cannot write PidFile {}: {e}", path.display()))
}

fn read_pid(path: &Path) -> Result<i32, String> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read PidFile {}: {e}", path.display()))?;
    s.trim()
        .parse()
        .map_err(|_| format!("invalid pid in {}", path.display()))
}

fn kill_action(path: &Path, sig: libc::c_int) -> Result<(), String> {
    let pid = read_pid(path)?;
    let rc = unsafe { libc::kill(pid, sig) };
    if rc != 0 {
        return Err(format!(
            "kill({pid}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn explain_config(cfg: &Config, args: &Args) -> Result<(), String> {
    let path = args.explain.as_deref().unwrap_or("/");
    let (raw_path, query) = match path.split_once('?') {
        Some((p, q)) => (p, q.as_bytes().to_vec()),
        None => (path, Vec::new()),
    };
    let method = args
        .explain_method
        .clone()
        .unwrap_or_else(|| "GET".to_string())
        .to_ascii_uppercase();
    let port = args
        .explain_port
        .or_else(|| cfg.listeners.first().map(|l| l.port))
        .unwrap_or(80);
    let host = args
        .explain_host
        .clone()
        .or_else(|| cfg.server_name.clone())
        .unwrap_or_else(|| "localhost".to_string());
    let vhost = cfg.select_vhost(None, port, Some(&host));

    let allow_encoded = cfg.encoded_slashes == EncodedSlashes::On;

    let mut headers = Headers::default();
    headers.insert("host", format!("{host}:{port}"));
    for (name, value) in &args.explain_headers {
        headers.insert(name, value.clone());
    }
    let req = Request {
        method: method.clone(),
        target: path.as_bytes().to_vec(),
        raw_path: raw_path.as_bytes().to_vec(),
        query,
        version: Version::Http11,
        headers,
        body: Vec::new(),
        body_spool: None,
        keep_alive: true,
        expect_continue: false,
        framing: BodyFraming::None,
    };
    let peer = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let target =
        vapached::request_plan::CanonicalTarget::from_raw_path(raw_path.as_bytes(), allow_encoded)
            .map_err(|e| format!("invalid request path '{raw_path}': {e:?}"))?;
    let plan = vapached::request_plan::RequestPlan::resolve(cfg, vhost, target)
        .map_err(|e| format!("mapping failed for '{path}': {e:?}"))?;
    let root = plan.root();
    let fs_path = plan.fs_path();
    let url_path = plan.url_path();
    let mut evaluated = plan.evaluate_scope(cfg, vhost, &req, peer);
    evaluated.apply_conditionals(cfg, vhost, fs_path, url_path, &req, peer);
    let scope = evaluated.scope;
    let override_enabled = cfg.override_enabled;
    let override_prefilter = cfg.override_applicable(fs_path);
    let access_files = cfg.access_file_names_for(&scope);

    println!("explain: {method} {path}");
    println!("  canonical_url_path: {url_path}");
    println!(
        "  vhost: {}",
        vhost
            .and_then(|v| v.server_name.as_deref())
            .unwrap_or("<global>")
    );
    println!("  document_root: {}", root.display());
    println!("  fs_path: {}", fs_path.display());
    println!("  access_layers:");
    for layer in plan.layers() {
        println!(
            "    dir={} url_mount={} subject={:?}",
            layer.identity.dir.display(),
            layer.identity.url_mount,
            layer.identity.subject(fs_path, url_path)
        );
    }
    println!("  override_policy: {:?}", scope.override_policy);
    println!("  override_enabled: {override_enabled}");
    println!("  override_prefilter: {override_prefilter}");
    println!("  access_file_names: {access_files:?}");
    println!("  matching_rules:");
    for rule in cfg.rule_inventory(vhost, &fs_path, &url_path, &req, peer) {
        println!("    {rule}");
    }
    println!("  access_file_trace:");
    for file in vapached::htaccess::trace_access_files_with_root(
        cfg,
        vhost,
        &fs_path,
        &url_path,
        Some(&root),
    ) {
        println!("    {file}");
    }
    println!("  options: {:?}", scope.effective_options());
    println!("  allow_methods: {:?}", scope.authorization.allow_methods);
    println!("  requires: {:?}", scope.authorization.requires);
    println!("  legacy: {:?}", scope.authorization.legacy);
    println!(
        "  auth: type={:?} name={:?} userfile={:?} groupfile={:?}",
        scope.authorization.auth_type,
        scope.authorization.auth_name,
        scope.authorization.auth_user_file,
        scope.authorization.auth_group_file
    );
    println!(
        "  rewrite_engine: {:?}, rules: {}",
        scope.rewrite_policy.rewrite_engine,
        scope.rewrite_policy.rewrite_rules.len()
    );
    println!("  cache_enable: {:?}", scope.rewrite_policy.cache_enable);
    println!("  cache_disable: {:?}", scope.rewrite_policy.cache_disable);
    if !override_prefilter {
        println!("  htaccess: skipped (no override-enabled directory in path)");
    } else if plan.layers().is_empty() {
        println!("  htaccess: no access files present");
    } else {
        println!("  htaccess: {} layer(s) applied", plan.layers().len());
    }
    Ok(())
}

fn main() {
    let raw_args: Vec<OsString> = std::env::args_os().collect();
    if raw_args.get(1).map(OsString::as_os_str) == Some(OsStr::new("--cgi-worker")) {
        let uid = raw_args
            .get(2)
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let gid = raw_args
            .get(3)
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let user = raw_args
            .get(4)
            .and_then(|s| s.to_str())
            .unwrap_or("www-data");
        vapached::cgi::worker_main(3, uid, gid, user);
        return;
    }
    let args = parse_args();
    if args.show_version {
        println!(
            "vapached/{} (Apache/2.4 configuration compatible)",
            vapached::VERSION
        );
        return;
    }
    if args.show_modules_compiled {
        println!("Compiled in modules:");
        for m in [
            "core",
            "http_core",
            "mod_alias",
            "mod_authz_core",
            "mod_authz_host",
            "mod_access_compat",
            "mod_dir",
            "mod_mime",
            "mod_autoindex",
            "mod_cgi",
            "mod_ssl",
            "mod_http2",
            "mod_rewrite",
            "mod_headers",
            "mod_auth_basic",
            "mod_authn_file",
            "mod_authz_user",
            "mod_authz_groupfile",
            "mod_filter",
            "mod_deflate",
            "mod_brotli",
            "mod_proxy",
            "mod_proxy_fcgi",
            "mod_proxy_http",
        ] {
            println!("  {m}");
        }
        return;
    }

    let server_root = if args.server_root.is_absolute() {
        args.server_root.clone()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(&args.server_root)
    };
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| server_root.join("apache2.conf"));

    let mut env = if args.no_envvars {
        std::env::vars().collect()
    } else {
        load_envvars(&server_root.join("envvars"))
    };
    env.entry("APACHE_CONFDIR".into())
        .or_insert_with(|| server_root.to_string_lossy().into_owned());
    env.entry("SERVER_ROOT".into())
        .or_insert_with(|| server_root.to_string_lossy().into_owned());

    let mut cfg = match Config::load(&config_path, &server_root, &env, &args.defines, args.strict) {
        Ok(c) => c,
        Err(errors) => {
            for e in errors {
                eprintln!("{e}");
            }
            eprintln!("vapached: configuration test failed");
            std::process::exit(1);
        }
    };
    for w in &cfg.warnings {
        eprintln!("vapached: {w}");
    }

    if args.show_build {
        println!("Server version: {}", cfg.server_header());
        println!("Server built: unknown");
        println!("ServerRoot: {}", cfg.server_root.display());
        println!("Config file: {}", config_path.display());
        println!("PidFile: {}", cfg.pid_file.display());
        println!(
            "Listen: {:?}",
            cfg.listeners.iter().map(|l| &l.raw).collect::<Vec<_>>()
        );
        return;
    }
    if args.dump_modules {
        for m in &cfg.modules {
            println!(" {m}");
        }
        return;
    }
    if args.dump_vhosts {
        println!("VirtualHost configuration:");
        for v in &cfg.vhosts {
            println!(
                "  {}:{:?} name={:?} docroot={:?}",
                v.addrs.join(" "),
                v.aliases,
                v.server_name,
                v.scope.content_policy.document_root
            );
        }
        return;
    }

    if let Some(_) = &args.explain {
        if let Err(e) = explain_config(&cfg, &args) {
            eprintln!("vapached: explain: {e}");
            std::process::exit(1);
        }
        return;
    }

    match args.action.as_deref() {
        Some("stop") => {
            if let Err(e) = kill_action(&cfg.pid_file, libc::SIGTERM) {
                eprintln!("vapached: {e}");
                std::process::exit(1);
            }
            return;
        }
        Some("graceful") => {
            if let Err(e) = kill_action(&cfg.pid_file, libc::SIGHUP) {
                eprintln!("vapached: {e}");
                std::process::exit(1);
            }
            return;
        }
        Some("graceful-stop") => {
            if let Err(e) = kill_action(&cfg.pid_file, libc::SIGTERM) {
                eprintln!("vapached: {e}");
                std::process::exit(1);
            }
            return;
        }
        Some("status") => match read_pid(&cfg.pid_file) {
            Ok(pid) if unsafe { libc::kill(pid, 0) } == 0 => {
                println!("vapached is running (pid {pid})");
                return;
            }
            _ => {
                eprintln!("vapached is not running");
                std::process::exit(3);
            }
        },
        Some("start") | Some("restart") | None => {}
        Some(other) => {
            eprintln!("vapached: unsupported -k action '{other}'");
            std::process::exit(1);
        }
    }

    if args.test {
        // Apache's configtest also validates SSL certificate/key material.
        // Do this before printing Syntax OK so missing or unreadable TLS
        // files fail closed rather than at first HTTPS connection attempt.
        for listener in &cfg.listeners {
            let local_ip = listener
                .addr
                .parse::<std::net::IpAddr>()
                .ok()
                .filter(|ip| !ip.is_unspecified())
                .map(vapached::access::canonical_ip);
            if let Err(e) = vapached::tls::server_config(&cfg, listener.port, local_ip) {
                eprintln!("vapached: SSL configuration error: {e}");
                eprintln!("vapached: configuration test failed");
                std::process::exit(1);
            }
        }
        println!("Syntax OK");
        return;
    }

    let mut bound = match server::bind(&cfg) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("vapached: cannot bind listener: {e}");
            std::process::exit(1);
        }
    };
    let mut logger = match Logger::new(&cfg) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            eprintln!("vapached: cannot open logs: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = write_pid(&cfg.pid_file) {
        eprintln!("vapached: {e}");
        std::process::exit(1);
    }
    if !args.foreground {
        if let Err(e) = daemonize() {
            eprintln!("vapached: {e}");
            std::process::exit(1);
        }
        // PID changes after fork; rewrite the pid file.
        let _ = write_pid(&cfg.pid_file);
    }
    if cfg.has_cgi() {
        if let Err(e) = vapached::cgi::init_pool(&cfg) {
            eprintln!("vapached: warning: CGI worker pool unavailable: {e}; using direct CGI");
        }
    }
    logger.prepare_permissions(&cfg);
    if let Err(e) = drop_privileges(&cfg.user, &cfg.group) {
        eprintln!("vapached: {e}");
        let _ = std::fs::remove_file(&cfg.pid_file);
        std::process::exit(1);
    }
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as libc::sighandler_t);
        libc::signal(libc::SIGHUP, on_reload as libc::sighandler_t);
        libc::signal(libc::SIGUSR1, on_reopen as libc::sighandler_t);
    }
    logger.info(&format!(
        "vapached/{} started, listening on {} socket(s)",
        vapached::VERSION,
        bound.len()
    ));

    loop {
        let srv = Server::new(Arc::new(cfg.clone()), logger.clone());
        let stop = srv.stop_flag();
        let monitor_logger = logger.clone();
        std::thread::spawn(move || loop {
            if STOP.load(Ordering::SeqCst) || RELOAD.load(Ordering::SeqCst) {
                stop.store(true, Ordering::SeqCst);
                break;
            }
            if REOPEN.swap(false, Ordering::SeqCst) {
                let _ = monitor_logger.reopen();
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        });
        if let Err(e) = srv.run(&bound) {
            logger.error(&format!("server loop failed: {e}"));
        }
        if STOP.load(Ordering::SeqCst) && !RELOAD.load(Ordering::SeqCst) {
            let deadline = std::time::Instant::now() + cfg.graceful_shutdown_timeout;
            while server::active_connections() > 0 && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            break;
        }
        if !RELOAD.swap(false, Ordering::SeqCst) {
            break;
        }
        logger.info("SIGHUP received; reloading configuration");
        let new_cfg =
            match Config::load(&config_path, &server_root, &env, &args.defines, args.strict) {
                Ok(c) => c,
                Err(errors) => {
                    for e in errors {
                        logger.error(&format!("reload rejected: {e}"));
                    }
                    logger.error("reload rejected; continuing with previous configuration");
                    continue;
                }
            };
        let new_bound = match server::rebind(&new_cfg, &bound) {
            Ok(b) => b,
            Err(e) => {
                logger.error(&format!("reload listener error: {e}"));
                continue;
            }
        };
        let new_logger = match Logger::new(&new_cfg) {
            Ok(l) => {
                let l = Arc::new(l);
                l.prepare_permissions(&new_cfg);
                l
            }
            Err(e) => {
                logger.error(&format!("reload logger error: {e}; reusing existing logs"));
                logger.clone()
            }
        };
        cfg = new_cfg;
        bound = new_bound;
        logger = new_logger;
        vapached::cache::clear(&cfg);
        logger.info("configuration reloaded; cache generation invalidated");
    }
    vapached::cgi::shutdown_pool();
    let _ = std::fs::remove_file(read_pid_path());
    let _ = std::io::stderr().flush();
}

fn read_pid_path() -> PathBuf {
    // The pid file has already been unlinked by the time this is called if
    // configuration failed; use the environment as a best effort.
    PathBuf::from(
        std::env::var("APACHE_PID_FILE").unwrap_or_else(|_| "/var/run/apache2/apache2.pid".into()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vapache-main-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir.join(name)
    }

    #[test]
    fn env_expansion() {
        let mut vars = HashMap::new();
        vars.insert("FOO".to_string(), "bar".to_string());
        vars.insert("EMPTY".to_string(), String::new());
        assert_eq!(expand_env("$FOO", &vars), "bar");
        assert_eq!(expand_env("x/${FOO}/y", &vars), "x/bar/y");
        assert_eq!(expand_env("${FOO##prefix}", &vars), "bar");
        assert_eq!(expand_env("$EMPTY!$MISSING", &vars), "!");
        assert_eq!(expand_env("cost $5 and $", &vars), "cost  and $");
        assert_eq!(expand_env("${UNCLOSED", &vars), "${UNCLOSED");
    }

    #[test]
    fn envvars_file() {
        let path = temp("envvars");
        std::fs::write(
            &path,
            "# comment\nexport A=one\nB=\"two words\"\nC='$A-${B}'\ninvalid-name=x\nunset PATH\nEMPTY=\n",
        )
        .unwrap();
        let vars = load_envvars(&path);
        assert_eq!(vars.get("A").map(String::as_str), Some("one"));
        assert_eq!(vars.get("B").map(String::as_str), Some("two words"));
        assert_eq!(vars.get("C").map(String::as_str), Some("one-two words"));
        assert!(!vars.contains_key("PATH"));
        assert_eq!(vars.get("EMPTY").map(String::as_str), Some(""));
        assert!(!vars.contains_key("invalid-name"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn pid_file_roundtrip() {
        let path = temp("pid");
        write_pid(&path).unwrap();
        assert_eq!(read_pid(&path).unwrap(), std::process::id() as i32);
        // signal 0 only checks for existence/permission
        kill_action(&path, 0).unwrap();
        std::fs::write(&path, "not-a-pid\n").unwrap();
        assert!(read_pid(&path).is_err());
        assert!(kill_action(&temp("missing-pid"), 0).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn user_lookup() {
        assert!(user_ids("0", "0").is_ok());
        assert!(user_ids("definitely-not-a-user", "definitely-not-a-group").is_err());
        assert!(user_ids("bad\0name", "0").is_err());
    }
}
