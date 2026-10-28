# Adversarial findings and exploit harness

This folder is the retained adversarial record for vapache: the numbered
finding write-ups from every adversarial pass, plus the pass-11 exploit
harness and its per-case dossiers.  Keeping the exact exploit shapes here
prevents re-deriving them from scratch.

## Layout

| Path | Contents |
|---|---|
| `findings.md` | Pass 3 write-ups (F31–F36, F38) |
| `findings_p4.md` … `findings_p9.md` | Pass 4–9 write-ups |
| `findings_p10.md` | Pass 10 write-ups (F60–F69) |
| `findings_p11.md` | Pass 11 write-ups (F61–F66, F69, F70; F66 was the only fixed survivor) |
| `findings_p12.md` | Pass 12 write-ups (P12-A–P12-F): trailing-slash `ProxyPass` auth bypass/local RCE, dotless-basename CGI execution, ScriptAlias PATH_INFO gate bypass, HTTP/2 body-window stall, plus secondary findings |
| `findings_p13.md` | Pass 13 write-ups (P13-A–P13-C): F69 closure incomplete — FastCGI and CGI `PATH_INFO` still classify by the canonical symlink-target basename, and a canonical `<Files>`/`<FilesMatch>` `SetHandler` force overrides the lexical name; PHP RCE and `execve` of `<Location>`-denied CGIs through a symlink |
| `findings_p14.md` | Pass 14 write-ups (P14-A–P14-E): `<Files>`/`<FilesMatch>` phase order lets an ancestor `.htaccess` override a deeper config section (RCE/auth bypass), `[P]` authority guard misses `\1`/`%1` (SSRF), `Require expr` file tests fall back to `/` without `DocumentRoot`, duplicate field lines defeat header guards, and `[C]` chain breaks skip one rule instead of the chain |
| `findings_p15.md` | Pass 15 write-ups (P15-A/P15-B/P15-C): FastCGI `PATH_INFO` rebinds `SCRIPT_FILENAME` to the canonical symlink target (PHP-FPM's `security.limit_extensions` gate and `<Location>` guards bypassed, Apache 403 vs vapache PHP RCE); `RemoteIPTrustedProxy`/`RemoteIPInternalProxy` share one list with no private-address rule (private `X-Forwarded-For` rewrite spoofs `REMOTE_ADDR`, Apache 403 vs vapache 200); and expression regexes skip load-time dialect validation, so PCRE-only `<If>`/`Require (not) expr`/`RewriteCond expr` guards silently become inert (protected CGI executed, Apache 403 vs vapache 200) |
| `findings_p16.md` | Pass 16 write-ups (P16-A/P16-B/P16-C/P16-D): `.htaccess` `SetEnv`/`SetEnvIf` values reach FastCGI as PHP-FPM `PHP_VALUE`/`PHP_ADMIN_VALUE`, so an uploaded non-PHP file is executed through `auto_prepend_file` (Apache does not forward access-file env to `mod_proxy_fcgi`; main-config env remains a positive control); directive regexes use Rust `regex` Unicode class semantics, so `\b`/`\W`/`\D`/`\S` deny guards miss non-ASCII input (protected CGI executes) and a positive `SetEnvIf`/`Require env` `^\w+$` gate over-grants it (Apache 403 vs vapache 200); header guards drop invalid UTF-8 (`header_str`), so `SetEnvIf`, `RewriteCond` and `<If>` deny rules miss `\xFFsqlmap`; and `SetEnvIf` action/attribute semantics (valueless `1`, env chaining, `$1` captures) diverge, allowing chained/expression/backreference deny guards to be bypassed |
| `p11/exploit_p11.py` | Pass-11 differential exploit battery: 13 micro-apps run against Apache 2.4.69 and vapached, one per finding row |
| `p11/case01-F61-A` … `case13-F61-C` | Captured case dossiers (rendered `apache.conf` / `vp.conf`, fixture tree, server logs, `ap.strace`) |
| `p11/f70_accessfilename.py` | F70 probe (dead finding: Apache rejects the configuration) |
| `p12/exploit_p12.py` | Pass-12 differential battery (P12-A–C/E/F vs Apache 2.4.69 on sibling loopback ports; P12-D single-server h2 body check) |
| `p13/exploit_p13.py` | Pass-13 differential battery (P13-A FastCGI symlink classification, P13-B CGI `PATH_INFO` symlink classification) |
| `p14/exploit_p14.py` | Pass-14 differential battery (P14-A `<Files>` phase order, P14-B `[P]` SSRF, P14-C expr file-test root, P14-D duplicate headers, P14-E `[C]` chain) |
| `p16/exploit_p16.py` | Pass-16 differential battery (P16-A `.htaccess` env → FastCGI `PHP_VALUE`/`PHP_ADMIN_VALUE`, P16-B Rust Unicode vs Apache PCRE directive-regex guards plus `SetEnvIf`/`Require env` over-grant, P16-C invalid-UTF-8 header deny-guard bypass, P16-D `SetEnvIf` value/chaining/backreference deny bypass; 36 verdicts with A6/B1/B2/C1-C3/D1-D3 controls) |

## Running the pass-11 battery

```sh
cargo build --release -p vapached
python3 adversarial/p11/exploit_p11.py 1 2 3 4 5 6 7 8 9 10 11 12 13
```

Each case rebuilds its dossier in place and prints the Apache-versus-vapached
verdict.  The oracle is `/usr/sbin/apache2` (Debian Apache 2.4.69); the
harness binds loopback ports only and scopes its cleanup to its own config
paths.  Case index: 1 F61-A, 2 F61-A2, 3 F61-B, 4 F62, 5 F63, 6 F63b, 7 F64,
8 F65, 9 F66, 10 F69, 11 F64b, 12 F62b, 13 F61-C (control).

The dossiers were captured at HEAD `d219efb` (before the pass-11
remediation) and are regenerated in place on each run.  The harness starts
Apache with `-X` (single process) and gives Apache and vapached *separate*
`logs/{apache,vapache}.pid` / `error-{apache,vapache}.log` files: the
original single `logs/httpd.pid` was written by whichever server started
last, so a concurrently starting vapached could make Apache abort with
`httpd (pid ...) already running` and produce an `apache=-1` row.  With the
split pidfiles the full 13-case battery completes without a single retry;
the retry loop and `-1` sentinel are kept as a safety net for the shared
host.

The matching end-to-end regression replays live in
`tests/adversarial_regressions.py` (`F61ToF69Pass11Tests`); the closure status
of every finding is tracked in `docs/adversarial-closure.md`.

## Running the pass-12 battery

```sh
cargo build --release -p vapached
python3 adversarial/p12/exploit_p12.py          # all groups A-F
python3 adversarial/p12/exploit_p12.py A B C    # proxy, extension, ScriptAlias cases
python3 adversarial/p12/exploit_p12.py D --keep # h2 body-window check, keep dossiers
```

Pass-12 cases: **A** trailing-slash/catch-all `ProxyPass` prefix (local
serving, `<Proxy>` authorization bypass, local CGI execution), with the
no-slash control; **B** dotless/hidden basenames (`cgi`, `.cgi`, `..cgi`, `pl`,
`php`) executed by the handler table, including the `<Files "*.cgi">` bypass;
**C** ScriptAlias + `SetHandler default-handler` + PATH_INFO; **D** HTTP/2
request bodies above the 256 KiB stream window (Apache oracle not applicable);
**E** `AuthType` with no applicable `Require` (Apache 500 vs vapache 200);
**F** streamed proxy responses skipping the `Header` policy.
Fixtures are built under `/tmp/opencode/p12-harness` unless `--keep` is given.
Both batteries now use separate per-server pidfiles (`<case>/logs/{apache,vapache}.pid`)
and single-process Apache (`-X`), so neither can trip over the other's
startup.

## Running the pass-13 battery

```sh
cargo build --release -p vapached
python3 adversarial/p13/exploit_p13.py            # all cases
python3 adversarial/p13/exploit_p13.py A          # FastCGI symlink classification
python3 adversarial/p13/exploit_p13.py B          # CGI PATH_INFO symlink classification
python3 adversarial/p13/exploit_p13.py --keep     # keep dossiers
```

Pass-13 cases: **A1** `SetHandler "proxy:…|fcgi://…"` + `pub/link.txt -> secret/app.php`
(Apache source vs vapache PHP-FPM execution); **A2** the same with a
`<Location "/secret/">` Basic-auth guard on the script (anonymous vapache
execution); **B1** `AddHandler cgi-script` + the same symlink requested as
`/pub/link.txt/x` (Apache 404 vs vapache `execve`); **B2** the same with a
`<Location "/secret/">` deny guard; **C1** canonical `<FilesMatch "\.cgi$">
SetHandler cgi-script` + the same symlink requested directly (Apache source vs
vapache `execve`, no global `AddHandler`); **C2** the same with a
`<Location "/secret/">` deny guard.  The Apache oracle runs `-X` on sibling
loopback ports; group A needs `php-fpm8.4`/`php-fpm`, otherwise a private fake
FastCGI responder records the `SCRIPT_FILENAME` vapache sends.  Fixtures are
built under `/tmp/opencode/p13-harness` unless `--keep` is given.

## Running the pass-14 battery

```sh
cargo build --release -p vapached
python3 adversarial/p14/exploit_p14.py            # all cases (8/8 differential verdicts)
python3 adversarial/p14/exploit_p14.py A B        # selected groups
python3 adversarial/p14/exploit_p14.py --keep     # keep dossiers
```

Pass-14 cases: **A1** deeper config `<Files "run.cgi"> Require all denied` /
`<Files "upload.txt"> SetHandler default-handler` vs an ancestor `.htaccess`
grant/force (Apache 403 and static source vs vapache 200 CGI execution);
**A2** the same with a deeper `<Files>` Basic-auth guard (Apache 401,
anonymous vapache execution); **B** `RewriteRule ... "http://\1/" [P]` and
`"%1" [P]` authority/substitution backreferences that the load-time
`proxy_template_authority_safe` guard misses (Apache 400/Apache-compatible
expansions vs attacker-controlled vapache upstream = SSRF); **C**
`Require expr "file('etc/passwd') =~ /^root/"` in `.htaccess` with no
`DocumentRoot` directive (filesystem-root fallback, single-server check);
**D** duplicate `User-Agent` field lines skipping a `RewriteCond ... [F]`
guard (Apache 403 vs vapache 200); **E** a failing `[C]` gate that fails to
skip the whole chain (Apache 404 vs vapache 200 privileged `[PT]` rewrite).
The Apache oracle runs `-X` on sibling loopback ports with a separate pid file
for each server.  Fixtures are built under `/tmp/opencode/p14-harness` unless
`--keep` is given.

## Running the pass-15 battery

```sh
cargo build --release -p vapached
python3 adversarial/p15/exploit_p15.py                    # all groups A1-A4 + B1-B2 + C1 (37 verdicts)
python3 adversarial/p15/exploit_p15.py A1 A3              # FastCGI symlink groups
python3 adversarial/p15/exploit_p15.py B1 B2              # RemoteIP groups (no PHP-FPM needed)
python3 adversarial/p15/exploit_p15.py C1                 # expression dialect group
python3 adversarial/p15/exploit_p15.py --keep --show-fpm-log
```

Pass-15 case **P15-A** — the project's own benchmark FastCGI spelling
(`ProxyPassMatch ^/(.*\.php(/.*)?)$ "unix:…|fcgi://localhost<docroot>/"`) with
an in-root symlink whose lexical name is not `.php`
(`pub/link.txt -> ../secret/app.php`).  Apache forwards the lexical path to
PHP-FPM, whose `security.limit_extensions` gate refuses the `.txt` split
script (`403 Access denied.`); vapache resolves the symlink, sends the
canonical `.php` path as `SCRIPT_FILENAME`, and PHP-FPM executes it (`200
PHPEXEC … uid=33`).  **A2** adds a live `<Location "/secret/"> Require all
denied` guard (direct URL 403 on both, symlink route still executes on
vapache); **A3** points the symlink at an uploaded `.php` inside a
`<Location "/uploads/">`-denied tree and executes attacker content; **A4** is
the `<Directory>` control (guard binds on vapache, fail-closed).

Pass-15 case **P15-B** — `mod_remoteip` chain semantics.  **B1**
(`RemoteIPTrustedProxy 127.0.0.1` + `<Directory> Require ip 10.1.2.3`) shows
the same request granting on vapache and denying on Apache for
`X-Forwarded-For: 10.1.2.3` (and for private values after a public entry, as
IPv4-mapped, or before a trailing empty entry): Apache keeps the real peer
and refuses the private presented address, vapache rewrites `REMOTE_ADDR` to
the attacker-supplied value.  **B2** (`RemoteIPInternalProxy`) is the control
that flips both servers to `200`, isolating the missing internal/trusted
distinction plus Apache's private-address rejection.  A CGI oracle prints
`REMOTE_ADDR` on both sides.

Pass-15 case **P15-C** — expression-regex dialect (single group **C1**).
`<If "/…/ =~ /PATTERN/"> Require all denied </If>`, an `<Else>` inversion, a
`<RequireAll>` `Require not expr` deny-list and a `RewriteCond expr` `[F]`
guard are each wrapped around a `.txt` and an executable `.cgi`, with a
plain-pattern control.  Apache evaluates the PCRE patterns
(`\Qsecret\E`, `secret\.txt\Z`, `sec(?#match)ret`, `\Ksecret`,
`(se)cret\1`) and denies/executes accordingly; vapache's lazy regex compile
errors, the error is swallowed as `false`, and the guards disappear
(protected file read, protected CGI `EXEC`, rewrite deny skipped).  The
control denies on both.

`--show-fpm-log` prints PHP-FPM's access log with the Apache/vapache
`SCRIPT_FILENAME` lines paired.  Fixtures and a private PHP-FPM pool are built
under `/tmp/opencode/p15-harness` unless `--keep` is given.

## Running the pass-16 battery

```sh
cargo build --release -p vapached
python3 adversarial/p16/exploit_p16.py            # all groups A1-A6 + B1-B2 + C1-C3 + D1-D3 (36 verdicts)
python3 adversarial/p16/exploit_p16.py A1 A3      # selected FastCGI cases
python3 adversarial/p16/exploit_p16.py B          # directive-regex cases
python3 adversarial/p16/exploit_p16.py C          # invalid-UTF-8 header-guard cases
python3 adversarial/p16/exploit_p16.py D          # SetEnvIf value/chaining/backref cases
python3 adversarial/p16/exploit_p16.py --keep     # keep fixtures
```

Pass-16 case **P16-A** — environment provenance across FastCGI.  The
benchmark `ProxyPassMatch` shape with `AllowOverride All` (or `FileInfo`):
the attacker writes a `.htaccess` containing
`SetEnv PHP_VALUE "auto_prepend_file=<uploads>/avatar.txt"` (also
`PHP_ADMIN_VALUE` and `SetEnvIf` variants, and a nested-directory variant)
and uploads a non-PHP file containing PHP.  Apache returns 200 without
executing the file; vapache's FastCGI request carries the access-file
`PHP_VALUE`, PHP-FPM prepends `avatar.txt`, and the marker is written.  **A6**
controls: no `.htaccess`, a harmless `SetEnv APP_ENV`, `AllowOverride None`,
and a main-config `SetEnv PHP_VALUE` positive control that executes on both
servers.

Pass-16 case **P16-B** — directive-regex dialect.  A `RewriteCond
%{HTTP:X-User} \badmin\b` + `RewriteRule ^ - [F]` deny guard around a CGI is
tested with `éadmin`, `^\W+$`/`é`, `^\D+$`/`١٢٣` and `^\S+$`/U+00A0.
Apache's ASCII PCRE denies (`403`, no `EXEC-P16B`); vapache's Unicode-aware
Rust `regex` misses and executes the CGI (`200`, `EXEC-P16B`).  Controls:
ASCII `admin` denied by both, `xadminx` allowed by both, and the `<If>` PCRE
form denied by both.

Pass-16 case **P16-B (B2)** — the over-grant direction at the same compiler.
`SetEnvIf User-Agent ^\w+$ TRUSTED` plus `Require env TRUSTED` admits the CGI
for `User-Agent: é` on vapache (Unicode `\w`) but denies it on Apache (ASCII
`\w`).  Controls: `abc` admitted/executing on both, `abc def` denied on both.

Pass-16 case **P16-C** — invalid UTF-8 in a guarded header.  A `SetEnvIf
User-Agent sqlmap BLOCK` + `Require not env BLOCK`, a `RewriteCond
%{HTTP:X-User} sqlmap` + `[F]`, and an `<If "%{HTTP:X-User} =~ /sqlmap/">`
deny are each tested with a raw signature prefix (`User-Agent: \xFFsqlmap`
for C1, `X-User: \xFFsqlmap` for C2/C3).  Apache matches the raw bytes and
denies (`403`, no `EXEC-P16C`); vapache's `header_str` conversion turns the
whole value into the empty string, the deny misses, and the CGI executes
(`200`, `EXEC-P16C`).  Controls: ASCII `sqlmap` denied by all three guards on
both, benign `curl/8` allowed on both, `\xFF` alone allowed on both, and valid
UTF-8 `ÿsqlmap` denied on both.

Pass-16 case **P16-D** — `SetEnvIf` action/attribute semantics.  **D1**
`SetEnvIf ... BLOCK` (valueless) plus `Require not expr "%{env:BLOCK} ==
'1'"` denies on Apache (`BLOCK=1`) but allows/executes on vapache (`BLOCK=""`).
**D2** `SetEnvIf ... BAD` then `SetEnvIf BAD "1" DENY` plus `Require not env
DENY` denies on Apache but allows on vapache because the prior variable is not
testable.  **D3** `SetEnvIf User-Agent "^([a-z]+)$" ID=$1` plus an
`env:ID == 'sqlmap'` test denies on Apache but allows on vapache, which stores
the literal `$1`.  Controls: explicit `BLOCK=1`, a single `DENY=1` rule, a
non-matching `curl` capture, and benign requests keep the guards live.

Each FastCGI case starts and stops its own PHP-FPM under
`/tmp/opencode/p16-harness/case-*/fpm`, so per-request `PHP_VALUE` state
cannot leak between cases.  The Apache oracle runs `-X` on sibling loopback
ports with separate pid files; fixtures are removed unless `--keep` is given.

