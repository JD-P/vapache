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
| `p11/exploit_p11.py` | Pass-11 differential exploit battery: 13 micro-apps run against Apache 2.4.69 and vapached, one per finding row |
| `p11/case01-F61-A` … `case13-F61-C` | Captured case dossiers (rendered `apache.conf` / `vp.conf`, fixture tree, server logs, `ap.strace`) |
| `p11/f70_accessfilename.py` | F70 probe (dead finding: Apache rejects the configuration) |
| `p12/exploit_p12.py` | Pass-12 differential battery (P12-A–C/E/F vs Apache 2.4.69 on sibling loopback ports; P12-D single-server h2 body check) |
| `p13/exploit_p13.py` | Pass-13 differential battery (P13-A FastCGI symlink classification, P13-B CGI `PATH_INFO` symlink classification) |
| `p14/exploit_p14.py` | Pass-14 differential battery (P14-A `<Files>` phase order, P14-B `[P]` SSRF, P14-C expr file-test root, P14-D duplicate headers, P14-E `[C]` chain) |

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
