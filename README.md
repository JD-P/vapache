# vapache

A memory-safe, formally verified, drop-in-compatible Apache HTTP Server
replacement written in Rust.

`vapached` reads ordinary Apache 2.4 configuration files, serves static files,
runs CGI programs, and keeps the security-critical parsing kernels in
[Verus](https://github.com/verus-lang/verus) so they can be machine-checked.
The project targets Apache-level compatibility while hardening the historical
CVE hotspots: request smuggling, path traversal, response splitting, range
amplification, CGI environment injection and descriptor leaks.

## Status

Implemented today:

- Apache 2.4 config grammar, `<IfModule>`/`<IfDefine>`, `Include`,
  `${VAR}` expansion, scopes, name-based virtual hosts and stock Debian
  `/etc/apache2/apache2.conf` parsing.
- Static files, `DocumentRoot`, `Alias`, `ScriptAlias`, `Redirect`,
  `DirectoryIndex`, autoindex, `AddType`/`RemoveType`/`ForceType`,
  `AddDefaultCharset`, MIME types and custom error documents.
- Byte ranges, `If-Range`, `If-Match`, `If-None-Match`,
  `If-Modified-Since`, `If-Unmodified-Since`, ETags and `Last-Modified`.
- Access control (`Require all`, `ip`, `host`, `method`, `local`, legacy
  `Order`/`Allow`/`Deny`, `<Limit>`/`<LimitExcept>` method-scoped rules,
  `AuthMerging Off`/`And`/`Or`, `AllowMethods`, and legacy `Satisfy All`/`Any`
  combining host access with authentication) with fail-closed handling of
  unsupported providers. Nested `<Limit>` sections intersect their method
  sets, and `GET` limits also cover `HEAD`. Directory indexes and local
  `ErrorDocument` files are authorized and dispatched as internal subrequests,
  so they run normal CGI/FastCGI/static handlers and cannot bypass `Require`,
  `AllowMethods` or request-conditional rules.
- Per-directory `.htaccess` overrides with category-specific `AllowOverride`
  (`All`/`None`, `AuthConfig`, `FileInfo`, `Indexes`, `Limit`, `Options`, and
  Apache 2.4 `Options=ExecCGI,Includes,...` forms) for access/auth rules,
  `Options`, `DirectoryIndex`, `ErrorDocument`, MIME/handlers, `Header`,
  `Redirect`, and rewrite rules. Unknown directives, disallowed categories and
  unsupported sections return `500` rather than silently ignoring a possible
  access rule; unknown-only `AllowOverride` values are rejected at startup.
- A fail-closed `mod_rewrite` implementation in server/vhost/`<Directory>`
  and `.htaccess` contexts: `RewriteEngine`, `RewriteBase`,
  `RewriteOptions Inherit`, `RewriteCond` (regex, `=`, `!=`, `<`, `>`,
  `-f`, `-d`, `-s`, `-l`, `NC`, `OR`, and `expr`), `RewriteMap`
  (`txt`, `rnd`, `prg`, `int`), and `RewriteRule` with the common flag set
  (`L`, `END`, `R`, `P`, `F`, `G`, `C`, `S`, `N`, `QSA`, `QSD`, `QSL`,
  `B`, `BCTLS`, `BNE`, `BNP`, `CO`, `E`, `H`, `T`, `NE`, `PT`,
  `UnsafeAllow3F`, `UnsafePrefixStat`), including backreferences, common
  `%{...}` variables and loop protection. `dbm` maps and exact `DPI`
  path-info handling remain unsupported; malformed patterns are rejected
  rather than approximated.
- HTTP Basic authentication (`AuthType Basic`, `AuthName`, `AuthUserFile`,
  `AuthGroupFile`, `Require valid-user`, `Require user` and `Require group`)
  with Apache-compatible `$apr1$`, `$1$`, bcrypt, `{SHA}` and `{SSHA}`
  htpasswd hashes. Plaintext and unknown hash formats fail closed.
- TLS 1.2/1.3 via Rustls with `SSLEngine`, certificate chains, SNI virtual-host
  certificate selection, ALPN and `-t` certificate validation on startup.
- HTTP/2 over TLS (ALPN `h2`) with bounded header/stream limits, Apache
  request/body limits, content-length validation, CGI POST, ranges and HEAD.
  Cleartext h2c is not implemented.
- CGI/1.1 executed directly (never through a shell) with a minimal
  environment, `PR_SET_NO_NEW_PRIVS`, rlimits, a new session, a watchdog and
  bounded output.
- gzip and Brotli response compression with `AddOutputFilterByType`,
  `SetOutputFilter`, `AddOutputFilter`, compression levels, `Vary`,
  encoding-aware ETags, range bypass and `.htaccess` filter support.
- Native FastCGI for PHP-FPM and compatible responders via `ProxyPassMatch`
  and `SetHandler "proxy:fcgi://..."`, over Unix or TCP sockets.
- HTTP/1.1 reverse proxying with `ProxyPass`/`ProxyPassReverse`, including
  prefix and regex routes, `<Proxy>`/`<ProxyMatch>` authorization, request/
  response header forwarding, chunked
  upstream bodies and `Location` rewriting, HTTPS upstreams with system or
  `SSLProxyCACertificateFile` roots, `balancer://` round-robin backends with
  active `hcmethod`/`hcuri` health checks, sticky sessions, `failonstatus`
  retries, same-request member failover and reusable upstream connections,
  and WebSocket tunneling over
  TCP/TLS (WSS on either side).
- TLS client-certificate authentication (`SSLVerifyClient`,
  `SSLCACertificateFile`), and OCSP stapling with AIA or
  `SSLStaplingForceURL` responders, startup warm-start persistence and
  periodic refresh, plus required or optional client certificates.
- `mod_remoteip` client-address rewriting for trusted proxy headers.
- `mod_expires` (`ExpiresActive`, `ExpiresDefault`, `ExpiresByType`),
  `SetEnv`/`SetEnvIf`/`PassEnv`/`UnsetEnv`, `Require env`, and a basic
  `/server-status` endpoint.
- `mod_rewrite` covers conditions with regex/comparisons/file tests and
  `RewriteCond expr`, `RewriteOptions Inherit`, `RewriteBase`, server and
  per-directory rules, `RewriteMap` (`txt`, `rnd`, `prg` and `int`), query
  string controls (`QSA`, `QSD`, `QSL`, `UnsafeAllow3F`), escaping (`B`,
  `BCTLS`, `BNE`, `BNP`, `NE`), chaining/skips/restarts (`C`, `S`, `N`,
  `END`), `E`/`CO`/`H`/`T` response effects, `Vary` for header conditions,
  proxy rewrites (`P`), and `UnsafePrefixStat`.
- `mod_cache`/`mod_cache_disk` subset: `CacheEnable`/`CacheDisable` in
  server/vhost/directory scopes, `CacheRoot`, expiration and size limits,
  `CacheIgnoreCacheControl`, `CacheIgnoreNoLastMod`, `CacheStorePrivate`,
  `CacheStoreNoStore`, `CacheIgnoreQueryString`, `CacheHeader`, `Age`,
  conditional hits, disk warm-start metadata and invalidation on unsafe
  methods.
- Apache expression evaluation for `Require expr`, `<If>`, `<ElseIf>`,
  `<Else>` and `<IfFile>`: comparisons, boolean logic, string concatenation,
  regex captures, request headers/environment variables, file tests,
  IP/glob matching and the common string/hash/base64 functions.
- Keep-alive, pipelining, strict HTTP/1.1 parsing, request-smuggling and
  obs-fold rejection, `Content-Length`/`Transfer-Encoding` conflict rejection.
  Request-line and header parsing plus body framing are Verus-verified.
  `RequestReadTimeout` header/body deadlines and header `MinRate`, configurable
  `MaxRequestWorkers`/`ListenBacklog`, graceful `SIGHUP` reload with listener
  reuse, `SIGUSR1` log reopen, `-k graceful`/`graceful-stop` with connection
  draining, reload cache isolation, and request-body spooling above 1 MB.
- Bounded-memory proxy and FastCGI traffic: large fixed-length upstream
  bodies stream through `Body::Stream`, large FastCGI stdout is spooled to a
  temporary file, and large request bodies are spooled to an unlinked file
  before being forwarded to proxy/FastCGI backends.
- Unsupported security-sensitive directives (`SSLRequire*`,
  `SecRuleEngine On`) fail closed even in
  compatibility mode rather than silently weakening access or TLS policy.
  Unsupported handlers (`mod_php`, `mod_perl`, `mod_wsgi`, ...) and output
  filters (SSI, unknown filters) return `500` instead of serving source.
- Access/error logging with Apache `LogFormat`, daemonization, pid files,
  privilege dropping, graceful reload/shutdown and log reopening.
- Defence in depth: URI percent-decoding, path canonicalization, and the
  HTTP/1.1 request-head parser/framer are Verus-verified; the server still
  cross-checks the canonical-path invariant at runtime, and all file opens go
  through `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)`, optionally
  `RESOLVE_NO_SYMLINKS`.

Not yet implemented: OCSP responder error-cache timeout tuning, rare
expression forms such as `LogMessage` interpolation, `RewriteMap dbm`, exact
`[DPI]` path-info discarding in per-directory contexts, some `[NE]`/`[PT]`
corner cases, `mod_cache_socache`/`mod_file_cache`, Digest/LDAP
authentication, h2c, and the long tail of Apache modules.
Unimplemented non-security directives are reported as warnings in
compatibility mode and as errors under `--strict-config`.  Security-sensitive
unimplemented directives (for example `ProxyBlock`, `RequestHeader`,
`SetEnvIfExpr`, `AcceptPathInfo`, non-file `AuthBasicProvider` values and
filter-provider directives) fail closed even in compatibility mode, and
unimplemented `.htaccess` directives fail closed with a `500`.

## Build

```sh
export PATH="$HOME/.cargo/bin:$HOME/verus-bin:$PATH"
cargo build --release -p vapached
```

The binary is `target/release/vapached`.

## Verify

The security kernels live in `crates/verified` and are checked with Verus:

```sh
cargo verus verify -p vapache-verified
```

Current result: **194 verified functions, 0 errors** (percent-decoding,
URI path canonicalization, request-head parsing and body framing, header-value
sanitization, token validation, byte-range arithmetic, the mmap/CGI
protocol bounds, HTTP/2 method/head/body admission, the stream/reset budget
model, the stream-ID admission/lifecycle model and the idempotent early-reset purge model, and the TLS listener client-certificate policy identity, the container/list merge append model, the rewrite target classification/internal-join/same-host authority model, the expression truthiness/condition-chain model, the regex dialect admission guard, directive disposition, access-layer slot translation, config front-end line-kind IR and section-context transitions, rewrite backreference
encoding and filesystem-target admission, and the configuration
access-plan, authorization-merge, Options-merge and `.htaccess`
rule-classification kernels used by the dispatcher).

Function count is not the progress metric. The verification ledger tracks
security obligations and proof debt:

```sh
python3 tests/verification_status.py
python3 tests/verification_status.py --run-verus   # include the Verus gate
```

Current ledger: **43.8% weighted obligations**, **6/6 proof debt**,
**8/8 grant-required sinks**, **3/8 inode-bound sinks**, **3/8
backend-target-bound sinks**, **2/8 policy-key-bound sinks**, **0 partially
bound sinks**, **0 unexplained replay failures**, and **194 Verus functions
with 0 errors**.

The ledger lives in `docs/verification-status.json`. It records:

- weighted progress on the eight proof obligations,
- named unverified security components,
- sinks that need stronger resource binding,
- explicit assumptions and unmodeled directive classes,
- the adversarial replay-failure budget.

The gate fails if proof debt exceeds its explicit budget, the weighted
obligation score falls below its floor, the inode-bound sink count regresses,
an `assume`/`external_body` proof escape appears, or a body/tunnel sink stops
requiring a grant. Raising a budget is a deliberate, reviewable change.

## Test

```sh
cargo test --workspace          # Rust unit tests
python3 tests/conformance.py    # 165 Apache differential/conformance tests
```

The conformance suite starts a real Apache `httpd` and `vapached` with
equivalent configurations, so it exercises both servers end to end. It covers
HTTP/1.1, HTTPS, HTTP/2, CGI, conditional requests, ranges, access control and
Basic auth. Use `--differential` to write `tests/differential_report.md`, which
compares status codes, selected headers and bodies.

Security-sensitive configuration semantics are checked separately:

```sh
python3 tests/config_semantics.py  # 194 generated differential cases
python3 tests/config_semantics.py --random 300 --seed 7  # deterministic randomized matrix
python3 tests/config_validity.py  # context acceptance matrix (Apache -t vs vapached -t)
python3 tests/config_grammar.py   # finite valid/invalid grammar matrix
```

`config_grammar.py` enumerates the supported directive/context grammar and
checks that Apache and vapached agree on acceptance and rejection.  It is the
finite executable counterpart of the “accept valid / reject invalid” proof
obligations.

`config_semantics.py` generates isolated combinations of `AllowOverride`
categories, `<Limit>`/`<LimitExcept>`, `Require` trees, `AuthMerging`,
`Satisfy`/legacy access, `<If>` chains, `Files`/`Directory` wildcards and
Directory/Files/Location ordering, then compares both servers. It caught
several fail-open ordering bugs during development, including conditional
sections being applied before a later grant, `<Location "/x/">` matching the
file `/x`, and access-file merges being ordered after `<Files>`.

### Apache CVE triage

The complete NVD CPE `apache:http_server` set is triaged in
`docs/cve/apache2-cve-matrix.json`:

- **371 CVEs** assessed,
- **370** prevented in principle by construction, verified primitives or
  fail-closed rejection,
- **0** partially covered,
- **1** not covered by the formal specification.

The sole not-covered row is the external Rustls certificate parser
(`CVE-2004-0488`), which is an explicit trusted-dependency boundary.
The full matrix is `docs/cve/apache2-cve-matrix.json` (and `.csv`); the
summary and methodology are in `docs/cve/apache2-cve-matrix.md` and
`docs/cve/README.md`. The grouped strengthening plan for the 1 not-covered
row is in `docs/cve/not-covered-strengthening.md`. Regenerate or validate
with:

```sh
python3 tests/cve_matrix.py
python3 tests/cve_matrix.py --check
```

This is a static triage, not a claim that every CVE has a working PoC replay.

For a specific request, the compiled policy can be inspected without starting
the server:

```sh
./target/release/vapached -f /etc/apache2/apache2.conf --explain /private/file \
  --explain-method GET --explain-header 'X-Test: yes'
```

The output shows the selected vhost/docroot, `AllowOverride`, the override
walk gate, matching top-level rules, effective `Options`, `Require`/legacy
policy, auth settings, rewrite/cache state, and whether an access file was
read or skipped.  The reference model and proof obligations for formal
verification are in `docs/config-semantics.md`.

Combined unit and end-to-end line coverage is measured against instrumented binaries:

```sh
tests/coverage.sh
```

Latest snapshot (`coverage/SUMMARY.md`, taken before the most recent
semantics tests): **81.9% lines**, **79.6% of functions** across the
then-current Rust and conformance suites. The current suite is 205 Rust
library tests, 4 CLI tests, 165 conformance tests and the generated
configuration matrices. Authentication is at 91.7% line coverage, TLS/HTTP/2 at
86.1%/79.7%, `.htaccess` at 84.9%, access logging at 85.1%, the verified
security kernels at 90.7%, compression at 89.3%, FastCGI at 84.3%, the HTTP
proxy at 90.3%, rewrite execution at 84.7%, cache at 82.0%, OCSP at 79.8%,
the expression engine at 74.6%, and the request-parsing and file-serving
modules at 71.8%/83.7%. CLI lifecycle, HTTP/2 error branches, OCSP
error-cache policies, rare expression forms, `dbm`/`DPI` edge cases and
exotic balancer policies remain the next coverage targets.

Known, deliberate divergences from Apache (reported by the differential run):

| Area | Apache | vapache | Why |
|---|---|---|---|
| `POST` to a static file | `200` + file body | `405` with `Allow` | Safer; matches common server policy |
| `OPTIONS *` | omits `Allow` | sends `Allow` | RFC 9110 requires advertising methods |
| Unsatisfiable range | omits `Content-Range` | `Content-Range: bytes */N` | RFC 9110 requires it |
| `TraceEnable Off` response | empty `Allow` | populated `Allow` | RFC 9110 requires `Allow` on 405 |
| Proxy auth on `RewriteRule [P]` | not enforced on the rewrite-proxy path | enforced | Prevents bypassing `<Proxy>` authorization via `[P]` |
| Unsupported handler/filter | may serve source if the module is absent | `500` | Fail closed instead of exposing source |
| Unimplemented security directive | may enforce a policy we do not implement | refuses to start | Fail closed instead of silently ignoring an access/auth/proxy/filter control |

Run the benchmark against real Apache (ports 8080/8081):

```sh
python3 bench/bench.py --quick   # 1s samples
python3 bench/bench.py           # 3s samples
```

`wrk` is used when available (HTTP/1.1, reliable keep-alive under load) with
`ab` as a fallback. Both servers use identical configurations and access logs
are written to `/dev/null` so the harness does not fill `/tmp`. Results are
appended to `bench/RESULTS.md`. Latest full run (2026-10-24, 3s samples, median of three,
100 connections for small files and 20 for the 1 MB case):

| scenario | Apache req/s | vapache req/s | ratio |
|---|---:|---:|---:|
| index.html | 101,155 | 216,600 | 2.14x |
| hello.txt (1.1 KB) | 95,172 | 193,079 | 2.03x |
| 10 KB file | 87,488 | 171,844 | 1.96x |
| 1 MB file | 8,785 | 11,677 | 1.34x |

The run recorded 2–27 Apache-side keep-alive read errors (out of ~20,000
requests), which lower Apache's measured rate and make these ratios
conservative. Absolute rates vary with host load; recent full runs put the
small-file ratio around 1.96–2.14x and the 1 MB scenario around 1.34–1.38x.
Recent hot-path work caches the `Date` header and document-root descriptors,
coalesces small response bodies, and reduces per-request allocation in MIME
and access-log formatting. The latest policy migration also caches
per-directory scopes, shares parsed `.htaccess` scopes through `Arc`, indexes
literal `<Directory>` rules, and avoids per-request ancestor sorting.

`bench/feature_bench.py` runs the same Apache-versus-vapache comparison
against the richer conformance configuration: static and large-file serving,
conditional/range requests, directory handling, access policies, Basic auth,
rewrites, `.htaccess`, CGI, proxy authorization, internal
`DirectoryIndex`/`ErrorDocument` handler dispatch, HTTPS/1.1 and HTTP/2. New
access-policy scenarios cover `<Limit>`/`<LimitExcept>`, `Satisfy`,
`AllowMethods`, `AuthMerging`, `<ElseIf>`, and `<Proxy>`/`<ProxyMatch>`.
After the hot-path fixes, the latest quick feature run puts `.htaccess`
rewrite at **1.05x** and `.htaccess` Header at **1.30x** (previously 0.67x
and 0.96x). Bound CGI scripts now execute inside the worker pool after
reopening and dev/inode-verifying the authorized script, instead of forking
the main server; CGI GET is **2.66x**, CGI POST **2.57x**, DirectoryIndex CGI
**3.22x**, ErrorDocument CGI **3.82x**, and HTTP/2 CGI **4.33–4.90x**.
All migrated access-policy scenarios remain ahead of Apache, and server
rewrite is 1.34x. The remaining sub-1.0 cases are proxy static/ProxyMatch
(0.85x/0.83x in this run), which are limited by the Python test backend and
backend connection setup, plus a 0.99x directory redirect within noise. See
`bench/FEATURE_RESULTS.md` for the full matrix and measurement caveats.

`bench/app_bench.py` exercises the production-shaped dynamic paths with the
same upstreams:

```sh
python3 bench/app_bench.py --quick
python3 bench/app_bench.py --only php
python3 bench/app_bench.py --only gunicorn
```

The fixture starts a private PHP-FPM pool over a Unix socket and eight Gunicorn
sync workers, then benchmarks `/index.php` through FastCGI and `/app/hello`
through the HTTP proxy against both front ends. Latest five-sample run:

| scenario | Apache req/s | vapache req/s | ratio |
|---|---:|---:|---:|
| PHP-FPM `/index.php` | 42,866 | 55,373 | 1.29x |
| Gunicorn `/app/hello` | 22,332 | 24,624 | 1.10x |

The handlers are intentionally trivial; these numbers isolate the front-end
and upstream hop. Real PHP/WSGI application time will usually dominate. The
Gunicorn sync workers close each upstream connection, and vapache deliberately
does not pool backend connections without strict response-framing checks.
See `bench/APP_RESULTS.md` for details.

These are static-file microbenchmark numbers with a minimal Apache module set,
not a general claim about Apache. TLS, HTTP/2, `.htaccess`, CGI/modules and
production tuning are outside this comparison. The 1 MB result is close to
parity because it is bound by kernel file/socket throughput; small-file
throughput is dominated by per-request CPU cost. In sampled runs both servers
used roughly five cores, so the advantage reflects CPU efficiency per request,
not extra parallelism.

## Usage

```sh
# Syntax check a stock Apache configuration
./target/release/vapached -f /etc/apache2/apache2.conf -t

# Run in the foreground
./target/release/vapached -f /etc/apache2/apache2.conf -DFOREGROUND

# Strict mode: reject directives/modules we do not implement
./target/release/vapached -f /etc/apache2/apache2.conf -t --strict-config
```

## Repository layout

```text
crates/verified   Verus specifications and verified pure functions
crates/server     HTTP/TLS/HTTP/2, config + .htaccess, pure config front-end + policy core, auth, file/CGI, daemon
tests             Apache differential conformance suite
bench             Apache-vs-vapache static/feature/app benchmark harness and history
```

## Roadmap

1. Finish the remaining rewrite edges: `dbm` maps and exact per-directory
   `[DPI]` path-info handling, keeping the parser fail closed.
2. Expand authentication to Digest/LDAP providers and per-directory policy.
3. Add h2c and cleartext HTTP/2 upgrade support for parity with mixed
   deployments.
4. Grow the conformance suite toward the full Apache test corpus and track
   line/branch coverage with `cargo-llvm-cov`.
5. Port chunked request-body decoding and response-header serialization into
   Verus, reusing the verified token, header-value and framing predicates.
6. Continue tuning large-file throughput (the 1 MB scenario is sensitive to
   host variance and has ranged from 1.26x to 1.39x Apache in recent runs).
