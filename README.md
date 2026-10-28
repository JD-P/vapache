# vapache

**WARNING: THIS ISN'T DONE YET AND HAS NOT UNDERGONE AN ADVERSARIAL PASS YET, THERE ARE PROBABLY STILL CRITICAL BUGS IN THIS DON'T USE IT**

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
- Static files, `DocumentRoot`, `Alias`, `ScriptAlias`, `AliasMatch`,
  `ScriptAliasMatch`, `Redirect`, `RedirectMatch`, `RedirectPermanent`/
  `RedirectTemp`, `DirectoryIndex`, autoindex, `AddType`/`RemoveType`/
  `ForceType`, `AddHandler`/`RemoveHandler`, `AddDefaultCharset`, MIME types
  and custom error documents. Regex aliases and redirects expand `$1`..`$9`
  captures and are resolved through the same target mapping as prefix aliases.
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
  `Options`, `DirectoryIndex`, `ErrorDocument`, MIME/handlers, `Header`
  (`set`/`add`/`unset` and `always`/`onsuccess`), `Redirect`, and rewrite
  rules. Unknown directives, disallowed categories and unsupported sections
  return `500` rather than silently ignoring a possible access rule. Every
  recognized directive has an explicit effectful, inert or rejected
  disposition and an `AllowOverride` category in the authoritative registry;
  an exhaustive test matrix checks all of them.
  `<IfModule>` covers every module whose directives the server implements, so
  wrapping auth, rewrite, IP, CGI or autoindex rules in a module block cannot
  silently disable them. Unknown-only `AllowOverride` values are rejected at
  startup.
- A fail-closed `mod_rewrite` implementation in server/vhost/`<Directory>`
  and `.htaccess` contexts: `RewriteEngine`, `RewriteBase`,
  `RewriteOptions Inherit`, `RewriteCond` (regex, `=`, `!=`, `<`, `>`,
  `-f`, `-d`, `-s`, `-l`, `NC`, `OR`, and `expr`), `RewriteMap`
  (`txt`, `rnd`, `prg`, `int`), and `RewriteRule` with the common flag set
  (`L`, `END`, `R`, `P`, `F`, `G`, `C`, `S`, `N`, `QSA`, `QSD`, `QSL`,
  `B`, `BCTLS`, `BNE`, `BNP`, `CO`, `E`, `H`, `T`, `NE`, `PT`,
  `UnsafeAllow3F`, `UnsafePrefixStat`), including backreferences, common
  `%{...}` variables and loop protection. Internal rewrites reauthorize the
  original URL with the original request context and accumulated rewrite
  effects, retain its `Options`/`AllowOverride`/header policy, and authorize
  the final target as a conjunction with the rewritten URL scope. A rewrite
  cannot launder a protected upload into an executable directory.
  `UnsafePrefixStat` is accepted for
  compatibility but never weakens the document/alias containment base. `dbm`
  maps and exact `DPI` path-info handling remain unsupported; malformed
  patterns are rejected rather than approximated.
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
  bounded output. `PATH_INFO` is split against the actual script and policy is
  re-evaluated for that script before execution. The worker control socket is
  close-on-exec, and request bodies above the spool threshold stay on disk
  through the CGI worker instead of being buffered in full. TLS requests set
  `REQUEST_SCHEME=https` and `HTTPS=on`, and authenticated requests export
  `REMOTE_USER`/`AUTH_TYPE`, for both CGI and FastCGI. The selected FastCGI
  target is authoritative for `SCRIPT_FILENAME`, `SCRIPT_NAME`, `PATH_INFO`
  and `PATH_TRANSLATED`; stale base-request values are removed before sending.
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
  and WebSocket tunneling over TCP/TLS (WSS on either side). Prefix and regex
  routes share one configuration-ordered route table, and `<Proxy>` sections
  match both the configured `balancer://` identity and the concrete member;
  failover re-authorizes the next member and atomically replaces the
  grant/resource binding instead of reusing the first member's grant.
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
  `CacheMaxDiskSize` (total on-disk quota with oldest-entry eviction and
  expiry cleanup), `CacheIgnoreCacheControl`, `CacheIgnoreNoLastMod`,
  `CacheStorePrivate`, `CacheStoreNoStore`, `CacheIgnoreQueryString` (dynamic
  query-driven CGI/FastCGI/proxy responses bypass the shared cache), `CacheHeader`, `Age`,
  conditional hits, disk warm-start metadata and invalidation on unsafe
  methods. Keys bind the listener/port, vhost, scheme, canonical URL
  (including its trailing slash), query and resolved filesystem/alias target,
  with CGI `PATH_INFO` keys bound to the script actually executed; entries
  also carry a configuration generation that a reload advances. The policy
  fingerprint covers every `Scope` policy slice and all request headers, with
  a matrix test over every policy field and key dimension. Every hit re-runs
  authorization against that mapped target. Multiple `Vary` field lines are
  combined, disk entries are rechecked against their variant, and credentialed
  or cookie-bearing requests are never stored in the shared cache.
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
  before being forwarded to proxy/FastCGI backends. Request and proxy chunk
  sizes, trailer counts/bytes, proxy head sizes and CGI/FastCGI output are
  explicitly bounded.
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
Unimplemented directives are reported as warnings in compatibility mode. Under
`--strict-config` every unhandled directive is an error, including
directives that are recognized but not implemented; strict mode never means
“only reject unknown names.”  Security-sensitive unimplemented directives
(for example `Action`, `ProxyBlock`, `RequestHeader`, `SetEnvIfExpr`,
`BrowserIPMatch`, `AcceptPathInfo`, `RLimit*`, `TransferLog`, `ScriptLog*`,
non-file `AuthBasicProvider` values and filter-provider/input-filter
directives) fail closed even in compatibility mode, and unimplemented
`.htaccess` directives fail closed with a `500`.

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

Current result: **433 verified functions, 0 errors** (percent-decoding,
URI path canonicalization, request-head parsing and body framing, header-value
sanitization, token validation, proxy request-line/header admission, byte-range
arithmetic, the mmap/CGI protocol bounds, HTTP/2 method/head/body admission,
the stream/reset budget model, the stream-ID admission/lifecycle model and the
idempotent early-reset purge model, and the TLS listener client-certificate
policy identity, the append-only container/list merge model, the rewrite target
classification/internal-join/same-host authority model, component-aware
filesystem containment for alias/rewrite/FastCGI targets, the expression
truthiness/comparison/glob/condition-chain model, the regex dialect admission
guard, directive disposition, access-layer slot translation, config front-end
line-kind IR and section-context transitions, rewrite backreference encoding
and filesystem-target admission, and the configuration access-plan,
authorization-merge, Options-merge and `.htaccess` rule-classification kernels
used by the dispatcher, plus route-prefix matching, handler-extension/removal
selection and authorization-configuration admission, the pass-6 ancestor
access-walk, URL-selected
alias mapping-root and `DirectoryIndex` cache-target/query-isolation
predicates, and the pass-10 I61 Options/handler/`AllowOverride` meet and
rewrite-scope-retention kernels, plus pass-12 admission proofs for exact
`Require method`/`Require env` operands, HTTP/2 pseudo-header identity, CGI
status/header framing, first-existing `AccessFileName`, `FileETag None`,
bounded and descriptor-snapshotted `RewriteMap prg` execution, exact disk-cache keys, targeted cache
invalidation and `[BNE]` escaping, plus the P13 lexical Files-scope handler
binding proof, the executable `AllowOverride`/`AllowOverrideList`/`Nonfatal`
admission gate, and the P14 per-depth Files phase plan, proxy-template dynamic
marker guard, full rewrite-chain resume and duplicate-header merge selection,
plus the executable rewrite expansion-token/match-action/program-counter state
machine and recursive configuration kind/phase/deferred-slot/order decisions).
The latest kernels also model the universal transform capability carried from
authorization to each protected sink, prove its inode/backend/cache-policy
requirements, validate descriptor snapshots used for access-file parsing, and
pin P15's fail-closed expression result, Apache-compatible RemoteIP proxy-class
transition, and dual lexical/canonical FastCGI script identity.

Function count is not the progress metric. The verification ledger tracks
security obligations and proof debt:

```sh
python3 tests/verification_status.py
python3 tests/verification_status.py --run-verus   # include the Verus gate
```

Current ledger: **53.1% weighted obligations**, **6/6 proof debt**,
**8/8 grant-required sinks**, **8/8 path-target-bound sinks**, **5/8
inode-bound sinks**, **3/8 backend-target-bound sinks**, **3/8
policy-key-bound sinks**, **0 partially bound sinks**, **0 unexplained replay
failures**, **106 adversarial replay cases** covering the findings classes,
and **433 Verus functions with 0 errors** (including the I3 fast-path
prefilter, I14 first-match, the pass-4 I35–I42 alias/limit/CGI/spool/cache/
expression dispositions, the pass-5 I43–I46 RequireNone/vhost/canonical-peer
kernels, the pass-6 I47–I49 access-walk/alias-root/cache-target kernels, the
pass-7 I50–I53 URL-mounted rewrite-base/cache-key-byte/ErrorDocument/
dynamic-handler kernels, the pass-8 I57/I58 canonical-REQUEST_URI and
access-file rewrite-subject kernels, the pass-9 I60 explicit-target
access-layer binding kernels, the pass-10 I61 resolved-target/rewrite
scope-conjunction kernels (`options_conjoin`, `handler_conjoin_admit`,
`override_categories_conjoin`, `rewrite_scope_retained_admit`), the pass-11
F61–F69 kernels (the class-capable `fnmatch_match` glob kernel,
`expr_var_known`, `set_handler_precedence_admit`/`set_handler_conjoin_admit`,
`cgi_exec_admit`, `handler_identity_lexical_admit`), the pass-12 configuration,
rewrite, HTTP/2, CGI, access-file, ETag and targeted-invalidation admission
kernels, the pass-13 `handler_scope_lexical_admit` scope-force obligation,
and the strengthened cache-key injectivity, lookup, store-admission,
freshness, disk-accounting and SHA-256 policy-binding proofs for I51/I54).

The ledger lives in `docs/verification-status.json`. It records:

- weighted progress on the sixty-five proof obligations,
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
python3 tests/conformance.py    # 165 local vapached conformance tests
python3 tests/conformance.py --differential  # also compare with Apache
python3 tests/adversarial_regressions.py  # F23-P15 end-to-end replay suite
```

The conformance suite starts a real `vapached` and covers HTTP/1.1, HTTPS,
HTTP/2, CGI, conditional requests, ranges, access control and Basic auth. Use
`--differential` when Apache is installed to start both servers and write
`tests/differential_report.md`, comparing status codes, selected headers and
bodies.  The `adversarial/`
folder holds the numbered findings write-ups (passes 3–14) and the pass-11,
pass-13 through pass-15 exploit harnesses (`adversarial/p11/exploit_p11.py`,
`adversarial/p13/exploit_p13.py`, `adversarial/p14/exploit_p14.py` and
`adversarial/p15/exploit_p15.py`) with
their Apache-versus-vapached case dossiers, so the exact exploit shapes are
documented rather than re-derived.

Security-sensitive configuration semantics are checked separately:

```sh
python3 tests/config_semantics.py  # 212 generated differential cases
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
verification are in `docs/config-semantics.md`; the per-finding closure matrix
for the adversarial pass is in `docs/adversarial-closure.md`. The Apache
source-model, binary-differential and future extracted-model refinement process
is in `docs/apache-access-parity.md`.

Combined unit and end-to-end line coverage is measured against instrumented binaries:

```sh
tests/coverage.sh
python3 tests/security_coverage.py --check
```

`security_coverage.py` reports executable production-line coverage before each
file's test module. Every server module is enforced at 100%, including the CLI,
cache, file serving, HTTP/2, logging, OCSP, proxying and rewrite execution.
Delimiter-only lines and narrowly documented unreachable invariants, external
failure races and privileged-kernel failures are excluded from that metric.

Latest snapshot: **18,913/18,913 executable server production lines (100%)**.
The current suite is 446 Rust library tests, 7 CLI unit tests, 3 CLI lifecycle
integration tests, 165 conformance tests and 212 generated configuration cases.
The separate Verus gate proves 433 functions with 0 errors; proof-only code is
measured by that gate rather than runtime line coverage.

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
appended to `bench/RESULTS.md`. Latest full run (2026-10-27, 3s samples, median of three,
100 connections for small files and 20 for the 1 MB case):

| scenario | Apache req/s | vapache req/s | ratio |
|---|---:|---:|---:|
| index.html | 92,792 | 205,324 | 2.21x |
| hello.txt (1.1 KB) | 96,773 | 188,648 | 1.95x |
| 10 KB file | 89,396 | 154,126 | 1.72x |
| 1 MB file | 8,850 | 12,388 | 1.40x |

The run recorded 13–22 Apache-side keep-alive read errors (out of ~20,000
requests), which lower Apache's measured rate and make these ratios
conservative. This run was taken during elevated host load, so absolute rates
are lower than the earlier snapshot while the server-to-server ratios remain
in the usual range. Recent full runs put the index/hello ratio around
1.95–2.21x, the 10 KB case around 1.72–1.96x and the 1 MB scenario around
1.34–1.40x.
Recent hot-path work caches the `Date` header and document-root descriptors,
coalesces small response bodies, and reduces per-request allocation in MIME
and access-log formatting. The latest policy migration also caches
per-directory scopes, shares parsed `.htaccess` scopes through `Arc`, indexes
literal `<Directory>` rules, and avoids per-request ancestor sorting.

`bench/feature_bench.py` runs the same Apache-versus-vapache comparison
against the richer conformance configuration: static and large-file serving,
conditional/range requests, directory handling, access policies, Basic auth,
rewrites, `.htaccess`, CGI, proxy authorization, internal
`DirectoryIndex`/`ErrorDocument` handler dispatch, HTTPS/1.1 and HTTP/2.
Access-policy scenarios cover `<Limit>`/`<LimitExcept>`, `Satisfy`,
`AllowMethods`, `AuthMerging`, `<ElseIf>`, and `<Proxy>`/`<ProxyMatch>`.
After the access-walk prefilter and per-request metadata memoization,
`.htaccess` rewrite moved from **0.70x** to **0.96x** and `.htaccess` Header to
**1.25x** in the latest 3s/five-sample run.
Bound CGI scripts execute inside the worker pool after reopening and
dev/inode-verifying the authorized script, instead of forking the main server;
the latest quick run measured CGI GET **2.60x**, CGI POST **2.57x**,
DirectoryIndex CGI **3.11x**, ErrorDocument CGI **3.55x**, and HTTP/2 CGI
**4.44–5.16x**. Most access-policy scenarios remain ahead of Apache, and
server rewrite is about **1.14x**. The remaining sub-1.0 cases are proxy
static/ProxyMatch (about 0.82–0.85x), limited by the Python test backend and
backend connection setup, HTTP/2 1 MB (about 0.82x), and `.htaccess` rewrite
near parity. See `bench/FEATURE_RESULTS.md` for the full matrix and
measurement caveats.

`bench/cache_bench.py` isolates the shared-cache hit path. Both servers warm
the same `/cached/` entries and the harness refuses to time a scenario unless
the second request reports `X-Cache: HIT`. It also measures an uncached static
file as the baseline:

```sh
python3 bench/cache_bench.py --quick
python3 bench/cache_bench.py
```

Latest full run (2026-10-27, 3s samples, median of three):

| scenario | Apache req/s | vapache req/s | ratio |
|---|---:|---:|---:|
| cache HIT 1.1 KB | 86,780 | 141,844 | 1.63x |
| cache HIT 10 KB | 80,218 | 136,152 | 1.70x |
| cache HIT 1 MB | 8,158 | 13,140 | 1.61x |
| static 1.1 KB baseline | 88,894 | 207,076 | 2.33x |

The cache-hit path still costs vapache some of its static throughput on small
files, but large cached bodies now use the file-body/sendfile path instead of
copying a heap buffer. Results are appended to `bench/CACHE_RESULTS.md`.

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
bench             Apache-vs-vapache static/feature/cache/app benchmark harness and history
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
