# Coverage

Snapshot: 2026-10-26, after the pass-4 F39–F45 hardening and 100%
production-line closures for CGI, configuration parsing, the expression engine,
the HTTP proxy and rewrite execution:
single-file alias target splitting, `<Limit>` directive effects, CGI/FastCGI
actual-target reauthorization, capture-only alias rejection, exclusive FastCGI
spool files, disk-cache quotas/expiry cleanup, expression file-test
confinement, stricter header serialization, sticky `Connection: close`, and
write-free mmap policy.

```

Filename                          Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
server/src/access.rs                 1363               118    91.34%          62                 6    90.32%         815                89    89.08%           0                 0         -
server/src/auth.rs                    445                40    91.01%          20                 3    85.00%         243                20    91.77%           0                 0         -
server/src/cache.rs                  3003               406    86.48%         194                24    87.63%        1984               220    88.91%           0                 0         -
server/src/cgi.rs                    3148               217    93.11%         163                35    78.53%        1878                82    95.63%           0                 0         -
server/src/compression.rs             750                79    89.47%          39                 1    97.44%         418                42    89.95%           0                 0         -
server/src/config.rs                11923               339    97.16%         417                18    95.68%        7642               156    97.96%           0                 0         -
server/src/config_frontend.rs         366                23    93.72%          10                 1    90.00%         218                16    92.66%           0                 0         -
server/src/expires.rs                 257                29    88.72%          20                 0   100.00%         159                19    88.05%           0                 0         -
server/src/expr.rs                   2275                86    96.22%          98                12    87.76%        1126                12    98.93%           0                 0         -
server/src/fastcgi.rs                2437                55    97.74%          89                 6    93.26%        1408                17    98.79%           0                 0         -
server/src/files.rs                  1303               283    78.28%          45                 9    80.00%         768               143    81.38%           0                 0         -
server/src/h2.rs                     1324               256    80.66%          59                13    77.97%         752               137    81.78%           0                 0         -
server/src/htaccess.rs               4051                69    98.30%         107                 9    91.59%        2528                18    99.29%           0                 0         -
server/src/http.rs                   2336               158    93.24%         118                 8    93.22%        1548               100    93.54%           0                 0         -
server/src/log.rs                     768               153    80.08%          41                 8    80.49%         490                76    84.49%           0                 0         -
server/src/main.rs                   1219               594    51.27%          48                18    62.50%         755               415    45.03%           0                 0         -
server/src/ocsp.rs                    744               157    78.90%          28                 4    85.71%         407                78    80.84%           0                 0         -
server/src/policy_ref.rs              336                 6    98.21%          13                 0   100.00%         252                 2    99.21%           0                 0         -
server/src/proxy.rs                  5987               209    96.51%         270                34    87.41%        3805                84    97.79%           0                 0         -
server/src/rewrite.rs                4358               107    97.54%         117                 5    95.73%        2145                29    98.65%           0                 0         -
server/src/scope_policy.rs            899                26    97.11%          59                 1    98.31%         517                20    96.13%           0                 0         -
server/src/server.rs                 3989               813    79.62%         115                31    73.04%        2735               591    78.39%           0                 0         -
server/src/status.rs                   44                 0   100.00%           3                 0   100.00%          19                 0   100.00%           0                 0         -
server/src/tls.rs                    1022                49    95.21%          51                10    80.39%         618                14    97.73%           0                 0         -
server/src/util.rs                    677                89    86.85%          41                 6    85.37%         339                39    88.50%           0                 0         -
verified/src/lib.rs                  2185               232    89.38%         112                15    86.61%        1589               206    87.04%           0                 0         -
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                               57209              4593    91.97%        2339               277    88.16%       35158              2625    92.53%           0                 0         -
```

`tests/security_coverage.py --check` reports **100% production-line coverage**
for the enforced `cgi`, `config`, `expr`, `fastcgi`, `htaccess`, `http`,
`proxy`, `rewrite` and `tls` modules.  The CGI closure adds worker-protocol, spool,
timeout, child-isolation, pool-lifecycle and response-parser cases; the
configuration closure adds directive-matrix, error-path, rule-phase, glob and
section-nesting cases; the proxy closure adds URL/alias, balancer/sticky,
health, websocket, response-framing and failover-authorization cases; the expression closure adds
value-conversion, variable/expansion, encoding/hash, parser-error and
evaluation-branch cases; the rewrite closure adds cookie/effect, condition and
header extraction, map/backreference, flag/error and process-helper cases; the
F39–F45 changes add targeted cases for the fastcgi spool and actual-target
branches, the single-file alias split, `<Limit>` effects, cache quota/expiry
and expression confinement, plus end-to-end replay cases in
`tests/adversarial_regressions.py`.

## Proxy coverage

`proxy.rs` is at **100% production-line coverage**. The covered surface
includes:

- URL parsing/canonicalization, path joining/encoding and redirect rewriting
- prefix and regex routes, balancers, sticky cookies, health checks and
  member selection
- upstream request/response framing, chunked decoding, body/trailer limits,
  duplicate `Content-Length`/`Transfer-Encoding` rejection and header
  sanitization
- WebSocket upgrade forwarding, including TLS, grant binding, backend
  handshake validation and non-upgrade responses
- failover authorization, `failonstatus` handling and 403/502 error paths

## Configuration coverage

`config.rs` is at **100% production-line coverage**. The covered surface
includes:

- directive parsing and application across server, virtual-host, directory,
  location, files, proxy and conditional sections
- `<Limit>`/`<LimitExcept>`, `<RequireAll>`/`<RequireAny>`/`<RequireNone>`,
  `AuthMerging`, legacy `Order`/`Allow`/`Deny`, and `AllowOverride` categories
- aliases, script aliases, `AliasMatch`, redirects, error documents, handlers,
  MIME types, headers, compression filters and cache limits
- proxy routes, balancer members/health templates, SSL directives, rewrite
  maps, include expansion, and directive fallback disposition
- rule phase collection (`Directory`, `Files`, `Location`, `If`/`Else`) and
  malformed-configuration error paths

## Expression engine coverage

`expr.rs` is at **100% production-line coverage**. The covered surface
includes:

- boolean/int/string comparisons and concatenation
- `&&`, `||`, `!`, `-n`, `-z`
- `-in` lists, regex literals and `$0..$N` captures
- request/header/environment variables and common `TIME_*`/`API_VERSION`
- `req()`, `http()`, `env()`, `toupper`, `tolower`, `escape`, `unescape`,
  `sha1`, `md5`, base64 functions
- `-f`, `-d`, `-e`, `-s`, `-F`, `-U`, `-R`, `-ipmatch`, `-strmatch`,
  `-strcmatch`, `-fnmatch`
- `Require expr`, `.htaccess <If>`, and config `<If>`/`<IfFile>`

File tests (`-f`/`-d`/`-e`/`-s`/`-F`/`-U`) use the canonical document-root
confinement; `<IfFile>` keeps its operator-supplied absolute path through the
separate `Expr::IfFile` variant.

Not covered / not implemented: `LogMessage` expression interpolation, some
rare string/list/function forms, and a few Apache 2.4.68+ file-function
restrictions.

## Rewrite engine coverage

`rewrite.rs` is at **100% production-line coverage**. The covered surface
includes:

- server and per-directory rule matching, chaining, skip, `[N]` loop limits,
  `[L]`/`[END]`, `[QSA]`/`[QSD]`/`[QSL]`, `[B]`/`[BNE]`/`[BCTLS]`/`[BNP]`,
  `[CO]`, `[E]`, `[H]`, `[T]`, and redirect/proxy/forbidden/gone outcomes
- regex, comparison, expression and file-test conditions, including negated
  matches, `[NC]`/`[OR]` and document-root confinement
- `ENV:`, `HTTP_`/`HTTP:`, request/server, query and filesystem variables
- `txt`, `rnd`, `prg` and `int` maps, including closed-pipe and child-failure
  handling for `prg`
- backreference expansion, cookie construction, redirect escaping, host
  comparison, and internal target normalization

Remaining semantic gaps rather than coverage gaps are `dbm` maps and exact
per-directory `[DPI]` path-info handling.

## Still missing from the first-six list

- OCSP responder error-cache timeout policies (`SSLStaplingCache` is still
  treated as local persistence rather than a shared socache).
- Rewrite edge semantics: `dbm` maps and exact per-directory `[DPI]`
  path-info handling.
- Advanced balancer policies beyond route-cookie stickiness, `failonstatus`,
  passive failover and GET/HEAD health checks.
- `mod_cache_socache` and `mod_file_cache` (disk warm-start metadata is
  implemented).
- `mod_info` (basic `mod_status` is implemented).

`llvm-cov` reported 152 functions with mismatched data when merging the release
daemon with the debug unit-test objects; line coverage is unaffected, but
function percentages should be treated as approximate.

Reproduce with `tests/coverage.sh`. The report merges profiles from the real
`vapached` process driving the 165-test conformance suite with the Rust unit
test binaries (337 library tests plus 4 CLI/daemon tests).
