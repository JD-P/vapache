# Adversarial finding closure

This document records how the `findings.md` adversarial pass is reflected in
the implementation and the security model.  The numbered findings are the
source of the regression classes; the invariants (`I9`–`I34` in
`docs/config-semantics.md`) are the properties that prevent the class from
returning through a different directive or dispatch path.

| Finding | Class | Implementation closure | Model obligation |
|---|---|---|---|
| F1 | Hidden-file bypass through ignored `RedirectMatch`; strict mode accepted unimplemented directives | `RedirectMatch` is parsed, regex-matched and expands captures; `RedirectPermanent`/`RedirectTemp` are handled. `directive_disposition` now fails strict mode for every unhandled directive | I9 |
| F2 | `AliasMatch`/`ScriptAliasMatch` ignored; `RemoveHandler` ignored | Regex aliases share `map_path` and capture expansion; handler operations are ordered, so a later `RemoveHandler` removes an `AddHandler`. `Action` fails closed | I9, I10 |
| F3 | CGI `PATH_INFO` selected the handler and authorized the wrong object | Handler selection uses the actual script basename. After `find_script`, policy is re-evaluated for the script path and the grant is bound to the script inode. FastCGI splits `PATH_INFO` to an existing script and re-authorizes it | I10, I11 |
| F4 | Cache authorized a different target than dispatch; trailing-slash `<Location>` missed | Cache and dispatch share `map_path`; the cache URL preserves its trailing slash and authorization runs against the mapped alias/target | I10, I12 |
| F5 | CGI inherited the worker control socket | The worker keeps the socket open for its own loop but marks it `FD_CLOEXEC` before spawning scripts; scripts see only stdio plus the explicit script descriptor | I13 |
| F6 | Duplicate `Vary` field lines collapsed | All `Vary` lines are concatenated and de-duplicated before building the variant key | I12 |
| F7 | Cache key omitted listener/vhost/target | Key includes scheme, listener address/port, vhost, Host, canonical URL, query, resolved target and policy fingerprint | I10, I12 |
| F8 | Disk fallback ignored `Vary` | `cache_lookup_admit` receives the real `vary_match` result on disk reload; a mismatch is neither served nor inserted | I12 |
| F9 | `<Proxy balancer://...>` never matched; failover reused the first grant | Proxy sections match both the logical balancer URL and the concrete member; failover re-runs proxy authorization and rebinds the member target | I8 |
| F10 | `.htaccess` `<IfModule>` allowlist skipped security blocks | Positive `<IfModule>` blocks are parsed for every module name; unknown directives inside still fail closed. Negated blocks only skip known built-ins | I9 |
| F11 | `SymLinksIfOwnerMatch` followed all links | Owner-only mode checks each symlink owner against its resolved target and returns `403` on mismatch; unconditional `FollowSymLinks` retains the previous behavior | I11 |
| F12 | Unsafe methods left disk entries stale | Invalidation removes persisted body/meta files as well as memory entries | I12 |
| F13 | `Header always`/`unset` ignored; child `set` duplicated | `always`/`onsuccess` are separate lists, `unset` runs after set/add, and child `set` replaces inherited same-name fields | Scope-merge header rule |
| F14 | TLS CGI/FastCGI claimed `http` | `CgiContext` carries listener TLS state; CGI/FastCGI set `REQUEST_SCHEME` and `HTTPS` correctly | I10 (scheme is request context) |
| F15 | `UseCanonicalName On` ignored in redirects | Canonical server name wins for `server_name_for`, absolute redirects and directory redirects; the Host header cannot override it | I10 |
| F16 | `%{HTTPS}` trusted `X-Forwarded-Proto` | Expression evaluation reads connection TLS state set by the listener; forwarded headers are never treated as TLS evidence. `SERVER_PORT` comes from the listener | I10 |
| F17 | Internal rewrite discarded original `<Location>` auth | Both the original request URL scope and the final target scope must allow after a rewrite | I11 |
| F18 | `ProxyPass`/`ProxyPassMatch` order ignored | Prefix and regex HTTP/FastCGI routes share a configuration-order `route_order`; the earliest matching route selects the handler | I8 |
| F19 | Chunked trailers bypassed the body deadline | Trailer lines check the request deadline and are bounded by count/bytes, matching the proxy reader | I12/I13-adjacent resource bounds |
| F20 | CGI buffered the entire request body | Bodies above the 1 MiB spool threshold remain on disk through the worker protocol and are streamed to stdin; small bodies stay in memory | Descriptor/body resource bound |
| F21 | Proxy chunk-size arithmetic could overflow | Chunk end offsets use `checked_add` and are bounded by `MAX_PROXY_BODY` before resizing | Resource bound |
| F22 | Alias target parent `.htaccess` skipped for subdirectories | Access-file walks stop at the actual alias root (prefix or regex alias), not `DocumentRoot`, so every parent `.htaccess` down to the target is read | I10, I11 |
| F23 | Two-stage internal rewrite then `[P]` dropped original-URL authorization | The post-loop original-URL check is a shared gate used by proxy and positive-redirect outcomes as well as static targets | I19 |
| F24 | Disk cache survived reload and a new `<Files>` deny via CGI `PATH_INFO` | Cache entries carry a configuration epoch; reload bumps it and removes persisted files. Cache scope/target resolve `PATH_INFO` to the actual CGI script | I12, I20 |
| F25 | Relative `AliasMatch` target skipped its target-tree `.htaccess` | Relative regex replacement roots are resolved against `ServerRoot` at parse time, matching `map_path()` and the access-file walk | I10, I21 |
| F26 | Autoindex emitted executable `javascript:`/scheme-relative links | Autoindex hrefs are built by `safe_relative_href`, which always prefixes `./` before URL encoding | I22 |
| F27 | `Require not env` parsed the wrong operand; `Require not expr` lost negation | `parse_require` consumes `rest.first()`/`rest.join(" ")`, and `Require::Expr` carries its negation into evaluation | I23 |
| F28 | `.htaccess` `SetEnv`/`SetEnvIf` silently ignored | Both `.htaccess` and main config use one environment-rule parser and populate `EnvironmentPolicy`; `UnsetEnv`/`PassEnv` are modeled too | I23 |
| F29 | `IndexIgnore` accepted and ignored | `IndexIgnore` is part of `ContentPolicy` in both parsers and filters autoindex entries | I24 |
| F30 | `DirectorySlash Off` let `/dir` bypass `<Location "/dir/">` | A no-slash directory target is reauthorized as its canonical trailing-slash URL before index or autoindex dispatch | I24 |
| F31 | Regex alias fallback re-rooted a target outside its alias base | `map_path()` returns `None` when a regex expansion leaves `fs_path`; dispatch, WebSocket and cache callers fail closed instead of using `target.parent()` as a new root; admission consumes the verified component-aware `path_under_base` kernel | I25 |
| F32 | `UnsafePrefixStat` rewrite changed the authorization base | `rewrite_filesystem_admit` admits only files below the current document/alias root; its `under_base` input comes from verified `path_under_base`; the flag is compatibility-only and cannot re-root at the target parent | I25 |
| F33 | FastCGI script construction and `PATH_INFO` walk could escape the document root | `script_from_prefix` and `split_path_info` clean/canonicalize inside the configured prefix or docroot and consume verified `path_under_base`; the ancestor walk stops at that base and rejects symlink escapes | I25 |
| F34 | Cache fingerprint omitted header-driven authorization inputs | The policy fingerprint hashes the complete request header set; a tenant/header branch therefore cannot share a cached representation | I26 |
| F35 | Proxy request-line/forwarded-host text was interpolated without a final check | Backend hosts and `X-Forwarded-Host` are validated; `validate_proxy_head` consumes verified `proxy_request_line_admit` and `proxy_header_admit` immediately before `write_all` | I28 |
| F36 | `.htaccess` `RequestHeader` was silently ignored | `RequestHeader` now fails closed with `500` in `.htaccess`, matching the main-config policy instead of pretending to be inert | I23 |
| F38 | Authenticated CGI/FastCGI requests lacked `REMOTE_USER`/`AUTH_TYPE` | The grant identity is carried into `CgiContext`; `build_env` emits both variables for CGI and FastCGI and keeps configured entries from overriding them | I27 |

## Additional hardening before the next pass

The first closure pass also made the following classes explicit in the model:

- alias and redirect mappings are one ordered table, so a later overlapping
  mapping cannot beat an earlier one (matching Apache's first-match behavior);
- handler operations are ordered, so `RemoveHandler` cancels an inherited
  `AddHandler`;
- response-header policy is applied to directory redirects and rewrite/redirect
  responses as well as static/CGI/proxy/error responses;
- the debug scope-merge audit now covers the separate `Header always` lists and
  child `set` replacement rather than assuming every header list appends;
- `%{SERVER_NAME}` uses the dispatcher-selected canonical name, not a raw Host
  lookup, and `UseCanonicalName DNS` conservatively uses `ServerName`;
- `ProxyPass`/`ProxyPassMatch` exclusions are rejected instead of silently
  ignored;
- trusted request context (scheme, peer, canonical name, identity) is separated
  from attacker-controlled forwarding headers in I16;
- a failed containment proof is a mapping failure, never a fallback to the
  target's parent directory (I25);
- an alias, rewrite or FastCGI mapping cannot change the base used by the
  authorization walk, even when a compatibility flag opts into a wider stat
  check;
- the cache key includes every header an expression or environment rule can
  read and the complete material of every `Scope` policy slice, so neither
  header-selected nor policy-selected branches can share an entry; the
  rewrite-map `HashMap` is canonicalized before hashing (I26);
- authenticated identity is a resolved-context field that follows the request
  into CGI/FastCGI rather than being dropped at the script boundary (I27);
- configuration-derived upstream text passes the same serialization
  predicates as native response headers (I28);
- every recognized `.htaccess` directive has one explicit disposition and an
  `AllowOverride` category in an authoritative registry; an exhaustive test
  matrix proves effectful directives change the scope, inert directives leave
  it unchanged, rejected directives fail, and every entry is gated by
  `AllowOverride None` (I29);
- the transform inventory is closed and every target-changing operation
  reauthorizes both the original request context and the current target,
  binding the sink grant to that target; query-only rewrites and `[E=...]`
  effects are included in the original-URL recheck (I30);
- CGI/FastCGI execution uses the selected script as the authority for
  containment, authorization, inode/backend binding and environment; the
  FastCGI target overwrites `SCRIPT_FILENAME`, `SCRIPT_NAME`, `PATH_INFO` and
  `PATH_TRANSLATED` exactly once, and authenticated identity is exported
  (I31);
- prefix and regex proxy routes share one order space; balancer authorization
  covers both logical and concrete identities, and failover replaces the
  grant/resource pair atomically before sending to the next member (I32);
- every untrusted stream has an explicit byte/count/deadline bound, with
  chunk arithmetic checked before allocation and trailers bounded on both the
  request and proxy sides (I33);
- main-configuration directives are handled, explicitly warned as inert
  presentation/module-absence, or fail closed; security, filter, audit and
  resource-limit directives can no longer disappear into the compatibility
  warning path, and strict mode rejects every unhandled directive (I34).

## Regression surface

The closure is exercised by:

- Rust unit tests for regex aliases/redirects, `RemoveHandler`, strict
  disposition, child header replacement, cache-key dimensions, cache
  generations, header-selected cache fingerprints, relative alias roots,
  negated `Require` operands, `.htaccess` environment rules, `IndexIgnore`,
  safe autoindex hrefs, alias/rewrite/FastCGI containment, proxy-head
  serialization, `.htaccess` `RequestHeader` rejection, CGI/FastCGI identity
  variables, the exhaustive `.htaccess` directive effect/category matrix, the
  cache input-closure matrix over every policy field, request header and
  listener/vhost/URL/target dimension, transform-gate replays for query-only
  rewrites and rewrite-set environment effects, CGI/FastCGI exact environment
  and script-containment cases, mixed prefix/regex plus balancer
  logical/concrete proxy identity cases, main-config directive disposition
  cases, and framing/trailer/record-limit cases for HTTP, proxy and FastCGI;
- `tests/conformance.py`, `tests/config_semantics.py`,
  `tests/config_validity.py` and `tests/config_grammar.py`;
- `tests/adversarial_regressions.py`, which starts a fresh server and replays
  the F23–F38 exploit shapes (rewrite-to-proxy/redirect authorization, cache
  reload plus PATH_INFO, relative and capture-only aliases, autoindex schemes,
  negated/env providers, `IndexIgnore`, `DirectorySlash Off`,
  `UnsafePrefixStat` re-rooting, header-selected cache entries,
  `.htaccess` `RequestHeader` and CGI `REMOTE_USER`/`AUTH_TYPE`);
- operator replay harnesses that reproduce the Apache-versus-vapached
  differentials in `findings.md`.

Any new directive that changes a request-to-resource mapping, cache key,
handler selection, authorization identity or inherited descriptor must state
which of I9–I28 it preserves.  A directive that is recognized but not
implemented is not allowed to pass as “inert” unless that inertness is
explicit and local to the directive; request-mutating directives such as
`RequestHeader` are never inert.
