# Adversarial finding closure

This document records how the `findings.md` adversarial pass is reflected in
the implementation and the security model.  The numbered findings are the
source of the regression classes; the invariants (`I9`–`I59` in
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
| F22 | Alias target parent `.htaccess` skipped for subdirectories | Access-file walks use the URL-selected alias root for URL-base derivation and include every applicable ancestor, so every parent `.htaccess` down to the target is read; the later F50/F51 fix removed the alias root as an authorization bound | I10, I11, I47, I48 |
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
| F39 | Single-file `Alias`/`ScriptAlias` skipped the target `.htaccess` and served CGI/PHP as source | Prefix file targets map to `(parent, basename)`; the access-file walk root for a file target is its parent; handler/MIME/FastCGI selection uses the resolved target basename (`alias_file_target_split`, `alias_access_root_admit`, `handler_name_from_target`) | I35, I36, I37 |
| F40 | Effectful directives inside `<Limit>` were warn-and-ignored | Main-configuration directives inside `<Limit>` are applied to the enclosing scope (auth directives remain method-scoped); `.htaccess` still rejects non-auth directives in `<Limit>` (`limit_directive_effect`) | I38 |
| F41 | CGI/FastCGI dispatch used lexical symlink policy | Static, PATH_INFO, CGI and FastCGI handlers re-authorize the actual opened/canonicalized target and bind that target before execution/forwarding; FastCGI sends the canonical `SCRIPT_FILENAME` (`cgi_actual_target_admit`) | I39 |
| F42 | Capture-only `AliasMatch` used `ServerRoot` as an implicit base | Empty replacement prefixes produce an empty alias base, so `map_path()` fails closed; relative/explicit-prefix aliases keep their stable base (`capture_only_alias_admit`) | I40 |
| F43 | FastCGI spool used a predictable `/tmp` name with truncate | Spool files use exclusive creation, mode `0600`, bounded collision retries and immediate unlink (`temp_file_create_admit`) | I41 |
| F44 | Disk cache had no total quota or expiry cleanup | Persisted bytes are tracked per cache root; store enforces `CacheMaxDiskSize` and the entry cap by evicting the oldest stems, removes oversized entries, deletes expired/stale generations on load, and caps per-key variants (`cache_disk_size_admit`) | I42-adjacent cache bounds |
| F45 | Expression file tests escaped the document-root confinement | `Expr::FileTest` consumes `confined_expr_path`; absolute, parent-relative and escaping-symlink tests are rejected, while main-config `<IfFile>` keeps its operator-supplied path (`expr_file_test_admit`) | I42 |
| F46 | Multi-provider `<RequireNone>` was combined with AND, turning a deny list into an allow list | Children are aggregated as an OR of positive hits before negation; any granted child makes the group deny (`combine_or_all`, `require_none_multi`, `require_none_multi_result`) | I43 |
| F47 | Regex alias file targets with a trailing slash skipped the target `.htaccess`; protected files were served and CGI executed | Regex targets that resolve to a regular file map to `(parent, basename)`, and the URL/base root uses the parent for every non-directory alias target (`alias_file_target_split`, `alias_access_root_admit`); ancestor authorization follows I47 independently of that root | I44, I47 |
| F48 | Address-specific virtual hosts were selected by port and Host only; a loopback-bound admin vhost was reachable through another address | `select_vhost` takes the destination address, excludes address-bound vhosts on other addresses and gives exact-address vhosts precedence over wildcards; HTTP/1.1, HTTP/2, WebSocket, TLS, cache and logging use the address-aware helper (`vhost_address_admit`, `vhost_address_precedence`) | I45 |
| F49 | IPv4-mapped IPv6 peers bypassed IPv4 `Require not ip` rules on dual-stack listeners | Peers and RemoteIP identities are canonicalized to IPv4 before policy evaluation; `ip_in_net` and `Require local` consume the canonical form (`ipv4_mapped_to_v4`) | I46 |
| F50 | The access-file walk stopped at `DocumentRoot`/the alias target and ignored an effective ancestor `.htaccess` | The walk covers every filesystem ancestor and asks the effective per-directory `AllowOverride` policy whether that layer participates; the mapping root is used only for URL/`RewriteBase` derivation (`access_walk_dir_admit`) | I47 |
| F51 | Overlapping aliases selected the first alias target containing the path instead of the URL-selected alias | `map_path()` returns the actual URL-mapping root and dispatch/cache/explain pass it through to the access walk; alias-target containment is never used to reconstruct the root (`alias_mapping_root_admit`) | I48 |
| F52 | Cache lookup/store used the directory URL instead of the selected `DirectoryIndex` target | `DirectoryIndex` is resolved before the cache decision; the cache key, target, grant and policy fingerprint bind that index. Dynamic index/script responses bypass `CacheIgnoreQueryString`, and a live `<Files>` change is visible in the recomputed index policy (`cache_directory_index_bind_admit`, `cache_ignore_query_admit`) | I49 |
| F53 | `.htaccess` anchored rules under an `Alias`/`AliasMatch`/`ScriptAlias` used the alias target-relative path, not the URL mount, so `[F]`/`[G]` deny rules were skipped | `request_plan::layer_url_mount()` derives every layer's substitution base from the requested URL and the layer's depth below the requested target; prefix/regex aliases, nested access files, `RewriteBase`, static files, CGI and `[F]`/`[G]`/`[E]`/`[R]` effects share the same identity (`htaccess_layer_url_base_admit`) | I50 |
| F54 | The `CacheIgnoreQueryString` dynamic-target classifier missed `SetHandler "proxy:…\|fcgi://…"` and other non-default handlers | The cache classifies the effective handler after `DirectoryIndex` resolution; any non-default handler (FastCGI proxy, `cgi-script`, `server-status`, future handlers) forces a cache bypass for query-bearing requests (`cache_dynamic_handler_admit`) | I49, I53 |
| F55 | Lossy UTF-8 conversion in cache-key material merged invalid-byte queries/paths with the empty or replacement value | Server root, host, path, raw query and resolved target are hex encoded losslessly; non-UTF-8 URL paths bypass the shared cache, invalid index names are rejected, and invalidation uses the same encoding (`cache_key_hex`) | I51 |
| F56 | A local `ErrorDocument` is an internal subrequest selected after the original URL's cache scope was built, so a query-dependent error document could be cached under the missing URL | A missing target whose scope can select a local `ErrorDocument` bypasses lookup, and an error-document response is never stored under the failing URL via a response-provenance marker; existing targets keep normal caching and the internal subrequest still runs normal authorization and handler dispatch (`cache_local_error_document_admit`) | I52 |
| F57 | `%{REQUEST_URI}` used the raw request-line target, including the query, percent escapes and dot segments, so expression/rewrite/environment path policies authorized different bytes than dispatch served | Every `%{REQUEST_URI}` implementation receives the dispatcher's decoded, normalized, query-free URL path: expression variables/functions, `Require expr`, `<If>`, `SetEnvIf Request_URI`, `RewriteCond`/rule expansion and CGI environment. `expr::Context::new` consumes `request_uri_identity_admit`; no path appends the query string | I57 |
| F58 | Access-file rewrite rules above the alias/document-root mapping root had an impossible URL match base, so anchored `[F]`/`[G]` deny rules were silently skipped | Every parsed access-file rule carries its layer directory; `request_plan::layer_subject()` matches the selected filesystem target relative to that directory, exactly Apache's per-directory subject. `htaccess_rewrite_subject_admit` requires a derivable subject or fails closed. `request_plan::layer_url_mount()` is used only for relative substitutions and uses the filesystem-directory form for ancestor layers instead of an unmatchable URL fallback | I58, I59 |
| Additional | `Require not valid-user` dropped negation; non-HTTP control bytes passed header serialization; `close, keep-alive` re-enabled a connection; mmap allowed other-owner write races | Negation is carried into `Require::ValidUser`; header values admit only HTAB/SP/VCHAR/obs-text; `close` is sticky; mmap requires no owner/group/other write bits | I23, I33-adjacent |

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
- rewrite-condition file tests (`-f`, `-d`, `-s`, `-l`) canonicalize both the
  document/alias root and the probed path before consuming the verified
  component-aware containment kernel, so an in-root symlink cannot become a
  metadata oracle for an outside file;
- the cache key's hex encoder is refined to a recursive byte-exact spec and
  proved injective; store admission is split into verified request/status/
  Cache-Control/response-shape/TTL predicates, freshness clamps cannot panic on
  reversed bounds, expiry is saturating, disk projection/eviction arithmetic
  is mechanized, and cache-policy binding uses verified length framing plus a
  256-bit SHA-256 digest instead of a 64-bit `DefaultHasher` fingerprint
  (I51, I54);
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
- `tests/adversarial_regressions.py`, which starts fresh servers and replays
  the F23–F58 exploit shapes (rewrite-to-proxy/redirect authorization, cache
  reload plus PATH_INFO, relative and capture-only aliases, autoindex schemes,
  negated/env providers, `IndexIgnore`, `DirectorySlash Off`,
  `UnsafePrefixStat` re-rooting, header-selected cache entries,
  `.htaccess` `RequestHeader`, CGI `REMOTE_USER`/`AUTH_TYPE`, single-file
  aliases, `<Limit>` `Options`, symlinked CGI/FastCGI targets,
  capture-only `AliasMatch`, expression file-test confinement,
  multi-provider `<RequireNone>`, regex alias file targets, address-bound
  vhosts, IPv4-mapped peers, ancestor `.htaccess` above `DocumentRoot`/an alias
  target, overlapping `Alias`/`ScriptAlias`/`AliasMatch` roots,
  `DirectoryIndex` cache-target/query/live-policy changes, canonical
  `REQUEST_URI` query/encoding/dot-segment policies, and document-root/ancestor
  rewrite subjects for alias and alias-match targets);
- operator replay harnesses that reproduce the Apache-versus-vapached
  differentials in `findings.md`.

Any new directive that changes a request-to-resource mapping, cache key,
handler selection, authorization identity or inherited descriptor must state
which of I9–I59 it preserves.  A directive that is recognized but not
implemented is not allowed to pass as “inert” unless that inertness is
explicit and local to the directive; request-mutating directives such as
`RequestHeader` are never inert.
