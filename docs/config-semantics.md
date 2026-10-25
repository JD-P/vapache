# Configuration semantics: model and proof plan

This document is the bridge between the implementation and a future
machine-checked model of Apache configuration semantics.  It is deliberately
smaller than the full Apache directive set.  The goal is to define the
security-relevant core precisely enough to prove, and to state exactly which
parts are still implementation detail.

The running implementation now uses `policy_ref::effective_scope_with_layers`
for both configuration phases and access-file interleaving.  The access-file
walker only parses files and builds `AccessLayer` values; it does not merge
them.  This discharges the production equivalence obligation by
construction: there is one evaluator, not two.  The phase plan and the
security-relevant merge decisions are now Verus-checked and consumed by that
evaluator (counts and exact boundaries in §10a).  Container/list merging,
directive disposition and `.htaccess` layer-slot translation use verified
helpers; raw parser tokenization remains the explicit parser-refinement
assumption.

## 1. Scope of the model

In scope:

- request path canonicalization and vhost selection
- `<Directory>`, `<DirectoryMatch>`, `<Files>`, `<FilesMatch>`,
  `<Location>`, `<LocationMatch>`
- `<If>`, `<ElseIf>`, `<Else>`, `<IfFile>`
- `<Limit>`, `<LimitExcept>`, method scoping, `AllowMethods`
- `AllowOverride`, `AllowOverrideList`, `Nonfatal=...`, `AllowOverride`
  categories, `.htaccess`
- `Require`, `<RequireAll>`, `<RequireAny>`, `<RequireNone>`, `AuthMerging`
- `Satisfy`, legacy `Order`/`Allow`/`Deny`
- `Options` merge algebra and `AllowOverride Options=...`
- cache-enable/disable prefix selection (for the prefilter invariant)

Out of scope for the first proof:

- TLS, HTTP/2 wire framing, CGI, proxy protocol details, rewrite substitution
- authorization backends (file/Digest/LDAP)
- regex implementation correctness (the model assumes a trusted `Regex`
  matcher with a stated language)
- filesystem race semantics beyond the `openat` containment argument
- logging and response formatting

## 2. Domains

Let:

- `Path` be a canonical absolute filesystem path.
- `Url` be a canonical absolute URL path with no `.`/`..` and a preserved
  trailing slash.
- `Method` be an HTTP method token, with the Apache-equivalence
  `HEAD ~ GET`.
- `Request` carry `(method, url, headers, peer, env)`.
- `Config` be the compiled immutable configuration.
- `Scope` be the merged directive state for a directory.
- `Rule` be `(kind, delta, order, condition, branch, chain, nested)`.
- `Phase` be one of `Directory < Files < Location < Condition`.
- `Match` be one of `Always`, `Directory(pattern)`, `DirectoryMatch(regex)`,
  `Files(pattern)`, `FilesMatch(regex)`, `Location(prefix)`,
  `LocationMatch(regex)`.

The implementation's `RulePhase` and `ScopeRule::phase` are the code-level
counterparts of `Phase`.

## 3. Matching

For a request `(url, fs_path, fname)`:

- `Directory(pattern)` matches a directory ancestor of `fs_path`, or
  `fs_path` itself if it is a directory, using Apache shell-glob semantics
  with `*`, `?`, `[]`, `[!...]`.  Wildcards do not cross `/`.
- `DirectoryMatch(regex)` matches the **full filesystem filename string**
  (observed Apache 2.4 behavior).  A pattern anchored at a directory name
  without allowing for the final filename does not match a file inside it.
- `Files(pattern)` and `FilesMatch(regex)` match the basename `fname`.
  `<Files>` patterns support `*`, `?`, `[]`, `[!...]`; `~ regex` is regex.
- `Location(prefix)`:
  - `/` or empty matches everything.
  - a prefix **not** ending in `/` matches exactly the prefix or a
    slash-boundary child;
  - a prefix ending in `/` matches only strings that begin with that exact
    prefix.  Thus `/admin/` does not match `/admin`.
- `LocationMatch(regex)` matches the canonical URL path.

## 4. Merge order

For one request define:

```
D = apply literal <Directory>/<DirectoryMatch> rules and .htaccess,
    interleaved from the root directory down to the target directory
F = apply <Files>/<FilesMatch> rules
L = apply <Location>/<LocationMatch> rules
C = apply <If>/<ElseIf>/<Else> conditionals
```

The effective scope is:

```
effective = C( L( F( D( base ) ) ) )
```

More precisely:

1. Walk directories root-to-leaf.  At each directory:
   1. apply matching literal/wildcard `<Directory>` rules, in
      least-specific-to-most-specific order;
   2. read that directory's access file if `AllowOverride` permits it and
      the file exists, and merge its **top-level** scope;
   3. defer its `<Files>` rules to phase `F` and its `<If>` rules to phase `C`.
2. Apply `<DirectoryMatch>` rules after all directory/access-file merges.
3. Apply `<Files>` rules from the configuration and from access files.
4. Apply `<Location>` rules.
5. Apply `<If>`/`<ElseIf>`/`<Else>` rules last, evaluating chains in order.

The implementation enforces this ordering with:

- `effective_scope_req_base_deferred` (base + top-level deferred rules)
- `apply_directory_rules_for_dir` (per-directory Directory rules)
- `apply_directory_match_rules`
- `apply_normal_rule_list` (Files then Location)
- `apply_deferred_req` (conditionals)

The fast path when no access file can apply uses
`effective_scope_req_deferred`, which folds Directory, Files and Location in
one pass because there is no access file to interleave.

## 5. Scope merge

`Scope::merge(child)` is a per-field operation, not a textual replacement:

- scalar overrides (`document_root`, `allow_override`, `auth_type`, ...)
  replace when present;
- `Options` is a sequence of `Set`/`Add`/`Remove`, applied left-to-right
  from the built-in default `FollowSymLinks`;
- `Require` is replaced by a child `Require` unless the child sets
  `AuthMerging And|Or`, in which case the child policy is combined with the
  inherited policy;
- every container/list field appends parent then child;
- `ErrorDocument` and `RewriteMap` are list-backed; a reverse lookup makes
  child entries win for duplicate keys;
- `RewriteRule`/`RewriteCond` lists append;
- `.htaccess` top-level directives merge in the same way.

The formal model should define `merge : Scope × Scope → Scope` as the
composition of these per-field operations and prove the ordering lemmas used
by the phases above.

## 6. Override gating

`AllowOverride` is valid only in a non-regex `<Directory>` section.  A
`None` mode means access files are not read at all.  For a read access file:

- `All` permits every implemented directive;
- each category permits its directive group;
- `AllowOverrideList` permits individual directive names even when
  `AllowOverride None` would otherwise disable access files; the effective
  permission set is the union of both;
- `Nonfatal=Override|Unknown|All` suppresses category/unknown errors while a
  genuine syntax error in a valid directive still fails with 500;
- `Options=...` permits an `Options` token only if the corresponding option
  is listed, except that `Options None` is always permitted once any
  `Options` override is enabled;
- the section containers `<If>`, `<IfFile>`, `<Files>`, `<FilesMatch>` do not
  themselves require a category; the directives **inside** them do;
- `<Limit>`/`<LimitExcept>` are permitted by `AuthConfig` or `Limit`, and
  their inner authorization directives still obey their own categories.

A disallowed directive is an error (500), not a silent skip.  This is the
fail-closed rule and must be preserved by the model.

## 7. Authorization evaluation

For a scope and method:

- ordinary `Require` directives form an implicit `RequireAny` list;
- an entry whose `MethodSet` does not apply is skipped;
- if every entry is skipped, the list is neutral/granted according to the
  surrounding `parent_and` context (root is granted);
- `<RequireAll>` is conjunction and requires at least one grant;
- `<RequireAny>` is disjunction;
- `<RequireNone>` cannot grant; a granted child becomes denied, a denied
  child is neutral;
- `AuthMerging And/Or` combines a child policy with the inherited policy;
- legacy `Order`/`Allow`/`Deny` is evaluated for the request method, then
  combined with the modern result by `Satisfy All|Any`.

## 8. Security invariants to prove

These are the target theorems.  The implementation should be shaped so they
are stated over pure functions.

### I1 — ACL reachability (non-bypass)

Every response path that serves a file, directory index, CGI, proxy target or
error document either:

- has called `access::check` on the effective scope with the request's
  identity and peer, and obtained `Allowed`; or
- is an explicitly documented pre-auth response (e.g. `401` challenge).

In particular, the cache lookup path may not return a stored response unless
the same check would have allowed the request.

### I1a — Resource-bound grant

The implementation refines I1 with a concrete `ResourceKey`:

```text
grant.resource = (vhost, method, URL, filesystem path,
                  proxy URL, cache host/path/query, identity)
```

Every body/tunnel sink checks the grant against the resource it is about to
serve. A grant for one URL/path/proxy target/cache entry cannot be reused for
another.  Static file and directory sinks additionally bind the grant to the
opened `dev`/`inode`; if `/proc/self/fd/N` resolves to a different path (a
symlink target), policy is re-evaluated for that target path before the file
is served.  Proxy, WebSocket and FastCGI grants are bound to the exact outbound
backend/script target.  CGI scripts are bound to the opened script inode and executed via
`/proc/self/fd`; cache grants are policy-key-bound.

### I1b — Opened-object binding

For static files and directories, the grant additionally carries the opened
`(dev, inode)`.  The server resolves `/proc/self/fd/N` for the opened
descriptor; if that path differs from the URL-selected filesystem path, the
target `<Directory>`/`<Files>`/`.htaccess` scope is re-evaluated before the
response is served.  A file replaced between policy evaluation and serving is
therefore either the exact inode that was authorized or causes a 500/403.

CGI scripts are also bound to the opened `(dev, inode)`.  Bound scripts bypass
the path-based worker-pool exchange and execute through `/proc/self/fd`, so a
path replacement cannot swap the script after authorization.  Proxy,
WebSocket and FastCGI grants are additionally bound to the exact outbound
backend/script target.

### I2 — Override gating

If a directive is not permitted by the effective `AllowOverride` mode, it has
no effect on the effective scope.  If it is a security directive, the request
fails closed with 500 rather than ignoring it.

### I3 — Fast-path implication

For every request:

```
htaccess_may_apply(fs_path) == false
  ⇒ no access file in the ancestor chain changes the effective scope
```

and

```
cache prefilter says "not cacheable"
  ⇒ cache_enabled(effective_scope, raw_path) == false
```

The prefilter must be an over-approximation, never an under-approximation.
The `/cache/` trailing-slash bug was a violation of this shape.

### I4 — Conditional-last

For any scope, a conditional rule cannot be overridden by a later
Directory/Files/Location rule; condition evaluation happens after all normal
merges, including access files.

### I5 — Method limits

`MethodSet::intersect` is exact:

```
intersect(a,b).matches(m) ⇔ a.matches(m) ∧ b.matches(m)
```

and a method-limited requirement cannot apply to a method outside its set.

### I6 — Path-prefix discipline

`Location("/x/")` does not match `/x`; `Directory("/srv/foo")` does not match
`/srv/foobar`; wildcard components do not cross `/`.

### I7 — Fail-closed unsupported constructs

Unsupported access-control directives, malformed `.htaccess` files, invalid
contexts, and unknown `Require` providers deny or error; they never widen
access.

### I8 — Rewrite/proxy authorization

A proxy target reached through a rewrite `[P]` is still subject to the
matching `<Proxy>` authorization section (the implementation already does
this deliberately).

## 9. Formalization boundary

The first Verus model should cover:

1. `merge_scope` and the per-field merge functions
2. `rule_matches` for Directory/Files/Location and glob patterns
3. `apply_phase` / `effective_scope` over an abstract rule list
4. `eval_require` over `AuthPolicy`, `MethodSet`, `AuthMerging`
5. `override_allowed` and the category table
6. `cache_maybe_enabled` and `htaccess_may_apply` prefilter predicates

The following remain assumptions or separate proofs:

- the regex engine implements the stated language;
- the filesystem contents match what the access-file walk sees;
- path canonicalization and `openat` containment (already separately
  verified in `crates/verified`);
- h2 wire framing and TLS/CGI/proxy protocol code;
- configuration parsing itself (the parser must produce a model accepted by
  the proofs; a parser proof can follow).

## 10. Proof obligations / lemmas

Suggested order:

1. `merge_assoc` where fields are associative, and explicit counterexamples
   for fields that are not (e.g. `Options Set`).
2. `phase_order`: folding phases in `Directory < Files < Location <
   Condition` order is equivalent to the reference interpreter.
3. `htaccess_interleave`: the per-directory fold matches the reference
   sequence `Directory, access-file` at each level.
4. `require_eval_sound`: `eval_policy` returns `Allowed` only if the policy
   actually grants under the provider semantics.
5. `require_none_never_grants`: a `<RequireNone>` subtree cannot produce a
   grant by itself.
6. `override_gate`: if `allowed(mode, directive) == false`, applying the
   directive leaves the scope unchanged (or produces the error result).
7. `prefilter_sound`: fast-path predicates imply the authoritative checks.
8. `acl_reachability`: every dispatch branch that returns a file/proxy body
   has a predecessor `check(scope, req) == Allowed`.

## 10a. Mechanized pieces already connected

`crates/server/src/policy_ref.rs` is the single pure evaluator for the
configuration phases **and** for access-file layers.  The walker only parses
`.htaccess` files into `AccessLayer` values; `effective_scope_with_layers`
performs the interleaving.  Production dispatch, cache and websocket paths
call this evaluator, so configuration/access-file ordering equivalence is by
construction: there is no second production interleaver.

`crates/verified` now reports **194 verified functions, 0 errors**.  The following pieces are Verus-checked; items marked model-only await a runtime projection/refinement:

- `PolicyResult`, `combine_and`, `combine_or`, `require_none_result`.
  `crates/server/src/access.rs` calls these for
  `<RequireAll>`/`<RequireAny>`/`<RequireNone>`.
- `AccessStep`, `access_walk_plan`, `access_plan`, `access_plan_exec`.
  `policy_ref::effective_scope_with_layers` iterates the verified plan.  The
  plan has one `Walk { access }` step per ancestor directory, with the
  per-directory `Directory; access-scope` interleaving inside that step, then
  the exact suffix `DirectoryMatch, ConfigFiles, AccessFiles, Location,
  config If, access If`.  `access_plan_interleaves` proves one step per
  directory, every walk before the suffix, and the suffix shape.
- `auth_merge_kind`.  `Scope::merge` uses this three-way verified decision
  (`Replace`/`And`/`Or`) before constructing the authorization tree.
  `auth_merge_kind_properties` proves that `And`/`Or` are impossible without
  an inherited parent policy.
- `option_child_wins` / `option_child_presence`.  Scalar and
  clone-based optional security fields in `Scope::merge` use verified
  child-wins combinators.  Presence is proved exact; the underlying clone is a
  standard-library primitive.
- `append_vec`, `merge_containers`, `container_append_preserves_parent`,
  `container_lookup_pair` and `container_append_child_lookup_wins`.  Every
  container/list field in `Scope::merge` now appends through the verified
  `append_vec` helper, including list-backed `ErrorDocument` and `RewriteMap`
  fields.  Child values win by reverse lookup.  Debug builds still audit the
  concrete `Scope` containers after every merge against a projected snapshot
  and fail if a field is omitted or reordered.
- `options_apply`.  `Scope::effective_options` uses the verified
  Set/Add/Remove operation instead of an open-coded match.
- `expr_value_truthy` and `cond_chain_eval`.  Expression values map to
  booleans through the verified truthiness table, and rewrite `[OR]` condition
  groups fold through the verified condition-chain evaluator.  Leaf evaluators
  that consult regex, filesystem, IP or request state remain explicit
  assumptions.
- `regex_dialect_admit` / `guard_regex` / `compile_regex`.  Every
  configuration- and expression-supplied regex is admitted only after the
  verified dialect guard: backreferences, look-around, other PCRE-only
  constructs, control bytes and oversized patterns fail closed.  The external
  regex engine still supplies the matching semantics for the accepted
  regular subset.
- `directive_disposition`.  The configuration fallback uses a verified
  four-way disposition: security-sensitive unhandled directives fail closed,
  known module directives warn, strict unknown directives fail, and ordinary
  unknown directives warn in compatibility mode.
- `access_layer_slot`.  Parsed `.htaccess` rules are translated into
  conditional, Files or top-level layer slots by a verified decision used by
  `collect_layers`.
- `config_line_kind`.  The pure front-end IR classifies a tokenized line as a
  directive, section start or section end using a verified decision.
  `config_frontend::parse_line` consumes this classification.
- `config_section_nesting_allowed`.  The recursive configuration compiler
  checks section transitions through the verified context table.  Raw
  tokenization, directive arguments and directive-specific refinements remain
  the explicit parser-refinement assumption.
- `classify_access_rule`.  `htaccess::collect_layers` uses this verified
  partition: condition/non-normal rules go to the deferred conditional bucket,
  `<Files>` rules to the Files bucket, and everything else to the top-level
  scope.
- `h2_method_ok`, `h2_head_admit`, `H2BodyState`/`h2_body_append`, and
  `H2Budget`.  The HTTP/2 adapter calls the verified method/head decision and
  advances a verified body budget as it consumes DATA frames.  `H2Settings`
  fixes the builder limits; `H2HeaderState` bounds the decoded header list;
  and `H2Flow` models connection/stream windows and send-buffer bounds.  The
  response path uses h2 reserve/poll capacity before each DATA send, so a
  zero/small client window cannot make the adapter queue unbounded response
  bytes.  `H2Budget` is
  now driven by the connection/task loop: `Begin` at accept, `Finish` when
  the task ends, `Reset` for a `SendResponse::poll_reset` event, a
  `RecvStream` reset error, a timeout, or a send failure, and `Reclaim` from a
  timer equal to the h2 reset-stream duration.  A replay
  theorem preserves both counters for any finite event sequence.  The adapter
  also tracks stream IDs and uses a verified idempotent purge set, so a
  duplicate early-reset/close cleanup is a no-op; this is the
  CVE-2026-23918 primitive.  The ledger's begin path now calls
  `h2_stream_admit`, which proves a new stream ID is neither active nor
  awaiting reset cleanup.  `H2StreamPhase`/`h2_stream_phase_step` fix the
  adapter-local lifecycle and prove `Closed` is absorbing, so a closed ID
  cannot be reopened.  The h2 crate still owns wire framing and resets that it
  handles internally without surfacing to the adapter; that external wire
  behavior is now an explicit assumption rather than an unverified adapter
  component.
- `rewrite_backref_no_qmark`, `rewrite_filesystem_admit`,
  `rewrite_target_external`, `rewrite_internal_path` and
  `rewrite_authority_equal`.  Rewrite backreference/variable expansion uses
  the verified question-mark encoder by default.  External HTTP(S)/scheme-
  relative targets are classified exactly, internal targets are given a
  single leading slash, and same-host internalization compares authority and
  optional decimal port with ASCII case folding.  Absolute rewritten
  filesystem targets are admitted only below the document root or, with
  explicit `UnsafePrefixStat`, the server root.
- `proxy_target_key`.  Proxy grant binding uses an exact, verified
  length-delimited identity of `(tls, host, port, path)`; host/path NUL
  characters are excluded by the validated inputs.  The runtime converts the
  key to hex for string comparison.
- `cache_lookup_admit`.  Cache hits require matching key, policy fingerprint,
  `Vary` values and freshness (`now < expires`); the runtime uses this
  verified decision for memory and disk entries.
- Cache credential exclusion.  Disk metadata stores response headers, not
  request headers, and explicitly drops Authorization/Proxy-Authorization;
  cache keys include the policy fingerprint and query.
- Proxy target authority binding.  `ProxyPassMatch` and rewrite `[P]`
  authority templates are rejected when derived from captures or variables;
  targets are canonical and paths are encoded exactly once.  Backend response
  `Location` values also pass the verified header sanitizer.
- Expression filesystem confinement.  `file()` and `filesize()` data paths
  are confined beneath `DOCUMENT_ROOT`; absolute, parent-relative and
  symlink-escaping reads fail closed.  `FileTest` remains metadata-only (and
  is also used by admin `<IfFile>`), so it does not expose file contents.
- `escape_log_bytes`.  Client-derived access-log fields are escaped by a
  verified primitive, including controls, quotes and backslashes.
- HTTP request/header/body and compression budgets.  The verified HTTP/1
  parser plus `H2Settings`, `H2HeaderState`, `H2Flow` and the fixed compression
  cap cover the generic DoS class; the remaining HPACK/zero-window behavior is
  delegated to the explicit h2 wire-framing assumption.
- `cgi_env_entry_admit`.  Configured/rewrite environment entries pass only
  when their key is valid and not a calculated CGI/`HTTP_*` name.
- CGI calculated-environment reservation.  `cgi::build_env` refuses to let
  configured/rewrite environment entries override request, connection or
  identity variables such as `REQUEST_METHOD`, `SCRIPT_FILENAME`,
  `CONTENT_LENGTH`, `REMOTE_ADDR` and `HTTP_*`; custom variables still pass
  through.  CGI stdout/stderr, timeouts, and FastCGI headers are bounded.
- `tls_client_policy_equal` / `ensure_uniform_client_policy`.  Every TLS
  listener requires one client-certificate policy across its virtual hosts;
  mixed `SSLVerifyClient`/`SSLCACertificateFile` configurations fail startup.
  The runtime compares a verified exact identity of verification mode and CA
  path bytes, with absent and present CA distinguished.  Per-location client
  authentication is rejected because Rustls verifies the connection, not an
  individual request; Rustls chain validation itself remains an external
  TLS assumption.
- `host_pattern_matches` / `host_suffix_matches`.  `VHost::matches_name`
  uses verified exact, `*.suffix` and `.suffix` matching with ASCII case
  folding and DNS-label boundaries.  Invalid regex `ServerAlias` patterns are
  rejected at configuration load.
- `first_true_index`.  Virtual-host candidate selection uses the verified
  first-match policy.
- `ipv4_in_net` / `ipv6_in_net` and `first_untrusted_index`.  RemoteIP trust
  chain selection and IP network membership use verified functions.  Literal
  IP/authority parsing remains an explicit assumption.

`crates/server/src/access.rs` also exposes an `AccessGrant` capability with a
concrete `ResourceKey` (vhost, method, URL, filesystem path, proxy target,
cache key, identity).  A grant for `/public/file` cannot authorize
`/private/file`, a different proxy target, or another cache key; the cache,
static file/directory, CGI, FastCGI, HTTP proxy and WebSocket sinks verify the
key.  This is the resource-binding part of I1.  The WebSocket upgrade path
canonicalizes the raw target, runs the same rewrite gate, evaluates the target
scope, and uses the same method/access helper before taking the connection.  A
rewrite that changes the filesystem target re-evaluates
`<Directory>`/`<Files>`/`.htaccess` policy for that target before dispatch.

Static file/directory grants now carry the opened inode and a symlink target
is re-authorized.  Proxy/cache grants remain path/URL-bound, and CGI/FastCGI
script descriptors are selected after the grant rather than bound to an
inode.  Those are the next resource-binding steps, along with the parser, the regex engine and expression leaf evaluators, and
directory sort/pairing outside Verus.

Security-sensitive unimplemented directives fail closed in compatibility mode.
The classifier covers the auth/TLS/proxy/filter/DAV/LDAP/cache families by
name prefix, not only an explicit denylist; the warning-only fallback is
reserved for directives with no access, auth, proxy, filter or path-policy
effect.

### Policy-core migration

The first `ScopePolicy` slice now exists in
`crates/server/src/scope_policy.rs`:

- `OptionsPolicy` stores the ordered Set/Add/Remove sequence and evaluates it
  through the verified `options_apply` primitive;
- `OverridePolicy` owns `AllowOverride`, `AllowOverrideList` and
  `Nonfatal=...` inheritance, with child-presence merge semantics;
- `AuthorizationPolicy` owns `requires`, `auth_merging`, `AllowMethods` and
  legacy `Order`/`Allow`/`Deny` state, using the verified `auth_merge_kind`
  decision and child-presence inheritance;
- `HeaderPolicy` owns header add/set/unset lists, expiration state,
  cookies and Vary, with append/child-presence merge rules;
- `EnvironmentPolicy` owns `SetEnv`/`UnsetEnv`/`PassEnv`/`SetEnvIf` state;
- `ContentPolicy` owns directory defaults, MIME add/remove/force types,
  ETag/sendfile/directory-slash and access-file names;
- `MappingPolicy` owns aliases, redirects, handlers and unsupported filters;
- `ErrorDocumentPolicy` owns the ordered status-code document list with
  reverse child-wins lookup;
- `RewriteCachePolicy` owns rewrite engine/maps/base/rules and cache
  enable/disable state; pending rewrite conditions remain section-local;
- `CompressionPolicy` owns compression rules and deflate/brotli settings;
- `ProxyPolicy` owns proxy rules, pass/reverse mappings and the proxy CA file;
- `AuthorizationPolicy` also owns the auth type/name and user/group file
  handles;
- `ContentPolicy` also owns the document root;
- `Scope` now contains only policy objects rather than the old ad-hoc fields;
- parser construction, access checks, `.htaccess` gating and cache policy
  fingerprints read the policy objects directly.

The `ScopePolicy` migration is complete at the runtime-data level: `Scope`
now stores policy objects for all former fields.  The next formal step is the
abstract model/projection proof over these policy objects.

### Parser-proof starting point

`crates/server/src/config_frontend.rs` now isolates the pure front-end pieces
that the proof will target:

- logical-line accumulation with source line numbers;
- Apache-style quoted/escaped tokenization;
- a small `ConfigLine` IR for directives, section starts and section ends.

Both the configuration parser and the `.htaccess` parser use the shared
tokenizer; the configuration compiler uses the shared logical-line helper.
The IR is deliberately free of filesystem access, include expansion, section
context and directive dispatch.  The config compiler and `.htaccess`
`parse_block` now consume the IR for line classification, and
`config_line_kind` plus `config_section_nesting_allowed` are verified and used
by the runtime.  `OptionsPolicy` and `OverridePolicy` are the first migrated
policy objects; authorization is the next slice.  The remaining proof work is
the byte-level tokenizer refinement, directive-argument semantics, and the full
IR-to-concrete `Scope` mapping; the AccessLayer slot and directive disposition
boundaries are already verified.

### Remaining refinement boundary

The verified plan is consumed by the evaluator.  The root-to-leaf directory
sort/pairing and raw configuration/access-file tokenization remain outside
mechanical proof; container/list field merging and the security disposition /
layer-slot translation use verified helpers.  The parser is covered by the
explicit `configuration parsing refines the model` assumption.

The authorization decision, access-phase interleaving, Options algebra,
scalar overrides, `.htaccess` rule classification, expression truthiness and
rewrite condition-chain folding are verified kernels.  The parser-to-model
translation, Directory sort, regex semantics and the
filesystem view are explicit assumptions, not hidden axioms.

## 10b. Verification progress ledger

Verification progress is tracked as **security obligations and proof debt**,
not as a count of verified functions. The machine-readable ledger is
`docs/verification-status.json`; the gate is:

```sh
python3 tests/verification_status.py
python3 tests/verification_status.py --run-verus
```

The current ledger (2026-10-24) is:

- weighted obligations: **3.5 / 8.0 (43.8%)** if partial obligations receive
  half credit;
- proof debt: **6 / 6** — 0 named unverified security components, 0 partially
  bound sinks, 6 assumptions and 0 accepted unmodeled security-directive
  classes;
- sinks: **8/8** grant-required, **8/8** path/target-bound, **3/8**
  inode-bound, **3/8** backend-target-bound, **2/8** policy-key-bound;
- unexplained adversarial replay failures: **0** (the CVE replay corpus is
  not yet systematic);
- Verus: **194 functions, 0 errors**, with no `assume` or `external_body`
  proof escapes.

The gate fails when proof debt exceeds its budget, the weighted score drops
below its floor, an inode-bound sink regresses, a proof escape appears, or a
sink stops requiring a grant. Raising a budget is an explicit change to the
ledger, not an implicit effect of adding code.

## 11. Current test oracle

## 11a. Acceptance/rejection obligations

Two finite obligations are checked explicitly:

- **Acceptance:** for every configuration in the supported directive/context
  grammar, if Apache accepts it, vapached accepts it.
- **Rejection:** every malformed/invalid configuration in that same grammar is
  rejected by vapached.

`tests/config_grammar.py` enumerates the grammar and currently reports **0
divergences** against Apache.  This is exhaustive for the listed finite
subset, not a proof over arbitrary Apache syntax.

## 11b. Test oracle

The pre-proof suite is:

- `tests/conformance.py` — 165 fixed Apache differential/conformance tests.
- `tests/config_semantics.py` — 194 systematic generated cases, plus
  `--random N --seed S` deterministic randomized cases.
- `tests/config_validity.py` — `apache2 -t` vs `vapached -t` context matrix.
- `tests/config_grammar.py` — finite supported directive/context grammar,
  including valid and invalid argument/section forms.
- Rust unit invariants in `config.rs`, `htaccess.rs`, `access.rs`.

Until the model is mechanized, any change to merge order or override gating
must be accompanied by a differential case.  The generated suite is the
current definition of “matches Apache” for the covered surface.

## 12. Known gaps before formal proof

- Configuration phases and access-file interleaving now run through a verified
  plan consumed by the single production evaluator.  The directory
  sort/pairing and raw parser tokenization are still outside Verus and remain
  covered by the explicit `configuration parsing refines the model`
  assumption.  Container/list field merging, directive disposition and
  `.htaccess` layer-slot translation use verified helpers.
- Some module-specific merge rules are not modelled.  `AllowOverrideList`,
  `Nonfatal=...`, `Include`/`IncludeOptional` and the covered contexts are now
  implemented or covered by the differential/context matrices.
- Regex semantics are assumed, not proved.
- Vhost/Include precedence is only lightly covered by the generated suite.
- `--explain` now lists matching nested configuration rules with phase,
  order and condition result, and traces access files with their override
  mode, list, nonfatal mode and parsed rule count.  It does not yet show the
  action-by-action merge of every `.htaccess` directive.
- I1 is capability-enforced for cache/file/directory/CGI/FastCGI/proxy and the
  WebSocket tunnel path.  A few explicit pre-auth error paths still construct
  responses before an access check; those are documented separately.
- I3 prefilters are covered by unit/property tests and the cache lookup now
  requires an `AccessGrant`; the prefilter implication itself is not yet a
  Verus theorem.
- The durable `.htaccess` cache/metadata invalidation is outside the model.

## 13. Apache CVE triage

The NVD CPE `apache:http_server` snapshot is triaged in
`docs/cve/apache2-cve-matrix.json` (371 CVEs).  The current result is:

- 370 prevented in principle by construction, verified primitives or
  fail-closed rejection,
- 0 partially covered,
- 1 not covered by the formal specification,
- 0 unclassified.

The sole uncovered row is the external Rustls certificate parser
(`CVE-2004-0488`), treated as an explicit dependency assumption.
The complete methodology and limits are in `docs/cve/README.md`; regenerate
and validate with:

```sh
python3 tests/cve_matrix.py
python3 tests/cve_matrix.py --check
```

This is a static per-CVE triage, not a claim that a working PoC replay exists
for every row.
