# Apache access-control parity

VApache treats Apache as an executable compatibility oracle for the supported
configuration surface.  This is stronger than waiting for an adversarial pass
to discover a semantic mismatch: every security-sensitive compatibility change
should add both a source-derived model and a differential case that runs the
same configuration and request against Apache and VApache.

## The refinement rule

For every supported configuration and request, VApache must not reach a
protected sink when Apache denies, challenges, or rejects that request.  Exact
status and selected identity parity is the default test.  A deliberate VApache
divergence is allowed only when it is documented and is a security refinement,
such as refusing to trust `RemoteIPHeader` when no proxy trust list exists.

The protected sinks are static-file reads, directory listings, CGI and FastCGI
execution, HTTP/WebSocket proxying, and cache reads and writes.  The compared
identity includes the original URL, effective client address, selected
filesystem object, handler, FastCGI lexical script name, backend, and relevant
authorization scope.

## Current gate

`tests/config_semantics.py` is the live oracle.  It starts Apache and VApache
with paired configurations, sends the same requests, and compares outcomes.
`tests/coverage.sh` runs its fixed corpus plus 128 deterministic generated ACL
cases.  P15 adds PCRE expression and `mod_remoteip` chain cases.  The
end-to-end P15 cases in `tests/adversarial_regressions.py` independently pin
FastCGI lexical/canonical identity, canonical-target authorization, trusted
proxy address handling, and fail-closed expression behavior.

The corresponding production decisions are small Verus kernels:

- `expr_regex_result` makes an expression evaluation error incapable of
  becoming a grant, including through negation.
- `remoteip_next_internal` and `remoteip_candidate_admit` model Apache's
  internal/trusted proxy class transition and its rejection of private
  addresses presented by an external chain.
- `fastcgi_script_identity_admit` requires the backend identity to bind both
  the lexical path sent as `SCRIPT_FILENAME` and the canonical path used for
  containment and authorization.

The RemoteIP model was derived from Apache 2.4.69
[`mod_remoteip.c`](https://github.com/apache/httpd/blob/2.4.69/modules/metadata/mod_remoteip.c).
The FastCGI behavior is pinned to Apache 2.4.69
[`mod_proxy_fcgi.c`](https://github.com/apache/httpd/blob/2.4.69/modules/proxy/mod_proxy_fcgi.c).
Expression parity is checked against Apache's PCRE implementation rather than
approximating PCRE with Rust's regular-expression dialect.

## Extracted Apache models

The proposed Apache extractor would help.  A source-derived transition system,
SMT model, or Lean embedding can cover combinations that a hand-maintained
differential corpus will miss and can turn “Apache already handles this” into a
refinement obligation.  The useful deliverable is the extractor plus a pinned,
reproducible model artifact; a prose claim of bisimilarity is not itself a
security boundary.

When such an artifact is available, integration should require:

1. Pin the Apache source revision and extractor revision and check in the model
   hash and generation command.
2. Validate the extracted model against the Apache binary on a generated
   configuration/request corpus.  This catches extraction and build-option
   drift.
3. Translate the supported subset into VApache's request-to-sink state and
   prove the security-refinement rule above.  Unsupported Apache states must
   reject at configuration load, not disappear from the model.
4. Keep the live differential gate.  It is an independent check of the
   extractor, model translation, and VApache runtime wiring.

Until an extractor artifact is published, the same structure is applied
manually: read the relevant upstream module, encode its decision as a consumed
kernel, and add fixed plus generated binary differentials.  This makes Apache
parity a pre-merge control instead of an adversarial-review afterthought.
