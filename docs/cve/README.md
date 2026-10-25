# Apache HTTP Server CVE triage matrix

This directory contains a complete static triage of the Apache HTTP Server
CVEs in the NVD CPE set:

```text
cpe:2.3:a:apache:http_server
```

The snapshot contains **371 CVEs**. It is a triage of whether the current
Vapache specification and implementation boundary would prevent each CVE
*in principle*, not a claim that every CVE has a working replay test.

## Files

- `nvd-cpe.json` — NVD 2.0 response used as the source snapshot.
- `apache2-cve-matrix.json` — one row per CVE with status, surface,
  severity, confidence, rationale and description.
- `apache2-cve-matrix.csv` — the same full matrix in spreadsheet form.
- `apache2-cve-matrix.md` — summary and the highest-risk gap list.

Regenerate and validate:

```sh
python3 tests/cve_matrix.py
python3 tests/cve_matrix.py --check
```

## Current result

| classification | count |
|---|---:|
| prevented by construction / verified primitive | 126 |
| fail closed / not applicable | 244 |
| **spec prevents in principle** | **370** |
| partial: some layers verified, full class not | 0 |
| **not covered by the formal spec** | **1** |

The sole not-covered CVE is:

| surface | count |
|---|---:|
| TLS client certificate / OCSP (external Rustls parser) | 1 |

It has medium severity; there are **0 high/critical not-covered rows**. There are no remaining partial rows.

This means the current spec is not a blanket “all Apache CVEs prevented”
claim. It is strong on the parsed/fail-closed core and weak on the
implemented-but-unmodelled protocol surfaces.

## Method and limits

Status meanings:

- **prevented** — Rust memory safety, verified parsing, `openat2`
  containment, Rustls, or another construction/verification primitive
  removes the vulnerability primitive.
- **fail_closed / not_applicable** — the module, platform, directive or
  feature is absent or rejected.
- **partial** — a relevant layer is verified, but the complete CVE class is
  not; for example HTTP/1 framing is verified while HTTP/2 or proxy
  translation is not.
- **not_covered** — the production behavior is implemented but outside the
  formal model.

Classification is static and intentionally conservative. It uses NVD
descriptions plus explicit human overrides for ambiguous historical cases.
It does not execute each CVE PoC, and NVD descriptions can be incomplete.
The grouping and proposed spec strengthening for the 1 not-covered row are
in `not-covered-strengthening.md`.  The next step is a replay corpus for the
0 high/critical not-covered rows.
