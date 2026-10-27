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
| `p11/exploit_p11.py` | Pass-11 differential exploit battery: 13 micro-apps run against Apache 2.4.69 and vapached, one per finding row |
| `p11/case01-F61-A` … `case13-F61-C` | Captured case dossiers (rendered `apache.conf` / `vp.conf`, fixture tree, server logs, `ap.strace`) |
| `p11/f70_accessfilename.py` | F70 probe (dead finding: Apache rejects the configuration) |

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
remediation) and are regenerated in place on each run.  On this shared host
Apache occasionally fails to start (a cron-restarted system Apache steals the
pidfile); the harness retries each case once, and an `apache=-1` row means the
oracle was unavailable, not that vapached diverged.

The matching end-to-end regression replays live in
`tests/adversarial_regressions.py` (`F61ToF69Pass11Tests`); the closure status
of every finding is tracked in `docs/adversarial-closure.md`.
