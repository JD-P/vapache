# PCRE2 compatibility-engine benchmark

Measured 2026-10-30 after the P23 remediation on Linux 6.18.55, an AMD EPYC
9V74 worker (5 available cores), Rust 1.99.1. The benchmark is single-threaded,
uses release builds, reports the median of seven samples, and compares the same
`captures` API because that is what vapache expressions use.

The “vapache” column is the safe-Rust compatibility frontend and deterministic
automata backend guarded by the Verus-verified engine-mode and resource
admission kernels. The automata implementation itself is a documented proof
assumption, not code translated from Verus.

```sh
cargo run -p vapache-pcre2 --release --example pcre2_benchmark
```

The C columns use the test-only PCRE2 10.46 oracle through `pcre2` 0.2.11,
once as the interpreter and once with JIT requested. Times are nanoseconds per
operation; lower is better.

| Case | Operation | vapache | C interpreter | C JIT | vapache / C interpreter |
|---|---|---:|---:|---:|---:|
| literal anchor | compile | 7,766.7 | 560.1 | 2,721.4 | 13.867 |
| literal anchor | captures | 103.4 | 124.4 | 93.2 | 0.831 |
| captures over 4 KiB | compile | 27,848.6 | 1,055.9 | 6,182.9 | 26.375 |
| captures over 4 KiB | captures | 65.1 | 6,014,311.4 | 2,481.4 | 0.000011 |
| alternation over 4 KiB | compile | 25,794.2 | 795.4 | 5,646.4 | 32.429 |
| alternation over 4 KiB | captures | 347.4 | 141,907.2 | 235.2 | 0.002448 |
| byte/POSIX class | compile | 65,779.3 | 685.4 | 3,447.4 | 95.973 |
| byte/POSIX class | captures | 133.4 | 193.3 | 89.7 | 0.690 |
| `\Q…\E\Z` lowering | compile | 8,583.5 | 501.1 | 4,040.0 | 17.130 |
| `\Q…\E\Z` lowering | captures | 122.7 | 117.3 | 86.6 | 1.046 |
| `a{8000}` / 8,190 bytes | resource guard / captures | 10.3 | 4,547.0 | 2,274.0 | 0.002258 |

Interpretation:

- Compilation is 13.9–96.0× slower than the C interpreter because vapache
  performs compatibility parsing, byte-class normalization, structural work
  accounting and automata compilation. Configuration load is the intended
  place to pay this cost; compiled expressions are reused.
- Warm captures are close to the C interpreter on simple cases (0.69–1.05×)
  and 1.11–1.49× the C JIT on the simple literal/class cases. The automata
  engine is dramatically faster than the C interpreter on the deliberately
  backtracking-sensitive 4 KiB capture and alternation subjects.
- The counted-repetition row is a security-policy comparison rather than a
  successful-match throughput comparison. Vapache rejects the request at its
  verified work gate in about 0.24 µs; PCRE2 executes it. Before P23-A, the
  vapache engine admitted this shape and the original adversarial live test
  measured roughly 350 ms. The checked-in row is a warmed median-of-seven;
  each C sample executes once while the much cheaper guard uses 10,000
  iterations per sample.

Microbenchmarks are sensitive to CPU placement and allocator state. The
checked-in example is the source of truth and should be rerun on deployment
hardware for capacity planning.
