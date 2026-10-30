#![no_main]

// Keep the security-review artifact beside the P23 findings while retaining
// this conventional cargo-fuzz entry point for CI and nightly campaigns.
include!("../../adversarial/p23/pcre2_differential_fuzzer.rs");
