#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if ! command -v cargo-careful >/dev/null 2>&1; then
    echo "careful: cargo-careful is required" >&2
    exit 2
fi
cargo +nightly careful test --workspace --all-targets -- --test-threads=1
