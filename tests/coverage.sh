#!/bin/sh
# Combined line coverage for vapached: Rust unit tests plus the end-to-end
# conformance suite.
#
# The server and test binaries are built with -C instrument-coverage into
# target/cov, the Python suite drives the real binary (Apache is only used for
# differential checks), and llvm-profdata/llvm-cov merge all profiles.
set -eu

cd "$(dirname "$0")/.."

SYSROOT="$(rustc --print sysroot)"
HOST="$(rustc -vV | awk '/^host:/ {print $2}')"
LLVM_BIN="$SYSROOT/lib/rustlib/$HOST/bin"
PROFILE_DIR="${PROFILE_DIR:-/tmp/vapcov}"

rm -rf target/cov "$PROFILE_DIR"
mkdir -p "$PROFILE_DIR"
chmod 777 "$PROFILE_DIR"

CARGO_TARGET_DIR=target/cov RUSTFLAGS="-C instrument-coverage" \
    cargo build --release -p vapached

CARGO_TARGET_DIR=target/cov RUSTFLAGS="-C instrument-coverage" \
LLVM_PROFILE_FILE="$PROFILE_DIR/unit-%p-%m.profraw" \
    cargo test --workspace -- --test-threads=1

if command -v apache2 >/dev/null 2>&1; then
    VAPACHED="$PWD/target/cov/release/vapached" \
    LLVM_PROFILE_FILE="$PROFILE_DIR/vapache-%p-%m.profraw" \
    PYTHONDONTWRITEBYTECODE=1 \
        python3 tests/config_grammar.py

    VAPACHED="$PWD/target/cov/release/vapached" \
    LLVM_PROFILE_FILE="$PROFILE_DIR/vapache-%p-%m.profraw" \
    PYTHONDONTWRITEBYTECODE=1 \
        python3 tests/config_validity.py

    VAPACHED="$PWD/target/cov/release/vapached" \
    LLVM_PROFILE_FILE="$PROFILE_DIR/vapache-%p-%m.profraw" \
    PYTHONDONTWRITEBYTECODE=1 \
        python3 tests/config_semantics.py --random 128 --seed 2469
else
    echo "coverage: Apache not found; skipping differential config suites"
fi

VAPACHED="$PWD/target/cov/release/vapached" \
LLVM_PROFILE_FILE="$PROFILE_DIR/vapache-%p-%m.profraw" \
PYTHONDONTWRITEBYTECODE=1 \
    python3 tests/conformance.py

VAPACHED="$PWD/target/cov/release/vapached" \
LLVM_PROFILE_FILE="$PROFILE_DIR/vapache-%p-%m.profraw" \
PYTHONDONTWRITEBYTECODE=1 \
    python3 tests/adversarial_regressions.py

"$LLVM_BIN/llvm-profdata" merge -sparse -failure-mode=all "$PROFILE_DIR"/*.profraw \
    -o "$PROFILE_DIR/all.profdata"

# Pass the release binary plus every instrumented test executable so the
# report covers both the daemon and the unit-test-only code paths.
set -- target/cov/release/vapached
if [ -x target/cov/debug/vapached ]; then
    set -- "$@" -object target/cov/debug/vapached
fi
for bin in target/cov/debug/deps/vapache*; do
    if [ -x "$bin" ] && [ ! -d "$bin" ]; then
        set -- "$@" -object "$bin"
    fi
done
"$LLVM_BIN/llvm-cov" report "$@" \
    -instr-profile="$PROFILE_DIR/all.profdata" \
    --ignore-filename-regex='(\.cargo|rustc|/root/\.rustup)'
