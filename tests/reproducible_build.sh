#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

first=$(mktemp -d /tmp/vapache-repro-a.XXXXXX)
second=$(mktemp -d /tmp/vapache-repro-b.XXXXXX)
trap 'rm -rf "$first" "$second"' EXIT INT TERM

SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
export SOURCE_DATE_EPOCH
CARGO_TARGET_DIR=$first cargo build --locked --release -p vapached
CARGO_TARGET_DIR=$second cargo build --locked --release -p vapached

first_hash=$(sha256sum "$first/release/vapached" | cut -d' ' -f1)
second_hash=$(sha256sum "$second/release/vapached" | cut -d' ' -f1)
[ "$first_hash" = "$second_hash" ] || {
    echo "reproducible-build: binary hashes differ" >&2
    echo "first:  $first_hash" >&2
    echo "second: $second_hash" >&2
    exit 1
}
echo "reproducible-build: $first_hash"
