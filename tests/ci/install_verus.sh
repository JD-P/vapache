#!/bin/sh
set -eu

version=${VERUS_VERSION:-0.2026.10.18.7d82994}
destination=${1:-"$PWD/.tools/verus"}
archive="verus-${version}-x86-linux.zip"
url="https://github.com/verus-lang/verus/releases/download/release/${version}/${archive}"

mkdir -p "$destination"
curl --fail --location --retry 3 "$url" -o "$destination/$archive"
unzip -q "$destination/$archive" -d "$destination/unpacked"
cargo_verus=$(find "$destination/unpacked" -type f -name cargo-verus -perm -u+x | head -n 1)
[ -n "$cargo_verus" ] || {
    echo "install-verus: cargo-verus not found in $archive" >&2
    exit 1
}
bin=$(dirname "$cargo_verus")
printf '%s\n' "$bin"
if [ -n "${GITHUB_PATH:-}" ]; then
    printf '%s\n' "$bin" >> "$GITHUB_PATH"
fi
