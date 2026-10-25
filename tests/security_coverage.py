#!/usr/bin/env python3
"""Track production-line coverage for unproven security-critical modules.

`tests/coverage.sh` produces whole-program coverage, including `#[cfg(test)]`
test modules.  For attack-surface tracking we care about the production lines
before the file's test module.  This script reads the same coverage artifacts
and reports those numbers, and fails when an enforced module drops below 100%.

Usage:
    sh tests/coverage.sh
    python3 tests/security_coverage.py
    python3 tests/security_coverage.py --check
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROFILE = Path(os.environ.get("SECURITY_COVERAGE_PROFILE", "/tmp/vapcov/all.profdata"))
COV_TARGET = ROOT / "target" / "cov"

# (name, source path, required percentage).  Start with the modules whose
# protocol/process boundaries are hardest to prove, and promote them one at a
# time as their production-line coverage reaches 100%.
MODULES = [
    ("fastcgi", "crates/server/src/fastcgi.rs", 100.0),
    ("cgi", "crates/server/src/cgi.rs", 100.0),
    ("http", "crates/server/src/http.rs", 100.0),
    ("h2", "crates/server/src/h2.rs", 100.0),
    ("proxy", "crates/server/src/proxy.rs", 100.0),
    ("tls", "crates/server/src/tls.rs", 100.0),
    ("server", "crates/server/src/server.rs", 100.0),
    ("htaccess", "crates/server/src/htaccess.rs", 100.0),
    ("config", "crates/server/src/config.rs", 100.0),
    ("expr", "crates/server/src/expr.rs", 100.0),
    ("rewrite", "crates/server/src/rewrite.rs", 100.0),
]

# Enforced modules are at 100% production-line coverage.  The rest are reported
# so the next module can be promoted without changing the measurement method.
ENFORCED = {"fastcgi", "http", "tls"}


def llvm_bin() -> Path:
    sysroot = subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip()
    host = subprocess.check_output(["rustc", "-vV"], text=True)
    host = next(line.split(":", 1)[1].strip() for line in host.splitlines() if line.startswith("host:"))
    return Path(sysroot) / "lib" / "rustlib" / host / "bin"


def coverage_objects() -> list[str]:
    objects = [str(COV_TARGET / "release" / "vapached")]
    for path in sorted((COV_TARGET / "debug" / "deps").glob("vapache*")):
        if path.is_file() and os.access(path, os.X_OK):
            objects.extend(["-object", str(path)])
    return objects


def export_lcov() -> str:
    if not PROFILE.exists():
        raise SystemExit(f"missing {PROFILE}; run tests/coverage.sh first")
    objects = coverage_objects()
    if not Path(objects[0]).exists():
        raise SystemExit(f"missing {objects[0]}; run tests/coverage.sh first")
    cmd = [
        str(llvm_bin() / "llvm-cov"),
        "export",
        objects[0],
        *objects[1:],
        f"-instr-profile={PROFILE}",
        r"--ignore-filename-regex=(\.cargo|rustc|/root/\.rustup)",
        "-format=lcov",
    ]
    return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)


def production_lines(source: Path, records: dict[int, int]) -> tuple[int, int]:
    text = source.read_text().splitlines()
    # Files such as htaccess.rs contain `#[cfg(test)]` helpers before the real
    # test module; the module itself starts at a top-level `mod tests`.
    test_start = next(
        (i for i, line in enumerate(text, 1) if line.strip().startswith("mod tests")),
        len(text) + 1,
    )
    executable = [(n, c) for n, c in records.items() if n < test_start]
    missed = sum(1 for _, count in executable if count == 0)
    return len(executable), missed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if an enforced module is below 100%")
    args = parser.parse_args()

    data: dict[str, dict[int, int]] = {}
    current = None
    for line in export_lcov().splitlines():
        if line.startswith("SF:"):
            current = line[3:]
            data[current] = {}
        elif line.startswith("DA:") and current:
            number, count = line[3:].split(",", 2)[:2]
            data[current][int(number)] = int(count)

    print("production-line coverage for unproven security-critical modules")
    print(f"{'module':12} {'lines':>7} {'missed':>7} {'cover':>8}   status")
    failed = False
    by_name = {name: path for name, path, _ in MODULES}
    for name, rel, required in MODULES:
        source = ROOT / rel
        suffix = "/" + rel
        record = next((v for k, v in data.items() if k.endswith(suffix)), None)
        if record is None:
            print(f"{name:12} {'-':>7} {'-':>7} {'-':>8}   missing from profile")
            failed = failed or name in ENFORCED
            continue
        total, missed = production_lines(source, record)
        cover = 100.0 if total == 0 else 100.0 * (total - missed) / total
        status = "enforced" if name in ENFORCED else "tracked"
        if name in ENFORCED and cover < required:
            status = "FAIL"
            failed = True
        print(f"{name:12} {total:7d} {missed:7d} {cover:7.2f}%   {status}")

    if args.check and failed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
