#!/usr/bin/env python3
"""Prevent unaudited growth of the libc/raw-pointer boundary."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "docs/unsafe-baseline.json"


def inventory():
    result = {}
    for path in sorted((ROOT / "crates/server/src").glob("*.rs")):
        count = sum(
            1 for line in path.read_text().splitlines()
            if re.search(r"\bunsafe\b", line) and not line.lstrip().startswith("//")
        )
        if count:
            result[str(path.relative_to(ROOT))] = count
    return result


def main():
    baseline = json.loads(BASELINE.read_text())
    current = inventory()
    failures = []
    for path in sorted(set(baseline) | set(current)):
        before = baseline.get(path, 0)
        now = current.get(path, 0)
        print(f"{path}: {now} unsafe sites (budget {before})")
        if now > before:
            failures.append(f"{path}: unsafe sites grew from {before} to {now}")
    if failures:
        raise SystemExit("unsafe-inventory: FAIL\n" + "\n".join(failures))
    print(f"unsafe-inventory: pass ({sum(current.values())} sites)")


if __name__ == "__main__":
    main()
