#!/usr/bin/env python3
"""Enforce the explicit PCRE2 native-code boundary."""

from __future__ import annotations

import argparse
import platform
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def fail(message: str) -> None:
    raise SystemExit(f"native dependency policy: {message}")


def check_source_policy() -> None:
    config = tomllib.loads((ROOT / ".cargo" / "config.toml").read_text())
    setting = config.get("env", {}).get("PCRE2_SYS_STATIC")
    if setting != {"value": "1", "force": True}:
        fail("PCRE2_SYS_STATIC must be forced to 1 in .cargo/config.toml")

    expr = (ROOT / "crates" / "server" / "src" / "expr.rs").read_text()
    for call in (".jit(", ".jit_if_available(", ".max_jit_stack_size("):
        if call in expr:
            fail(f"expression regexes must not enable PCRE2 JIT ({call})")


def check_binary(binary: Path) -> None:
    if not binary.is_file():
        fail(f"binary does not exist: {binary}")
    if platform.system() != "Linux":
        return
    result = subprocess.run(
        ["ldd", str(binary)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode != 0:
        fail(f"ldd failed for {binary}: {result.stdout.strip()}")
    if "libpcre2" in result.stdout.lower():
        fail(f"{binary} dynamically links an ambient PCRE2 library")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    check_source_policy()
    if args.binary is not None:
        check_binary(args.binary)
    print("native dependency policy: pinned static PCRE2, JIT disabled")


if __name__ == "__main__":
    try:
        main()
    except (OSError, tomllib.TOMLDecodeError) as error:
        print(f"native dependency policy: {error}", file=sys.stderr)
        raise SystemExit(1) from error
