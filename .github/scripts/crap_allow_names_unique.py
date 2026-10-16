#!/usr/bin/env python3
"""Check that each bare function name in .cargo-crap.toml's `allow` is defined once.

cargo-crap matches an `allow` entry with no `/`, `*` or `::` against every
function of that name in the workspace, not only the one the entry was
written for. A generic name such as `walk` or `date` therefore hides
functions in other crates from the CRAP gate too. This check fails when a
bare entry is defined anywhere other than exactly once, so each one names
exactly one function.

Run `mise run crap:allow:check` to check the current tree.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG = ".cargo-crap.toml"


def bare_names(allow: list[str]) -> list[str]:
    """The entries cargo-crap matches by function name alone. An entry with
    `/` or `*` matches files, and `Type::method` is already qualified."""
    return [a for a in allow if "/" not in a and "*" not in a and "::" not in a]


def definitions(name: str, cwd: Path = REPO_ROOT) -> list[str]:
    """Each `fn name` in the tracked Rust sources, as `path:line:text`."""
    out = subprocess.run(
        ["git", "grep", "-nP", rf"\bfn {re.escape(name)}\s*[<(]", "--", "*.rs"],
        cwd=cwd,
        stdout=subprocess.PIPE,
        text=True,
    )
    # git grep exits 1 when nothing matches, which is an answer, not an error.
    if out.returncode not in (0, 1):
        raise RuntimeError(f"git grep failed with exit {out.returncode}")
    return out.stdout.splitlines()


def problems(allow: list[str], cwd: Path = REPO_ROOT) -> dict[str, list[str]]:
    """Each bare entry not defined exactly once, with its definitions."""
    found = {name: definitions(name, cwd) for name in bare_names(allow)}
    return {name: defs for name, defs in found.items() if len(defs) != 1}


def main() -> int:
    with open(REPO_ROOT / CONFIG, "rb") as f:
        allow = tomllib.load(f).get("allow", [])
    bad = problems(allow)
    for name, defs in bad.items():
        print(
            f"::error file={CONFIG}::allow entry {name!r} is defined {len(defs)} times;"
            " it must name exactly one function"
        )
        for line in defs:
            print(f"  {line}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
