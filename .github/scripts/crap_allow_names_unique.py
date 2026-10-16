#!/usr/bin/env python3
"""Check that each bare function name in .cargo-crap.toml's `allow` is defined once.

cargo-crap matches an `allow` entry with no `/`, `*` or `::` against every
function of that name in the workspace, not only the one the entry was
written for. A generic name such as `walk` or `date` therefore hides
functions in other crates from the CRAP gate too. This check fails when a
bare entry matches anything other than exactly one function, so each one
names exactly one function.

The functions are the ones cargo-crap itself analyses, not a text search:
a name in a comment, a doc example or a string is not a function, and a
file the config excludes is never scored. cargo-crap has no switch to turn
the allow list off, and it finds its config by walking up from the working
directory, so this runs it from a temporary directory over each workspace
member, passing the config's `exclude` list, which is what
`cargo crap --workspace` does with the config minus its `allow`.

Run `mise run crap:allow:check` to check the current tree. It needs
cargo-crap on the PATH.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import tomllib
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG = ".cargo-crap.toml"


def bare_names(allow: list[str]) -> list[str]:
    """The entries cargo-crap matches by function name alone. An entry with
    `/` or `*` matches files, and `Type::method` is already qualified."""
    return [a for a in allow if "/" not in a and "*" not in a and "::" not in a]


def problems(allow: list[str], functions: list[str]) -> dict[str, int]:
    """Each bare entry that does not match exactly one of `functions` (the
    names cargo-crap reports), with how many it matches."""
    counts = Counter(functions)
    return {name: counts[name] for name in bare_names(allow) if counts[name] != 1}


def workspace_members(cwd: Path = REPO_ROOT) -> list[Path]:
    """The root directory of each workspace member."""
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    meta = json.loads(out.stdout)
    members = set(meta["workspace_members"])
    return sorted(
        Path(p["manifest_path"]).parent for p in meta["packages"] if p["id"] in members
    )


def analysed_functions(members: list[Path], exclude: list[str]) -> list[str]:
    """The name of every function cargo-crap analyses in `members`, with
    `exclude` applied and no allow list."""
    names: list[str] = []
    with tempfile.TemporaryDirectory() as outside:
        for member in members:
            cmd = ["cargo", "crap", "--path", str(member), "--format", "json", "--no-cache"]
            for pattern in exclude:
                cmd += ["--exclude", pattern]
            out = subprocess.run(cmd, cwd=outside, check=True, stdout=subprocess.PIPE, text=True)
            names += [row["function"] for row in json.loads(out.stdout)["entries"]]
    return names


def main() -> int:
    with open(REPO_ROOT / CONFIG, "rb") as f:
        config = tomllib.load(f)
    functions = analysed_functions(workspace_members(), config.get("exclude", []))
    bad = problems(config.get("allow", []), functions)
    for name, count in bad.items():
        print(
            f"::error file={CONFIG}::allow entry {name!r} matches {count} functions;"
            " it must name exactly one"
        )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
