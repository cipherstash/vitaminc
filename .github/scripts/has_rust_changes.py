#!/usr/bin/env python3
"""Decide whether a pull request has Rust changes for a required gate.

`🚦 CRAP gate` and `🧬 Mutants gate` are required checks on `main`. A
workflow-level `paths:` filter stops the workflow from starting at all, and a
required check that never reports leaves the PR at "Expected" forever. So
both workflows start on every PR, and a cheap job runs this script to decide
whether the expensive gate job needs to run. GitHub reports a skipped job
as passed.

Skipping a gate that should have run lets untested code merge, so doubt
resolves to running it: an empty diff counts as Rust changes, and any error
exits non-zero, which the workflow also treats as run.

Run `mise run pr:gate:has_rust_changes -- <gate>` to see the answer for
the current branch against origin/main.
"""

from __future__ import annotations

import argparse
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SELF = ".github/scripts/has_rust_changes.py"


@dataclass(frozen=True)
class RustPaths:
    """Paths that count as a Rust change for a gate: anything under `dirs`,
    plus the exact `files`."""

    dirs: tuple[str, ...]
    files: tuple[str, ...]

    def covers(self, path: str) -> bool:
        # Markdown can't change either gate's result, even the READMEs that
        # crates `include_str!` as docs: coverage excludes doctests, and
        # `--in-diff` mutates only changed `.rs` lines.
        if path.endswith(".md"):
            return False
        return path in self.files or path.startswith(self.dirs)


_WORKSPACE_DIRS = ("packages/",)
_WORKSPACE_FILES = ("Cargo.toml", "Cargo.lock", SELF)

RUST_PATHS = {
    "crap": RustPaths(
        dirs=_WORKSPACE_DIRS,
        files=_WORKSPACE_FILES
        + (
            ".cargo-crap.toml",
            ".github/workflows/crap.yml",
            ".github/scripts/crap_allow_names_unique.py",
        ),
    ),
    "mutants": RustPaths(
        dirs=_WORKSPACE_DIRS,
        files=_WORKSPACE_FILES + (".cargo/mutants.toml", ".github/workflows/mutants.yml"),
    ),
}


def changed_paths(base: str, head: str, cwd: Path = REPO_ROOT) -> list[str]:
    """Paths changed on `head` since it forked from `base`."""
    out = subprocess.run(
        [
            "git",
            "diff",
            "--name-only",
            # A rename lists only its new path by default, so moving a file
            # out of packages/ would look like a docs-only change.
            "--no-renames",
            # Raw NUL-separated paths: no quoting of unusual characters.
            "-z",
            f"{base}...{head}",
            "--",
        ],
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def has_rust_changes(rust_paths: RustPaths, paths: list[str]) -> bool:
    # A PR with no changes is rarer than a wrong base, so don't trust it.
    return not paths or any(rust_paths.covers(p) for p in paths)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Decide whether a PR has Rust changes for a gate, so the gate runs only when it does."
    )
    parser.add_argument("gate", choices=sorted(RUST_PATHS))
    parser.add_argument(
        "--base", default="origin/main", help="the PR's base branch (default: %(default)s)"
    )
    parser.add_argument("--head", default="HEAD", help="the PR's head (default: %(default)s)")
    args = parser.parse_args(argv)

    rust_paths = RUST_PATHS[args.gate]
    paths = changed_paths(args.base, args.head)
    rust_changes = has_rust_changes(rust_paths, paths)

    verdict = "Rust changes, run" if rust_changes else "no Rust changes, skip"
    print(f"{args.gate} gate: {verdict} ({len(paths)} path(s) changed since {args.base})")
    for path in paths:
        print(f"  {'rust    ' if rust_paths.covers(path) else 'not rust'}  {path}")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as f:
            f.write(f"has_rust_changes={'true' if rust_changes else 'false'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
