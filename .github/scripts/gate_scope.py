#!/usr/bin/env python3
"""Decide whether a pull request needs a path-scoped required gate to run.

`🚦 CRAP gate` and `🧬 Mutants gate` are required checks on `main`. A
workflow-level `paths:` filter stops the workflow from starting at all, and a
required check that never reports leaves the PR at "Expected" forever. So
both workflows start on every PR, and a cheap job runs this script to decide
whether the expensive gate job runs. GitHub reports a skipped job as passed.

Skipping a gate that should have run lets untested code merge, so doubt
resolves to running it: an empty diff means run, and any error exits non-zero,
which the workflow also treats as run.

Run `mise run gate-scope -- <gate>` to see the decision for the current
branch against origin/main.
"""

from __future__ import annotations

import argparse
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SELF = ".github/scripts/gate_scope.py"


@dataclass(frozen=True)
class Scope:
    """Paths a gate checks: anything under `dirs`, plus the exact `files`."""

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

SCOPES = {
    "crap": Scope(
        dirs=_WORKSPACE_DIRS,
        files=_WORKSPACE_FILES + (".cargo-crap.toml", ".github/workflows/crap.yml"),
    ),
    "mutants": Scope(
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


def gate_needed(scope: Scope, paths: list[str]) -> bool:
    # A PR with no changes is rarer than a wrong base, so don't trust it.
    return not paths or any(scope.covers(p) for p in paths)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Decide whether a PR's changes need a path-scoped gate to run."
    )
    parser.add_argument("gate", choices=sorted(SCOPES))
    parser.add_argument(
        "--base", default="origin/main", help="the PR's base branch (default: %(default)s)"
    )
    parser.add_argument("--head", default="HEAD", help="the PR's head (default: %(default)s)")
    args = parser.parse_args(argv)

    scope = SCOPES[args.gate]
    paths = changed_paths(args.base, args.head)
    needed = gate_needed(scope, paths)

    verdict = "needed" if needed else "not needed"
    print(f"{args.gate} gate {verdict}: {len(paths)} path(s) changed since {args.base}")
    for path in paths:
        print(f"  {'in scope    ' if scope.covers(path) else 'out of scope'}  {path}")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as f:
            f.write(f"needed={'true' if needed else 'false'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
