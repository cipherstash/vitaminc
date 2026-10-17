#!/usr/bin/env python3
"""Copy the workspace crates' versions from the root Cargo.lock into the nested ones.

Two test workspaces keep their own lockfiles, which pin the workspace crates
by version: the Node addon (packages/aead-napi/tests/addon) and the Go
bindings' wasm guest (bindings/go/vcencrypt/guest). release-plz bumps the root
lockfile but not these, and the addon builds with --locked, so every release
PR would fail CI until they are re-synced.

This does the re-sync as a text edit, without running cargo. The release
workflow runs it, holding a token that can push and publish, over a branch
it did not write; cargo would honour that branch's .cargo/config.toml (a
rustc-wrapper, say), and a text edit runs nothing from it. A workspace crate
is a package with no `source` line in the root lockfile. In each nested
lockfile, every package of that name with no `source` line takes the root's
version; nothing else changes.

Usage: sync_nested_lockfiles.py <repository root>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

NESTED = (
    "packages/aead-napi/tests/addon/Cargo.lock",
    "bindings/go/vcencrypt/guest/Cargo.lock",
)

FIELD = re.compile(r'^(name|version|source) = "([^"]*)"$', re.MULTILINE)

# A dependency entry that names its package with a version, which cargo
# writes when a lockfile holds two packages of one name.
QUALIFIED_REF = re.compile(r'^ "([^" ]+) [^"]+",?$', re.MULTILINE)


def packages(lock: str) -> list[tuple[int, int, dict[str, str]]]:
    """Each `[[package]]` block as its start, its end and its fields."""
    starts = [m.start() for m in re.finditer(r"^\[\[package\]\]$", lock, re.MULTILINE)]
    blocks = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(lock)
        fields = {m.group(1): m.group(2) for m in FIELD.finditer(lock, start, end)}
        blocks.append((start, end, fields))
    return blocks


def workspace_versions(root_lock: str) -> dict[str, str]:
    """The version of every package in the root lockfile with no `source`."""
    return {
        fields["name"]: fields["version"]
        for _, _, fields in packages(root_lock)
        if "source" not in fields
    }


def check_unqualified(nested_lock: str, versions: dict[str, str]) -> None:
    """Refuse a lockfile whose dependency entries name a workspace crate with
    its version. `sync` changes only `version` lines, so such an entry would
    be left pointing at the old version and the `--locked` build would fail
    with nothing in the commit to say why. Cargo can re-sync that lockfile."""
    for m in QUALIFIED_REF.finditer(nested_lock):
        if m.group(1) in versions:
            raise SystemExit(
                f"{m.group(0).strip()}: a version-qualified reference to a "
                "workspace crate; re-sync this lockfile with cargo"
            )


def sync(nested_lock: str, versions: dict[str, str]) -> str:
    """`nested_lock` with each workspace crate's version set from `versions`."""
    out = []
    last = 0
    for start, end, fields in packages(nested_lock):
        name = fields.get("name")
        if "source" in fields or name not in versions or fields.get("version") == versions[name]:
            continue
        block = nested_lock[start:end]
        new = versions[name]
        block = re.sub(
            r'^version = "[^"]*"$',
            # A function, not a template: a backslash in the version would
            # otherwise be read as an escape.
            lambda _: f'version = "{new}"',
            block,
            count=1,
            flags=re.MULTILINE,
        )
        out.append(nested_lock[last:start])
        out.append(block)
        last = end
    out.append(nested_lock[last:])
    return "".join(out)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    root = Path(argv[1])
    versions = workspace_versions((root / "Cargo.lock").read_text())
    for nested in NESTED:
        path = root / nested
        before = path.read_text()
        check_unqualified(before, versions)
        after = sync(before, versions)
        if after != before:
            path.write_text(after)
            print(f"re-synced {nested}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
