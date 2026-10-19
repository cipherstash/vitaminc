#!/usr/bin/env python3
"""Check a pull request's changesets, and that it has one if it needs one.

A changeset (.sampo/changesets/*.md) is the changelog entry for a change,
written in the pull request that makes it. The release workflow turns the
pending changesets into the next version and the crates' changelogs, so a
change that ships without one is missing from both.

A pull request needs a changeset when it changes what a crate ships: a file
under a published crate's directory other than its tests, benches, examples
and changelog. Each changeset it adds or edits must:

- name only published workspace crates, as `cargo/<crate>`;
- give a bump of `patch` or `minor`, never `major` while the workspace is
  0.x: sampo takes `major` literally and would release 1.0.0, and in 0.x a
  breaking change is a minor bump;
- give one of the `[changesets] tags` in .sampo/config.toml in parentheses,
  so the entry lands under a heading (`minor (Breaking)`, `patch (Fixes)`);
- use the Breaking tag only with a breaking bump, so a breaking entry never
  ships in a patch release;
- have a body, which is the entry.

A pull request that needs no entry (CI, internal refactoring) can carry the
`no-changeset` label instead; this script is then not run.

Usage: check_changesets.py <repository root> <base ref>
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

CHANGESETS = ".sampo/changesets/"
NOT_SHIPPED = ("tests", "benches", "examples", "CHANGELOG.md")
LINE = re.compile(r"(?P<id>[^:\s]+)\s*:\s*(?P<bump>\w+)(?:\s*\((?P<tag>[^)]*)\))?")


def toml(path: Path) -> dict:
    return tomllib.loads(path.read_text())


def published(root: Path) -> dict[str, str]:
    """Each published workspace crate's directory, relative to root, by name."""
    crates = {}
    for member in toml(root / "Cargo.toml")["workspace"]["members"]:
        package = toml(root / member / "Cargo.toml")["package"]
        if package.get("publish", True) not in (False, []):
            crates[package["name"]] = member.rstrip("/")
    return crates


def breaking_bump(version: str) -> str:
    return "minor" if version.startswith("0.") else "major"


def check_changeset(text: str, crates: dict[str, str], tags: list[str], version: str) -> list[str]:
    """What is wrong with one changeset, if anything."""
    match = re.fullmatch(r"---\n(.*?)\n---\n(.*)", text, re.DOTALL)
    if match is None:
        return ["it has no front matter between `---` lines"]
    front, body = match.groups()
    errors = []
    lines = [line.strip() for line in front.split("\n") if line.strip()]
    if not lines:
        errors.append("it names no crate")
    for line in lines:
        entry = LINE.fullmatch(line)
        if entry is None:
            errors.append(f"`{line}` is not `cargo/<crate>: <bump> (<tag>)`")
            continue
        crate = entry["id"].strip("'\"").removeprefix("cargo/")
        if crate not in crates:
            errors.append(f"`{entry['id']}` is not a published workspace crate")
        bump, tag = entry["bump"], entry["tag"]
        bump_ok = False
        if bump not in ("patch", "minor", "major"):
            errors.append(f"`{bump}` is not a bump; use patch or minor")
        elif bump == "major" and version.startswith("0."):
            errors.append(
                f"`major` would release 1.0.0; a breaking change in {version} is `minor (Breaking)`"
            )
        else:
            bump_ok = True
        if tag is None:
            errors.append(f"`{line}` has no tag; add one of {', '.join(tags)} in parentheses")
        elif tag not in tags:
            errors.append(f"`{tag}` is not one of {', '.join(tags)}")
        elif tag == "Breaking" and bump_ok and bump != breaking_bump(version):
            errors.append(
                f"a Breaking entry needs a `{breaking_bump(version)}` bump in {version}, not `{bump}`"
            )
    if not body.strip():
        errors.append("it has no entry below the front matter")
    return errors


def ships(path: str, crates: dict[str, str]) -> bool:
    """Whether a changed path is part of what a published crate ships."""
    for directory in crates.values():
        if path.startswith(directory + "/"):
            return path[len(directory) + 1 :].split("/")[0] not in NOT_SHIPPED
    return False


def check(root: Path, changed: list[tuple[str, str]]) -> list[str]:
    """What is wrong with a pull request's changes, given (status, path) pairs."""
    crates = published(root)
    tags = toml(root / ".sampo" / "config.toml").get("changesets", {}).get("tags", [])
    version = toml(root / "Cargo.toml")["workspace"]["package"]["version"]
    changesets = [
        path
        for status, path in changed
        if status != "D" and path.startswith(CHANGESETS) and path.endswith(".md")
    ]
    errors = [
        f"{path}: {error}"
        for path in changesets
        for error in check_changeset((root / path).read_text(), crates, tags, version)
    ]
    shipped = sorted(path for _, path in changed if ships(path, crates))
    if shipped and not changesets:
        errors.append(
            f"this changes what a crate ships ({shipped[0]}"
            + (f" and {len(shipped) - 1} more" if len(shipped) > 1 else "")
            + ") but adds no changeset; run `sampo add`, or label the PR `no-changeset`"
        )
    return errors


def changed_files(root: Path, base: str) -> list[tuple[str, str]]:
    out = subprocess.run(
        ["git", "-C", str(root), "diff", "--name-status", "--no-renames", f"{base}...HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [(line[0], line.split("\t", 1)[1]) for line in out.splitlines() if line]


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    root = Path(argv[1])
    errors = check(root, changed_files(root, argv[2]))
    for error in errors:
        print(f"::error::{error}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
