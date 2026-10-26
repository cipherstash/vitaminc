#!/usr/bin/env python3
"""Synchronize managed README dependency declarations with workspace manifests.

Usage: sync_readme_versions.py <repository root> [--check]

Requires Python 3.11+. Reads TOML as data; never runs cargo or branch code.
Discovers the root README and each workspace member's README. Wrap current
installation examples in <!-- workspace-deps:start --> / <!-- workspace-deps:end -->.
Use workspace-deps:keep instead of workspace-deps:start for historical examples.
Unmarked versioned workspace dependency declarations are errors, so new examples
cannot silently fall outside release automation. Supported declarations are
single-line TOML assignments, including inline tables and renamed dependencies,
either on their own line or in Markdown inline code. Only version strings change.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

MARKER = re.compile(r"^<!-- workspace-deps:(start|keep|end) -->[ \t]*$", re.MULTILINE)
DECLARATION = re.compile(
    r"(?:^[ \t]*|(?<=`))(?P<name>[A-Za-z0-9_-]+)[ \t]*=[ \t]*(?P<value>[^\n`]+)",
    re.MULTILINE,
)
VERSION = re.compile(r"\bversion\s*=\s*([\"'])(?P<version>[^\"']*)\1")


def inside(root: Path, path: Path) -> Path:
    """Do not let release-branch paths or symlinks escape the worktree."""
    resolved = path.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError(f"path outside the worktree: {path}")
    return resolved


def inventory(root: Path) -> tuple[dict[str, str], list[Path]]:
    manifest = tomllib.loads(inside(root, root / "Cargo.toml").read_text())
    workspace = manifest["workspace"]
    defaults = workspace.get("package", {})
    excluded = {
        path.resolve()
        for pattern in workspace.get("exclude", [])
        for path in root.glob(pattern)
    }
    members = set()
    for pattern in workspace["members"]:
        matches = list(root.glob(pattern))
        if not matches:
            raise ValueError(f"workspace member pattern matches nothing: {pattern}")
        members.update(inside(root, path) for path in matches if path.resolve() not in excluded)
    if "package" in manifest:
        members.add(root)

    versions = {}
    readmes = set()
    if (root / "README.md").exists():
        readmes.add(inside(root, root / "README.md"))
    for member in sorted(members):
        package = tomllib.loads(inside(root, member / "Cargo.toml").read_text())["package"]
        version = package["version"]
        if version == {"workspace": True}:
            version = defaults["version"]
        if not isinstance(version, str):
            raise ValueError(f"unsupported version in {member / 'Cargo.toml'}")
        versions[package["name"]] = version
        readme = package.get("readme", "README.md")
        base = member
        if readme == {"workspace": True}:
            readme = defaults["readme"]
            base = root
        if readme is False:
            continue
        if readme is True:
            readme = "README.md"
        path = inside(root, base / readme)
        if path.is_file():
            readmes.add(path)
        elif "readme" in package:
            raise ValueError(f"configured README does not exist: {path}")
    return versions, sorted(readmes)


def sync(text: str, versions: dict[str, str]) -> str:
    def section(content: str, mode: str | None) -> str:
        if mode == "keep":
            return content

        def declaration(match: re.Match) -> str:
            name, value = match["name"], match["value"]
            try:
                dependency = tomllib.loads("dependency = " + value)["dependency"]
            except tomllib.TOMLDecodeError:
                if name in versions:
                    raise ValueError(f"use a single-line TOML dependency declaration for {name}")
                return match[0]
            package = dependency.get("package", name) if isinstance(dependency, dict) else name
            if package not in versions:
                return match[0]
            old = dependency.get("version") if isinstance(dependency, dict) else dependency
            if not isinstance(old, str):
                return match[0]  # e.g. path-only or workspace-inherited dependencies
            if mode is None:
                raise ValueError(f"unmarked dependency {name}; add workspace-deps:start/end (or keep/end)")
            if isinstance(dependency, dict):
                field = VERSION.search(value)
                if field is None:
                    raise ValueError(f"unsupported version field for {name}")
                start, end = field.span("version")
                expected = dict(dependency, version=versions[package])
            else:
                start, end = 1, 1 + len(old)
                expected = versions[package]
            updated = value[:start] + versions[package] + value[end:]
            # Refuse ambiguous formatting rather than altering a different string.
            if tomllib.loads("dependency = " + updated)["dependency"] != expected:
                raise ValueError(f"unsupported version formatting for {name}")
            offset = match.start("value") - match.start()
            return match[0][:offset] + updated

        return DECLARATION.sub(declaration, content)

    out = []
    mode = None
    last = 0
    for marker in MARKER.finditer(text):
        out.append(section(text[last:marker.start()], mode))
        kind = marker[1]
        if kind == "end":
            if mode is None:
                raise ValueError("workspace-deps:end without start/keep")
            mode = None
        else:
            if mode is not None:
                raise ValueError("nested workspace-deps markers")
            mode = kind
        out.append(marker[0])
        last = marker.end()
    if mode is not None:
        raise ValueError("unclosed workspace-deps marker")
    out.append(section(text[last:], None))
    return "".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--check", action="store_true", help="report drift without writing")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    changes = []
    try:
        versions, readmes = inventory(root)
        for path in readmes:
            before = path.read_text()
            try:
                after = sync(before, versions)
            except ValueError as error:
                raise ValueError(f"{path.relative_to(root)}: {error}") from error
            if after != before:
                changes.append((path, after))
    except (ValueError, OSError, KeyError) as error:
        print(f"sync_readme_versions: {error}", file=sys.stderr)
        return 1
    # Validate every file before writing any of them.
    for path, after in changes:
        print(f"{'stale' if args.check else 'updated'}: {path.relative_to(root)}")
        if not args.check:
            path.write_text(after)
    if args.check and changes:
        print("Run python3 .github/scripts/sync_readme_versions.py .", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
