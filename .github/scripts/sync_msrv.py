#!/usr/bin/env python3
"""Synchronize documented Rust requirements and emit the MSRV CI matrix.

Usage: sync_msrv.py <repository root> [--check | --matrix]

Python 3.11+, standard library only. Reads worktree files as data, without Cargo.
Mark a version with <!-- msrv:package-name -->**1.88.0**<!-- /msrv -->.
Sources are package names, `workspace`, or declared `package/feature` requirements.
Use `msrv:keep` for historical statements. Markers must fit on one line, including
inside //! and /// comments. New unmarked `Rust 1.x` / `MSRV 1.x` claims are errors.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from workspace_metadata import inside, readmes, workspace

NAME = re.compile(r"[A-Za-z0-9_-]+")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?")
MARKER = re.compile(r"<!-- msrv:([A-Za-z0-9_/-]+) -->|<!-- /msrv -->")
VALUE = re.compile(r"(?P<format>\*\*|`|)(?P<version>[0-9]+\.[0-9]+(?:\.[0-9]+)?)(?P=format)")
CLAIM = re.compile(r"\b(?:Rust|MSRV|rust-version)\b", re.IGNORECASE)
RUST_VERSION = re.compile(r"\b(?:[1-9][0-9]*)\.[0-9]+(?:\.[0-9]+)?\b")


def version_key(value: str) -> tuple[int, ...]:
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise ValueError(f"invalid rust-version: {value!r}")
    parts = tuple(map(int, value.split(".")))
    return parts + (0,) * (3 - len(parts))


def inventory(root: Path) -> tuple[dict[str, str], list[Path], dict]:
    defaults, members = workspace(root)
    versions = {"workspace": defaults["rust-version"]}
    version_key(versions["workspace"])
    packages = {}
    files = readmes(root, defaults, members)
    groups = defaultdict(list)
    for member, manifest in members.items():
        package = manifest["package"]
        name = package["name"]
        if not isinstance(name, str) or not NAME.fullmatch(name) or name in versions or name == "keep":
            raise ValueError(f"invalid or duplicate package name: {name!r}")
        value = package.get("rust-version")
        if value == {"workspace": True}:
            value = defaults["rust-version"]
        toolchain = ".".join(map(str, version_key(value)))
        versions[name] = value
        packages[name] = manifest
        groups[toolchain].append(name)
        source = inside(root, member / "src")
        files.update(inside(root, p) for p in source.rglob("*.rs"))
        if "path" in manifest.get("lib", {}):
            files.add(inside(root, member / manifest["lib"]["path"]))

    matrix = []
    workspace_toolchain = ".".join(map(str, version_key(versions["workspace"])))
    for toolchain in sorted(groups, key=lambda v: (v != workspace_toolchain, version_key(v))):
        names = sorted(groups[toolchain])
        # Every member is checked at its own floor, including non-published fixtures.
        matrix.append({
            "name": "workspace" if toolchain == workspace_toolchain else ", ".join(names),
            "toolchain": toolchain,
            "args": "--all-targets " + " ".join(f"-p {name}" for name in names),
        })

    # Explicit feature scenarios describe workspace dependencies that can raise
    # a facade's floor. Cargo checks the complete resolved graph at that floor.
    for name, manifest in sorted(packages.items()):
        scenarios = manifest["package"].get("metadata", {}).get("msrv", {}).get("features", {})
        if not isinstance(scenarios, dict):
            raise ValueError(f"{name}: metadata.msrv.features must be a table")
        for feature, dependencies in sorted(scenarios.items()):
            if not NAME.fullmatch(feature) or feature not in manifest.get("features", {}):
                raise ValueError(f"{name}: unknown feature scenario {feature!r}")
            if not isinstance(dependencies, list) or not dependencies:
                raise ValueError(f"{name}/{feature}: expected workspace dependency names")
            for dependency in dependencies:
                if not isinstance(dependency, str) or dependency not in packages:
                    raise ValueError(f"{name}/{feature}: unknown workspace dependency {dependency!r}")
            value = max((versions[p] for p in [name, *dependencies]), key=version_key)
            source = f"{name}/{feature}"
            versions[source] = value
            matrix.append({
                "name": source,
                "toolchain": ".".join(map(str, version_key(value))),
                "args": f"--all-targets -p {name} --no-default-features --features {feature}",
            })
    return versions, sorted(files), {"include": matrix}


def sync_line(line: str, versions: dict[str, str]) -> str:
    """Update only marked version tokens, keeping surrounding prose intact."""
    out = []
    masked = []
    source = None
    last = 0
    for marker in MARKER.finditer(line):
        content = line[last:marker.start()]
        if source is None:
            out.append(content)
            masked.append(content)
        else:
            masked.append(" " * len(content))
            if source == "keep":
                out.append(content)
            else:
                value = VALUE.fullmatch(content)
                if value is None:
                    raise ValueError("MSRV markers must enclose one version, optionally bold or code-formatted")
                version_key(value["version"])
                out.append(value["format"] + versions[source] + value["format"])
        if marker[1] is None:
            if source is None:
                raise ValueError("MSRV end marker without start")
            source = None
        else:
            if source is not None:
                raise ValueError("nested MSRV markers")
            source = marker[1]
            if source != "keep" and source not in versions:
                raise ValueError(f"unknown MSRV source: {source}")
        out.append(marker[0])
        masked.append(" " * len(marker[0]))
        last = marker.end()
    if source is not None:
        raise ValueError("unclosed MSRV marker (markers must be on one line)")
    out.append(line[last:])
    masked.append(line[last:])
    remaining = "".join(masked)
    if "<!-- msrv" in remaining or "<!-- /msrv" in remaining:
        raise ValueError("malformed MSRV marker")
    if CLAIM.search(remaining) and RUST_VERSION.search(remaining):
        raise ValueError("unmarked Rust/MSRV version; add msrv markers (or msrv:keep for history)")
    return "".join(out)


def sync(text: str, versions: dict[str, str], *, rust: bool = False) -> str:
    lines = []
    for number, line in enumerate(text.splitlines(keepends=True), 1):
        if not rust or re.match(r"\s*(?://!|///(?!/))", line):
            try:
                line = sync_line(line, versions)
            except ValueError as error:
                raise ValueError(f"line {number}: {error}") from error
        lines.append(line)
    return "".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="report drift without writing")
    mode.add_argument("--matrix", action="store_true", help="emit GitHub Actions matrix JSON without writing")
    args = parser.parse_args(argv)
    changes = []
    root = args.root.resolve()
    try:
        versions, files, matrix = inventory(root)
        if args.matrix:
            print(json.dumps(matrix, separators=(",", ":")))
            return 0
        for path in files:
            before = path.read_text()
            try:
                after = sync(before, versions, rust=path.suffix == ".rs")
            except ValueError as error:
                raise ValueError(f"{path.relative_to(root)}: {error}") from error
            if before != after:
                changes.append((path, after))
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"sync_msrv: {error}", file=sys.stderr)
        return 1
    # Validate the entire inventory before writing any files.
    for path, after in changes:
        print(f"{'stale' if args.check else 'updated'}: {path.relative_to(root)}")
        if not args.check:
            path.write_text(after)
    if args.check and changes:
        print("Run python3 .github/scripts/sync_msrv.py .", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
