"""Read workspace manifests and README paths as data (Python 3.11+).

Shared by release synchronization scripts. Never import or execute worktree code.
"""

from __future__ import annotations

import tomllib
from pathlib import Path


def inside(root: Path, path: Path) -> Path:
    """Do not let release-branch paths or symlinks escape the worktree."""
    resolved = path.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError(f"path outside the worktree: {path}")
    return resolved


def workspace(root: Path) -> tuple[dict, dict[Path, dict]]:
    manifest = tomllib.loads(inside(root, root / "Cargo.toml").read_text())
    config = manifest["workspace"]
    excluded = {
        path.resolve()
        for pattern in config.get("exclude", [])
        for path in root.glob(pattern)
    }
    members = set()
    for pattern in config["members"]:
        matches = list(root.glob(pattern))
        if not matches:
            raise ValueError(f"workspace member pattern matches nothing: {pattern}")
        members.update(inside(root, path) for path in matches if path.resolve() not in excluded)
    if "package" in manifest:
        members.add(root)
    return config.get("package", {}), {
        member: tomllib.loads(inside(root, member / "Cargo.toml").read_text())
        for member in sorted(members)
    }


def readmes(root: Path, defaults: dict, members: dict[Path, dict]) -> set[Path]:
    paths = set()
    if (root / "README.md").exists():
        paths.add(inside(root, root / "README.md"))
    for member, manifest in members.items():
        package = manifest["package"]
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
            paths.add(path)
        elif "readme" in package:
            raise ValueError(f"configured README does not exist: {path}")
    return paths
