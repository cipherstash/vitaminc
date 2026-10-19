#!/usr/bin/env python3
"""Tidy the release section sampo just wrote to each crate's CHANGELOG.md.

Every workspace crate is in one fixed version group, so a release bumps all
of them, and sampo explains each bump it was not asked for in the crate's
changelog: "Bumped due to fixed dependency group policy", and "Updated
dependencies: ..." for every sibling crate it depends on. That is twenty
changelogs saying the versions moved together, which the version already
says. sampo has no setting to leave them out, so this drops them.

sampo also lists the sections of a release in the order the changesets
named them. This puts them in the order of `[changesets] tags` in
.sampo/config.toml, so Breaking always leads.

Only the newest section of each changelog is touched; released sections are
left as they are. A section left with no entries keeps its heading, so every
crate's changelog still records the version.

Usage: tidy_changelogs.py <repository root>
Prints the release notes (each crate's tidied section) for the release PR.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

AUTOMATIC = re.compile(
    r"- (?:Bumped due to fixed dependency group policy"
    r"|Bumped to stay aligned with the packages it shares a version with"
    r"|Updated dependencies: [^\s,@]+@\S+(?:, [^\s,@]+@\S+)*)"
)


def split_release(text: str) -> tuple[str, str, str]:
    """The text before the newest release section, the section, and the text after it."""
    start = re.search(r"^## ", text, re.MULTILINE)
    if start is None:
        return text, "", ""
    end = re.search(r"^## ", text[start.end() :], re.MULTILINE)
    stop = len(text) if end is None else start.end() + end.start()
    return text[: start.start()], text[start.start() : stop], text[stop:]


def tidy_section(section: str, order: list[str]) -> str:
    """The section without sampo's automatic entries, its subsections in `order`."""
    heading, _, body = section.partition("\n")
    parts = re.split(r"^### (.*)\n", body, flags=re.MULTILINE)
    subsections = []
    for title, content in zip(parts[1::2], parts[2::2]):
        # sampo indents the blank line between an entry's paragraphs too.
        kept = "\n".join(
            line if line.strip() else ""
            for line in content.split("\n")
            if not AUTOMATIC.fullmatch(line)
        )
        if kept.strip():
            subsections.append((title.strip(), kept.strip("\n")))
    rank = {title: i for i, title in enumerate(order)}
    subsections.sort(key=lambda s: rank.get(s[0], len(order)))
    out = heading + "\n\n"
    if parts[0].strip():
        out += parts[0].strip("\n") + "\n\n"
    for title, content in subsections:
        out += f"### {title}\n\n{content}\n\n"
    return out


def tidy(root: Path) -> str:
    """Tidy every crate's changelog under root/packages, and return the release notes."""
    config = tomllib.loads((root / ".sampo" / "config.toml").read_text())
    order = config.get("changesets", {}).get("tags", [])
    notes = []
    for path in sorted((root / "packages").glob("*/CHANGELOG.md")):
        before, section, after = split_release(path.read_text())
        if not section:
            continue
        section = tidy_section(section, order)
        path.write_text(before + section + after)
        _, _, entries = section.partition("\n")
        if entries.strip():
            crate = tomllib.loads((path.parent / "Cargo.toml").read_text())["package"]["name"]
            entries = re.sub(r"^### ", "#### ", entries.strip(), flags=re.MULTILINE)
            notes.append(f"### {crate}\n\n{entries}")
    return "\n\n".join(notes)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-2], file=sys.stderr)
        return 2
    print(tidy(Path(argv[1])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
