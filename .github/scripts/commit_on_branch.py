#!/usr/bin/env python3
"""Print the GraphQL request that commits a worktree's edits to its branch.

The release workflow commits a release (versions, changelogs, lockfiles) to
the release branch. A commit it made with git and pushed would be unsigned,
and the ruleset on main requires signed commits, so the release PR could not
merge until a maintainer re-signed it. GitHub signs a commit it creates
itself through the `createCommitOnBranch` mutation, attributed to the app
whose token made the call.

This builds that request from the worktree's changes. The commit's parent is
the worktree's HEAD (`expectedHeadOid`), so GitHub refuses the commit if the
branch moved since it was checked out. A release modifies files and deletes
the changesets it consumed from `.sampo/changesets/`; nothing else is
supported. A release never adds or renames a file, or deletes any other, so
a change of that kind means something else has edited the worktree.

Usage: commit_on_branch.py <worktree> <owner/repo> <branch> <headline>
Pipe the output to `gh api graphql --input -`.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

MUTATION = (
    "mutation($input: CreateCommitOnBranchInput!) {"
    " createCommitOnBranch(input: $input) { commit { oid url } } }"
)

CHANGESETS = ".sampo/changesets/"


def git(worktree: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(worktree), *args], check=True, capture_output=True, text=True
    ).stdout


def consumed_changeset(path: str) -> bool:
    """Whether a path is a changeset file, which a release deletes once consumed."""
    name = path.removeprefix(CHANGESETS)
    return name != path and "/" not in name and name.endswith(".md")


def request(worktree: Path, repository: str, branch: str, headline: str) -> dict:
    """The request body, or ValueError if the worktree holds anything but a release's changes."""
    status = [line for line in git(worktree, "status", "--porcelain=v1", "-z").split("\0") if line]
    modified = sorted(line[3:] for line in status if line[:2] == " M")
    deleted = sorted(line[3:] for line in status if line[:2] == " D" and consumed_changeset(line[3:]))
    other = [line for line in status if line[3:] not in modified and line[3:] not in deleted]
    if other:
        raise ValueError(
            f"only modified files and consumed changesets, unstaged, can be committed: {other}"
        )
    if not status:
        raise ValueError("nothing to commit")
    file_changes: dict = {
        "additions": [
            {
                "path": path,
                "contents": base64.b64encode((worktree / path).read_bytes()).decode("ascii"),
            }
            for path in modified
        ]
    }
    if deleted:
        file_changes["deletions"] = [{"path": path} for path in deleted]
    return {
        "query": MUTATION,
        "variables": {
            "input": {
                "branch": {"repositoryNameWithOwner": repository, "branchName": branch},
                "expectedHeadOid": git(worktree, "rev-parse", "HEAD").strip(),
                "message": {"headline": headline},
                "fileChanges": file_changes,
            }
        },
    }


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print(__doc__.strip().splitlines()[-2], file=sys.stderr)
        return 2
    _, worktree, repository, branch, headline = argv
    try:
        body = request(Path(worktree), repository, branch, headline)
    except ValueError as error:
        print(f"commit_on_branch: {error}", file=sys.stderr)
        return 1
    json.dump(body, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
