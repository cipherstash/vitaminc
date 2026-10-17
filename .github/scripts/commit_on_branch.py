#!/usr/bin/env python3
"""Print the GraphQL request that commits a worktree's edits to its branch.

The release workflow re-syncs the nested lockfiles on the release branch.
A commit it made with git and pushed was unsigned, and the ruleset on main
requires signed commits, so every release PR needed its maintainer to
re-sign that commit before it could merge. GitHub signs a commit it creates
itself through the `createCommitOnBranch` mutation, attributed to the app
whose token made the call; for the release workflow that is the release-plz
app, a `[bot]` login, so release-plz still force-pushes its PR afterwards.

This builds that request from the worktree's modified files. The commit's
parent is the worktree's HEAD (`expectedHeadOid`), so GitHub refuses the
commit if the branch moved since it was checked out. Only modified files are
supported: the re-sync never adds, deletes or renames one, and a change of
that kind means something else has edited the worktree.

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


def git(worktree: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(worktree), *args], check=True, capture_output=True, text=True
    ).stdout


def request(worktree: Path, repository: str, branch: str, headline: str) -> dict:
    """The request body, or ValueError if the worktree holds anything but modifications."""
    status = [line for line in git(worktree, "status", "--porcelain=v1", "-z").split("\0") if line]
    other = [line for line in status if line[:2] != " M"]
    if other:
        raise ValueError(f"only modified, unstaged files can be committed: {other}")
    if not status:
        raise ValueError("nothing to commit")
    additions = [
        {
            "path": path,
            "contents": base64.b64encode((worktree / path).read_bytes()).decode("ascii"),
        }
        for path in sorted(line[3:] for line in status)
    ]
    return {
        "query": MUTATION,
        "variables": {
            "input": {
                "branch": {"repositoryNameWithOwner": repository, "branchName": branch},
                "expectedHeadOid": git(worktree, "rev-parse", "HEAD").strip(),
                "message": {"headline": headline},
                "fileChanges": {"additions": additions},
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
