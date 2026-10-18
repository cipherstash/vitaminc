"""Tests for commit_on_branch.py.

Run with `python3 -m unittest discover -s .github/scripts -p 'test_commit_on_branch.py'`.
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from commit_on_branch import main, request


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def repository(root: Path) -> None:
    git(root, "init", "-q")
    (root / "a").mkdir()
    (root / "a" / "Cargo.lock").write_text("version = 1\n")
    (root / "b.lock").write_text("version = 1\n")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "init")


class RequestTest(unittest.TestCase):
    def test_a_modified_file_is_sent_whole_on_top_of_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository(root)
            (root / "a" / "Cargo.lock").write_text("version = 2\n")
            body = request(root, "cipherstash/vitaminc", "release-plz-x", "chore: sync")
            input_ = body["variables"]["input"]
            self.assertEqual(input_["expectedHeadOid"], git(root, "rev-parse", "HEAD").strip())
            self.assertEqual(
                input_["branch"],
                {"repositoryNameWithOwner": "cipherstash/vitaminc", "branchName": "release-plz-x"},
            )
            self.assertEqual(input_["message"], {"headline": "chore: sync"})
            [addition] = input_["fileChanges"]["additions"]
            self.assertEqual(addition["path"], "a/Cargo.lock")
            self.assertEqual(base64.b64decode(addition["contents"]), b"version = 2\n")
            self.assertNotIn("deletions", input_["fileChanges"])

    def test_every_modified_file_is_sent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository(root)
            (root / "a" / "Cargo.lock").write_text("version = 2\n")
            (root / "b.lock").write_text("version = 2\n")
            additions = request(root, "o/r", "b", "h")["variables"]["input"]["fileChanges"]["additions"]
            self.assertEqual([a["path"] for a in additions], ["a/Cargo.lock", "b.lock"])

    def test_a_clean_worktree_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository(root)
            with self.assertRaisesRegex(ValueError, "nothing to commit"):
                request(root, "o/r", "b", "h")

    def test_anything_but_a_modification_is_refused(self):
        for change in ("add", "delete", "stage"):
            with self.subTest(change), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                repository(root)
                (root / "b.lock").write_text("version = 2\n")
                if change == "add":
                    (root / "new.lock").write_text("x\n")
                elif change == "delete":
                    (root / "a" / "Cargo.lock").unlink()
                else:
                    git(root, "add", "b.lock")
                with self.assertRaisesRegex(ValueError, "only modified"):
                    request(root, "o/r", "b", "h")


class MainTest(unittest.TestCase):
    def test_prints_the_request_as_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository(root)
            (root / "b.lock").write_text("version = 2\n")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main(["commit_on_branch.py", str(root), "o/r", "b", "h"]), 0)
            self.assertIn("createCommitOnBranch", json.loads(out.getvalue())["query"])

    def test_a_refusal_exits_one_and_prints_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository(root)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(main(["commit_on_branch.py", str(root), "o/r", "b", "h"]), 1)
            self.assertEqual(out.getvalue(), "")

    def test_wrong_arguments_exit_two(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["commit_on_branch.py"]), 2)


if __name__ == "__main__":
    unittest.main()
