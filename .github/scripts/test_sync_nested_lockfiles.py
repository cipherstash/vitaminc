"""Tests for sync_nested_lockfiles.py.

Run with `python3 -m unittest discover -s .github/scripts -p 'test_sync_nested_lockfiles.py'`.
"""

from __future__ import annotations

import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path

from sync_nested_lockfiles import NESTED as NESTED_PATHS
from sync_nested_lockfiles import check_unqualified, main, sync, workspace_versions

REPO = Path(__file__).resolve().parents[2]

ROOT = """\
version = 4

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aa"

[[package]]
name = "vitaminc-aead"
version = "0.6.0"
dependencies = [
 "serde",
]

[[package]]
name = "vitaminc-protected"
version = "0.6.0"
"""

NESTED = """\
version = 4

[[package]]
name = "addon"
version = "0.0.0"
dependencies = [
 "vitaminc-aead",
]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aa"

[[package]]
name = "vitaminc-aead"
version = "0.5.1"
dependencies = [
 "serde",
 "vitaminc-protected",
]

[[package]]
name = "vitaminc-protected"
version = "0.5.1"
"""


class SyncNestedLockfilesTest(unittest.TestCase):
    def test_the_workspace_crates_are_those_with_no_source(self):
        self.assertEqual(
            workspace_versions(ROOT),
            {"vitaminc-aead": "0.6.0", "vitaminc-protected": "0.6.0"},
        )

    def test_only_the_workspace_crates_version_lines_change(self):
        synced = sync(NESTED, workspace_versions(ROOT))
        self.assertEqual(
            synced,
            NESTED.replace(
                'name = "vitaminc-aead"\nversion = "0.5.1"',
                'name = "vitaminc-aead"\nversion = "0.6.0"',
            ).replace(
                'name = "vitaminc-protected"\nversion = "0.5.1"',
                'name = "vitaminc-protected"\nversion = "0.6.0"',
            ),
        )

    def test_a_registry_package_of_a_workspace_name_is_left_alone(self):
        nested = NESTED.replace(
            'name = "serde"', 'name = "vitaminc-protected-old"'
        )
        versions = {"vitaminc-protected-old": "9.9.9"}
        self.assertEqual(sync(nested, versions), nested)

    def test_the_nested_workspaces_own_crate_is_left_alone(self):
        synced = sync(NESTED, workspace_versions(ROOT))
        self.assertIn('name = "addon"\nversion = "0.0.0"', synced)

    def test_an_in_step_lockfile_is_unchanged(self):
        synced = sync(NESTED, workspace_versions(ROOT))
        self.assertEqual(sync(synced, workspace_versions(ROOT)), synced)

    def test_a_backslash_in_a_version_is_copied_as_it_is(self):
        synced = sync(NESTED, {"vitaminc-aead": r"0.6.0\1"})
        self.assertIn('name = "vitaminc-aead"\nversion = "0.6.0\\1"', synced)

    def test_a_version_qualified_reference_to_a_workspace_crate_is_refused(self):
        qualified = NESTED.replace(
            ' "vitaminc-protected",', ' "vitaminc-protected 0.5.1",'
        )
        with self.assertRaises(SystemExit) as refused:
            check_unqualified(qualified, workspace_versions(ROOT))
        self.assertIn("vitaminc-protected 0.5.1", str(refused.exception))
        # Qualified references to registry crates are not this script's
        # business, and the lockfiles as they stand pass.
        check_unqualified(
            NESTED.replace(' "serde",', ' "serde 1.0.0",'), workspace_versions(ROOT)
        )
        check_unqualified(NESTED, workspace_versions(ROOT))


class NestedPathsTest(unittest.TestCase):
    def test_nested_names_every_lockfile_except_the_root(self):
        # A new workspace with its own lockfile must be added to NESTED, or
        # the release PR fails CI again for the reason this script exists.
        tracked = subprocess.run(
            ["git", "ls-files", "*Cargo.lock"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()
        self.assertEqual(sorted(set(tracked) - {"Cargo.lock"}), sorted(NESTED_PATHS))


class MainTest(unittest.TestCase):
    """`main` is what the release workflow runs, over real files."""

    def repo(self) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "Cargo.lock").write_text(ROOT)
        for path in NESTED_PATHS:
            (root / path).parent.mkdir(parents=True)
            (root / path).write_text(NESTED)
        return root

    def test_main_re_syncs_every_nested_lockfile(self):
        root = self.repo()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["sync_nested_lockfiles.py", str(root)]), 0)
        expected = sync(NESTED, workspace_versions(ROOT))
        for path in NESTED_PATHS:
            self.assertEqual((root / path).read_text(), expected)

    def test_main_leaves_a_qualified_lockfile_alone_and_fails(self):
        root = self.repo()
        first = root / NESTED_PATHS[0]
        first.write_text(NESTED.replace(' "vitaminc-protected",', ' "vitaminc-protected 0.5.1",'))
        before = {path: (root / path).read_text() for path in NESTED_PATHS}
        with self.assertRaises(SystemExit):
            main(["sync_nested_lockfiles.py", str(root)])
        for path in NESTED_PATHS:
            self.assertEqual((root / path).read_text(), before[path])

    def test_main_with_no_root_is_a_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["sync_nested_lockfiles.py"]), 2)


if __name__ == "__main__":
    unittest.main()
