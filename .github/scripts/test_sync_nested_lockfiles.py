"""Tests for sync_nested_lockfiles.py.

Run with `python3 -m unittest discover -s .github/scripts -p 'test_sync_nested_lockfiles.py'`.
"""

from __future__ import annotations

import unittest

from sync_nested_lockfiles import sync, workspace_versions

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


if __name__ == "__main__":
    unittest.main()
