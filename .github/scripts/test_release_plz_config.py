"""Tests that release-plz.toml agrees with the workspace.

Run with `python3 -m unittest discover -s .github/scripts -p 'test_release_plz_config.py'`.
"""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def toml(path: str) -> dict:
    return tomllib.loads((REPO / path).read_text())


class ReleasePlzConfigTest(unittest.TestCase):
    def test_an_unpublished_member_is_unpublished_in_release_plz_toml(self):
        # A member with `publish = false` that release-plz.toml still treats
        # as publishable fails every Release run on main, and no check on the
        # pull request that added it would have said so (e005ba4).
        config = toml("release-plz.toml")
        default = config["workspace"].get("publish", True)
        entries = {p["name"]: p for p in config.get("package", [])}
        for member in toml("Cargo.toml")["workspace"]["members"]:
            package = toml(f"{member}/Cargo.toml")["package"]
            if package.get("publish", True) in (False, []):
                with self.subTest(package["name"]):
                    self.assertIs(entries.get(package["name"], {}).get("publish", default), False)

    def test_sampo_versions_every_published_member_together(self):
        # A published crate missing from the fixed group would be versioned on
        # its own, and the 0.x lockstep that release-plz.toml's version group
        # promised would quietly split.
        config = tomllib.loads((REPO / ".sampo" / "config.toml").read_text())
        [group] = config["packages"]["fixed"]
        members = set()
        for member in toml("Cargo.toml")["workspace"]["members"]:
            package = toml(f"{member}/Cargo.toml")["package"]
            if package.get("publish", True) not in (False, []):
                members.add(f"cargo/{package['name']}")
        self.assertEqual(set(group), members)


if __name__ == "__main__":
    unittest.main()
