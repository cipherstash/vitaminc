"""Tests for check_changesets.py.

Run with `python3 -m unittest discover -s .github/scripts -p 'test_check_changesets.py'`.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from check_changesets import check, check_changeset

CRATES = {"vitaminc-aead": "packages/aead"}
TAGS = ["Breaking", "Features", "Fixes"]


def changeset(front: str, body: str = "An entry.\n") -> str:
    return f"---\n{front}\n---\n\n{body}"


class ChangesetTest(unittest.TestCase):
    def errors(self, text: str, version: str = "0.6.1") -> list[str]:
        return check_changeset(text, CRATES, TAGS, version)

    def test_a_tagged_patch_or_minor_passes(self):
        self.assertEqual(self.errors(changeset("cargo/vitaminc-aead: patch (Fixes)")), [])
        self.assertEqual(self.errors(changeset("'cargo/vitaminc-aead': minor (Features)")), [])

    def test_major_is_refused_in_0x_and_allowed_from_1_0(self):
        [error] = self.errors(changeset("cargo/vitaminc-aead: major (Breaking)"))
        self.assertIn("1.0.0", error)
        self.assertEqual(self.errors(changeset("cargo/vitaminc-aead: major (Breaking)"), "1.2.0"), [])

    def test_breaking_needs_the_breaking_bump(self):
        [error] = self.errors(changeset("cargo/vitaminc-aead: patch (Breaking)"))
        self.assertIn("`minor`", error)
        self.assertEqual(self.errors(changeset("cargo/vitaminc-aead: minor (Breaking)")), [])

    def test_a_missing_or_unknown_tag_is_refused(self):
        self.assertIn("no tag", self.errors(changeset("cargo/vitaminc-aead: patch"))[0])
        self.assertIn("not one of", self.errors(changeset("cargo/vitaminc-aead: patch (Feature)"))[0])

    def test_an_unknown_crate_is_refused(self):
        [error] = self.errors(changeset("cargo/vitaminc-nope: patch (Fixes)"))
        self.assertIn("not a published workspace crate", error)

    def test_no_front_matter_or_no_body_is_refused(self):
        self.assertIn("front matter", self.errors("An entry.\n")[0])
        self.assertIn("no entry", self.errors(changeset("cargo/vitaminc-aead: patch (Fixes)", ""))[0])


class CheckTest(unittest.TestCase):
    def workspace(self, root: Path) -> None:
        (root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["packages/aead", "packages/derive-tests/direct"]\n'
            '[workspace.package]\nversion = "0.6.1"\n'
        )
        for member, extra in (("packages/aead", ""), ("packages/derive-tests/direct", "publish = false\n")):
            (root / member).mkdir(parents=True)
            (root / member / "Cargo.toml").write_text(f'[package]\nname = "{Path(member).name}x"\n{extra}')
        (root / "packages/aead/Cargo.toml").write_text('[package]\nname = "vitaminc-aead"\n')
        (root / ".sampo/changesets").mkdir(parents=True)
        (root / ".sampo/config.toml").write_text('[changesets]\ntags = ["Breaking", "Features", "Fixes"]\n')

    def test_a_shipped_change_needs_a_changeset(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.workspace(root)
            [error] = check(root, [("M", "packages/aead/src/lib.rs")])
            self.assertIn("adds no changeset", error)
            (root / ".sampo/changesets/x.md").write_text(changeset("cargo/vitaminc-aead: patch (Fixes)"))
            self.assertEqual(
                check(root, [("M", "packages/aead/src/lib.rs"), ("A", ".sampo/changesets/x.md")]), []
            )

    def test_tests_ci_and_unpublished_crates_need_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.workspace(root)
            changed = [
                ("M", "packages/aead/tests/frame.rs"),
                ("M", "packages/aead/CHANGELOG.md"),
                ("M", "packages/derive-tests/direct/src/lib.rs"),
                ("M", ".github/workflows/test.yml"),
                ("M", "Cargo.lock"),
            ]
            self.assertEqual(check(root, changed), [])

    def test_a_deleted_changeset_is_not_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.workspace(root)
            self.assertEqual(check(root, [("D", ".sampo/changesets/gone.md")]), [])


if __name__ == "__main__":
    unittest.main()
