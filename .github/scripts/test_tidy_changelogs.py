"""Tests for tidy_changelogs.py.

Run with `python3 -m unittest discover -s .github/scripts -p 'test_tidy_changelogs.py'`.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tidy_changelogs import tidy, tidy_section

ORDER = ["Breaking", "Features", "Fixes"]

RELEASED = "## 0.6.1 — 2026-10-18\n\n### Fixes\n\n- Updated dependencies: a@0.6.1\n"


class TidySectionTest(unittest.TestCase):
    def test_automatic_entries_go_and_an_emptied_subsection_with_them(self):
        section = (
            "## 0.6.2 — 2026-10-19\n\n"
            "### Features\n\n- A real entry.\n- Updated dependencies: a@0.6.2, b@0.6.2\n\n"
            "### Patch changes\n\n- Bumped due to fixed dependency group policy\n"
            "- Updated dependencies: c@0.6.2\n\n"
        )
        self.assertEqual(
            tidy_section(section, ORDER),
            "## 0.6.2 — 2026-10-19\n\n### Features\n\n- A real entry.\n\n",
        )

    def test_a_section_with_only_automatic_entries_keeps_its_heading(self):
        section = (
            "## 0.6.2 — 2026-10-19\n\n### Patch changes\n\n"
            "- Bumped to stay aligned with the packages it shares a version with\n\n"
        )
        self.assertEqual(tidy_section(section, ORDER), "## 0.6.2 — 2026-10-19\n\n")

    def test_subsections_follow_the_configured_order_and_unknown_ones_go_last(self):
        section = (
            "## 1.0.0\n\n### Patch changes\n\n- p\n\n### Fixes\n\n- f\n\n"
            "### Breaking\n\n- **Breaking:** b\n\n"
        )
        self.assertEqual(
            tidy_section(section, ORDER),
            "## 1.0.0\n\n### Breaking\n\n- **Breaking:** b\n\n### Fixes\n\n- f\n\n"
            "### Patch changes\n\n- p\n\n",
        )

    def test_a_blank_line_inside_an_entry_loses_its_indent(self):
        section = "## 1.0.0\n\n### Fixes\n\n- First paragraph.\n  \n  Second.\n\n"
        self.assertEqual(
            tidy_section(section, ORDER), "## 1.0.0\n\n### Fixes\n\n- First paragraph.\n\n  Second.\n\n"
        )

    def test_text_before_the_first_subsection_is_kept(self):
        section = "## 0.2.0\n\nFirst release.\n\n### Features\n\n- f\n\n"
        self.assertEqual(tidy_section(section, ORDER), section)

    def test_an_entry_that_only_mentions_dependencies_is_kept(self):
        section = (
            "## 1.0.0\n\n### Fixes\n\n- Updated dependencies: see the notes.\n"
            "  - a nested line\n\n"
        )
        self.assertEqual(tidy_section(section, ORDER), section)


class TidyTest(unittest.TestCase):
    def workspace(self, root: Path, changelog: str) -> Path:
        (root / ".sampo").mkdir()
        (root / ".sampo" / "config.toml").write_text(
            '[changesets]\ntags = ["Breaking", "Features", "Fixes"]\n'
        )
        crate = root / "packages" / "a"
        crate.mkdir(parents=True)
        (crate / "Cargo.toml").write_text('[package]\nname = "vitaminc-a"\n')
        (crate / "CHANGELOG.md").write_text(changelog)
        return crate / "CHANGELOG.md"

    def test_only_the_newest_section_is_touched(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.workspace(
                Path(tmp),
                "# vitaminc-a\n\n## 0.6.2 — 2026-10-19\n\n### Patch changes\n\n"
                "- Bumped due to fixed dependency group policy\n\n" + RELEASED,
            )
            self.assertEqual(tidy(Path(tmp)), "")
            self.assertEqual(
                path.read_text(), "# vitaminc-a\n\n## 0.6.2 — 2026-10-19\n\n" + RELEASED
            )

    def test_the_notes_name_each_crate_with_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.workspace(
                Path(tmp),
                "# Changelog\n\n## 0.6.2 — 2026-10-19\n\n### Fixes\n\n- A fix.\n\n" + RELEASED,
            )
            self.assertEqual(tidy(Path(tmp)), "### vitaminc-a\n\n#### Fixes\n\n- A fix.")


if __name__ == "__main__":
    unittest.main()
