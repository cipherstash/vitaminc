"""Release-bump regression tests for README version synchronization."""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from sync_readme_versions import inventory, main, sync


def managed(text: str, mode: str = "start") -> str:
    return f"<!-- workspace-deps:{mode} -->\n{text}\n<!-- workspace-deps:end -->\n"


class SyncTest(unittest.TestCase):
    def test_preserves_features_comments_third_party_and_historical_examples(self):
        snippet = '''```toml
[dependencies]
vitaminc = "0.8.1"  # keep this comment
vitaminc-random = { features = ["derive"], version = '0.8.1' }
renamed = { package = "vitaminc", version = "0.8.1", default-features = false }
chrono = { version = "0.8.1", features = ["std"] }
```
Also use `vitaminc-random = "0.8.1"` for key generation.'''
        history = '\nReleased in 0.8.1.\n' + managed('vitaminc = "0.1.0"', "keep")
        text = managed(snippet) + history
        versions = {"vitaminc": "0.9.0-pre.2", "vitaminc-random": "1.2.3"}
        expected = managed(snippet.replace(
            'vitaminc = "0.8.1"', 'vitaminc = "0.9.0-pre.2"'
        ).replace(
            "version = '0.8.1'", "version = '1.2.3'"
        ).replace(
            'package = "vitaminc", version = "0.8.1"',
            'package = "vitaminc", version = "0.9.0-pre.2"'
        ).replace(
            'vitaminc-random = "0.8.1"', 'vitaminc-random = "1.2.3"'
        )) + history
        self.assertEqual(sync(text, versions), expected)
        self.assertEqual(sync(expected, versions), expected)

    def test_new_unmarked_snippets_fail_even_when_version_is_current(self):
        for text in ('vitaminc = "1.0.0"', 'Use `vitaminc = "1.0.0"`.',
                     'vc = { package = "vitaminc", version = "1.0.0" }'):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "unmarked"):
                sync(text, {"vitaminc": "1.0.0"})

    def test_invalid_markers_fail(self):
        for text in ("<!-- workspace-deps:end -->", "<!-- workspace-deps:start -->",
                     managed(managed('vitaminc = "0.1.0"'))):
            with self.subTest(text=text), self.assertRaises(ValueError):
                sync(text, {"vitaminc": "1.0.0"})

    def test_multiline_declaration_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "single-line"):
            sync(managed('vitaminc = {\nversion = "0.1.0"\n}'), {"vitaminc": "1.0.0"})

    def test_non_versioned_dependencies_are_unchanged(self):
        text = 'vitaminc = { workspace = true }\nvitaminc-random = { path = "../random" }'
        self.assertEqual(sync(text, {"vitaminc": "1.0.0", "vitaminc-random": "1.0.0"}), text)


class ReleaseTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.write("Cargo.toml", '''[workspace]
members = ["packages/*"]
exclude = ["packages/excluded"]
[workspace.package]
version = "0.9.0"
''')
        self.write("README.md", managed('vitaminc-one = "0.8.1"'))
        self.write("packages/one/Cargo.toml", '''[package]
name = "vitaminc-one"
version.workspace = true
''')
        self.write("packages/one/README.md", managed('vitaminc-one = "0.8.1"'))
        self.write("packages/two/Cargo.toml", '''[package]
name = "vitaminc-two"
version = "2.0.0-pre.1"
readme = "GUIDE.md"
''')
        self.write("packages/two/GUIDE.md", managed('vitaminc-two = "0.8.1"'))
        self.write("packages/excluded/Cargo.toml", "invalid TOML; must not be read")

    def write(self, path: str, content: str):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def run_script(self, *args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main([str(self.root), *args])

    def test_release_bump_check_is_read_only_then_sync_and_check_pass(self):
        paths = inventory(self.root)[1]
        before = {path: path.read_bytes() for path in paths}
        self.assertEqual(len(paths), 3)
        self.assertEqual(self.run_script("--check"), 1)
        self.assertEqual({path: path.read_bytes() for path in paths}, before)
        self.assertEqual(self.run_script(), 0)
        self.assertEqual(self.run_script("--check"), 0)
        self.assertIn('"0.9.0"', (self.root / "README.md").read_text())
        self.assertIn('"2.0.0-pre.1"', (self.root / "packages/two/GUIDE.md").read_text())

    def test_new_workspace_members_are_automatically_included(self):
        self.write("packages/new/Cargo.toml", '[package]\nname = "vitaminc-new"\nversion.workspace = true')
        self.write("packages/new/README.md", managed('vitaminc-new = "0.1.0"'))
        self.assertEqual(self.run_script(), 0)
        self.assertIn('"0.9.0"', (self.root / "packages/new/README.md").read_text())

    def test_no_files_written_if_another_readme_has_an_unmarked_example(self):
        path = self.root / "README.md"
        before = path.read_bytes()
        self.write("packages/two/GUIDE.md", 'vitaminc-two = "0.8.1"')
        self.assertEqual(self.run_script(), 1)
        self.assertEqual(path.read_bytes(), before)

    def test_missing_or_disabled_default_readmes_need_no_configuration(self):
        (self.root / "packages/one/README.md").unlink()
        self.write("packages/two/Cargo.toml", '[package]\nname = "two"\nversion = "1.0.0"\nreadme = false')
        self.assertEqual(inventory(self.root)[1], [self.root / "README.md"])

    def test_readme_path_cannot_escape_worktree(self):
        self.write("packages/two/Cargo.toml", '[package]\nname = "two"\nversion = "1.0.0"\nreadme = "../../../outside.md"')
        self.assertEqual(self.run_script(), 1)

    def test_shared_internal_symlink_readme_is_updated_once(self):
        path = self.root / "packages/one/README.md"
        path.unlink()
        path.symlink_to(self.root / "README.md")
        self.assertEqual(len(inventory(self.root)[1]), 2)
        self.assertEqual(self.run_script(), 0)
        self.assertTrue(path.is_symlink())
        self.assertIn('"0.9.0"', path.read_text())

    def test_external_symlink_readme_is_rejected(self):
        path = self.root / "packages/one/README.md"
        path.unlink()
        path.symlink_to(self.root.parent / "outside.md")
        self.assertEqual(self.run_script(), 1)

    def test_inherited_readme_is_relative_to_workspace(self):
        path = self.root / "Cargo.toml"
        path.write_text(path.read_text() + 'readme = "README.md"\n')
        path = self.root / "packages/one/Cargo.toml"
        path.write_text(path.read_text() + 'readme.workspace = true\n')
        self.assertEqual(len(inventory(self.root)[1]), 2)


if __name__ == "__main__":
    unittest.main()
