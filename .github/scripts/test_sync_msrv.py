"""Manifest-bump regression tests for MSRV documentation and CI selection."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from sync_msrv import inventory, main, sync


def marked(source: str, value: str) -> str:
    return f"<!-- msrv:{source} -->{value}<!-- /msrv -->"


class TextTest(unittest.TestCase):
    def test_formats_and_history_are_preserved(self):
        text = "Requires Rust " + marked("core", "**1.88.0**") + ".\n"
        text += "MSRV " + marked("kms", "`1.94.1`") + "; " + marked("core", "1.88.0") + "\n"
        text += marked("keep", "Earlier releases required Rust 1.70.0.") + "\n"
        result = sync(text, {"core": "1.90.0", "kms": "1.96.0"})
        self.assertEqual(result, text.replace("1.88.0", "1.90.0").replace("1.94.1", "1.96.0"))
        self.assertEqual(sync(result, {"core": "1.90.0", "kms": "1.96.0"}), result)

    def test_only_rust_doc_comments_are_updated(self):
        claim = "Rust " + marked("core", "1.88.0")
        source = f'//!{claim}\n    ///{claim}\n// {claim}\n//// {claim}\nconst LABEL: &str = "{claim}";\n'
        result = sync(source, {"core": "1.90.0"}, rust=True)
        self.assertEqual(result.count("1.90.0"), 2)
        self.assertEqual(result.count("1.88.0"), 3)

    def test_unmarked_claims_are_errors_even_when_current(self):
        for text in ("Requires Rust **1.88.0**", "MSRV: `1.88`", "rust-version is 1.88.0"):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "unmarked"):
                sync(text, {"core": "1.88.0"})
        # Package release numbers and unrelated prose are not Rust requirements.
        self.assertEqual(sync("MSRV bumps require 0.8 -> 0.9.\ncrate = 1.0.0", {}),
                         "MSRV bumps require 0.8 -> 0.9.\ncrate = 1.0.0")

    def test_bad_markers_and_sources_fail(self):
        cases = [
            "<!-- /msrv -->", "<!-- msrv:core -->1.88.0",
            marked("core", marked("core", "1.88.0")),
            marked("unknown", "1.88.0"), marked("core", "not a version"),
            marked("core", "**1.88.0`"), marked("core", "\n1.88.0\n"),
            "<!-- msrv:core-->1.88.0<!-- /msrv -->",
        ]
        for text in cases:
            with self.subTest(text=text), self.assertRaises(ValueError):
                sync(text, {"core": "1.88.0"})


class WorkspaceTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.write("Cargo.toml", '''[workspace]
members = ["packages/*"]
[workspace.package]
rust-version = "1.88.0"
''')
        self.package("core")
        self.package("kms", 'rust-version = "1.94.1"')
        self.package("facade", extra='''
[features]
aws-kms = []
[package.metadata.msrv.features]
aws-kms = ["kms"]
''')
        self.write("README.md", "Rust " + marked("workspace", "**1.88.0**") + "\n")
        self.write("packages/core/README.md", "Rust " + marked("core", "1.88.0") + "\n")
        self.write("packages/kms/src/lib.rs", "//! Rust " + marked("kms", "1.94.1") + "\n")
        self.write("packages/facade/README.md", "Rust " + marked("facade/aws-kms", "1.94.1") + "\n")

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def package(self, name, msrv='rust-version.workspace = true', extra=""):
        self.write(f"packages/{name}/Cargo.toml", f'[package]\nname = "{name}"\n{msrv}\n{extra}')

    def run_sync(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = main([str(self.root), *args])
        return result, out.getvalue(), err.getvalue()

    def bump(self, path, old, new):
        p = self.root / path
        p.write_text(p.read_text().replace(old, new))

    def test_manifest_bumps_update_readmes_rustdoc_and_feature_requirement(self):
        self.bump("Cargo.toml", "1.88.0", "1.90.0")
        self.bump("packages/kms/Cargo.toml", "1.94.1", "1.96.0")
        before = (self.root / "README.md").read_text()
        result, out, err = self.run_sync("--check")
        self.assertEqual(result, 1)
        self.assertIn("stale: packages/kms/src/lib.rs", out)
        self.assertIn("sync_msrv.py", err)
        self.assertEqual((self.root / "README.md").read_text(), before)
        self.assertEqual(self.run_sync()[0], 0)
        self.assertIn("1.90.0", (self.root / "packages/core/README.md").read_text())
        self.assertIn("1.96.0", (self.root / "packages/kms/src/lib.rs").read_text())
        self.assertIn("1.96.0", (self.root / "packages/facade/README.md").read_text())
        self.assertEqual(self.run_sync("--check"), (0, "", ""))

    def test_matrix_covers_every_member_at_its_floor_and_feature_scenario(self):
        self.package("new-crate", 'rust-version = "1.92"')
        self.package("private-fixture", extra="publish = false\n")
        versions, _, matrix = inventory(self.root)
        rows = matrix["include"]
        self.assertEqual([r["toolchain"] for r in rows], ["1.88.0", "1.92.0", "1.94.1", "1.94.1"])
        self.assertIn("-p private-fixture", rows[0]["args"])
        self.assertNotIn("-p kms", rows[0]["args"])
        self.assertEqual(rows[1]["args"], "--all-targets -p new-crate")
        self.assertEqual(rows[-1]["args"], "--all-targets -p facade --no-default-features --features aws-kms")
        self.assertEqual(versions["new-crate"], "1.92")
        result, out, err = self.run_sync("--matrix")
        self.assertEqual((result, err), (0, ""))
        self.assertEqual(json.loads(out), matrix)

    def test_feature_floor_is_max_of_facade_and_dependencies(self):
        self.package("facade", 'rust-version = "1.100.0"', extra='''
[features]
aws-kms = []
[package.metadata.msrv.features]
aws-kms = ["kms"]
''')
        versions, _, matrix = inventory(self.root)
        self.assertEqual(versions["facade/aws-kms"], "1.100.0")
        self.assertEqual(matrix["include"][-1]["toolchain"], "1.100.0")

    def test_future_crate_and_custom_source_are_discovered(self):
        self.package("new-crate", 'rust-version = "1.90.0"', extra='[lib]\npath = "entry.rs"\n')
        self.write("packages/new-crate/entry.rs", "/// Rust " + marked("new-crate", "1.88.0"))
        self.write("packages/new-crate/src/module.rs", "//! Rust " + marked("new-crate", "1.88.0"))
        self.assertEqual(self.run_sync()[0], 0)
        for file in ("entry.rs", "src/module.rs"):
            self.assertIn("1.90.0", (self.root / "packages/new-crate" / file).read_text())

    def test_root_package_inherited_readme_and_symlink_are_deduplicated(self):
        root = self.root / "Cargo.toml"
        root.write_text(root.read_text().replace('rust-version = "1.88.0"', 'rust-version = "1.88.0"\nreadme = "README.md"') +
                        '\n[package]\nname = "root-package"\nrust-version.workspace = true\n')
        self.package("inherited", extra="readme.workspace = true\n")
        self.package("linked")
        (self.root / "packages/linked/README.md").symlink_to(self.root / "README.md")
        versions, files, matrix = inventory(self.root)
        self.assertEqual(files.count(self.root / "README.md"), 1)
        self.assertEqual(versions["root-package"], "1.88.0")
        self.assertIn("-p root-package", matrix["include"][0]["args"])

    def test_invalid_late_file_prevents_all_writes(self):
        self.bump("Cargo.toml", "1.88.0", "1.90.0")
        before = (self.root / "README.md").read_bytes()
        self.write("packages/kms/src/z.rs", "//! Rust " + marked("missing", "1.0.0"))
        self.assertEqual(self.run_sync()[0], 1)
        self.assertEqual((self.root / "README.md").read_bytes(), before)

    def test_missing_floor_and_invalid_toolchain_fail(self):
        for field in ("", 'rust-version = "stable"', 'rust-version = "1.88.0; echo bad"'):
            with self.subTest(field=field):
                self.package("core", field)
                self.assertEqual(self.run_sync("--matrix")[0], 1)

    def test_unknown_feature_and_dependency_fail(self):
        for old, new in [('aws-kms = ["kms"]', 'missing = ["kms"]'),
                         ('["kms"]', '["missing"]'), ('["kms"]', '"kms"')]:
            with self.subTest(new=new):
                p = self.root / "packages/facade/Cargo.toml"
                original = p.read_text()
                p.write_text(original.replace(old, new))
                self.assertEqual(self.run_sync("--matrix")[0], 1)
                p.write_text(original)

    def test_manifest_readme_and_source_cannot_escape_worktree(self):
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "outside"
            outside.write_text("Rust 1.88.0")
            for file in ("packages/core/Cargo.toml", "packages/core/README.md", "packages/core/src/lib.rs"):
                with self.subTest(file=file):
                    p = self.root / file
                    original = p.read_bytes() if p.exists() else None
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.unlink(missing_ok=True)
                    p.symlink_to(outside)
                    self.assertEqual(self.run_sync()[0], 1)
                    self.assertEqual(outside.read_text(), "Rust 1.88.0")
                    p.unlink()
                    if original is not None:
                        p.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
