"""Tests for has_rust_changes.py. Run with `mise run pr:gate:has_rust_changes:test`."""

from __future__ import annotations

import io
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import has_rust_changes as script
from has_rust_changes import REPO_ROOT, RUST_PATHS, changed_paths, has_rust_changes

CRAP = RUST_PATHS["crap"]
MUTANTS = RUST_PATHS["mutants"]


class HasRustChangesTest(unittest.TestCase):
    def test_rust_source_is_a_rust_change_for_both_gates(self):
        for rust_paths in (CRAP, MUTANTS):
            self.assertTrue(has_rust_changes(rust_paths, ["packages/aead/src/lib.rs"]))

    def test_workspace_manifests_are_rust_changes_for_both_gates(self):
        for rust_paths in (CRAP, MUTANTS):
            self.assertTrue(has_rust_changes(rust_paths, ["Cargo.toml"]))
            self.assertTrue(has_rust_changes(rust_paths, ["Cargo.lock"]))

    def test_this_script_is_a_rust_change_for_both_gates(self):
        for rust_paths in (CRAP, MUTANTS):
            self.assertTrue(has_rust_changes(rust_paths, [script.SELF]))

    def test_docs_only_has_no_rust_changes(self):
        paths = ["README.md", "docs/design.md", "packages/aead/README.md"]
        for rust_paths in (CRAP, MUTANTS):
            self.assertFalse(has_rust_changes(rust_paths, paths))

    def test_unrelated_files_have_no_rust_changes(self):
        paths = [".github/workflows/go.yml", "bindings/go/vcencrypt/go.mod", "LICENSE"]
        for rust_paths in (CRAP, MUTANTS):
            self.assertFalse(has_rust_changes(rust_paths, paths))

    def test_one_rust_file_among_docs_is_a_rust_change(self):
        self.assertTrue(has_rust_changes(CRAP, ["README.md", "packages/hmac/src/lib.rs"]))

    def test_each_gate_owns_its_config_and_workflow(self):
        crap_only = [".cargo-crap.toml", ".github/workflows/crap.yml"]
        mutants_only = [".cargo/mutants.toml", ".github/workflows/mutants.yml"]
        for path in crap_only:
            self.assertTrue(has_rust_changes(CRAP, [path]), path)
            self.assertFalse(has_rust_changes(MUTANTS, [path]), path)
        for path in mutants_only:
            self.assertTrue(has_rust_changes(MUTANTS, [path]), path)
            self.assertFalse(has_rust_changes(CRAP, [path]), path)

    def test_directory_match_needs_a_path_separator(self):
        self.assertFalse(has_rust_changes(CRAP, ["packagesextra/lib.rs"]))

    def test_manifests_match_only_at_the_root(self):
        self.assertFalse(has_rust_changes(CRAP, ["bindings/go/Cargo.toml"]))
        self.assertTrue(has_rust_changes(CRAP, ["packages/aead/Cargo.toml"]))

    def test_empty_diff_counts_as_rust_changes(self):
        for rust_paths in (CRAP, MUTANTS):
            self.assertTrue(has_rust_changes(rust_paths, []))


class RustPathsMatchTheRepoTest(unittest.TestCase):
    """A renamed config file would otherwise drop out of the list silently."""

    def test_every_listed_path_exists(self):
        for gate, rust_paths in RUST_PATHS.items():
            for d in rust_paths.dirs:
                self.assertTrue(d.endswith("/"), f"{gate}: {d!r} needs a trailing /")
                self.assertTrue((REPO_ROOT / d).is_dir(), f"{gate}: {d} is missing")
            for f in rust_paths.files:
                self.assertTrue((REPO_ROOT / f).is_file(), f"{gate}: {f} is missing")


class ChangedPathsTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        # Isolate from the developer's git config, e.g. commit signing.
        env = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.git("init", "-q", "-b", "main")
        self.write("packages/aead/src/lib.rs", "fn main() {}\n")
        self.write("README.md", "# vitaminc\n")
        self.commit("base")
        self.git("switch", "-q", "-c", "feature")

    def git(self, *args: str) -> None:
        subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
            cwd=self.repo,
            check=True,
        )

    def write(self, path: str, text: str) -> None:
        (self.repo / path).parent.mkdir(parents=True, exist_ok=True)
        (self.repo / path).write_text(text)

    def commit(self, message: str) -> None:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def changed(self) -> list[str]:
        return sorted(changed_paths("main", "HEAD", cwd=self.repo))

    def test_lists_files_changed_on_the_branch(self):
        self.write("README.md", "# changed\n")
        self.commit("docs")
        self.assertEqual(self.changed(), ["README.md"])

    def test_rename_lists_both_old_and_new_paths(self):
        (self.repo / "docs").mkdir()
        self.git("mv", "packages/aead/src/lib.rs", "docs/lib.rs")
        self.commit("move")
        self.assertEqual(self.changed(), ["docs/lib.rs", "packages/aead/src/lib.rs"])
        self.assertTrue(has_rust_changes(CRAP, self.changed()))

    def test_ignores_changes_made_on_the_base_after_the_fork(self):
        self.write("README.md", "# changed\n")
        self.commit("docs")
        self.git("switch", "-q", "main")
        self.write("packages/aead/src/lib.rs", "fn changed() {}\n")
        self.commit("base moves on")
        self.git("switch", "-q", "feature")
        self.assertEqual(self.changed(), ["README.md"])

    def test_keeps_unusual_characters_unquoted(self):
        self.write("packages/aead/src/ünïcode file.rs", "\n")
        self.commit("odd name")
        self.assertEqual(self.changed(), ["packages/aead/src/ünïcode file.rs"])

    def test_unknown_base_raises(self):
        with self.assertRaises(subprocess.CalledProcessError):
            changed_paths("no-such-branch", "HEAD", cwd=self.repo)


class MainTest(unittest.TestCase):
    def run_main(self, paths: list[str], gate: str = "crap") -> str:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "github_output"
            with (
                mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
                mock.patch.object(script, "changed_paths", return_value=paths),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(script.main([gate]), 0)
            return output.read_text()

    def test_writes_true_for_rust_changes(self):
        self.assertEqual(self.run_main(["packages/aead/src/lib.rs"]), "has_rust_changes=true\n")

    def test_writes_false_for_docs_only(self):
        self.assertEqual(self.run_main(["README.md"]), "has_rust_changes=false\n")

    def test_rejects_an_unknown_gate(self):
        with self.assertRaises(SystemExit), redirect_stdout(io.StringIO()):
            with mock.patch("sys.stderr", io.StringIO()):
                script.main(["clippy"])


if __name__ == "__main__":
    unittest.main()
