"""Tests for gate_scope.py. Run with `mise run gate-scope:test`."""

from __future__ import annotations

import io
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import gate_scope
from gate_scope import REPO_ROOT, SCOPES, changed_paths, gate_needed

CRAP = SCOPES["crap"]
MUTANTS = SCOPES["mutants"]


class GateNeededTest(unittest.TestCase):
    def test_rust_source_needs_both_gates(self):
        for scope in (CRAP, MUTANTS):
            self.assertTrue(gate_needed(scope, ["packages/aead/src/lib.rs"]))

    def test_workspace_manifests_need_both_gates(self):
        for scope in (CRAP, MUTANTS):
            self.assertTrue(gate_needed(scope, ["Cargo.toml"]))
            self.assertTrue(gate_needed(scope, ["Cargo.lock"]))

    def test_this_script_needs_both_gates(self):
        for scope in (CRAP, MUTANTS):
            self.assertTrue(gate_needed(scope, [gate_scope.SELF]))

    def test_docs_only_needs_neither_gate(self):
        paths = ["README.md", "docs/design.md", "packages/aead/README.md"]
        for scope in (CRAP, MUTANTS):
            self.assertFalse(gate_needed(scope, paths))

    def test_unrelated_files_need_neither_gate(self):
        paths = [".github/workflows/go.yml", "bindings/go/vcencrypt/go.mod", "LICENSE"]
        for scope in (CRAP, MUTANTS):
            self.assertFalse(gate_needed(scope, paths))

    def test_one_rust_file_among_docs_needs_the_gate(self):
        self.assertTrue(gate_needed(CRAP, ["README.md", "packages/hmac/src/lib.rs"]))

    def test_each_gate_owns_its_config_and_workflow(self):
        crap_only = [".cargo-crap.toml", ".github/workflows/crap.yml"]
        mutants_only = [".cargo/mutants.toml", ".github/workflows/mutants.yml"]
        for path in crap_only:
            self.assertTrue(gate_needed(CRAP, [path]), path)
            self.assertFalse(gate_needed(MUTANTS, [path]), path)
        for path in mutants_only:
            self.assertTrue(gate_needed(MUTANTS, [path]), path)
            self.assertFalse(gate_needed(CRAP, [path]), path)

    def test_directory_match_needs_a_path_separator(self):
        self.assertFalse(gate_needed(CRAP, ["packagesextra/lib.rs"]))

    def test_manifests_match_only_at_the_root(self):
        self.assertFalse(gate_needed(CRAP, ["bindings/go/Cargo.toml"]))
        self.assertTrue(gate_needed(CRAP, ["packages/aead/Cargo.toml"]))

    def test_empty_diff_runs_the_gate(self):
        for scope in (CRAP, MUTANTS):
            self.assertTrue(gate_needed(scope, []))


class ScopesMatchTheRepoTest(unittest.TestCase):
    """A renamed config file would otherwise drop out of scope silently."""

    def test_every_scoped_path_exists(self):
        for gate, scope in SCOPES.items():
            for d in scope.dirs:
                self.assertTrue(d.endswith("/"), f"{gate}: {d!r} needs a trailing /")
                self.assertTrue((REPO_ROOT / d).is_dir(), f"{gate}: {d} is missing")
            for f in scope.files:
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
        self.assertTrue(gate_needed(CRAP, self.changed()))

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
                mock.patch.object(gate_scope, "changed_paths", return_value=paths),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(gate_scope.main([gate]), 0)
            return output.read_text()

    def test_writes_needed_true_for_rust_changes(self):
        self.assertEqual(self.run_main(["packages/aead/src/lib.rs"]), "needed=true\n")

    def test_writes_needed_false_for_docs_only(self):
        self.assertEqual(self.run_main(["README.md"]), "needed=false\n")

    def test_rejects_an_unknown_gate(self):
        with self.assertRaises(SystemExit), redirect_stdout(io.StringIO()):
            with mock.patch("sys.stderr", io.StringIO()):
                gate_scope.main(["clippy"])


if __name__ == "__main__":
    unittest.main()
