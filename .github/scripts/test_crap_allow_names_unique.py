"""Tests for crap_allow_names_unique.py. Run with `mise run crap:allow:check:test`."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from crap_allow_names_unique import bare_names, problems


def repo(files: dict[str, str]) -> tempfile.TemporaryDirectory:
    """A throwaway git repository holding `files`, all tracked."""
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    return tmp


class BareNamesTest(unittest.TestCase):
    def test_file_globs_and_methods_are_not_bare_names(self):
        allow = ["**/random-derives/**", "src/gen/*.rs", "JsRef::visit", "js_walk"]
        self.assertEqual(bare_names(allow), ["js_walk"])


class ProblemsTest(unittest.TestCase):
    def test_a_name_defined_once_passes(self):
        with repo({"a/src/lib.rs": "fn js_walk<S>(s: S) {}\n"}) as root:
            self.assertEqual(problems(["js_walk"], Path(root)), {})

    def test_a_name_defined_in_two_crates_fails_with_both_places(self):
        files = {
            "a/src/lib.rs": "fn walk<S>(s: S) {}\n",
            "b/src/lib.rs": "pub fn walk(node: Node) {}\n",
        }
        with repo(files) as root:
            bad = problems(["walk"], Path(root))
        self.assertEqual(list(bad), ["walk"])
        self.assertEqual(len(bad["walk"]), 2)

    def test_a_name_defined_nowhere_fails(self):
        with repo({"a/src/lib.rs": "fn other() {}\n"}) as root:
            self.assertEqual(problems(["gone"], Path(root)), {"gone": []})

    def test_a_longer_name_or_a_call_is_not_a_definition(self):
        files = {"a/src/lib.rs": "fn walk() { js_walk(); }\nfn walk_all() {}\nfn js_walk() {}\n"}
        with repo(files) as root:
            self.assertEqual(problems(["walk"], Path(root)), {})

    def test_methods_and_qualified_entries_are_not_checked(self):
        with repo({"a/src/lib.rs": "fn x() {}\n"}) as root:
            self.assertEqual(problems(["JsRef::visit", "**/gen/**"], Path(root)), {})


if __name__ == "__main__":
    unittest.main()
