"""Tests for crap_allow_names_unique.py. Run with `mise run crap:allow:check:test`."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from crap_allow_names_unique import analysed_functions, bare_names, problems


class BareNamesTest(unittest.TestCase):
    def test_file_globs_and_methods_are_not_bare_names(self):
        allow = ["**/random-derives/**", "src/gen/*.rs", "JsRef::visit", "js_walk"]
        self.assertEqual(bare_names(allow), ["js_walk"])


class ProblemsTest(unittest.TestCase):
    def test_a_name_defined_once_passes(self):
        self.assertEqual(problems(["js_walk"], ["js_walk", "walk"]), {})

    def test_a_name_defined_twice_fails_with_its_count(self):
        self.assertEqual(problems(["walk"], ["walk", "js_walk", "walk"]), {"walk": 2})

    def test_a_name_defined_nowhere_fails(self):
        self.assertEqual(problems(["gone"], ["walk"]), {"gone": 0})

    def test_a_method_with_the_same_name_is_not_a_match(self):
        self.assertEqual(problems(["map"], ["map", "JsBuilder::map"]), {})

    def test_qualified_and_path_entries_are_not_checked(self):
        self.assertEqual(problems(["JsRef::visit", "**/gen/**"], []), {})


@unittest.skipUnless(shutil.which("cargo-crap"), "needs cargo-crap on the PATH")
class AnalysedFunctionsTest(unittest.TestCase):
    """Runs cargo-crap itself over a small crate."""

    def crate(self, files: dict[str, str]) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for path, text in files.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text)
        return root

    def test_a_name_in_a_comment_a_doc_example_or_a_string_is_not_a_function(self):
        root = self.crate(
            {
                "src/lib.rs": (
                    "/// ```\n"
                    "/// fn js_walk() {}\n"
                    "/// ```\n"
                    "pub fn js_walk() {}\n"
                    "// fn js_walk() {}\n"
                    'pub const S: &str = "fn js_walk() {}";\n'
                ),
            }
        )
        self.assertEqual(analysed_functions([root], []).count("js_walk"), 1)

    def test_an_excluded_file_is_not_analysed(self):
        root = self.crate(
            {
                "src/lib.rs": "pub fn walk() {}\n",
                "src/test_support.rs": "pub fn walk() {}\n",
            }
        )
        self.assertEqual(analysed_functions([root], []).count("walk"), 2)
        self.assertEqual(analysed_functions([root], ["src/test_support.rs"]).count("walk"), 1)

    def test_a_config_beside_the_code_does_not_apply(self):
        root = self.crate(
            {
                "src/lib.rs": "pub fn js_walk() {}\n",
                ".cargo-crap.toml": 'allow = ["js_walk"]\n',
            }
        )
        # cargo-crap run from beside the config hides the allowlisted name...
        beside = subprocess.run(
            ["cargo", "crap", "--path", str(root), "--format", "json", "--no-cache"],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(json.loads(beside.stdout)["entries"], [])
        # ...and the check, which runs it from elsewhere, still sees it.
        self.assertEqual(analysed_functions([root], []), ["js_walk"])


if __name__ == "__main__":
    unittest.main()
