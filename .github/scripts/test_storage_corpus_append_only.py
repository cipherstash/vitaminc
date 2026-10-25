"""Tests for storage_corpus_append_only.py. Run with `mise run storage:corpus:check:test`."""

from __future__ import annotations

import copy
import unittest

from storage_corpus_append_only import problems

BASE = {
    "description": "corpus",
    "version": 1,
    "header": "56435301",
    "vectors": [
        {"name": "null", "value": None, "blob": "5643530100"},
        {"name": "true", "value": {"bool": True}, "blob": "5643530103"},
    ],
    "refused": [{"name": "empty", "refusal": "not_a_blob", "blob": ""}],
}


class ProblemsTest(unittest.TestCase):
    def test_the_same_corpus_passes(self):
        self.assertEqual(problems(BASE, copy.deepcopy(BASE)), [])

    def test_a_new_row_and_a_new_section_pass(self):
        head = copy.deepcopy(BASE)
        head["vectors"].append({"name": "false", "value": {"bool": False}, "blob": "5643530102"})
        head["normalized"] = [{"name": "x"}]
        self.assertEqual(problems(BASE, head), [])

    def test_rows_may_move(self):
        head = copy.deepcopy(BASE)
        head["vectors"].reverse()
        self.assertEqual(problems(BASE, head), [])

    def test_the_description_may_change(self):
        head = copy.deepcopy(BASE)
        head["description"] = "clearer"
        self.assertEqual(problems(BASE, head), [])

    def test_a_changed_row_fails(self):
        head = copy.deepcopy(BASE)
        head["vectors"][1]["blob"] = "5643530102"
        self.assertEqual(problems(BASE, head), ["vectors: row 'true' was changed"])

    def test_a_changed_refusal_class_fails(self):
        head = copy.deepcopy(BASE)
        head["refused"][0]["refusal"] = "malformed"
        self.assertEqual(problems(BASE, head), ["refused: row 'empty' was changed"])

    def test_a_removed_row_fails(self):
        head = copy.deepcopy(BASE)
        del head["vectors"][0]
        self.assertEqual(problems(BASE, head), ["vectors: row 'null' was removed"])

    def test_a_renamed_row_is_a_removed_row(self):
        head = copy.deepcopy(BASE)
        head["vectors"][0]["name"] = "unit"
        self.assertEqual(problems(BASE, head), ["vectors: row 'null' was removed"])

    def test_a_removed_section_fails_for_every_row(self):
        head = copy.deepcopy(BASE)
        del head["refused"]
        self.assertEqual(problems(BASE, head), ["refused: row 'empty' was removed"])

    def test_the_header_and_version_are_frozen(self):
        head = copy.deepcopy(BASE)
        head["header"] = "56435302"
        head["version"] = 2
        self.assertEqual(
            problems(BASE, head),
            ["version changed from 1 to 2", "header changed from '56435301' to '56435302'"],
        )


if __name__ == "__main__":
    unittest.main()
