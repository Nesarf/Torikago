# -*- coding: utf-8 -*-
"""Every ceiling a run is subject to is answerable, and the report says so.

Nine caps used to live where their parsers happened to sit. Each was right; together they meant a reader had
no way to tell "512 functions" as a cap from "512 functions" as a count. The budget is one object, printed in
the report, and the constants stay where the parsers read them -- moving those would have been a rename
dressed as a design, and this item was about being able to answer the question, not about tidying.

Two assertions, and they fail differently: the budget must report the values the code actually uses (a copy
that drifts is worse than none), and the report must carry it (a budget nobody publishes answers nothing).
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

spec = importlib.util.spec_from_file_location("torikago_budget", ROOT / "torikago.py")
tri = importlib.util.module_from_spec(spec)
sys.modules["torikago_budget"] = tri
spec.loader.exec_module(tri)

PARSER_CONSTANTS = {
    "import_descriptors": "DESCRIPTOR_CAP",
    "functions_per_descriptor": "FUNC_CAP",
    "names_per_descriptor": "NAME_CAP",
    "peek_bytes": "PEEK_BYTES",
    "scan_coverage_bytes": "SCAN_COVERAGE",
    "max_file_bytes": "DEFAULT_MAX_BYTES",
    "nested_unpack_depth": "NESTED_UNPACK_MAX_DEPTH",
    "nested_unpack_total": "NESTED_UNPACK_MAX_TOTAL",
    "yara_corpus_bytes": "YARA_CORPUS_CAP",
}


class TestTheBudgetIsAnswerable(unittest.TestCase):

    def test_every_entry_reports_the_constant_it_names(self):
        """The budget must not become a second copy of the truth -- that is how a limit and its own
        documentation start disagreeing."""
        budget = tri.analysis_budget()
        for field, constant in PARSER_CONSTANTS.items():
            self.assertIn(field, budget, "%r is missing from the budget" % field)
            self.assertEqual(budget[field], getattr(tri, constant),
                             "%r reports %r but %s is %r"
                             % (field, budget[field], constant, getattr(tri, constant)))

    def test_the_budget_does_not_invent_entries(self):
        self.assertEqual(set(tri.analysis_budget()),
                         set(PARSER_CONSTANTS),
                         "the budget gained a field nothing maps to a constant for")

    def test_the_report_carries_it(self):
        import tempfile
        tn = importlib.util.spec_from_file_location("tn_budget", HERE / "test_torikago.py")
        module = importlib.util.module_from_spec(tn)
        sys.modules["tn_budget"] = module
        tn.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as d:
            sample = Path(d) / "one.exe"
            sample.write_bytes(module.build_pe())
            report = tri.build_report_with_unpack(
                sample, None, False, max_bytes=int(tri.DEFAULT_MAX_BYTES),
                force=False, yara_corpus=None)
        self.assertIn("budget", report)
        self.assertEqual(report["budget"], tri.analysis_budget())


if __name__ == "__main__":
    unittest.main()
