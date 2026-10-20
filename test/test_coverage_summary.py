# -*- coding: utf-8 -*-
"""The summary must not re-flatten what `coverage_of` separated.

A row measured over the whole file, a row that stopped at a cap, and a row from an older schema that never
recorded coverage used to look identical. `coverage_of` gave them three names. **A summary that counts rows
without asking which name each carries puts them back together** -- and the summary is the number a reader
quotes, so that is exactly where the flattening would do damage.

Three states, asserted on the data and on both outputs of the command that shows it.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


corpus = load("corpus_coverage", "corpus.py")
tri = load("torikago_coverage", "torikago.py")

COMPLETE_ROW = {"sha256": "a" * 64, "packer": "none", "kind": "pe", "attention": 0, "limits": {}}
PARTIAL_ROW = {"sha256": "b" * 64, "packer": "none", "kind": "pe", "attention": 0, "truncated": True}
UNKNOWN_ROW = {"sha256": "c" * 64, "packer": "none", "kind": "pe", "attention": 0}


class TestTheSummaryKeepsTheThreeStatesApart(unittest.TestCase):

    def test_the_counts_are_per_state(self):
        entries = {r["sha256"]: r for r in (COMPLETE_ROW, PARTIAL_ROW, UNKNOWN_ROW)}
        stats = corpus.summarize(entries)
        self.assertEqual(stats["coverage"],
                         {corpus.MEASUREMENT_COMPLETE: 1,
                          corpus.MEASUREMENT_PARTIAL: 1,
                          corpus.MEASUREMENT_UNKNOWN: 1})

    def test_a_corpus_of_only_complete_rows_says_so(self):
        entries = {("d" * 64): dict(COMPLETE_ROW, sha256="d" * 64)}
        stats = corpus.summarize(entries)
        self.assertEqual(stats["coverage"][corpus.MEASUREMENT_COMPLETE], 1)
        self.assertEqual(stats["coverage"][corpus.MEASUREMENT_PARTIAL], 0)


class TestTheCommandShowsIt(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.manifest = Path(self.tmp.name) / "manifest.jsonl"
        self.manifest.write_text(
            "\n".join(json.dumps(r) for r in (COMPLETE_ROW, PARTIAL_ROW, UNKNOWN_ROW)) + "\n",
            encoding="utf-8")

    def _run(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = tri.main(argv)
        return rc, buf.getvalue()

    def test_the_human_output_names_the_states(self):
        rc, out = self._run(["--corpus-check", str(self.manifest)])
        self.assertEqual(rc, 0)
        self.assertIn("coverage", out)
        self.assertIn("complete=1", out)
        self.assertIn("partial=1", out)
        self.assertIn("unknown=1", out)

    def test_it_says_a_truncated_row_is_not_a_verdict(self):
        rc, out = self._run(["--corpus-check", str(self.manifest)])
        self.assertEqual(rc, 0)
        self.assertIn("not a verdict", out)
        self.assertIn("re-sweep", out)

    def test_json_carries_the_counts(self):
        rc, out = self._run(["--corpus-check", str(self.manifest), "--json"])
        self.assertEqual(rc, 0)
        body = json.loads(out)
        self.assertEqual(body["coverage"][corpus.MEASUREMENT_PARTIAL], 1)
        self.assertEqual(body["coverage"][corpus.MEASUREMENT_UNKNOWN], 1)


if __name__ == "__main__":
    unittest.main()
