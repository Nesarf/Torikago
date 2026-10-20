# -*- coding: utf-8 -*-
"""An old schema row is old, not untrustworthy, and the summary must say which it is.

The `schema` field has been written since the beginning and nothing ever read it back. Two rows measured
under different generations therefore look like two measurements of the same thing -- and a rate computed
across them is a rate across two different questions.

**Re-measuring quietly would also be wrong**, because it erases the record that the schema moved. So the count
is reported and the difference is stated.
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
    path = Path(filename)
    if not path.is_absolute():
        path = ROOT / path
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


tri = load("torikago_schema", "torikago.py")
corpus = load("corpus_schema", "corpus.py")

CURRENT = {"sha256": "a" * 64, "schema": corpus.SCHEMA_VERSION, "packer": "none", "kind": "pe",
           "attention": 0, "limits": {}}
OLDER = {"sha256": "b" * 64, "schema": corpus.SCHEMA_VERSION - 1, "packer": "none", "kind": "pe",
         "attention": 0, "limits": {}}


class TestSchemaGenerationIsVisible(unittest.TestCase):

    def test_the_summary_counts_rows_per_generation(self):
        stats = corpus.summarize({r["sha256"]: r for r in (CURRENT, OLDER)})
        self.assertEqual(stats["schema"][str(corpus.SCHEMA_VERSION)], 1)
        self.assertEqual(stats["schema"][str(corpus.SCHEMA_VERSION - 1)], 1)

    def test_the_command_says_old_is_not_untrustworthy(self):
        with tempfile.TemporaryDirectory() as d:
            manifest = Path(d) / "manifest.jsonl"
            manifest.write_text("\n".join(json.dumps(r) for r in (CURRENT, OLDER)) + "\n",
                                encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = tri.main(["--corpus-check", str(manifest)])
            out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("schema", out)
        self.assertIn("old, not untrustworthy", out)
        self.assertIn("re-measure them before mixing", out)

    def test_a_single_generation_says_nothing_about_migration(self):
        with tempfile.TemporaryDirectory() as d:
            manifest = Path(d) / "manifest.jsonl"
            manifest.write_text(json.dumps(CURRENT) + "\n", encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                tri.main(["--corpus-check", str(manifest)])
            out = buf.getvalue()
        self.assertIn("schema", out)
        self.assertNotIn("old, not untrustworthy", out)


if __name__ == "__main__":
    unittest.main()
