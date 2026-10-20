# -*- coding: utf-8 -*-
"""Two layers: a manifest that reads as a diff, and a scan row that allows a re-measurement.

The first version of this test asked whether the raw file had *more keys* than the manifest row. It came out
13 against 18, and that reading was wrong: the manifest row is longer only because it adds bookkeeping
(sha, schema, first_seen), while the scan row carries facts the manifest drops on purpose -- `all_imports`
above all, which is what the injection-triad judgement is made from.

So the question is not how many fields, it is **which fields**. That is what this file asserts.
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


tri = load("torikago_raw", "torikago.py")
corpus = load("corpus_raw", "corpus.py")
tn = load("tn_raw", HERE / "test_torikago.py")

#: The field that makes the second layer worth having: dropped from the manifest on purpose, needed to
#: re-derive the injection-triad judgement.
DROPPED = "all_imports"


class TestTheRawLayer(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.samples = self.dir / "samples"
        self.samples.mkdir()
        (self.samples / "one.exe").write_bytes(tn.build_pe())
        self.manifest = self.dir / "manifest.jsonl"

    def _write(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = tri.main(["--corpus-write", str(self.samples), "--corpus-file", str(self.manifest),
                           "--scan-limit", "5"])
        return rc, buf.getvalue()

    def _layers(self):
        rc, out = self._write()
        self.assertEqual(rc, 0, out)
        rows = [json.loads(line) for line in
                self.manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(len(rows), 1)
        raw_dir = self.manifest.parent / corpus.RAW_DIR
        files = sorted(raw_dir.glob("*.json"))
        self.assertEqual(len(files), 1, "expected one raw row, found %r" % (files,))
        return rows[0], json.loads(files[0].read_text(encoding="utf-8"))

    def test_the_raw_file_is_named_by_the_sample_hash(self):
        manifest_row, _ = self._layers()
        raw_dir = self.manifest.parent / corpus.RAW_DIR
        self.assertEqual(next(raw_dir.glob("*.json")).stem, manifest_row["sha256"])

    def test_the_raw_row_carries_what_the_manifest_drops(self):
        manifest_row, raw_row = self._layers()
        self.assertIn(DROPPED, raw_row, "the raw row is missing the field it exists to keep")
        self.assertNotIn(DROPPED, manifest_row,
                         "the manifest gained the dropped field, which is what the second layer exists to "
                         "avoid")

    def test_the_manifest_did_not_grow(self):
        manifest_row, _ = self._layers()
        allowed = set(corpus.ROW_FIELDS) | {"sha256", "schema", "first_seen", "last_seen",
                                            "times_seen", "path_hint", "coverage", "import_count"}
        self.assertTrue(set(manifest_row) <= allowed,
                        "the manifest gained fields: %r" % (sorted(set(manifest_row) - allowed),))


if __name__ == "__main__":
    unittest.main()
