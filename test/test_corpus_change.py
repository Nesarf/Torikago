# -*- coding: utf-8 -*-
"""A changed measurement for a hash already in the manifest is reported, not absorbed.

`merge_manifest` has been recording the differences all along -- field, old value, new value -- and nothing
printed them. So the file kept the newer number and said nothing, which made "the sample changed" and "the
detector changed" the same event. Those two are the reason a corpus exists at all.

This cannot tell them apart either. What it asserts is that the question is put to the reader instead of
being buried under a silent overwrite.
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


tri = load("torikago_change", "torikago.py")
tn = load("tn_change", HERE / "test_torikago.py")


class TestAChangedMeasurementIsReported(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.samples = self.dir / "samples"
        self.samples.mkdir()
        (self.samples / "one.exe").write_bytes(tn.build_pe())
        self.manifest = self.dir / "manifest.jsonl"

    def sweep(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = tri.main(["--corpus-write", str(self.samples), "--corpus-file", str(self.manifest),
                           "--scan-limit", "5"])
        return rc, buf.getvalue()

    def test_an_unchanged_rescan_says_nothing_about_changes(self):
        self.assertEqual(self.sweep()[0], 0)
        rc, out = self.sweep()
        self.assertEqual(rc, 0)
        self.assertNotIn("differ from what this hash was measured as before", out)

    def test_a_field_that_moved_is_named_with_both_values(self):
        self.assertEqual(self.sweep()[0], 0)
        # Pretend an earlier detector recorded a different packer verdict for the same bytes.
        rows = [json.loads(line) for line in
                self.manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
        rows[0]["packer"] = "upx"
        self.manifest.write_text(
            "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n", encoding="utf-8")

        rc, out = self.sweep()
        self.assertEqual(rc, 0)
        self.assertIn("differ from what this hash was measured as before", out)
        self.assertIn("packer", out)
        self.assertIn("upx", out)

    def test_it_says_what_it_cannot_tell_apart(self):
        self.assertEqual(self.sweep()[0], 0)
        rows = [json.loads(line) for line in
                self.manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
        rows[0]["packer"] = "upx"
        self.manifest.write_text(
            "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n", encoding="utf-8")

        _, out = self.sweep()
        self.assertIn("changed sample or a", out)
        self.assertIn("cannot tell you which", out)


if __name__ == "__main__":
    unittest.main()
