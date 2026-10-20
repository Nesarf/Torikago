# -*- coding: utf-8 -*-
"""A defanged copy changes two bytes and says so. The original is never written.

Three things have to hold at once, and they pull in different directions:

* the original must be byte-identical afterwards -- it is evidence;
* the copy must genuinely not be runnable, not merely named differently;
* the record must let somebody reconstruct what was done, because a variant whose hash changed for unstated
  reasons is indistinguishable from a damaged file.

The wording is part of the interface here: nothing may call the copy clean, safe or fixed, and the output says
what it is before it says where it is.
"""
from __future__ import annotations

import contextlib
import hashlib
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


tri = load("torikago_neutralize", "torikago.py")
tn = load("tn_neutralize", HERE / "test_torikago.py")


class TestTheDefangedCopy(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.sample = self.dir / "sample.exe"
        self.sample.write_bytes(tn.build_pe())
        self.before = hashlib.sha256(self.sample.read_bytes()).hexdigest()

    def test_the_original_is_untouched(self):
        tri.neutralize_copy(self.sample, self.dir / "out")
        after = hashlib.sha256(self.sample.read_bytes()).hexdigest()
        self.assertEqual(self.before, after,
                         "the original was modified: %s -> %s" % (self.before, after))

    def test_exactly_two_bytes_differ(self):
        original = self.sample.read_bytes()
        record = tri.neutralize_copy(self.sample, self.dir / "out")
        variant = Path(record["variant"]).read_bytes()
        self.assertEqual(len(variant), len(original))
        differing = [i for i in range(len(original)) if original[i] != variant[i]]
        self.assertEqual(differing, [0, 1], "expected offsets 0 and 1, got %r" % (differing,))
        self.assertEqual(variant[:2], b"XX")
        self.assertEqual(record["unchanged_bytes"], len(original) - 2)

    def test_the_record_can_reconstruct_the_edit(self):
        record = tri.neutralize_copy(self.sample, self.dir / "out")
        change = record["changes"][0]
        self.assertEqual(change["offset"], 0)
        self.assertEqual((change["was"], change["now"]), ("MZ", "XX"))
        self.assertIn("why", change)
        self.assertEqual(record["original_sha256"], self.before)
        variant = Path(record["variant"]).read_bytes()
        self.assertEqual(record["variant_sha256"], hashlib.sha256(variant).hexdigest())
        self.assertNotEqual(record["original_sha256"], record["variant_sha256"])

    def test_a_file_that_is_not_a_pe_is_refused(self):
        other = self.dir / "notes.txt"
        other.write_bytes(b"just text")
        with self.assertRaises(ValueError) as ctx:
            tri.neutralize_copy(other, self.dir / "out")
        self.assertIn("DOS header", str(ctx.exception))

    def test_the_command_never_calls_it_clean(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = tri.main([str(self.sample), "--neutralize", "-o", str(self.dir / "out")])
        out = buf.getvalue()
        self.assertEqual(rc, 0, out)
        self.assertIn("variant", out)
        self.assertIn("nothing inside it was analysed", out)
        # The words may appear only in a sentence that refuses them.
        for word in ("clean", "safe", "fixed"):
            for line in out.splitlines():
                low = line.lower()
                if word in low and "not because" not in low and "not called" not in low:
                    self.fail("%r appears in a line that is not refusing it: %r" % (word, line))

    def test_the_record_is_written_beside_the_variant(self):
        tri.neutralize_copy(self.sample, self.dir / "out")
        record_path = self.dir / "out" / "sample_defanged.json"
        self.assertTrue(record_path.is_file())
        body = json.loads(record_path.read_text(encoding="utf-8"))
        self.assertEqual(body["kind"], "defanged copy")
        self.assertTrue(body["caveats"])


if __name__ == "__main__":
    unittest.main()
