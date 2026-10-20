# -*- coding: utf-8 -*-
"""A rewritten variant is staged on structure, not on a tally that belongs to the original.

`should_stage` was calibrated on ordinary files, so a `_defanged` copy's attention count would be quoted as
if it described the sample somebody submitted. Capability and destructive findings are structural and survive
a rewrite, so they still stand on their own -- the tally does not, and the verdict says which case happened.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
import unittest.mock as mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

spec = importlib.util.spec_from_file_location("torikago_stage", ROOT / "torikago.py")
tri = importlib.util.module_from_spec(spec)
sys.modules["torikago_stage"] = tri
spec.loader.exec_module(tri)

LOW = {"level": "low", "reasons": []}
HIGH = {"level": "high", "reasons": ["reaches a kernel API"]}


def report(path, attention=1, destructive=None):
    return {
        "file": path,
        "assessment": {"attention": attention, "reasons": ["a reason"] * attention},
        "destructive": destructive or {},
    }


class TestAVariantIsJudgedOnStructure(unittest.TestCase):

    def stage(self, rep, capability=LOW, strong=()):
        with mock.patch.object(tri, "evaluate_capability", return_value=dict(capability)), \
             mock.patch.object(tri, "high_confidence_reasons", return_value=list(strong)):
            return tri.should_stage(rep)

    def test_the_original_is_staged_on_its_attention(self):
        staged, why = self.stage(report("sample.exe", attention=2), strong=["a strong signal"])
        self.assertTrue(staged, why)
        self.assertIn("attention", why)

    def test_the_variant_is_not_staged_on_a_tally_that_belongs_to_the_original(self):
        staged, why = self.stage(report("sample_defanged.exe", attention=2), strong=["a strong signal"])
        self.assertFalse(staged, why)
        self.assertIn("rewritten variant", why)
        self.assertIn("re-run this on the original", why)

    def test_a_structural_finding_still_stages_a_variant(self):
        """Capability survives a rewrite, so it is still a reason -- and the reason says which file it is
        about, so a reader cannot take it for the original's."""
        staged, why = self.stage(report("sample_defanged.exe", attention=0), capability=HIGH)
        self.assertTrue(staged, why)
        self.assertTrue(why.startswith("rewritten variant:"), why)

    def test_a_destructive_finding_still_stages_a_variant(self):
        rep = report("sample_defanged.exe", attention=0, destructive={"highest": "critical"})
        staged, why = self.stage(rep)
        self.assertTrue(staged, why)
        self.assertIn("critical", why)

    def test_the_word_variant_is_enough_without_the_filename(self):
        """`variant_of` is the report's own field; the filename is a fallback for files renamed by hand."""
        rep = report("renamed.exe", attention=3)
        rep["variant_of"] = "sample.exe"
        staged, why = self.stage(rep, strong=["a strong signal"])
        self.assertFalse(staged, why)
        self.assertIn("rewritten variant", why)


if __name__ == "__main__":
    unittest.main()
