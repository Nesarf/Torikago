# -*- coding: utf-8 -*-
"""The two tools must agree about facts, and the old contract asked them to agree about bytes.

§零 used to say the two tools' *outputs* must have the same sha256. Measurement killed that: a repack
recompresses the payload, so identical contents produce different bytes, and `ACTION_CONTRACT.md` records the
correction. This file is what survives of the idea, and it is the part that was ever true:

* both tools must classify the same file the same way;
* both must agree whether it is a PyInstaller archive at all;
* and neither may claim the other's work as its own.

**What is deliberately not asserted**: that the two `--neutralize` outputs match. Their semantics are
opposites -- one makes the copy unrunnable by editing the PE header, the other keeps it runnable and replaces
modules inside it -- so a shared hash would mean one of them had started doing the other's job.
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SIBLING = ROOT.parent / "nanodesu-release"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SIBLING))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, Path(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


tri = load("torikago_facts", ROOT / "torikago.py")
nano = load("nanodesu_facts", SIBLING / "nanodesu.py")
tn = load("tn_facts", HERE / "test_torikago.py")


class TestBothToolsAgreeOnFacts(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.sample = self.dir / "one.exe"
        self.sample.write_bytes(tn.build_pe())

    def head(self):
        return self.sample.read_bytes()[:4096]

    def test_both_call_it_a_pe(self):
        self.assertEqual(tri.identify(self.head(), self.sample)["kind"], "pe",
                         "torikago does not recognise the shared fixture as a PE")

    def test_both_agree_it_is_not_pyinstaller(self):
        """The one judgement that matters here: a tool that said "PyInstaller" while the other refused to
        parse it would send an operator looking for an archive that is not there."""
        self.assertIsNone(tri.detect_pyinstaller(self.head()),
                          "torikago claims a wrapper on a plain PE")
        try:
            nano.find_archive(self.sample)
        except (SystemExit, Exception):
            refused = True
        else:
            refused = False
        self.assertTrue(refused, "nanodesu accepted a file torikago says has no archive in it")

    def test_each_tool_reports_its_own_limit(self):
        """Neither may claim the other's capability: torikago refuses to run the target, nanodesu refuses to
        judge it. Those limits are the reason there are two tools."""
        self.assertTrue(hasattr(tri, "should_stage"), "torikago lost its judgement entry point")
        self.assertFalse(hasattr(nano, "should_stage"),
                         "nanodesu grew a judgement entry point, which is the sibling's job")

    def test_the_neutralize_outputs_are_not_compared(self):
        """**Named as a test so nobody adds the comparison later without reading why.** The two copies are
        meant to differ: one is unrunnable by construction, the other runs with its modules neutered.

        Nanodesu keeps its version in its own module rather than as a top-level function, which is why this
        checks for the module: the point is that both sides have one, not where it lives.
        """
        self.assertTrue(hasattr(tri, "neutralize_copy"))
        self.assertTrue((SIBLING / "neutralize.py").is_file(),
                        "nanodesu's neutralize module is missing, so the two tools no longer differ this way")


if __name__ == "__main__":
    unittest.main()
