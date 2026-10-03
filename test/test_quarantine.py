# -*- coding: utf-8 -*-
"""Tests for staging a flagged file for isolated analysis.

The feature exists to automate everything up to the one step that must stay manual. So the
tests that matter most are the negative ones: the original file is never moved or deleted,
nothing is ever executed, and a file with no signals is not staged at all.

Run:
    python -m unittest discover -s test -v
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE.parent / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tri = _load("triage", "triage.py")
tt = _load("tt5", "test/test_triage.py")

SUSPICIOUS_IMPORTS = [("KERNEL32.dll", ["VirtualAlloc", "WriteProcessMemory",
                                        "CreateRemoteThread"])]


class TestShouldStage(unittest.TestCase):
    def _report(self, payload: bytes):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "s.exe"
            p.write_bytes(payload)
            return tri.build_report(p, None)

    def test_signals_above_the_threshold_stage(self):
        r = self._report(tt.build_pe(imports=SUSPICIOUS_IMPORTS))
        stage, why = tri.should_stage(r, min_attention=1)
        self.assertTrue(stage)
        self.assertIn("injection triad", why, "the reason must be quoted so it can be checked")

    def test_a_quiet_file_does_not_stage(self):
        """A file with nothing to say must not consume a VM slot."""
        r = self._report(tt.build_pe(imports=[("KERNEL32.dll", ["CreateFileW", "ReadFile",
                                                               "CloseHandle", "GetLastError",
                                                               "Sleep", "GetTickCount"])]))
        stage, why = tri.should_stage(r, min_attention=1)
        self.assertFalse(stage, why)
        self.assertIn("nothing flagged", why)
        self.assertIn("weak signals", why, "say how close it came to the threshold")

    def test_one_weak_signal_does_not_stage(self):
        """258 of 260 real binaries report a "suspicious string"; it cannot gate alone."""
        report = {"assessment": {"attention": 1, "reasons": ["1 suspicious strings"]},
                  "destructive": {"highest": None, "findings": []},
                  "wrapper": None}
        stage, why = tri.should_stage(report, min_attention=1)
        self.assertFalse(stage, why)

    def test_several_weak_signals_do_stage(self):
        report = {"assessment": {"attention": 6, "reasons": ["a", "b", "c", "d", "e", "f"]},
                  "destructive": {"highest": None, "findings": []},
                  "wrapper": None}
        stage, why = tri.should_stage(report, min_attention=1)
        self.assertTrue(stage)
        self.assertIn("weak signals", why)

    def test_destructive_findings_bypass_the_threshold(self):
        """Something that would detonate on first run is staged even with attention 0."""
        report = {"assessment": {"attention": 0, "reasons": []},
                  "destructive": {"highest": "critical", "findings": []},
                  "wrapper": None}
        stage, why = tri.should_stage(report, min_attention=99)
        self.assertTrue(stage)
        self.assertIn("destructive", why)

    def test_a_wrapper_stages_because_it_self_extracts(self):
        report = {"assessment": {"attention": 0, "reasons": []},
                  "destructive": {"highest": None, "findings": []},
                  "wrapper": {"wrapper": "PyInstaller"}}
        stage, why = tri.should_stage(report, min_attention=99)
        self.assertTrue(stage)
        self.assertIn("PyInstaller", why)


class TestQuarantineCopy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.sample = self.root / "sample.exe"
        self.sample.write_bytes(tt.build_pe(imports=SUSPICIOUS_IMPORTS)
                                + b"http://evil-c2.top/x\x00")
        self.report = tri.build_report(self.sample, None)
        self.shuttle = self.root / "shuttle"

    def tearDown(self):
        self.tmp.cleanup()

    def test_the_original_is_never_moved_or_removed(self):
        before = self.sample.read_bytes()
        res = tri.quarantine_copy(self.sample, self.shuttle, self.report, reason="test")
        self.assertTrue(res["ok"], res)
        self.assertTrue(self.sample.is_file(), "staging must not relocate the original")
        self.assertEqual(self.sample.read_bytes(), before)

    def test_the_copy_is_byte_identical(self):
        res = tri.quarantine_copy(self.sample, self.shuttle, self.report, reason="test")
        staged = Path(res["staged"])
        self.assertTrue(staged.is_file())
        self.assertEqual(staged.read_bytes(), self.sample.read_bytes())

    def test_nothing_is_executed(self):
        res = tri.quarantine_copy(self.sample, self.shuttle, self.report, reason="test")
        self.assertIs(res["executed"], False)

    def test_a_sidecar_records_why(self):
        res = tri.quarantine_copy(self.sample, self.shuttle, self.report, reason="because")
        why = json.loads(Path(res["why"]).read_text(encoding="utf-8"))
        self.assertEqual(why["reason"], "because")
        self.assertEqual(why["sha256"], self.report["hashes"]["sha256"])
        self.assertEqual(why["original_path"], str(self.sample))
        self.assertIs(why["executed"], False)
        self.assertIn("attention", why)

    def test_the_manifest_is_append_only_ndjson(self):
        tri.quarantine_copy(self.sample, self.shuttle, self.report, reason="first")
        tri.quarantine_copy(self.sample, self.shuttle, self.report, reason="second")
        lines = [l for l in (self.shuttle / tri.QUARANTINE_MANIFEST)
                 .read_text(encoding="utf-8").splitlines() if l.strip()]
        self.assertEqual(len(lines), 2)
        for line in lines:
            json.loads(line)

    def test_two_copies_of_different_files_do_not_collide(self):
        other = self.root / "other.exe"
        other.write_bytes(tt.build_pe(imports=SUSPICIOUS_IMPORTS) + b"different payload")
        r1 = tri.quarantine_copy(self.sample, self.shuttle, self.report, reason="a")
        r2 = tri.quarantine_copy(other, self.shuttle, tri.build_report(other, None), reason="b")
        self.assertNotEqual(r1["staged"], r2["staged"])
        self.assertEqual(len(list(self.shuttle.glob("*.why.json"))), 2)

    def test_the_staged_name_carries_the_hash(self):
        res = tri.quarantine_copy(self.sample, self.shuttle, self.report, reason="test")
        self.assertIn(self.report["hashes"]["sha256"][:12], Path(res["staged"]).name)

    def test_a_missing_directory_is_created(self):
        deep = self.root / "a" / "b" / "shuttle"
        res = tri.quarantine_copy(self.sample, deep, self.report, reason="test")
        self.assertTrue(res["ok"])
        self.assertTrue(deep.is_dir())


class TestQuarantineCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.shuttle = self.root / "shuttle"

    def tearDown(self):
        self.tmp.cleanup()

    def test_cli_stages_a_flagged_file_and_says_the_next_step_is_manual(self):
        src = self.root / "bad.exe"
        src.write_bytes(tt.build_pe(imports=SUSPICIOUS_IMPORTS))
        rc = tri.main([str(src), "--quarantine", str(self.shuttle), "--quiet"])
        self.assertEqual(rc, 0)
        self.assertTrue(list(self.shuttle.glob("*.why.json")))
        self.assertTrue(src.is_file(), "the original must survive the CLI path too")

    def test_cli_leaves_a_clean_file_alone(self):
        src = self.root / "clean.dll"
        src.write_bytes(tt.build_pe(imports=[("KERNEL32.dll", [
            "CreateFileW", "ReadFile", "CloseHandle", "GetLastError", "Sleep",
            "GetTickCount"])]))
        rc = tri.main([str(src), "--quarantine", str(self.shuttle), "--quiet"])
        self.assertEqual(rc, 0)
        staged = list(self.shuttle.glob("*.why.json")) if self.shuttle.is_dir() else []
        self.assertEqual(staged, [], "a file with no signals must not be staged")

    def test_quarantine_min_raises_the_bar(self):
        src = self.root / "one-signal.exe"
        src.write_bytes(tt.build_pe(imports=SUSPICIOUS_IMPORTS))
        tri.main([str(src), "--quarantine", str(self.shuttle),
                  "--quarantine-min", "99", "--quiet"])
        staged = list(self.shuttle.glob("*.why.json")) if self.shuttle.is_dir() else []
        self.assertEqual(staged, [])

    def test_listing_an_empty_directory_says_so(self):
        self.assertEqual(tri.list_quarantine(self.root / "nowhere"), 0)

    def test_listing_shows_what_is_waiting(self):
        src = self.root / "bad2.exe"
        src.write_bytes(tt.build_pe(imports=SUSPICIOUS_IMPORTS))
        tri.main([str(src), "--quarantine", str(self.shuttle), "--quiet"])
        self.assertEqual(tri.list_quarantine(self.shuttle), 0)
        text = (self.shuttle / tri.QUARANTINE_MANIFEST).read_text(encoding="utf-8")
        self.assertIn("attention", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
