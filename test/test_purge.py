# -*- coding: utf-8 -*-
"""`--purge`: removing a staged copy, and the three things that stop it removing the wrong one.

A delete is the only action here that the manifest cannot undo, so the tests are about refusal: a path is a
weak identity for a file whose purpose is to be dangerous.
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import torikago


def sha_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_shuttle(directory: Path) -> dict:
    shuttle = directory / "shuttle"
    shuttle.mkdir()
    (shuttle / torikago.QUARANTINE_MANIFEST).write_text("", encoding="utf-8")
    staged = shuttle / "20260101T000000_abcdef012345_sample.exe"
    staged.write_bytes(b"MZ-staged-copy")
    return {"dir": shuttle, "file": staged}


class TestPurge(unittest.TestCase):

    def test_it_removes_the_copy_and_records_it(self):
        with tempfile.TemporaryDirectory() as d:
            s = make_shuttle(Path(d))
            digest = sha_of(s["file"])
            self.assertEqual(torikago.purge_staged(s["file"], digest), 0)
            self.assertFalse(s["file"].exists(), "the copy should be gone")
            rows = [json.loads(line) for line in
                    (s["dir"] / torikago.QUARANTINE_MANIFEST).read_text(encoding="utf-8").splitlines() if line]
            self.assertEqual(rows[-1]["sha256"], digest)
            self.assertEqual(rows[-1]["staged_name"], s["file"].name)
            self.assertIn("not touched", rows[-1]["note"])

    def test_the_original_outside_the_shuttle_is_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            s = make_shuttle(Path(d))
            original = Path(d) / "sample.exe"
            original.write_bytes(b"MZ-original")
            torikago.purge_staged(s["file"], sha_of(s["file"]))
            self.assertTrue(original.exists(), "only the staged copy may be removed")
            self.assertEqual(original.read_bytes(), b"MZ-original")

    def test_a_hash_that_does_not_match_refuses_and_keeps_the_file(self):
        with tempfile.TemporaryDirectory() as d:
            s = make_shuttle(Path(d))
            wrong = "0" * 64
            self.assertEqual(torikago.purge_staged(s["file"], wrong), 2)
            self.assertTrue(s["file"].exists(), "a mismatched confirmation must not delete anything")

    def test_a_path_outside_a_quarantine_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            loose = Path(d) / "not-a-shuttle.exe"
            loose.write_bytes(b"MZ")
            self.assertEqual(torikago.purge_staged(loose, sha_of(loose)), 2)
            self.assertTrue(loose.exists())

    def test_a_missing_confirmation_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            s = make_shuttle(Path(d))
            self.assertEqual(torikago.purge_staged(s["file"], ""), 2)
            self.assertTrue(s["file"].exists())


if __name__ == "__main__":
    unittest.main()
