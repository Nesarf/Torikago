# -*- coding: utf-8 -*-
"""All four beats are spoken, on the human paths, and none of them reaches a machine path.

A line that exists but is never said is dead code, which this project has already removed once. So each beat
is asserted where it is supposed to be heard:

    1  --scan            watching           a sweep looks, it does not touch
    2  --corpus-write    stopped_here       or unknown_ahead, because those are different answers
    3  the report        see_through        the file was understood without opening it
    4  --handoff         credit_the_engine  the verdict is somebody else's
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


tri = load("torikago_beats", "torikago.py")
tn = load("tn_beats", HERE / "test_torikago.py")


class TestTheFourBeats(unittest.TestCase):

    def setUp(self):
        self.addCleanup(tri.set_plain, False)
        tri.set_plain(False)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def run_main(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = tri.main(argv)
        return rc, buf.getvalue()

    def test_the_scan_speaks_the_first_beat(self):
        samples = self.dir / "samples"
        samples.mkdir()
        (samples / "one.exe").write_bytes(tn.build_pe())
        rc, out = self.run_main(["--scan", str(samples)])
        self.assertEqual(rc, 0, out)
        self.assertIn(tri.say("watching"), out)

    def test_the_report_speaks_the_third_beat(self):
        target = self.dir / "one.exe"
        target.write_bytes(tn.build_pe())
        rc, out = self.run_main([str(target)])
        self.assertEqual(rc, 0, out)
        self.assertIn(tri.say("see_through"), out)

    def test_the_corpus_speaks_the_second_beat(self):
        samples = self.dir / "samples"
        samples.mkdir()
        (samples / "one.exe").write_bytes(tn.build_pe())
        rc, out = self.run_main(["--corpus-write", str(samples),
                                 "--corpus-file", str(self.dir / "manifest.jsonl")])
        self.assertEqual(rc, 0, out)
        # A synthetic PE carries no coverage bookkeeping, so this sweep is `unknown` rather than `complete`.
        self.assertIn(tri.say("unknown_ahead"), out)
        self.assertNotIn(tri.say("stopped_here"), out,
                         "a sweep that recorded nothing is not the same as one that hit a cap")

    def test_the_handoff_speaks_the_fourth_beat(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            tri._print_handoff({"engines": {"clamav": {"ok": False, "reason": "not installed"}}})
        self.assertIn(tri.say("credit_the_engine"), buf.getvalue())

    def test_the_handoff_says_nothing_when_there_was_none(self):
        """No handoff at all means no output at all."""
        for empty in (None, {}):
            with self.subTest(handoff=empty):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    tri._print_handoff(empty)
                self.assertEqual(buf.getvalue().strip(), "")

    def test_it_credits_only_when_there_is_a_verdict(self):
        """`{"engines": {}}` still prints the standing disclaimer -- that is existing behaviour and not this
        beat -- but it must not credit anybody, because nobody answered."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            tri._print_handoff({"engines": {}})
        self.assertNotIn(tri.say("credit_the_engine"), buf.getvalue())

    def test_no_beat_reaches_the_json_paths(self):
        target = self.dir / "one.exe"
        target.write_bytes(tn.build_pe())
        rc, out = self.run_main([str(target), "--json"])
        self.assertEqual(rc, 0)
        json.loads(out)
        for key in ("watching", "see_through", "stopped_here", "unknown_ahead", "credit_the_engine"):
            self.assertNotIn(tri.say(key), out)


if __name__ == "__main__":
    unittest.main()
