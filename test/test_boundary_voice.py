# -*- coding: utf-8 -*-
"""The boundary sentence exists once, is wired to the human path, and reaches no machine path.

Two claims, and they fail differently. A boundary line that two call sites word differently is the defect the
sibling tool's `boundary_voice.py` exists to prevent. A boundary line that reaches `--json` is worse: it turns
a human sentence into part of a contract somebody's parser reads.
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


tri = load("torikago_boundary", "torikago.py")
tn = load("tn_boundary", HERE / "test_torikago.py")


def all_lines():
    out = []
    for entry in tri.PROSE.values():
        out.extend(entry)
    return out


class TestTheBoundaryLine(unittest.TestCase):

    def setUp(self):
        self.addCleanup(tri.set_plain, False)
        tri.set_plain(False)

    def test_it_prints_the_spoken_line(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            tri.emit_boundary()
        self.assertIn(tri.say("watching"), buf.getvalue())

    def test_plain_switches_it_like_everything_else(self):
        tri.set_plain(True)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            tri.emit_boundary()
        self.assertIn("watching only", buf.getvalue())

    def test_the_human_report_calls_it(self):
        """A module nobody calls is dead code, and this project has just finished removing nine lines of it.

        Built from a real report rather than a hand-made dictionary: `print_human` reads a dozen fields, and a
        fixture that guesses them tests the fixture.
        """
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "one.exe"
            target.write_bytes(tn.build_pe())
            report = tri.build_report_with_unpack(target, None, False,
                                                  max_bytes=int(tri.DEFAULT_MAX_BYTES),
                                                  force=False, yara_corpus=None)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            tri.print_human(report)
        self.assertIn(tri.say("watching"), buf.getvalue())

    def test_no_persona_line_reaches_the_json_path(self):
        """The machine path is asserted on the whole table, not only on the boundary line: one sentence
        arriving there by another route would be the same defect."""
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "one.exe"
            target.write_bytes(tn.build_pe())
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = tri.main([str(target), "--json"])
            out = buf.getvalue()
        self.assertEqual(rc, 0)
        json.loads(out)                      # still parses, which prose would break
        for line in all_lines():
            self.assertNotIn(line, out, "a persona line reached the JSON path: %r" % line)


if __name__ == "__main__":
    unittest.main()
