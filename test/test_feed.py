# -*- coding: utf-8 -*-
"""Tests for handing evidence to something that decides (ClamAV, MISP, STIX).

The ClamAV tests use a stand-in executable that prints the line ClamAV prints for an
infected file. That is not a substitute for ClamAV -- it checks that our parser agrees with
the format ClamAV actually emits, which is the part that would silently break.

Run:
    python -m unittest discover -s test -v
"""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE.parent / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tri = _load("torikago", "torikago.py")
tt = _load("tt2", "test/test_torikago.py")

# The batch argument is literally %~1, so these bodies are concatenated rather than
# %-formatted: a format string would read %~ as a conversion specifier.
WIN_HEAD = "@echo off\n"
WIN_TAIL = "\nexit /b 1\n"
SH_HEAD = "#!/bin/sh\n"


def fake_clamscan(dirpath: Path, signature: str) -> Path:
    """An executable that prints what ClamAV prints for one infected file.

    The template walks its arguments to find the LAST one, because the command line puts
    the switches first and the file list last -- %~1 would print a switch instead of a
    path. The body is embedded by repr() rather than typed as an escape sequence: this
    file already lost a round to a mangled 
.
    """
    script = dirpath / ("clamscan.bat" if os.name == "nt" else "clamscan")
    template = '@echo off\n:loop\nset "last=%~1"\nshift\nif not "%~1"=="" goto loop\necho %last%: __SIG__ FOUND\nexit /b 1\n' if os.name == "nt" else '#!/bin/sh\nfor last in "$@"; do :; done\necho "$last: __SIG__ FOUND"\nexit 1\n'
    script.write_text(template.replace("__SIG__", signature), encoding="utf-8")
    if os.name != "nt":
        script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return script


def clean_clamscan(dirpath: Path) -> Path:
    script = dirpath / ("clean.bat" if os.name == "nt" else "clean")
    if os.name == "nt":
        script.write_text("@echo off\nexit /b 0\n", encoding="utf-8")
    else:
        script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


class TestClamAv(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _with_env(self, value, fn):
        old = os.environ.get("CLAMSCAN_PATH")
        try:
            if value is None:
                os.environ.pop("CLAMSCAN_PATH", None)
            else:
                os.environ["CLAMSCAN_PATH"] = str(value)
            return fn()
        finally:
            if old is None:
                os.environ.pop("CLAMSCAN_PATH", None)
            else:
                os.environ["CLAMSCAN_PATH"] = old

    def test_absent_binary_is_reported_not_worked_around(self):
        def run():
            return tri.scan_with_clamav([self.root / "nothing-here"])
        res = self._with_env(self.root / "definitely-missing", run)
        if not res["available"]:              # a system clamscan may exist
            self.assertFalse(res["ok"])
            self.assertIs(res["executed"], False)
            self.assertIn("clamav.net", res["install"])

    def test_environment_variable_selects_the_binary(self):
        script = fake_clamscan(self.root, "Win.Trojan.Fake-1")
        self.assertEqual(self._with_env(script, tri.find_clamav), str(script))

    def test_no_files_is_not_a_failure(self):
        res = tri.scan_with_clamav([])
        self.assertIn("reason", res)
        self.assertIs(res["executed"], False)

    def test_infected_output_is_parsed(self):
        script = fake_clamscan(self.root, "Win.Trojan.Fake-1")
        victim = self.root / "sample.exe"
        victim.write_bytes(b"MZ" + b"\x00" * 32)
        res = tri.scan_with_clamav([victim], clamscan=str(script))
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["available"])
        self.assertIs(res["executed"], False, "scanning must never count as execution")
        self.assertEqual(res["infected"], 1)
        self.assertEqual(res["verdicts"][0]["signature"], "Win.Trojan.Fake-1")
        self.assertIn("sample.exe", res["verdicts"][0]["file"])

    def test_clean_output_yields_no_verdicts(self):
        script = clean_clamscan(self.root)
        victim = self.root / "ok.exe"
        victim.write_bytes(b"MZ")
        res = tri.scan_with_clamav([victim], clamscan=str(script))
        self.assertEqual(res["infected"], 0)
        self.assertEqual(res["verdicts"], [])


class TestMisp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.sample = self.root / "sample.exe"
        self.sample.write_bytes(
            tt.build_pe(imports=[("KERNEL32.dll", ["VirtualAlloc", "WriteProcessMemory",
                                                   "CreateRemoteThread"])])
            + b"http://185.220.101.5/gate.php\x00"
            + b"evil-c2.top\x00"
            + b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Upd\x00")
        self.report = tri.build_report(self.sample, None)

    def tearDown(self):
        self.tmp.cleanup()

    def test_event_is_wellformed_and_has_attributes(self):
        root = ET.fromstring(tri.build_misp_event(self.report))
        self.assertTrue(root.tag.endswith("misp"))
        self.assertIsNotNone(root.find("Event"))
        self.assertIsNotNone(root.find("Event/Attribute"))

    def test_hashes_are_present_and_marked_to_ids(self):
        root = ET.fromstring(tri.build_misp_event(self.report))
        attrs = {}
        for a in root.iter("Attribute"):
            attrs[a.findtext("type")] = (a.findtext("value"), a.findtext("to_ids"))
        self.assertIn("sha256", attrs)
        self.assertEqual(attrs["sha256"][0], self.report["hashes"]["sha256"])
        self.assertEqual(attrs["sha256"][1], "true")

    def test_indicators_become_attributes_with_category(self):
        root = ET.fromstring(tri.build_misp_event(self.report))
        by_type = {}
        for a in root.iter("Attribute"):
            by_type.setdefault(a.findtext("type"), []).append(a.findtext("category"))
        self.assertIn("url", by_type)
        self.assertIn("Network activity", by_type["url"])
        self.assertIn("domain", by_type)
        self.assertIn("ip-dst", by_type)
        self.assertIn("regkey", by_type)
        self.assertIn("Artifacts dropped", by_type["regkey"])

    def test_event_is_unpublished_and_tagged(self):
        root = ET.fromstring(tri.build_misp_event(self.report))
        self.assertEqual(root.findtext("Event/published"), "false")
        tags = {t.findtext("name") for t in root.iter("Tag")}
        self.assertIn("torikago:static", tags)
        self.assertIn("torikago:never-executed", tags)

    def test_no_iocs_still_produces_a_valid_event(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "plain.dll"
            p.write_bytes(tt.build_pe())
            report = tri.build_report(p, None)
        root = ET.fromstring(tri.build_misp_event(report))
        self.assertIsNotNone(root.find("Event"))
        self.assertIsNotNone(root.find("Event/Attribute"))     # at least the hashes


class TestStix(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sample = Path(self.tmp.name) / "sample.exe"
        self.sample.write_bytes(tt.build_pe() + b"http://evil-c2.top/x\x00")
        self.report = tri.build_report(self.sample, None)

    def tearDown(self):
        self.tmp.cleanup()

    def test_bundle_shape(self):
        bundle = tri.build_stix_bundle(self.report)
        self.assertEqual(bundle["type"], "bundle")
        self.assertTrue(bundle["id"].startswith("bundle--"))
        kinds = {o["type"] for o in bundle["objects"]}
        self.assertIn("file", kinds)
        self.assertIn("indicator", kinds)

    def test_file_object_carries_all_three_hashes(self):
        bundle = tri.build_stix_bundle(self.report)
        f = next(o for o in bundle["objects"] if o["type"] == "file")
        self.assertEqual(set(f["hashes"]), {"SHA-256", "SHA-1", "MD5"})
        self.assertEqual(f["hashes"]["SHA-256"], self.report["hashes"]["sha256"])

    def test_indicators_are_wellformed_patterns(self):
        bundle = tri.build_stix_bundle(self.report)
        inds = [o for o in bundle["objects"] if o["type"] == "indicator"]
        self.assertTrue(inds)
        for i in inds:
            self.assertEqual(i["pattern_type"], "stix")
            self.assertTrue(i["pattern"].startswith("["), i["pattern"])
            self.assertTrue(i["pattern"].endswith("]"), i["pattern"])
            self.assertIn(":", i["pattern"])

    def test_bundle_is_json_serialisable(self):
        json.dumps(tri.build_stix_bundle(self.report))

    def test_indicator_ids_are_stable_for_the_same_input(self):
        a = {o["id"] for o in tri.build_stix_bundle(self.report)["objects"]
             if o["type"] == "indicator"}
        b = {o["id"] for o in tri.build_stix_bundle(self.report)["objects"]
             if o["type"] == "indicator"}
        self.assertEqual(a, b, "the same indicator must get the same id")


class TestFeedCli(unittest.TestCase):
    def test_feed_writes_event_and_bundle(self):
        with tempfile.TemporaryDirectory() as t:
            src = Path(t) / "s.exe"
            src.write_bytes(tt.build_pe() + b"http://evil-c2.top/x\x00")
            out = Path(t) / "out"
            rc = tri.main([str(src), "--feed", "both", "-o", str(out), "--quiet"])
            self.assertEqual(rc, 0)
            self.assertTrue((out / "event.xml").is_file())
            self.assertTrue((out / "stix.json").is_file())
            ET.fromstring((out / "event.xml").read_text(encoding="utf-8"))
            json.loads((out / "stix.json").read_text(encoding="utf-8"))

    def test_feed_misp_only(self):
        with tempfile.TemporaryDirectory() as t:
            src = Path(t) / "s.exe"
            src.write_bytes(tt.build_pe())
            out = Path(t) / "out"
            tri.main([str(src), "--feed", "misp", "-o", str(out), "--quiet"])
            self.assertTrue((out / "event.xml").is_file())
            self.assertFalse((out / "stix.json").exists())

    def test_report_omits_unpack_when_not_requested(self):
        with tempfile.TemporaryDirectory() as t:
            src = Path(t) / "s.exe"
            src.write_bytes(tt.build_pe())
            report = tri.build_report_with_unpack(src, None, False)
            self.assertNotIn("unpack", report,
                             "an unrequested unpack must not be reported as a failure")


if __name__ == "__main__":
    unittest.main(verbosity=2)