# -*- coding: utf-8 -*-
"""Tests for the unpacking and batch-scanning half of triage.

Kept in its own file because these tests touch the filesystem more than the pure
parsing tests do, and because "does it unpack" and "does it parse" fail for very
different reasons.

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


tri = _load("torikago", "torikago.py")
unp = _load("unpack", "unpack.py")
tt = _load("tt", "test/test_torikago.py")     # reuse the PE fixture


class TestFactory(unittest.TestCase):
    def test_build_pe_fixture_is_valid(self):
        data = tt.build_pe()
        pe = tri.parse_pe(data)
        self.assertIsNotNone(pe, "the shared PE fixture must parse")
        self.assertEqual(pe["machine"], "x64")


class TestUnpackModule(unittest.TestCase):
    def test_never_reports_execution(self):
        """Every unpack path must carry executed=False, including the failure paths."""
        with tempfile.TemporaryDirectory() as t:
            bogus = Path(t) / "not-a-pe.exe"
            bogus.write_bytes(b"nope")
            res = unp.unpack_pyinstaller(bogus, Path(t) / "out")
            self.assertIs(res["executed"], False)
            self.assertFalse(res["ok"])

    def test_missing_nanodesu_reports_a_hint_not_a_crash(self):
        """The same intent as before, expressed against the current discovery chain.

        It used to neutralise a hard-coded candidate list; that list is gone, so the test
        now points the environment variable at a path that does not exist. Either way the
        contract under test is unchanged: a missing tool must produce a result dict with a
        reason, never an exception.
        """
        import os
        old = os.environ.get(unp.NANODESU_ENV)
        try:
            with tempfile.TemporaryDirectory() as t:
                os.environ[unp.NANODESU_ENV] = str(Path(t) / "absent-nanodesu.py")
                p = Path(t) / "x.exe"
                p.write_bytes(b"MZ")
                res = unp.unpack_pyinstaller(p, Path(t) / "out")
                self.assertIn("executed", res)
                self.assertIs(res["executed"], False)
                self.assertIn("reason", res)
        finally:
            if old is None:
                os.environ.pop(unp.NANODESU_ENV, None)
            else:
                os.environ[unp.NANODESU_ENV] = old

    def test_find_nanodesu_honours_the_environment_variable(self):
        import os
        with tempfile.TemporaryDirectory() as t:
            fake = Path(t) / "nanodesu.py"
            fake.write_text("# stand-in\n", encoding="utf-8")
            old = os.environ.get(unp.NANODESU_ENV)
            try:
                os.environ[unp.NANODESU_ENV] = str(fake)
                self.assertEqual(unp.find_nanodesu(), fake)
            finally:
                if old is None:
                    os.environ.pop(unp.NANODESU_ENV, None)
                else:
                    os.environ[unp.NANODESU_ENV] = old

    def test_directory_is_accepted_for_the_environment_variable(self):
        import os
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            (d / "nanodesu.py").write_text("# stand-in\n", encoding="utf-8")
            old = os.environ.get(unp.NANODESU_ENV)
            try:
                os.environ[unp.NANODESU_ENV] = str(d)
                self.assertEqual(unp.find_nanodesu(), d / "nanodesu.py")
            finally:
                if old is None:
                    os.environ.pop(unp.NANODESU_ENV, None)
                else:
                    os.environ[unp.NANODESU_ENV] = old


class TestForwarderHandling(unittest.TestCase):
    """An API-set forwarder has almost no imports by design; calling it packed is noise."""

    def _forwarder(self, name="api-ms-win-core-file-l1-1-0.dll"):
        # a small image that exports something
        pe = bytearray(tt.build_pe(sections=((".text", b"\x00" * 512,
                                             tt.SEC_CODE | tt.SEC_EXEC | tt.SEC_READ),)))
        # set the export directory in the optional header (index 0)
        opt_off = 0x80 + 24
        ddir = opt_off + (112 if True else 96)
        import struct
        struct.pack_into("<II", pe, ddir + 0, 0x1000, 0x40)
        return name, bytes(pe)

    def test_api_set_dll_is_not_called_packed(self):
        name, data = self._forwarder()
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / name
            p.write_bytes(data)
            r = tri.build_report(p, None)
        self.assertEqual(r["packer"]["verdict"], "none",
                         "a forwarder must not be reported as packed: %s" % r["packer"])

    def test_small_exporting_image_without_imports_is_not_called_packed(self):
        name, data = self._forwarder("normal-looking.dll")
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / name
            p.write_bytes(data)
            r = tri.build_report(p, None)
        self.assertEqual(r["packer"]["verdict"], "none")


class TestScanTree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_quiet_directory_reports_nothing(self):
        (self.root / "notes.txt").write_bytes(b"just text, nothing to see")
        (self.root / "data.json").write_bytes(b'{"ok": true}')
        r = tri.scan_tree(self.root)
        self.assertEqual(r["interesting"], 0)
        self.assertEqual(r["scanned"], 2)

    def test_injection_triad_raises_attention(self):
        (self.root / "svchost.exe").write_bytes(tt.build_pe(
            imports=[("KERNEL32.dll", ["VirtualAlloc", "WriteProcessMemory",
                                       "CreateRemoteThread"])]))
        r = tri.scan_tree(self.root)
        self.assertEqual(r["interesting"], 1)
        note = r["rows"][0]["note"]
        self.assertIn("injection triad", note)

    def test_weak_signal_alone_does_not_raise_attention(self):
        """IsDebuggerPresent is how CPython implements sys.gettrace."""
        (self.root / "module.pyd").write_bytes(tt.build_pe(
            imports=[("KERNEL32.dll", ["IsDebuggerPresent"])]))
        r = tri.scan_tree(self.root)
        self.assertEqual(r["interesting"], 0, "a weak import must not flag a file on its own")
        self.assertIn("IsDebuggerPresent", r["rows"][0]["noted_imports"])

    def test_misnamed_extension_raises_attention(self):
        (self.root / "setup.png").write_bytes(tt.build_pe())
        r = tri.scan_tree(self.root)
        self.assertEqual(r["interesting"], 1)
        self.assertIn("PE executable", r["rows"][0]["mismatch"])

    def test_python_extension_is_not_treated_as_a_disguise(self):
        (self.root / "_ctypes.pyd").write_bytes(tt.build_pe())
        r = tri.scan_tree(self.root)
        self.assertIsNone(r["rows"][0]["mismatch"])

    def test_rows_are_sorted_by_attention(self):
        (self.root / "plain.dll").write_bytes(tt.build_pe())
        (self.root / "bad.exe").write_bytes(tt.build_pe(
            imports=[("KERNEL32.dll", ["VirtualAlloc", "WriteProcessMemory",
                                       "CreateRemoteThread"])]))
        r = tri.scan_tree(self.root)
        self.assertEqual(r["rows"][0]["path"], "bad.exe")

    def test_limit_is_respected(self):
        for i in range(5):
            (self.root / ("f%d.dll" % i)).write_bytes(tt.build_pe())
        r = tri.scan_tree(self.root, limit=3)
        self.assertEqual(r["scanned"], 3)

    def test_scan_cli_writes_json(self):
        (self.root / "a.exe").write_bytes(tt.build_pe())
        out = self.root / "out"
        rc = tri.main(["--scan", str(self.root), "-o", str(out), "--quiet"])
        self.assertEqual(rc, 0)
        data = json.loads((out / "report.json").read_text(encoding="utf-8"))
        self.assertIn("rows", data)
        self.assertGreaterEqual(data["scanned"], 1)

    def test_scan_cli_needs_no_positional_file(self):
        (self.root / "a.exe").write_bytes(tt.build_pe())
        self.assertEqual(tri.main(["--scan", str(self.root), "--quiet"]), 0)

    def test_missing_target_is_an_error_not_a_traceback(self):
        self.assertEqual(tri.main([]), 2)


class TestInnerExecutables(unittest.TestCase):
    def test_only_executable_files_are_listed(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "a.dll").write_bytes(tt.build_pe())
            (root / "b.pyd").write_bytes(tt.build_pe())
            (root / "c.txt").write_bytes(b"text")
            (root / "d.py").write_bytes(b"print(1)")
            rows = tri.find_inner_executables(root)
            names = sorted(r["path"] for r in rows)
            self.assertEqual(names, ["a.dll", "b.pyd"])

    def test_large_file_is_read_only_partially(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            big = root / "huge.dll"
            big.write_bytes(tt.build_pe() + b"\x00" * (tri.PEEK_BYTES + 1024))
            rows = tri.find_inner_executables(root)
            self.assertTrue(rows)
            self.assertTrue(rows[0]["truncated_head"])
            self.assertLess(rows[0]["size"], tri.PEEK_BYTES * 2)

    def test_missing_directory_is_not_a_crash(self):
        self.assertEqual(tri.find_inner_executables(Path("no-such-dir-xyz")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
