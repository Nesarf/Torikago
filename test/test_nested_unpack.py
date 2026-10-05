# -*- coding: utf-8 -*-
"""Following a wrapper inside a wrapper, and the two ways that silently did nothing.

**The list was ordered by name, so the wrapper was never in it.** `find_inner_executables` sorted by
path and took the first 40 entries. On a real PyInstaller build that fills with
`binary___bz2.pyd`, `binary___decimal.pyd` and their neighbours -- alphabetically early, individually
uninteresting -- while a nested executable sitting in the same directory never appeared at all. The
recursion then did nothing, and `--unpack` reported success.

**And wrapper detection used a head peek, when the cookie is at the end.** Same shape of mistake as
the PDB debug directory one function over: a CArchive cookie is the last occurrence of its magic, so
reading the first 4 MB of an 8.5 MB inner executable cannot see it, `detect_pyinstaller` returned
None, and the recursion skipped exactly the file it was built to follow.

Both failed silently. Neither raised, neither was reported, and the only reason either was found is
that a real nested sample was built and the output did not contain what was expected.

Run:
    python -m unittest discover -s test -v
"""
from __future__ import annotations

import importlib.util
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

spec = importlib.util.spec_from_file_location("tk_nested", HERE.parent / "torikago.py")
tk = importlib.util.module_from_spec(spec)
sys.modules["tk_nested"] = tk
spec.loader.exec_module(tk)

COOKIE_MAGIC = b"MEI\014\013\012\013\016"
PKG_HEADER = 88
STUB = 4096


def make_pyinstaller_archive(payload_name="data.bin", payload=b"x" * 64) -> bytes:
    """A minimal but structurally valid onefile: stub, PKG header, payload, TOC, cookie.

    `toc_offset` is measured from the start of the PKG archive, which begins with its own 88-byte
    header. Writing it relative to the payload makes every archive look corrupt, which cost several
    rounds in an earlier attempt at this fixture.
    """
    stored = zlib.compress(payload, 9)
    raw_name = payload_name.encode()
    pad = (-(18 + len(raw_name))) % 16
    name_field = raw_name + bytes(pad)
    toc = struct.pack("!IIIIBc", 18 + len(name_field), 0, len(stored), len(payload), 1,
                      b"b") + name_field
    pkg_len = PKG_HEADER + len(stored) + len(toc)
    cookie = struct.pack("!8sIIII64s", COOKIE_MAGIC, pkg_len, PKG_HEADER + len(stored),
                         len(toc), 312, b"python312.dll")
    return bytes(STUB) + bytes(PKG_HEADER) + stored + toc + cookie


class TestWrapperDetectionReadsTheEnd(unittest.TestCase):
    """The cookie is at the end; a head peek cannot see it."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="tk-wrap-"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, blob, name="inner.exe"):
        p = self.tmp / name
        p.write_bytes(blob)
        return p

    def test_a_small_archive_is_detected_from_the_path(self):
        p = self._write(make_pyinstaller_archive())
        self.assertIsNotNone(tk.detect_pyinstaller_at(p))

    def test_a_large_archive_is_detected_where_a_head_peek_fails(self):
        """The regression: pad the archive past PEEK_BYTES and the head no longer contains the
        cookie, while the tail always does."""
        blob = make_pyinstaller_archive()
        # Put the archive at the end of something larger than the peek window.
        padded = b"\x00" * (tk.PEEK_BYTES + 4096) + blob
        # A real file has the archive at the end, so the cookie is the last occurrence either way.
        p = self._write(padded)
        with open(p, "rb") as fh:
            head = fh.read(tk.PEEK_BYTES)
        self.assertIsNone(tk.detect_pyinstaller(head),
                          "the head should not contain the cookie -- that is the whole point")
        self.assertIsNotNone(tk.detect_pyinstaller_at(p),
                             "reading the tail must find it")

    def test_an_ordinary_binary_is_not_called_a_wrapper(self):
        p = self._write(b"MZ" + b"\x00" * 8192)
        self.assertIsNone(tk.detect_pyinstaller_at(p))

    def test_a_missing_file_is_not_an_error(self):
        self.assertIsNone(tk.detect_pyinstaller_at(self.tmp / "absent.exe"))


class TestInnerOrdering(unittest.TestCase):
    """The list must be ordered by interest, or the limit removes the entries that matter."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="tk-order-"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _binary(self, name, size):
        p = self.tmp / name
        # A header the PE parser rejects is fine here: ordering is what is under test, and the row
        # is built from size and path either way.
        p.write_bytes(b"MZ" + b"\x00" * max(0, size - 2))
        return p

    def test_a_large_nested_executable_outranks_small_stdlib_extensions(self):
        """Reproduces the real failure: alphabetically early .pyd files crowding out the one file
        worth following."""
        for name in ("binary___bz2.pyd", "binary___decimal.pyd", "binary___hashlib.pyd"):
            self._binary(name, 90_000)
        self._binary("binary__inner.exe", 8_500_000)
        rows = tk.find_inner_executables(self.tmp, limit=2)
        self.assertEqual(rows[0]["path"], "binary__inner.exe",
                         "the largest is the most likely wrapper and must survive the limit")

    def test_the_limit_still_applies(self):
        for i in range(10):
            self._binary("f%02d.exe" % i, 10_000 + i)
        self.assertEqual(len(tk.find_inner_executables(self.tmp, limit=3)), 3)

    def test_the_order_is_stable(self):
        for i in range(5):
            self._binary("same%02d.exe" % i, 50_000)
        a = [r["path"] for r in tk.find_inner_executables(self.tmp)]
        b = [r["path"] for r in tk.find_inner_executables(self.tmp)]
        self.assertEqual(a, b)


class TestRecursionBounds(unittest.TestCase):
    """The bounds matter more than the recursion: without them this writes an unbounded tree."""

    def test_the_depth_and_total_limits_exist(self):
        self.assertGreaterEqual(tk.NESTED_UNPACK_MAX_DEPTH, 1)
        self.assertGreaterEqual(tk.NESTED_UNPACK_MAX_TOTAL, 1)
        self.assertLessEqual(tk.NESTED_UNPACK_MAX_DEPTH, 10,
                             "a deep limit is a slow way to fill a disk")

    def test_a_path_outside_the_parent_directory_is_refused(self):
        """Unpacking writes files, so an inner entry must not be able to direct that write
        somewhere the parent did not already own."""
        import shutil
        tmp = Path(tempfile.mkdtemp(prefix="tk-bounds-"))
        try:
            parent = tmp / "tree"
            parent.mkdir()
            outside = tmp / "outside.exe"
            outside.write_bytes(make_pyinstaller_archive())
            result = tk._unpack_nested([{"path": "../outside.exe"}], parent, depth=1)
            self.assertEqual(result["unpacked"], [])
            self.assertTrue(any("outside" in (s.get("why") or "") for s in result["skipped"]),
                            result["skipped"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_a_row_without_a_wrapper_is_left_alone(self):
        import shutil
        tmp = Path(tempfile.mkdtemp(prefix="tk-bounds-"))
        try:
            parent = tmp / "tree"
            parent.mkdir()
            (parent / "plain.dll").write_bytes(b"MZ" + b"\x00" * 4096)
            result = tk._unpack_nested([{"path": "plain.dll", "wrapper": None}], parent, depth=1)
            self.assertEqual(result["unpacked"], [])
            self.assertEqual(result["skipped"], [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_past_the_depth_limit_nothing_is_unpacked(self):
        result = tk._unpack_nested([{"path": "x.exe", "wrapper": "PyInstaller"}], Path("."),
                                   depth=tk.NESTED_UNPACK_MAX_DEPTH + 1)
        self.assertEqual(result["unpacked"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
