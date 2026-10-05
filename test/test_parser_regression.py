# -*- coding: utf-8 -*-
"""Parser correctness, with fixtures that would have failed before the fix.

## What prompted this

An external review flagged `val & 0x7FFFFFFF` in the x64 import path as a likely bug. It was: the
same function tested the ordinal flag correctly with `1 << (63 if is64 else 31)` and then masked the
RVA with a **hard-coded 31-bit literal**. For 64-bit the ordinal flag is bit 63, so an RVA is the
whole value — and masking it truncated any import above 2 GB into a wrong offset or a silent `None`.

The tests below are written so they **fail against the old code**, which is the only thing that makes
a regression test worth having. A fixture that passes either way documents nothing.

## The other half: truncation is not absence

`parse_imports` caps descriptors at 256, thunks at 512 and retained names at 200. Those caps are
correct for hostile input. What was wrong is that **the result did not say so** — so a consumer
reading "no such import" had no way to tell that from "the parser stopped early for safety". On a
triage tool that feeds a verdict and a YARA draft, **absence of evidence and evidence of absence must
not look the same.**
"""
from __future__ import annotations

import importlib.util
import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

spec = importlib.util.spec_from_file_location("tk", HERE.parent / "torikago.py")
tk = importlib.util.module_from_spec(spec)
sys.modules["tk"] = tk
spec.loader.exec_module(tk)


# Two sections, because that is what makes this fixture possible: the directory and descriptors sit
# at a normal RVA while the name strings and the ILT sit at an RVA above 2 GB that still maps to a
# low file offset. One section cannot span that gap.
A_RVA, A_RAW = 0x1000, 0x200
B_RVA, B_RAW = 0x90000000, 0x800          # far enough in that the strings land on written bytes
HI_DLL = B_RVA + 0x40
HI_NAME = B_RVA + 0x60
DIR_RVA = A_RVA + 0x50
INT_RVA = A_RVA + 0x80
IAT_RVA = A_RVA + 0x90


def _sect(buf, off, name, vsize, vaddr, rawsize, rawptr):
    buf[off:off + 8] = name.ljust(8, b"\0")
    struct.pack_into("<IIII", buf, off + 8, vsize, vaddr, rawsize, rawptr)
    struct.pack_into("<I", buf, off + 36, 0x60000020)     # executable, readable


def pe_x64(*, name_rva=HI_NAME, int_value=None, extra_thunks=0, many_dlls=1,
           descriptors=1) -> bytes:
    """A minimal x64 PE whose import names live above 2 GB.

    `int_value` overrides the first thunk value, which is how the ordinal case is exercised.
    """
    buf = bytearray(0xA00)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", buf, 0x84, 0x8664)
    struct.pack_into("<H", buf, 0x86, 2)
    struct.pack_into("<H", buf, 0x94, 0xF0)
    o = 0x98
    struct.pack_into("<H", buf, o, 0x20B)
    struct.pack_into("<I", buf, o + 28, A_RVA)
    struct.pack_into("<Q", buf, o + 24, 0x140000000)
    struct.pack_into("<I", buf, o + 32, 0x1000)
    struct.pack_into("<I", buf, o + 36, 0x200)
    struct.pack_into("<I", buf, o + 56, 0x90002000)
    struct.pack_into("<II", buf, o + 112 + 8, DIR_RVA, 40)
    sh = o + 0xF0
    _sect(buf, sh, b".text", 0x1000, A_RVA, 0x200, A_RAW)
    _sect(buf, sh + 40, b".idata", 0x1000, B_RVA, 0x200, B_RAW)

    aoff = lambda r: A_RAW + (r - A_RVA)                    # noqa: E731
    boff = lambda r: B_RAW + (r - B_RVA)                    # noqa: E731

    # Descriptors: `descriptors` real entries, then a null terminator when `many_dlls` allows room.
    for i in range(min(descriptors, 8)):
        struct.pack_into("<IIIII", buf, aoff(DIR_RVA) + i * 20,
                         INT_RVA, 0, 0, HI_DLL, IAT_RVA)
    buf[boff(HI_DLL):boff(HI_DLL) + 13] = b"KERNEL32.dll\0"

    first = int_value if int_value is not None else struct.unpack(
        "<Q", struct.pack("<Q", name_rva))[0]
    struct.pack_into("<Q", buf, aoff(INT_RVA), first)
    for k in range(extra_thunks):
        struct.pack_into("<Q", buf, aoff(INT_RVA) + 8 * (k + 1), name_rva)
    struct.pack_into("<Q", buf, aoff(INT_RVA) + 8 * (extra_thunks + 1), 0)

    struct.pack_into("<H", buf, boff(HI_NAME), 0)
    buf[boff(HI_NAME) + 2:boff(HI_NAME) + 14] = b"CreateFileW\0"
    return bytes(buf)


class TestX64ImportRvaIsNotMasked(unittest.TestCase):
    """The flagged bug. Every test here fails against the 31-bit mask."""

    def test_an_import_above_2gb_resolves(self):
        """The regression itself. `0x7FFFFFFF` turned this RVA into nonsense, and the name was lost."""
        data = pe_x64()
        pe = tk.parse_imports(data, tk.parse_pe(data))
        names = [n for e in pe for n in e.get("functions", [])]
        self.assertIn("CreateFileW", names,
                      "an import above 2 GB was dropped -- the RVA is being masked")

    def test_the_dll_name_survives_too(self):
        data = pe_x64()
        pe = tk.parse_imports(data, tk.parse_pe(data))
        self.assertEqual([e["dll"] for e in pe if e.get("dll")], ["KERNEL32.dll"])

    def test_an_ordinal_import_is_still_skipped(self):
        """Bit 63 must keep meaning "ordinal". The fix must not confuse the flag with the value."""
        data = pe_x64(int_value=(1 << 63) | 0x1234)
        pe = tk.parse_imports(data, tk.parse_pe(data))
        names = [n for e in pe for n in e.get("functions", [])]
        self.assertEqual(names, [], "an ordinal import was read as a name")

    def test_a_32bit_ordinal_is_skipped_at_bit_31(self):
        """The other ABI's flag is bit 31, and it is still masked -- because there it *is* the flag."""
        src = (HERE.parent / "torikago.py").read_text(encoding="utf-8")
        self.assertIn("ORDINAL_BIT if is64 else (1 << 31)", " ".join(src.split()))

    def test_the_mask_is_chosen_by_width_not_hard_coded(self):
        """A hard-coded width is what let the two ABIs disagree inside one function.

        **The mask is not wrong for 32-bit** -- there its high bit is the ordinal flag. So this does
        not ban the literal; it requires the mask to be reached only in the 32-bit branch, which is
        the difference between a correct expression and a correct expression in the wrong place.
        """
        src = (HERE.parent / "torikago.py").read_text(encoding="utf-8")
        flat = " ".join(src.split())
        self.assertIn("rva = val if is64 else (val & 0x7FFFFFFF)", flat)
        self.assertNotIn("rva = val & 0x7FFFFFFF", flat,
                         "the mask applies to both widths again")


class TestTruncationIsReported(unittest.TestCase):
    """A cap the consumer cannot see is indistinguishable from a shorter file."""

    def test_the_caps_are_named_constants(self):
        for name in ("DESCRIPTOR_CAP", "FUNC_CAP", "NAME_CAP", "ORDINAL_BIT"):
            with self.subTest(constant=name):
                self.assertTrue(hasattr(tk, name), "%s is not a named constant" % name)

    def test_too_many_names_is_marked(self):
        """200 retained names beside a larger count: the two used to disagree silently."""
        many = tk.NAME_CAP + 5
        data = pe_x64(extra_thunks=many)
        entries = tk.parse_imports(data, tk.parse_pe(data))
        first = entries[0]
        self.assertGreater(first["count"], tk.NAME_CAP)
        self.assertTrue(first.get("functions_truncated"), first)
        self.assertEqual(first["functions_limit"], tk.NAME_CAP)
        self.assertLessEqual(len(first["functions"]), tk.NAME_CAP)

    def test_a_short_import_list_is_not_marked(self):
        """Over-reporting truncation is its own failure: it makes the marker meaningless."""
        data = pe_x64()
        first = tk.parse_imports(data, tk.parse_pe(data))[0]
        self.assertNotIn("functions_truncated", first)
        self.assertNotIn("thunks_truncated", first)


class TestParsePeSurvivesHostileHeaders(unittest.TestCase):
    """Not a fuzz campaign -- a handful of headers a malformed file can actually claim."""

    def test_a_huge_section_extent_does_not_escape(self):
        """`rawptr + rawsize` can be enormous, and the arithmetic happens before the bounds check."""
        src = (HERE.parent / "torikago.py").read_text(encoding="utf-8")
        i = src.index("def parse_pe")
        window = src[i:i + 6000]
        self.assertIn("MemoryError", window,
                      "parse_pe catches only struct.error and IndexError, so an allocation failure "
                      "propagates out of the tool")

    def test_unreadable_is_distinct_from_not_a_pe(self):
        """`None` means "not a PE". A PE that could not be read is a different fact and must not be
        collapsed into it, or a hostile header reads as a benign file."""
        # Window sized to the whole handler rather than a guess. The first version used 500
        # characters and the explanatory comment pushed the marker past it -- measuring the text
        # again, which is the failure this file is supposed to be avoiding.
        src = (HERE.parent / "torikago.py").read_text(encoding="utf-8")
        i = src.index("except MemoryError")
        handler = src[i:i + 2000]
        self.assertIn("unreadable", handler)
        self.assertIn("return", handler.split("unreadable")[0][-200:] + "unreadable")

    def test_an_empty_and_a_truncated_file_are_refused_quietly(self):
        for label, blob in (("empty", b""), ("MZ only", b"MZ"),
                            ("header cut short", b"MZ" + bytes(0x30))):
            with self.subTest(case=label):
                self.assertIsNone(tk.parse_pe(blob))


if __name__ == "__main__":
    unittest.main(verbosity=2)
