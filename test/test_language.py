# -*- coding: utf-8 -*-
"""Tests for runtime/language identification.

Language matters for triage: a Rust binary needs different tooling from a C# one, and
Rust in particular is on the rise in malware precisely because its binaries are harder to
read. All of this is decidable statically, so it belongs here rather than in a sandbox.

The .NET fixture is assembled byte by byte rather than by calling the real compiler, so the
suite keeps working on a machine with no .NET installed. The structural path it exercises
was validated against a real `dotnet build` output: CLI header at the COM descriptor RVA
(cb=72, runtime 2.5) -> metadata RVA at +8 -> BSJB with "v4.0.30319".

Run:
    python -m unittest discover -s test -v
"""
from __future__ import annotations

import importlib.util
import struct
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
tt = _load("tt3", "test/test_torikago.py")


def with_dotnet_layout(base: bytes, *, cli_rva=0x2000, md_rva=0x2100,
                       version=b"v4.0.30319") -> bytes:
    """Take a plain PE fixture and give it a CLR header + metadata root.

    Layout: COM descriptor directory -> CLI header at cli_rva -> metadata RVA at +8 ->
    BSJB root at md_rva. The section that tt.build_pe writes maps RVA 0x1000 to its own
    first byte, so both targets must live inside it.
    """
    pe = tri.parse_pe(base)
    if pe is None:
        raise AssertionError("fixture is not a PE")
    sec = pe["sections"][0]
    buf = bytearray(base)
    need = sec["rawptr"] + 0x1400
    if len(buf) < need:
        buf.extend(b"\x00" * (need - len(buf)))
    # Grow the section too: its header has to cover RVA 0x2100 with **file-backed bytes**, or
    # `rva_to_offset` refuses the metadata address and the fixture looks like a plain binary.
    #
    # **Both fields, and at the right offsets.** This wrote VirtualSize=0x1000 (not the 0x1400 the
    # comment described) and then wrote 0x1400 to +16, which is VirtualAddress -- so the section
    # claimed a virtual size smaller than its raw size and a virtual address of 0x1400. The old
    # `max(vsize, rawsize)` mapping happened to cover RVA 0x2100 anyway, which is why the mistake was
    # invisible until the mapping stopped conflating the two.
    opt_size = 240 if pe["bits"] == 64 else 224
    sec_table_off = 0x80 + 24 + opt_size
    struct.pack_into("<I", buf, sec_table_off + 8, 0x1400)     # VirtualSize
    struct.pack_into("<I", buf, sec_table_off + 16, 0x1400)    # SizeOfRawData

    # point the COM descriptor directory at the CLI header (well, at its RVA)
    opt_off = 0x80 + 24
    ddir = opt_off + (112 if pe["bits"] == 64 else 96)
    struct.pack_into("<II", buf, ddir + 14 * 8, cli_rva, 72)

    cli_off = sec["rawptr"] + (cli_rva - 0x1000)
    struct.pack_into("<IHH", buf, cli_off, 72, 2, 5)          # cb, runtime 2.5
    struct.pack_into("<II", buf, cli_off + 8, md_rva, 0x100)  # metadata rva + size

    md_off = sec["rawptr"] + (md_rva - 0x1000)
    struct.pack_into("<4sHHII", buf, md_off, b"BSJB", 1, 1, 0, len(version) + 4)
    buf[md_off + 16:md_off + 16 + len(version)] = version
    return bytes(buf)


class TestDotNet(unittest.TestCase):
    def test_a_real_clr_layout_is_identified(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "Managed.dll"
            p.write_bytes(with_dotnet_layout(tt.build_pe()))
            r = tri.build_report(p, None)
        lang = r["language"]
        self.assertEqual(lang["likely"], "C#/.NET")
        self.assertIn("v4.0.30319", " ".join(lang["all"][0]["markers"]))

    def test_plain_pe_is_not_dotnet(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "Native.dll"
            p.write_bytes(tt.build_pe())
            r = tri.build_report(p, None)
        self.assertNotEqual((r["language"] or {}).get("likely"), "C#/.NET")

    def test_bsjb_in_the_middle_of_a_file_is_not_enough(self):
        """Chance occurrences of the signature must not identify anything."""
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "Native2.dll"
            p.write_bytes(tt.build_pe() + b"\x00" * 64 + b"BSJB" + b"\x01\x02\x03\x04" * 8)
            r = tri.build_report(p, None)
        self.assertIsNone((r["language"] or {}).get("likely"))

    def test_com_descriptor_pointing_at_nothing_is_rejected(self):
        good = with_dotnet_layout(tt.build_pe())
        buf = bytearray(good)
        pe = tri.parse_pe(good)
        sec = pe["sections"][0]
        # break the metadata signature at its stated location
        md_off = sec["rawptr"] + (0x2100 - 0x1000)
        buf[md_off:md_off + 4] = b"XXXX"
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "Broken.dll"
            p.write_bytes(bytes(buf))
            r = tri.build_report(p, None)
        self.assertNotEqual((r["language"] or {}).get("likely"), "C#/.NET")


class TestOtherRuntimes(unittest.TestCase):
    def test_rust_markers_are_recognised(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "sample.exe"
            p.write_bytes(tt.build_pe() + b"rustc 1.80.0\ncore::panicking\nRUST_BACKTRACE")
            r = tri.build_report(p, None)
        self.assertEqual((r["language"] or {}).get("likely"), "Rust")

    def test_go_markers_are_recognised(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "tool.exe"
            p.write_bytes(tt.build_pe() + b"Go build ID: abc\nruntime.gopanic\ngo1.22")
            r = tri.build_report(p, None)
        self.assertEqual((r["language"] or {}).get("likely"), "Go")

    def test_pyinstaller_binary_reports_python(self):
        cookie = struct.pack("!8sIIII64s", tri.MEI_COOKIE, 500, 100, 64, 312,
                             b"python312.dll".ljust(64, b"\x00"))
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "frozen.exe"
            p.write_bytes(tt.build_pe() + b"_MEIPASS" + b"PyInstaller" + b"\x00" * 200 + cookie)
            r = tri.build_report(p, None)
        self.assertEqual((r["language"] or {}).get("likely"), "Python-frozen")

    def test_no_markers_means_no_claim(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "plain.dll"
            p.write_bytes(tt.build_pe())
            r = tri.build_report(p, None)
        self.assertIsNone((r["language"] or {}).get("likely"))
        self.assertEqual((r["language"] or {}).get("all"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
