# -*- coding: utf-8 -*-
"""Tests for destructive-capability detection.

This tier exists because of a real gap: an MBR overwriter needs a raw device write, and
nothing in the import tiers covered that at all. Getting it right meant two corrections in
both directions, and both are locked here:

* FALSE POSITIVES. A first version keyed on DeviceIoControl plus WriteFile and flagged five
  benign binaries out of seven -- later even Nanodesu's own executable, because those are
  ordinary imports. Separately, a plain substring test for "MBR" flagged a Python extension
  module, because unicode character data contains "UMBRELLA".
* FALSE NEGATIVES. Tightening the boot-sector check after those fixes silenced it entirely
  on a genuine MBR, because the plausibility test rejected a 0xFF sentinel field.

The fixtures below therefore build a boot sector to the on-disk format exactly, and the
"must stay quiet" cases are real-shaped benign binaries rather than empty ones.

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


tri = _load("triage", "triage.py")
tt = _load("tt4", "test/test_triage.py")


def make_mbr(*, ptype=0x07, start_lba=2048, sectors=1_000_000,
             start_chs=(0x00, 0x02, 0x00), end_chs=(0xFE, 0xFF, 0xFF),
             status=0x80, boot_code=True) -> bytes:
    """A 512-byte boot sector laid out per the on-disk format.

    Offsets that matter: 446 is the first partition entry, its 16-byte fields are
    status(0) head(1) sector+cyl(2,3) type(4) head(5) sector+cyl(6,7) and two little-endian
    dwords at 8 and 12; the signature 0x55AA sits at 510.
    """
    m = bytearray(512)
    if boot_code:
        m[0:6] = b"\xfa\x33\xc0\x8e\xd0\xbc"
    if status is not None:
        entry = bytearray(16)
        entry[0] = status
        entry[1], entry[2], entry[3] = start_chs
        entry[4] = ptype
        entry[5], entry[6], entry[7] = end_chs
        struct.pack_into("<II", entry, 8, start_lba, sectors)
        m[446:462] = entry
    m[510:512] = b"\x55\xaa"
    return bytes(m)


class TestBootSectorDetection(unittest.TestCase):
    def test_a_real_mbr_is_detected(self):
        hits = tri.find_boot_sector_pattern(make_mbr())
        self.assertTrue(hits, "a structurally valid MBR must be detected")
        self.assertEqual(hits[0]["offset"], 0)
        self.assertEqual(hits[0]["partitions"][0]["type"], "0x7")

    def test_all_three_common_geometries_are_detected(self):
        cases = {
            "windows convention (end FE FF FF)":
                make_mbr(start_chs=(0x00, 0x02, 0x00), end_chs=(0xFE, 0xFF, 0xFF)),
            "small cylinders, CHS consistent with LBA":
                make_mbr(start_chs=(0x00, 0x01, 0x01), end_chs=(0x10, 0x0F, 0x3F),
                         start_lba=63, sectors=500_000),
            "modern MBR, CHS left at LBA-only values":
                make_mbr(start_chs=(0x00, 0x00, 0x02), end_chs=(0xFE, 0xFF, 0xFF),
                         start_lba=4096, sectors=204_800, ptype=0x83),
        }
        for label, mbr in cases.items():
            with self.subTest(label):
                self.assertTrue(tri.find_boot_sector_pattern(mbr),
                                "not detected: %s" % label)

    def test_rejects_an_unknown_partition_type(self):
        self.assertEqual(tri.find_boot_sector_pattern(make_mbr(ptype=0x24)), [])

    def test_rejects_a_0xff_sentinel_field(self):
        self.assertEqual(
            tri.find_boot_sector_pattern(make_mbr(start_chs=(0xFF, 0x02, 0x00))), [],
            "0xFF is the field's unused marker")

    def test_rejects_absurd_geometry_from_compressed_data(self):
        """The false positive that forced this check: two bytes reading 55 AA are common."""
        noise = bytearray(512)
        noise[446] = 0x80
        noise[450] = 0x06                                  # valid type byte, by chance
        noise[447:450] = bytes([0x0B, 0xFF, 0xFF])
        noise[451:454] = bytes([0xFE, 0xFF, 0xFF])
        struct.pack_into("<II", noise, 458, 1_761_936_277, 2_951_039_675)
        noise[510:512] = b"\x55\xaa"
        self.assertEqual(tri.find_boot_sector_pattern(bytes(noise)), [])

    def test_555a_alone_is_not_a_boot_sector(self):
        blob = bytearray(512)
        blob[510:512] = b"\x55\xaa"
        self.assertEqual(tri.find_boot_sector_pattern(bytes(blob)), [])


class TestDestructiveCapability(unittest.TestCase):
    def _report(self, payload: bytes, imports=None):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "sample.exe"
            p.write_bytes(payload)
            return tri.build_report(p, None)

    def test_embedded_mbr_raises_critical(self):
        pe = tt.build_pe()
        r = self._report(pe + make_mbr())
        self.assertGreaterEqual(r["destructive"]["count"], 1)
        self.assertEqual(r["destructive"]["highest"], "critical")
        caps = [f["capability"] for f in r["destructive"]["findings"]]
        self.assertIn("embedded boot sector", caps)

    def test_raw_device_path_is_reported_as_moderate(self):
        r = self._report(tt.build_pe() + b"\\\\.\\PhysicalDrive0\x00")
        findings = r["destructive"]["findings"]
        self.assertTrue(findings)
        self.assertEqual(findings[0]["severity"], "medium")

    def test_ordinary_imports_alone_are_not_destructive(self):
        """DeviceIoControl and WriteFile are in most Windows binaries; they are not evidence."""
        r = self._report(tt.build_pe(imports=[("KERNEL32.dll",
                                               ["DeviceIoControl", "WriteFile",
                                                "SetFilePointer"])]))
        self.assertEqual(r["destructive"]["count"], 0)

    def test_umbrella_does_not_trigger_destructive_terminology(self):
        r = self._report(tt.build_pe() + b"UMBRELLA UMBRELL\xc1")
        self.assertEqual(r["destructive"]["count"], 0,
                         "a substring inside a word must not be read as a marker")

    def test_a_clean_pe_reports_nothing(self):
        r = self._report(tt.build_pe())
        self.assertEqual(r["destructive"]["count"], 0)
        self.assertIsNone(r["destructive"]["highest"])

    def test_critical_appears_in_the_assessment_reasons(self):
        r = self._report(tt.build_pe() + make_mbr())
        joined = " ".join(r["assessment"]["reasons"])
        self.assertIn("EMBEDDED BOOT SECTOR", joined)


class TestBootSectorNotMisread(unittest.TestCase):
    """The boot-sector marker by itself must never be enough."""

    def test_plain_data_with_555a_is_not_reported(self):
        blob = bytearray(512)
        blob[510:512] = b"\x55\xaa"
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "data.dll"
            p.write_bytes(tt.build_pe() + bytes(blob))
            r = tri.build_report(p, None)
        self.assertEqual(r["destructive"]["count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
