# -*- coding: utf-8 -*-
"""Is "not a PE" distinguishable from "a PE whose header will not parse"?

The measurement behind `TODO.md` §零之七 F-2, and behind the section of the same name in
`FORMAT_MATRIX.md`. The bytes are built here rather than taken from a file so that what each sample
is doing is readable in the script.

Three samples:

  good     a minimal but real PE32 header (DOS stub + `PE\\0\\0` + optional header + one section)
  broken   starts with `MZ`, and `e_lfanew` points at bytes that are not a PE signature
  notpe    plain text

For each one, print what `identify()` says, what `parse_pe()` returns, and the three fields a scan
report would carry: kind, packer verdict, import count.

Run from anywhere:

    python tools/probe_pe_vs_broken.py
"""
from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location("tk_probe", REPO / "torikago.py")
tk = importlib.util.module_from_spec(spec)
sys.modules["tk_probe"] = tk
spec.loader.exec_module(tk)


def make_good_pe() -> bytes:
    """DOS header, stub, PE signature, COFF header, a minimal optional header, one section."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)  # e_lfanew
    pe_off = 0x40
    coff = struct.pack("<4sHHIIIHH", b"PE\x00\x00", 0x14C, 1, 0, 0, 0, 224, 0x0102)
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)        # PE32
    struct.pack_into("<I", opt, 16, 0x1000)      # AddressOfEntryPoint
    struct.pack_into("<I", opt, 24, 0x400000)    # ImageBase
    struct.pack_into("<I", opt, 92, 16)          # NumberOfRvaAndSizes
    sec = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x200, 0x1000, 0x200, 0x200,
                      0, 0, 0, 0, 0x60000020)
    body = bytes(0x200)
    return bytes(dos) + coff + bytes(opt) + sec + body


def make_broken_pe() -> bytes:
    """`MZ`, an `e_lfanew` that lands inside the file, and no PE signature where it points."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    return bytes(dos) + b"\x00" * 0x80  # 0xC0 bytes, no PE\0\0 anywhere


SAMPLES = {
    "good": (make_good_pe(), "a real PE32 header"),
    "broken": (make_broken_pe(), "MZ, and no PE signature at e_lfanew"),
    "notpe": (b"just a plain text file, no header at all\n" * 4, "not a PE in any reading"),
}


def main() -> int:
    print("%-8s %-8s %-26s %-10s %-8s %s"
          % ("sample", "kind", "label", "parse_pe", "packer", "imports"))
    print("-" * 88)
    for name, (blob, _why) in SAMPLES.items():
        kind = tk.identify(blob, Path(name + ".bin"))
        pe = tk.parse_pe(blob) if kind["kind"] == "pe" else None
        # The three fields a scan report carries, from the same branches as lines 1699-1718.
        packer = (tk.identify_packer(pe, blob, []) if pe else {"verdict": "n/a"})["verdict"]
        imports = len(tk.parse_imports(blob, pe)) if pe else 0
        print("%-8s %-8s %-26s %-10s %-8s %d" % (
            name, kind["kind"], kind["label"], "dict" if pe else "None", packer, imports))

    print()
    print("what a reader sees for the broken one:")
    print("  kind = pe  -> it IS an executable")
    print("  packer = n/a, imports = 0, entropy_max = 0.0 -> nothing worth noting")
    print("  (no field anywhere says the header did not parse)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
