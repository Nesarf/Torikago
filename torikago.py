#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""torikago.py - static triage for an unknown executable.

Design rule, and the reason this tool is safe to point at malware:

    It never executes the target. Not once, not for one code path.

Unpacking is a byte-level reading problem. A sample cannot act on a machine it is
never allowed to run on, which makes "never execute" a stronger guarantee than any
user-mode sandbox could offer. Where a format genuinely cannot be unpacked without
running it (runtime packers, some installers), this tool identifies that and stops;
it prints what would have to be run and where to run it, and does not do so itself.

What it produces is evidence for a decision-maker: what the file really is, whether
it is packed, what is inside it, which indicators it carries, and a draft YARA rule.
Detection and removal are deliberately left to engines that maintain signatures --
building one here would only create a bypass target, and the sample's real value to
a defender is the structure and indicators this extracts.

Usage:
    python torikago.py <file> [--out DIR] [--json] [--quiet]

No third-party dependencies. Python 3.9+.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import shutil
import struct
import sys
import time
import uuid
import zlib
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import unpack as unpack_mod
except ImportError:                                # pragma: no cover - unpack.py ships with us
    unpack_mod = None

def _version() -> str:
    """The version of the installed distribution, or of this file.

    Reading it from the package metadata means the number cannot drift from `pyproject.toml` --
    which it had: the module reported 0.8.0 across five releases while the package said otherwise.
    A caller loading this module by path (as the sibling tool does when it finds the file on disk)
    has no distribution to ask, so the constant below is the fallback for exactly that case.
    """
    try:
        from importlib.metadata import version as _dist_version
        return _dist_version("torikago")
    except Exception:
        return _SOURCE_VERSION


# Kept only for the by-path case. When the package is installed this value is not used.
_SOURCE_VERSION = "1.7.0"
VERSION = _version()

# --------------------------------------------------------------------------- #
# format identification (magic bytes, because extensions lie)
# --------------------------------------------------------------------------- #

# Deliberately small and honest: each entry is a prefix seen in the wild, and the
# list grows from real misses rather than from imagination. MZ/PE is checked
# structurally further down, not by prefix alone.
MAGIC = [
    (b"MZ", "PE executable (DOS/PE)", "pe"),
    (b"\x7fELF", "ELF executable", "elf"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal binary", "macho"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit", "macho"),
    (b"PK\x03\x04", "ZIP container", "zip"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "7z"),
    (b"Rar!\x1a\x07", "RAR archive", "rar"),
    (b"\x1f\x8b", "gzip stream", "gzip"),
    (b"BZh", "bzip2 stream", "bzip2"),
    (b"\xfd7zXZ\x00", "xz stream", "xz"),
    (b"%PDF", "PDF document", "pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound file (legacy MSI/Office)", "ole"),
    (b"\x4d\x53\x43\x46", "Microsoft Cabinet (CAB)", "cab"),
    (b"ITSF", "CHM help file", "chm"),
    (b"\x89PNG\r\n\x1a\n", "PNG image", "png"),
    (b"\xff\xd8\xff", "JPEG image", "jpeg"),
    (b"GIF8", "GIF image", "gif"),
    (b"#!", "script with shebang", "script"),
    (b"{\\rtf", "RTF document", "rtf"),
    (b"!<arch>", "ar archive", "ar"),
    (b"SQLite format 3\x00", "SQLite database", "sqlite"),
    (b"\x50\x4b\x05\x06", "empty ZIP", "zip"),
]


def identify(data: bytes, path: Path) -> dict:
    """What the bytes say this is, independent of what the name claims."""
    for prefix, label, kind in MAGIC:
        if data.startswith(prefix):
            return {"kind": kind, "label": label, "by": "magic", "prefix": prefix.hex()}
    # No known prefix: say so rather than guessing from the extension.
    return {"kind": "unknown", "label": "unrecognised", "by": "magic", "prefix": data[:8].hex()}


def extension_mismatch(kind: str, path: Path) -> str | None:
    """A .png that is really an executable is worth saying out loud."""
    ext = path.suffix.lower().lstrip(".")
    if not ext:
        return None
    # .pyd is a Python extension module: a real DLL under a conventional name, not a disguise.
    binary_exts = {"exe", "dll", "scr", "com", "sys", "ocx", "cpl", "pyd", "so", "node",
                   "dylib", "efi", "acm", "ax", "drv", "tsp"}
    image_exts = {"png", "jpg", "jpeg", "gif", "bmp", "webp", "ico"}
    if kind == "pe" and ext not in binary_exts:
        return f"named .{ext} but is a PE executable"
    if kind in ("png", "jpeg", "gif") and ext in binary_exts:
        return f"named .{ext} but is an image"
    if kind == "pe" and ext in image_exts:
        return f"named .{ext} but is a PE executable"
    return None


# --------------------------------------------------------------------------- #
# PE structure
# --------------------------------------------------------------------------- #

PACKER_SECTION_HINTS = {
    "upx": "UPX",
    ".themida": "Themida/WinLicense",
    ".vmp": "VMProtect",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".enigma": "Enigma Protector",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    ".packed": "generic packer",
    ".mpress": "MPRESS",
    ".petite": "Petite",
    ".nsp": "NsPack",
    ".mew": "MEW",
    ".pebundle": "PEBundle",
    ".spack": "Simple Pack",
    "pec1": "PECompact",
    "pec2": "PECompact",
    ".boom": "The Boomerang",
}

SUSPICIOUS_IMPORTS = {
    "virtualalloc": "allocates executable memory (unpacking / injection)",
    "virtualprotect": "changes memory protection (self-modifying code)",
    "writeprocessmemory": "writes into another process",
    "createremotethread": "runs code in another process",
    "setwindowshookex": "installs a hook",
    "getprocaddress": "resolves APIs dynamically (hides the import table)",
    "loadlibrary": "loads a library at runtime",
    "isdebuggerpresent": "checks for a debugger",
    "checkremotedebuggerpresent": "checks for a debugger",
    "ntqueryinformationprocess": "checks for a debugger (anti-analysis)",
    "outputdebugstring": "debugger detection trick",
    "cryptencrypt": "encrypts data (possible ransomware)",
    "cryptgenrandom": "generates keys",
    "shellexecute": "launches something else",
    "winexec": "launches something else",
    "createtoolhelp32snapshot": "enumerates processes",
    "urldownloadtofile": "downloads a file",
    "internetopen": "network access",
    "httpsendrequest": "network access",
    "wsastartup": "network access",
    "socket": "network access",
    "regsetvalue": "writes the registry",
    "regcreatekey": "writes the registry",
    "createservice": "creates a service (persistence)",
    "schtasks": "schedules a task (persistence)",
    "adjusttokenprivileges": "escalates privileges",
}

HIGH_ENTROPY = 7.2

# APIs that are only meaningful alongside other evidence (packing, an embedded image,
# a network indicator). On their own they are ordinary program behaviour.
# APIs that are rare enough to raise attention on their own. Deliberately excludes the ones
# ordinary software calls constantly: IsDebuggerPresent is how CPython implements
# sys.gettrace, GetProcAddress is how every delay-load stub works, VirtualProtect is used by
# any JIT. Those are recorded as "noted" instead, and the injection triad below is what
# actually escalates.
STRONG_SIGNAL_IMPORTS = {
    "writeprocessmemory", "createremotethread", "ntmapviewofsection", "queueuserapc",
    "setwindowshookex", "cryptencrypt", "urldownloadtofile", "createservice",
    "ntunmapviewofsection", "rtlcreateuserthread",
}

# Capabilities that destroy rather than infect. Kept in a separate tier because the evidence
# for them is structural and precise, while the APIs involved are individually ordinary:
# DeviceIoControl is used by every driver-adjacent program. What is not ordinary is writing
# to a physical drive, or carrying a boot sector.
DESTRUCTIVE_IMPORTS = {
    "deviceiocontrol": "can issue raw device control codes (IOCTL_DISK_* writes the "
                       "partition table or boot sector)",
    "ntwritefile": "raw write, used to reach \\\\.\\PhysicalDrive from native code",
    "zwwritefile": "raw write, used to reach \\\\.\\PhysicalDrive from native code",
    "shellexecutew": "launches other programs",
}

# Paths that address a raw disk or volume rather than a file. Legitimate disk utilities use
# these; almost nothing else does, which is what makes them worth reporting.
RAW_DISK_PATTERNS = (
    b"\\\\.\\PhysicalDrive",
    b"\\\\.\\physicaldrive",
    b"\\\\.\\Scsi",
    b"\\\\.\\C:",
    b"\\\\.\\Harddisk",
    b"IOCTL_DISK_SET_DRIVE_LAYOUT",
    b"IOCTL_DISK_WRITE",
)


# Partition type bytes that the on-disk format actually defines. A boot sector carrying a
# replacement partition table will use one of these; a chance byte pair in compressed data
# will not.
KNOWN_PARTITION_TYPES = {
    0x01, 0x04, 0x05, 0x06, 0x07, 0x0B, 0x0C, 0x0E, 0x0F, 0x11, 0x12, 0x14, 0x16, 0x17,
    0x1B, 0x1C, 0x1E, 0x27, 0x2B, 0x2C, 0x39, 0x42, 0x44, 0x4D, 0x4E, 0x4F, 0x50, 0x51,
    0x52, 0x63, 0x64, 0x65, 0x70, 0x75, 0x7F, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
    0x8E, 0x93, 0x9F, 0xA0, 0xA5, 0xA6, 0xA8, 0xA9, 0xAB, 0xAF, 0xBE, 0xBF, 0xC1, 0xC2,
    0xC3, 0xC4, 0xC6, 0xC7, 0xDA, 0xDB, 0xDE, 0xDF, 0xE1, 0xE3, 0xE4, 0xE6, 0xEB, 0xEE,
    0xEF, 0xFB, 0xFC, 0xFD,
}


def find_boot_sector_pattern(data: bytes, limit: int = 8 << 20) -> list:
    """Look for a boot sector embedded in a file.

    A 512-byte MBR has a very specific shape: it ends with 0x55 0xAA at offset 510, and the
    bytes just before it are a partition table. Tooling that overwrites a boot sector has to
    carry a replacement for it, so finding that shape inside an ordinary executable is worth
    reporting -- it is the difference between 'this program touches disks' and 'this program
    brings its own boot code'.
    """
    head = data[:limit]
    hits = []
    # len - 511, not len - 512: a 512-byte boot sector at offset 0 needs the loop to run
    # at least once, and the off-by-one made that case invisible.
    for i in range(0, max(0, len(head) - 511)):
        if head[i + 510] != 0x55 or head[i + 511] != 0xAA:
            continue
        # A real partition table is four 16-byte entries, and the type byte has to be a
        # value the format actually defines. Accepting an arbitrary byte here produced a
        # false positive on an ordinary binary: two bytes reading 55 AA at the right place
        # are common in compressed data, and the byte after the status was 0x24 -- not a
        # partition type at all.
        # Every one of the four slots must be either a well-formed partition or a well-formed
        # empty slot. This requirement was missing, and its absence produced an "embedded boot
        # sector [critical]" on an ordinary 51 MB remote-desktop DLL -- twice.
        #
        # The old rule looked for *any* slot that validated and stopped there, so a random window
        # whose first slot happened to carry a known type and sane-looking geometry was a hit
        # regardless of what the other three slots held. A real partition table cannot look like
        # that: an MBR with one partition has three zeroed slots, and the slots sit on a 16-byte
        # grid that arbitrary code does not respect.
        #
        # Measured on both sides before adopting it: five genuine boot sectors (including CHS
        # variants and four partition types) satisfy it, and both false positives do not.
        entries = []
        for k in range(4):
            e = head[i + 446 + k * 16:i + 462 + k * 16]
            if len(e) < 16:
                entries = []
                break
            status, ptype = e[0], e[4]
            if ptype == 0x00:
                # An empty slot. A disk with one partition still has four entries and three of
                # them are type 0x00, so this has to be accepted -- but accepted as *empty*
                # rather than as a partition, which is what the last check below is for.
                continue
            if status not in (0x00, 0x80):
                entries = []
                break
            if ptype not in KNOWN_PARTITION_TYPES:
                entries = []
                break
            if e[1] == 0xFF or e[5] == 0xFF:
                entries = []
                break      # 0xFF is the field's "unused" value; 0xFE is a legitimate head
            # Two discriminators, chosen after testing both mistakes:
            #
            # A chance 55 AA window in compressed data carried a valid type byte (0x06) with a
            # start LBA of 1.7 billion and 2.9 billion sectors, so the geometry has to be bounded.
            # But requiring the CHS field to agree with the LBA rejected genuine MBRs, because
            # those fields are legacy and tools leave them at sentinel values. So CHS only has to
            # be in range and the LBA has to be a plausible size.
            start_cyl, start_head, start_sector = e[1], e[2], e[3] & 0x3F
            end_cyl = ((e[6] << 2) | (e[7] >> 6)) & 0x3FF
            end_sector = e[7] & 0x3F
            start_lba = int.from_bytes(e[8:12], "little")
            sectors = int.from_bytes(e[12:16], "little")
            if not (0 <= start_cyl <= 1023 and 0 <= end_cyl <= 1023):
                entries = []
                break
            if not (1 <= end_sector <= 63):
                entries = []
                break
            if start_sector and not (1 <= start_sector <= 63):
                entries = []
                break
            if not (0 < start_lba < (1 << 32)):
                entries = []
                break
            if not (0 < sectors < (1 << 32)):
                entries = []
                break
            if sectors > 4096 * 1024 * 1024 // 512:      # 4 TiB of 512-byte sectors
                entries = []
                break
            entries.append({"type": hex(ptype), "start_lba": start_lba, "sectors": sectors})

        # At least one slot must actually describe a partition. Everything above establishes
        # that the slots it looked at are *well formed*; this establishes that there is a
        # partition table here rather than an empty window that happened to be shaped like one.
        if entries:
            hits.append({"offset": i, "size": 512, "partitions": entries,
                         "sha256": hashlib.sha256(head[i:i + 512]).hexdigest()[:32]})
        if len(hits) >= 8:
            break
    return hits


def detect_destructive(pe: dict | None, data: bytes, imports: list,
                       strings: dict) -> dict:
    """Report capabilities whose effect is unrecoverable, as distinct from merely hostile.

    This tier exists because of a real gap: an MBR overwriter needs DeviceIoControl plus a
    write to \\\\.\\PhysicalDrive0, and none of that appeared anywhere in the import tiers.
    A tool aimed at unknown files should say "this can destroy the machine" when the evidence
    is there, and should say it with the precision the evidence actually has.
    """
    findings = []
    all_funcs = {fn.lower() for imp in imports for fn in imp["functions"]}
    all_dlls = {imp["dll"].lower() for imp in imports}

    disks = []
    if pe:
        for s in pe["sections"]:
            off = s["rawptr"]
            body = data[off:off + min(s["rawsize"], 4 << 20)]
            for pat in RAW_DISK_PATTERNS:
                if pat in body and pat not in [d.encode() for d in disks]:
                    disks.append(pat.decode("latin1", "replace"))
    for pat in RAW_DISK_PATTERNS[:4]:
        if pat in data[:1 << 20] and pat.decode("latin1", "replace") not in disks:
            disks.append(pat.decode("latin1", "replace"))
    if disks:
        findings.append({
            "capability": "raw disk or volume access",
            "evidence": "device path string(s) present: " + ", ".join(disks[:4]) +
                        " (a reference only; not proof of a write)",
            "severity": "medium",
        })

    boot = find_boot_sector_pattern(data)
    if boot:
        findings.append({
            "capability": "embedded boot sector",
            "evidence": "%d region(s) ending in 0x55AA at offset 510, first at %#x"
                        % (len(boot), boot[0]["offset"]),
            "severity": "critical",
        })

    # DeviceIoControl and WriteFile are not evidence of anything: both are ordinary imports
    # in most Windows binaries (kernel32.dll and shell32.dll import them, and so does every
    # archiver). The pair was tried as a rule and flagged five benign binaries out of seven.
    #
    # Then a real MBR overwriter was checked against this code, and its import table contains
    # NEITHER of them: the disk APIs are resolved at runtime through the PE export table, so
    # they never appear as imports at all. The rule was not merely noisy, it was aimed at the
    # wrong evidence. What the real sample imports is a different and more honest signal:
    # an input hook, a screen grabber, a crypto RNG and a launcher, with no disk write
    # anywhere -- a program that is busy with the machine while showing nothing on it.
    if {"setwindowshookexw", "setwindowshookexa"} & all_funcs             and "cryptgenrandom" in all_funcs:
        findings.append({
            "capability": "input hook plus crypto RNG without any disk write",
            "evidence": "SetWindowsHookEx with CryptGenRandom, and no write-to-disk import: "
                        "consistent with a program whose effect is on the desktop and whose "
                        "payload is fetched or generated at runtime",
            "severity": "medium",
        })
    # Word-boundary matching: a plain substring test flagged a Python extension module
    # because unicode character data contains "UMBRELLA", which contains "MBR".
    interesting = " ".join(strings.get("interesting", [])).lower()
    for marker in ("physicaldrive", "boot sector", "bsod", "format c:"):
        if marker in interesting and not any(marker in f["evidence"].lower() for f in findings):
            findings.append({"capability": "destructive terminology",
                             "evidence": "string mentions %r" % marker,
                             "severity": "low"})

    severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    worst = max((f["severity"] for f in findings), key=lambda s: severity_rank[s],
                default=None)
    return {"findings": findings, "highest": worst, "count": len(findings),
            "boot_sectors": boot}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    val = -sum((n / total) * math.log2(n / total) for n in counts.values())
    return 0.0 if val <= 0 else val          # an empty or single-byte section is 0.0, not -0.0


def parse_pe(data: bytes) -> dict | None:
    """Parse just enough PE to make a judgement. Returns None if it is not a PE."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
            return None
        machine, nsec, timestamp = struct.unpack_from("<HHI", data, pe_off + 4)
        opt_size, chars = struct.unpack_from("<HH", data, pe_off + 20)
        opt_off = pe_off + 24
        magic = struct.unpack_from("<H", data, opt_off)[0]
        is64 = magic == 0x20B
        entry = struct.unpack_from("<I", data, opt_off + 16)[0]
        image_base = struct.unpack_from("<Q" if is64 else "<I", data, opt_off + 24)[0]
        ddir_off = opt_off + (112 if is64 else 96)
        directories = {}
        names = ["export", "import", "resource", "exception", "security", "basereloc",
                 "debug", "architecture", "globalptr", "tls", "load_config", "bound_import",
                 "iat", "delay_import", "com_descriptor"]
        for i, nm in enumerate(names):
            rva, size = struct.unpack_from("<II", data, ddir_off + i * 8)
            if rva and size:
                directories[nm] = {"rva": rva, "size": size}
        # section table
        sec_off = opt_off + opt_size
        sections = []
        for i in range(nsec):
            base = sec_off + i * 40
            if base + 40 > len(data):
                break
            raw_name = data[base:base + 8].rstrip(b"\x00")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
            characteristics = struct.unpack_from("<I", data, base + 36)[0]
            body = data[rawptr:rawptr + rawsize] if rawptr + rawsize <= len(data) else b""
            sections.append({
                "name": raw_name.decode("latin1", "replace"),
                "vsize": vsize, "vaddr": vaddr,
                "rawsize": rawsize, "rawptr": rawptr,
                "characteristics": characteristics,
                "executable": bool(characteristics & 0x20000000),
                "writable": bool(characteristics & 0x80000000),
                "entropy": round(shannon_entropy(body), 3),
                "packed_ratio": round(vsize / rawsize, 2) if rawsize else None,
            })
        return {
            "machine": {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64"}.get(machine, hex(machine)),
            "bits": 64 if is64 else 32,
            "timestamp": timestamp,
            "characteristics": chars,
            "is_dll": bool(chars & 0x2000),
            "entry_point_rva": entry,
            "image_base": image_base,
            "sections": sections,
            "directories": directories,
        }
    except (struct.error, IndexError):
        return None


def rva_to_offset(pe: dict, rva: int) -> int | None:
    for s in pe["sections"]:
        if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
            return s["rawptr"] + (rva - s["vaddr"])
    return None


def parse_imports(data: bytes, pe: dict) -> list:
    """Import names, because the import table is the cheapest behavioural hint there is."""
    d = pe["directories"].get("import")
    if not d:
        return []
    is64 = pe["bits"] == 64
    off = rva_to_offset(pe, d["rva"])
    if off is None:
        return []
    out = []
    for i in range(256):
        base = off + i * 20
        if base + 20 > len(data):
            break
        oft, _t, _f, name_rva, first_thunk = struct.unpack_from("<IIIII", data, base)
        if not any((oft, name_rva, first_thunk)):
            break
        dll = ""
        if name_rva:
            no = rva_to_offset(pe, name_rva)
            if no is not None:
                end = data.find(b"\x00", no, no + 260)
                dll = data[no:end if end > 0 else no + 60].decode("latin1", "replace")
        funcs = []
        thunk_rva = oft or first_thunk
        toff = rva_to_offset(pe, thunk_rva)
        if toff is not None:
            step = 8 if is64 else 4
            fmt = "<Q" if is64 else "<I"
            for k in range(512):
                p = toff + k * step
                if p + step > len(data):
                    break
                val = struct.unpack_from(fmt, data, p)[0]
                if val == 0:
                    break
                if val & (1 << (63 if is64 else 31)):
                    continue                      # imported by ordinal
                no = rva_to_offset(pe, val & 0x7FFFFFFF)
                if no is None:
                    continue
                end = data.find(b"\x00", no + 2, no + 2 + 128)
                nm = data[no + 2:end if end > 0 else no + 40].decode("latin1", "replace")
                if nm:
                    funcs.append(nm)
        out.append({"dll": dll, "functions": funcs[:200], "count": len(funcs)})
        if not dll and not funcs:
            break
    return out


# A Windows API-set forwarder (api-ms-win-*, ext-ms-win-*) has almost no imports by design:
# it exists to forward names to the real DLL. So do delay-load stubs. Calling those "packed"
# is a false positive, and a triage tool that cries wolf on every system DLL is not used twice.
def identify_packer(pe: dict, data: bytes, imports: list) -> dict:
    """Name the packer when the evidence is there, otherwise say 'unknown'."""
    findings = []
    for s in pe["sections"]:
        low = s["name"].lower()
        for hint, name in PACKER_SECTION_HINTS.items():
            if low.startswith(hint.strip(".")) or low == hint:
                findings.append({"packer": name, "evidence": f"section {s['name']!r}"})
    if b"UPX!" in data[:0x2000] or data.count(b"UPX!") >= 2:
        findings.append({"packer": "UPX", "evidence": "UPX! marker in the header area"})
    if data.count(b".themida") or b"Themida" in data[:0x4000]:
        findings.append({"packer": "Themida/WinLicense", "evidence": "marker near the entry"})
    if b"VMProtect" in data[:0x4000]:
        findings.append({"packer": "VMProtect", "evidence": "marker near the entry"})

    # UPX leaves its name in the file more than once; scanning the whole image (not just
    # the header) is what makes this reliable for packed UPX stubs.
    if data.count(b"UPX!") >= 2:
        findings.append({"packer": "UPX",
                         "evidence": f"{data.count(b'UPX!')} occurrences of the UPX! marker"})
    stub_names = {s["name"].lower() for s in pe["sections"]}
    if {"upx0", "upx1"} <= stub_names or {"upx0", "upx1", "upx2"} <= stub_names:
        findings.append({"packer": "UPX", "evidence": "upx0/upx1 section pair"})

    # Forwarders and stubs legitimately have almost no imports, so the empty-import evidence
    # is only reported when the file does not look like one. Two tells: an API-set name
    # (api-ms-win-*, ext-ms-win-*), which exists purely to forward names, and a small image
    # that exports things it does not import.
    name_is_api_set = bool(re.search(rb"(?:api|ext)-ms-win-", data[:0x2000], re.I))
    has_exports = bool(pe["directories"].get("export"))
    stub_like = name_is_api_set or (len(data) < 0x10000 and has_exports)

    # A .NET assembly is not packed just because its code section is dense. Managed binaries carry
    # IL plus metadata in .text, which is far less redundant than native machine code, so they sit
    # near the top of the entropy range by construction. A real sample measured 7.98 and was
    # reported as "likely packed" -- which is the kind of false positive that makes a report less
    # than useless, because the answer was sitting in the COM descriptor the whole time.
    if pe.get("is_dotnet"):
        total_imports_net = sum(i["count"] for i in imports)
        dedup_net = {}
        for f in findings:
            dedup_net.setdefault(f["packer"], set()).add(f["evidence"])
        return {"verdict": sorted(dedup_net)[0] if len(dedup_net) == 1
                else ("multiple" if dedup_net else "none"),
                "findings": [{"packer": k, "evidence": sorted(v)} for k, v in dedup_net.items()],
                "forwarder_or_stub": False,
                "note": "managed assembly: section entropy says nothing about packing here"}

    exec_sections = [s for s in pe["sections"] if s["executable"]]
    high = [s for s in pe["sections"] if s["entropy"] >= HIGH_ENTROPY]
    if exec_sections and len(high) == len(pe["sections"]):
        findings.append({"packer": "unknown (all sections high-entropy)",
                         "evidence": f"{len(high)} sections at entropy >= {HIGH_ENTROPY}"})
    if exec_sections and high and any(s["executable"] for s in high):
        findings.append({"packer": "likely packed",
                         "evidence": "executable section is high-entropy (encrypted or compressed code)"})
    total_imports = sum(i["count"] for i in imports)
    # Whether this file is code at all decides what an empty import table means. A data-only module
    # has no imports because it calls nothing: ICU ships its tables as `icudt*.dll`, one .rdata
    # section of 30+ MB and no code, and reporting that as a packer stub was simply the wrong
    # reading of an expected shape. Code-less files are named as such instead, which is the more
    # useful statement anyway -- "a 30 MB data blob" is worth knowing about a file, and "packed"
    # is not true of it.
    has_code = any(s.get("executable") for s in (pe.get("sections") or []))
    if not stub_like and total_imports == 0:
        # A near-empty import table is the classic packer stub, but "few imports" is not: a small
        # legitimate DLL can import one function. Only zero imports counts, and the high-entropy
        # evidence above covers stubs that do resolve a handful of APIs.
        if has_code:
            findings.append({"packer": "likely packed or delay-loaded",
                             "evidence": "no imported functions"})
        else:
            findings.append({"packer": "data module, not code",
                             "evidence": "no executable section and no imported functions: this is "
                                         "a data file in a PE container, so an empty import "
                                         "table is expected rather than a packer stub"})

    dedup = {}
    for f in findings:
        dedup.setdefault(f["packer"], set()).add(f["evidence"])
    return {"verdict": sorted(dedup)[0] if len(dedup) == 1 else ("multiple" if dedup else "none"),
            "findings": [{"packer": k, "evidence": sorted(v)} for k, v in dedup.items()],
            "forwarder_or_stub": stub_like}


# --------------------------------------------------------------------------- #
# wrappers we can unpack without running anything
# --------------------------------------------------------------------------- #
# Debug information: the PE debug directory, and a .pdb sitting beside the binary
#
# A debug build carries two gifts, and one of them needs no second file at all.
#
# The first is in the PE: the CodeView record holds the absolute path of the .pdb **on the build
# machine**. A real sample yielded
#
#   D:\Development\OpenSource\PowerfulWindSlickedBackHairCS-LX_Improve\...\obj\Debug\....pdb
#
# which names the project, the source layout and the build configuration, and is readable whether
# or not the .pdb ever shipped. Nothing here is inferred -- the path is in the file.
#
# The second is the .pdb itself, when it did ship, and shipping it is a disclosure in its own
# right: a PDB holds type names, method names, source paths and more. On that same sample the type
# and method names were recoverable in seconds, where disassembling to the same understanding
# would have taken far longer.
#
# What this claims and what it does not. The MSF container is parsed as the structure it is --
# block size, stream directory, per-stream sizes. The **symbol records inside those streams are
# not parsed**: the native PDB record format is large and thinly documented, and a half-written
# reader would produce confident nonsense, which is worse than none. So the identifiers are
# *extracted* from stream bytes, and the report labels them as extracted rather than interpreted.
# The PE-side helpers (parse_pe, rva_to_offset) are the ones already in this module; there is no
# second PE parser here.
# --------------------------------------------------------------------------- #

# Identifier shapes worth pulling out of a symbol stream. A PDB is full of strings that name
# nothing; a list of those is noise, so these are the ones that name something.
_RE_TYPE_NAME = re.compile(rb"[A-Z][A-Za-z0-9_]{2,60}(?:\.[A-Z][A-Za-z0-9_]{1,60})*")
_RE_NAMESPACE = re.compile(rb"(?:^|\x00)((?:[A-Z][A-Za-z0-9_]{1,40}\.){1,6}[A-Z][A-Za-z0-9_]{1,40})(?:\x00|$)")
_RE_SOURCE_PATH = re.compile(rb"[A-Za-z]:\\[^\x00\r\n]{3,200}\.(?:cs|vb|fs|cpp|c|h|hpp|py|js|ts)")
_RE_REL_SOURCE = re.compile(rb"(?:[\w.\-]+[\\/]){1,6}[\w.\-]+\.(?:cs|vb|fs|cpp|c|h|hpp|py|js|ts)")

# Names that appear in essentially every managed assembly, or every C++ object, and therefore say
# nothing about *this* one. Without this list the output is a wall of framework names.
_PDB_STOPWORDS = frozenset("""
System Microsoft Windows Collections Generic Object String Int32 Boolean Void Byte Char Double
Single Decimal Attribute Exception EventArgs IDisposable IEnumerable IEnumerator List Dictionary
Runtime Compiler Version CultureInfo Threading Text Drawing Forms Component Container Marshal
Nullable Activator Console Math Convert Array Type Enum Delegate Action Func Task Reflection
Resources Properties Settings Designer AssemblyInfo Program Main Dispose InitializeComponent
std basic_string vector allocator iterator char_traits ostream istream
""".split())

MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"


def parse_debug_directory(read, pe: dict) -> dict | None:
    """The CodeView record from the PE debug directory.

    `read(offset, length)` supplies bytes, so this works equally from a buffer and from a file
    seeked on demand. That matters: the debug directory sits near the *end* of both real samples
    (95%), so a caller holding only a head peek cannot reach it, and quietly returning "none"
    there would be a false negative on the most useful thing in the file.

    Returns the .pdb path recorded at build time, with the GUID and age that identify *which* .pdb
    it was. Those two values make it possible to say whether a .pdb found beside the binary is the
    one it was built with, rather than one that merely shares a name.
    """
    ddir = (pe.get("directories") or {}).get("debug")
    if not ddir:
        return None
    file_off = rva_to_offset(pe, ddir["rva"])
    if file_off is None:
        return None
    entries, pdb = [], None
    for i in range(min(ddir["size"] // 28, 64)):
        base = file_off + i * 28
        raw = read(base, 28)
        if len(raw) < 28:
            break
        (characteristics, timestamp, major, minor, dtype,
         size_of_data, _addr, pointer) = struct.unpack("<IIHHIIII", raw)
        entry = {"type": dtype, "size": size_of_data, "timestamp": timestamp}
        # type 2 is IMAGE_DEBUG_TYPE_CODEVIEW; the payload is at `pointer`, a file offset.
        if dtype == 2 and pointer and size_of_data:
            rec = read(pointer, min(size_of_data, 4096))
            if rec[:4] == b"RSDS" and len(rec) >= 24:
                guid = rec[4:20]
                age, = struct.unpack_from("<I", rec, 20)
                path = rec[24:].split(b"\x00", 1)[0].decode("utf-8", "replace")
                entry["codeview"] = {
                    "format": "RSDS",
                    "guid": "%s-%s-%s-%s-%s" % (guid[0:4].hex(), guid[4:6].hex(),
                                                guid[6:8].hex(), guid[8:10].hex(),
                                                guid[10:16].hex()),
                    "age": age,
                    "pdb_path": path,
                    "pdb_name": path.replace("/", "\\").rsplit("\\", 1)[-1] if path else "",
                }
                if pdb is None:
                    pdb = entry["codeview"]
            elif rec[:4] == b"NB10" and len(rec) >= 16:
                path = rec[16:].split(b"\x00", 1)[0].decode("utf-8", "replace")
                entry["codeview"] = {"format": "NB10", "pdb_path": path,
                                     "pdb_name": path.replace("/", "\\").rsplit("\\", 1)[-1]}
                if pdb is None:
                    pdb = entry["codeview"]
        entries.append(entry)
    if not entries:
        return None
    return {"entries": entries, "pdb": pdb}


def parse_msf(blob: bytes) -> dict | None:
    """Read the MSF superblock and stream directory -- the container, as the structure it is."""
    if not blob.startswith(MSF_MAGIC) or len(blob) < 64:
        return None
    try:
        (block_size, _free_block, num_blocks, num_dir_bytes,
         _unknown, block_map) = struct.unpack_from("<IIIIII", blob, 32)
        if block_size not in (512, 1024, 2048, 4096) or num_blocks <= 0:
            return None
        num_dir_blocks = (num_dir_bytes + block_size - 1) // block_size
        map_off = block_map * block_size
        if map_off + num_dir_blocks * 4 > len(blob):
            return None
        dir_blocks = [struct.unpack_from("<I", blob, map_off + i * 4)[0]
                      for i in range(num_dir_blocks)]
        directory = b"".join(blob[b * block_size:(b + 1) * block_size]
                             for b in dir_blocks)[:num_dir_bytes]
        if len(directory) < 4:
            return None
        count, = struct.unpack_from("<I", directory, 0)
        # A directory claiming more streams than could possibly fit is corrupt, not interesting.
        if count > 200000 or count * 8 > len(directory):
            return None
        off, streams = 4, []
        for _ in range(count):
            if off + 8 > len(directory):
                break
            _ver, size = struct.unpack_from("<II", directory, off)
            off += 8
            n = (size + block_size - 1) // block_size
            if off + n * 4 > len(directory):
                break
            blocks = list(struct.unpack_from("<%dI" % n, directory, off))
            off += n * 4
            streams.append({"size": size, "blocks": blocks})
    except (struct.error, IndexError, MemoryError):
        return None
    return {"block_size": block_size, "num_blocks": num_blocks, "streams": streams,
            "format": "msf-native-pdb"}


def msf_stream(blob: bytes, msf: dict, index: int, limit: int = 4 << 20) -> bytes:
    """One stream's bytes, capped so a corrupt directory cannot ask for the whole file."""
    if index < 0 or index >= len(msf["streams"]):
        return b""
    st = msf["streams"][index]
    bs = msf["block_size"]
    want = min(st["size"], limit)
    out, got = [], 0
    for b in st["blocks"]:
        if got >= want:
            break
        chunk = blob[b * bs:(b + 1) * bs][:want - got]
        out.append(chunk)
        got += len(chunk)
    return b"".join(out)


def extract_pdb_identifiers(blob: bytes, msf: dict, *, limit: int = 500) -> dict:
    """Source paths and identifier-shaped names recoverable from the symbol streams.

    Extraction, not interpretation. These are strings that look like the things they are, taken
    from streams whose record format this code does not claim to read. The report says so, because
    a caller deciding whether to trust a name deserves to know how it was obtained.
    """
    paths, namespaces, types, methods = set(), set(), set(), set()
    # Stream 1 is the PDB info stream; the rest carry symbol records.
    for i in range(1, len(msf["streams"])):
        if len(types) > limit and len(paths) > limit:
            break
        chunk = msf_stream(blob, msf, i, limit=2 << 20)
        if not chunk:
            continue
        for m in _RE_SOURCE_PATH.finditer(chunk):
            paths.add(m.group(0).decode("utf-8", "replace"))
        for m in _RE_REL_SOURCE.finditer(chunk):
            paths.add(m.group(0).decode("utf-8", "replace"))
        for m in _RE_NAMESPACE.finditer(chunk):
            namespaces.add(m.group(1).decode("utf-8", "replace"))
        for m in _RE_TYPE_NAME.finditer(chunk):
            word = m.group(0).decode("utf-8", "replace")
            if word.split(".", 1)[0] in _PDB_STOPWORDS:
                continue
            if "." in word:
                owner, method = word.rsplit(".", 1)
                types.add(owner.split(".")[-1])
                if len(method) > 3 and method not in _PDB_STOPWORDS:
                    methods.add(method)
            elif len(word) > 3:
                types.add(word)
    return {"source_paths": sorted(paths), "namespaces": sorted(namespaces),
            "type_names": sorted(types), "method_names": sorted(methods)}


_PDB_INFO_VERSION = 20000404


def _find_pdb_info_stream(blob: bytes):
    """Locate the PDB information stream by its own marker, and return what it holds.

    The stream directory is not trusted for this. On a real PDB it resolved every stream to the
    same wrong block, which did not stop a GUID-shaped value from being produced -- and a wrong
    GUID turns "this .pdb is the one this binary was built with" into a confident denial. So the
    stream is found by the marker it must begin with, and its shape is checked before use.
    """
    needle = struct.pack("<I", _PDB_INFO_VERSION)
    start = 0
    while True:
        idx = blob.find(needle, start)
        if idx < 0:
            return None
        if idx + 28 <= len(blob):
            ver, sig, age = struct.unpack_from("<III", blob, idx)
            guid = blob[idx + 12:idx + 28]
            # Age is a small counter; a plausible value plus a non-empty GUID is the shape.
            if ver == _PDB_INFO_VERSION and 0 < age < 100000 and guid != bytes(16):
                return ver, sig, age, guid
        start = idx + 4


def read_pdb(path) -> dict:
    """Container format, and for the container that can be read, what is recoverable from it.

    A Portable PDB is recognised and reported but **not** parsed: it is a different container
    (ECMA-335 metadata) and a second reader is not something to guess at.
    """
    p = Path(path)
    try:
        if p.stat().st_size > (256 << 20):
            return {"path": str(p), "name": p.name, "format": "too large to read",
                    "readable": False}
        blob = p.read_bytes()
    except OSError as exc:
        return {"path": str(p), "name": p.name, "format": "unreadable", "readable": False,
                "reason": str(exc)}

    out = {"path": str(p), "name": p.name, "size": len(blob), "readable": False}
    if blob.startswith(MSF_MAGIC):
        out["format"] = "msf-native-pdb"
        msf = parse_msf(blob)
        if msf is None:
            # The container itself did not hold up, so nothing inside it is claimed. Say that,
            # rather than letting a caller read an absent field as "there was nothing to find".
            out["reason"] = "the superblock or stream directory is malformed"
            out["info_stream"] = "not located: the MSF stream directory could not be read"
            return out
        out["readable"] = True
        out["stream_count"] = len(msf["streams"])

        # The PDB information stream identifies itself: it begins with Version == 20000404. That
        # is a check the directory cannot provide, and without it a wrong block number yields a
        # GUID-shaped value that is not a GUID -- which produced a confident "this .pdb does not
        # match the binary" on a .pdb that did. A false mismatch is worse than no answer, so the
        # stream is validated before anything is read out of it, and failure is reported as
        # unknown rather than as a result.
        info = _find_pdb_info_stream(blob)
        if info is None:
            out["guid"] = None
            out["info_stream"] = "not located: no stream begins with the PDB version marker"
        else:
            ver, sig, age, guid = info
            out["guid"] = "%s-%s-%s-%s-%s" % (guid[0:4].hex(), guid[4:6].hex(),
                                           guid[6:8].hex(), guid[8:10].hex(),
                                           guid[10:16].hex())
            out["age"] = age
            out["signature"] = "%#x" % sig
        out["identifiers_are"] = "extracted from stream bytes, not parsed from symbol records"
        out.update(extract_pdb_identifiers(blob, msf))
        return out
    if blob[:4] == b"BSJB":
        out["format"] = "portable-pdb"
        out["reason"] = ("ECMA-335 metadata rather than the native MSF container, so it is not "
                         "parsed here. Its #Strings heap holds type and method names in plain "
                         "text and is readable with a metadata reader.")
        return out
    out["format"] = "unknown"
    return out


def find_sibling_pdb(target) -> Path | None:
    """A .pdb beside the binary. That is the one that shipped, which is the disclosure."""
    t = Path(target)
    for candidate in (t.with_suffix(".pdb"), t.with_suffix(".PDB")):
        if candidate.is_file():
            return candidate
    return None


def analyse_debug_info(data_or_path, pe: dict | None = None, target=None) -> dict:
    """Everything recoverable about how this binary was built.

    Reads the PE debug directory, then a .pdb beside it, and says whether the two belong together.
    A .pdb whose GUID does not match the binary's CodeView record is **not its PDB**, and reporting
    names out of it as though it were would be a quiet lie -- so the match is recorded, and `None`
    means it could not be established rather than that it failed.

    Call it with a path. That form seeks instead of loading, because the debug directory of both
    real samples sat at **95% of the file** -- past any head peek a caller might reasonably have
    taken -- and a truncated head would have produced a silent "no debug information" rather than
    an error. The bytes form is kept for a caller that already has the whole file.
    """
    if target is None and not isinstance(data_or_path, (bytes, bytearray)):
        target = data_or_path
    t = Path(target) if target is not None else None

    if isinstance(data_or_path, (bytes, bytearray)):
        if pe is None:
            return {"available": False, "reason": "no PE to read a debug directory from"}
        full = bytes(data_or_path)
        size = len(full)
        read = lambda off, n: full[off:off + n]        # noqa: E731
        complete = True
    else:
        if t is None or not t.is_file():
            return {"available": False, "reason": "not a file"}
        try:
            size = t.stat().st_size
        except OSError as exc:
            return {"available": False, "reason": str(exc)}
        if pe is None:
            # Only the headers are needed to learn where the directory is.
            with open(t, "rb") as fh:
                pe = parse_pe(fh.read(min(size, 1 << 20)))
            if pe is None:
                return {"available": False, "reason": "not a PE"}
        complete = True

        def read(off, n):
            if off is None or off < 0 or off >= size:
                return b""
            with open(t, "rb") as fh:
                fh.seek(off)
                return fh.read(min(n, size - off))

    if pe is None:
        return {"available": False}

    dbg = parse_debug_directory(read, pe)
    if dbg is None:
        return {"available": False}

    out = {"available": True, "executed": False, "directory_entries": len(dbg["entries"]),
           "types": sorted({_DEBUG_TYPE_NAMES.get(e["type"], str(e["type"]))
                            for e in dbg["entries"]})}
    cv = dbg["pdb"]
    if cv:
        out["codeview"] = cv
        # The path alone is the prize: project name, source layout, build configuration -- and it
        # is in the binary whether or not the .pdb was ever distributed.
        path = cv.get("pdb_path") or ""
        if path:
            out["build_pdb_path"] = path
            out["build_machine_dirs"] = [p for p in path.replace("/", "\\").split("\\")[:-1]
                                         if p][:12]

    sibling = find_sibling_pdb(t) if t is not None else None
    if sibling is None:
        out["sibling_pdb"] = None
        return out

    pdb = read_pdb(sibling)
    out["sibling_pdb"] = pdb
    if cv and cv.get("guid") and pdb.get("guid"):
        out["pdb_matches_binary"] = cv["guid"].lower() == pdb["guid"].lower()
    else:
        out["pdb_matches_binary"] = None
    return out


_DEBUG_TYPE_NAMES = {
    0: "unknown", 1: "coff", 2: "codeview", 3: "fpo", 4: "misc", 5: "exception",
    6: "fixup", 7: "omap_to_src", 8: "omap_from_src", 9: "borland", 10: "reserved10",
    11: "clsid", 12: "vc_feature", 13: "pogo", 14: "iltcg", 16: "repro",
    17: "embedded_portable_pdb", 19: "pdb_checksum", 20: "ex_dllcharacteristics",
}


def detect_pyinstaller_at(path: Path) -> dict | None:
    """Wrapper detection for a file, reading the end of it rather than the beginning.

    A CArchive cookie is the last occurrence of `MEI\014\013\012\013\016` in the file, so the tail
    is where to look. Reading only a head works for a small file and silently fails for a large one,
    which is how a nested 8.5 MB wrapper went unnoticed: the head is 4 MB and the cookie is not in
    it. `detect_pyinstaller` is unchanged and correct given a complete buffer.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return None
    # Enough to hold the cookie and the table it points at; a cookie needs only its own 88 bytes,
    # but the reader that follows wants the payload length and TOC offset to be plausible.
    window = min(size, 8 << 20)
    try:
        with open(path, "rb") as fh:
            fh.seek(size - window)
            tail = fh.read(window)
    except OSError:
        return None
    found = detect_pyinstaller(tail)
    if found is None:
        return None
    # The offsets are relative to the archive's base, which the tail may not contain; that is
    # fine here because only the presence and the Python version are wanted.
    return found


# --------------------------------------------------------------------------- #

MEI_COOKIE = b"MEI\x0c\x0b\x0a\x0b\x0e"
PYZ_MAGIC = b"PYZ\0"


def detect_pyinstaller(data: bytes) -> dict | None:
    """A PyInstaller onefile ends with an 88-byte CArchive cookie.

    Detection is `rfind` of the cookie magic, not an entropy heuristic: a cookie is
    either the last occurrence of those eight bytes or it is not, which is a fact
    rather than a guess.
    """
    pos = data.rfind(MEI_COOKIE)
    if pos < 0 or pos + 88 > len(data):
        return None
    try:
        _magic, pkg_len, toc_off, toc_len, pyver, raw_lib = struct.unpack(
            "!8sIIII64s", data[pos:pos + 88])
    except struct.error:
        return None
    pylib = raw_lib.split(b"\x00", 1)[0].decode("latin1", "replace")
    if not (0 < toc_len <= pkg_len):
        return None
    return {
        "wrapper": "PyInstaller",
        "python_version": "%d.%d" % divmod(pyver, 100),
        "python_library": pylib,
        "archive_length": pkg_len,
        "toc_entries_length": toc_len,
        "has_pyz": data.rfind(PYZ_MAGIC) > 0,
        "note": "unpack with nanodesu.py (extract / verify / pyz); no execution needed",
    }


# Language runtimes that are worth naming, because language changes how a binary must be
# analysed. Rust in particular is on the rise in malware precisely because its binaries are
# harder to read: symbols are mangled, the runtime is large, and strings are scattered.
# All of this is detectable statically, without running anything.
RUNTIME_MARKERS = (
    ("Rust", (
        b"rustc", b"core::panicking", b"RUST_BACKTRACE", b"/rustc/", b"library/std/src",
        b"rust_begin_unwind", b"__rust_alloc", b".rustc",
    )),
    ("Go", (
        b"Go build ID", b"go1.", b"runtime.gopanic", b"golang.org/", b"go.buildid",
        b"runtime.main", b"GOROOT",
    )),
    # .NET is decided structurally, by the COM descriptor directory, not by this table.
    # Scanning for a four-byte marker produced false positives on ordinary Win32 libraries.
    ("AutoIt", (b"AutoIt", b"AU3!EA06")),
    ("Python-frozen", (b"_MEIPASS", b"PyInstaller", b"PYZ" + bytes(1), b"pyi-")),
    ("Delphi/Pascal", (b"Borland", b"Embarcadero", b"System.pas")),
    ("Nim", (b"NimMain", b"nimFrame", b"nim_program_result")),
    ("Electron/Node", (b"node.exe", b"electron", b"v8::internal")),
)


def is_dotnet(pe: dict | None, data: bytes) -> dict | None:
    """Decide .NET structurally: the COM descriptor directory must point at CLR metadata.

    Not by scanning for the four-byte BSJB signature -- that appears by chance inside large
    Win32 binaries, and keying on it reported kernel32.dll as .NET. The metadata root is
    supposed to start with BSJB followed by a plausible header length, and it is supposed to
    be where the directory says it is.
    """
    if not pe:
        return None
    d = (pe.get("directories") or {}).get("com_descriptor")
    if not d:
        return None
    # The COM descriptor points at the CLI header, not at the metadata. Verified against a
    # real assembly: CLI header at the directory RVA (cb=72, runtime 2.5), whose +8 field is
    # the metadata RVA, whose target begins with BSJB. Skipping this hop is why a genuine
    # .NET build was not recognised while a chance BSJB in kernel32.dll was.
    cli_off = rva_to_offset(pe, d["rva"])
    if cli_off is None or cli_off + 16 > len(data):
        return None
    try:
        cb, runtime_major, runtime_minor = struct.unpack_from("<IHH", data, cli_off)
        md_rva, _md_size = struct.unpack_from("<II", data, cli_off + 8)
    except struct.error:
        return None
    if not (0 < cb <= 256) or not md_rva:
        return None
    md_off = rva_to_offset(pe, md_rva)
    if md_off is None or md_off + 20 > len(data):
        return None
    if data[md_off:md_off + 4] != b"BSJB":
        return None
    try:
        meta_major, meta_minor = struct.unpack_from("<HH", data, md_off + 4)
        version_len = struct.unpack_from("<I", data, md_off + 12)[0]
    except struct.error:
        return None
    if not (0 < version_len <= 256):
        return None
    version = data[md_off + 16:md_off + 16 + version_len].split(bytes(1), 1)[0]
    version_text = version.decode("latin1", "replace").strip() or "unknown"
    return {"language": "C#/.NET",
            "markers": ["COM descriptor -> CLI header -> BSJB",
                        "runtime %d.%d" % (runtime_major, runtime_minor),
                        "metadata %s" % version_text],
            "count": 3}



def detect_language(data: bytes, limit: int = 6 << 20, pe: dict | None = None) -> dict:
    """Name the language runtime when the evidence is there.

    This is a pointer for the analyst, not a claim: "Rust" says the binary was built with
    rustc, which changes which tooling is worth reaching for.
    """
    head = data[:limit]
    hits = []
    for lang, markers in RUNTIME_MARKERS:
        found = [m.decode("latin1", "replace") for m in markers if m in head]
        if not found:
            continue
        # A single weak reference is not identification. .NET in particular needs its
        # metadata signature, not just a mention of the CLR shim.

        hits.append({"language": lang, "markers": found[:6], "count": len(found)})
    net = is_dotnet(pe, data)
    if net:
        hits.append(net)
    hits.sort(key=lambda h: -h["count"])
    return {
        "likely": hits[0]["language"] if hits else None,
        "all": hits,
        # A Rust or Go binary with no symbol names left is worth flagging: stripping is
        # normal, but it also removes the analyst's best tool.
        "symbols_stripped_hint": bool(
            hits and hits[0]["language"] in ("Rust", "Go")
            and b"rust_begin_unwind" not in head and b"runtime.main" not in head),
    }


def detect_other_wrappers(data: bytes) -> list:
    """Wrappers we can only *name*. Naming one is useful; pretending to unpack it is not."""
    out = []
    checks = [
        (b"PYZ\0", "PyInstaller PYZ archive"),
        (b"pyi-", "PyInstaller runtime bits"),
        (b"NullsoftInst", "NSIS installer (needs its own extractor)"),
        (b"Nullsoft", "NSIS installer (needs its own extractor)"),
        (b"Inno Setup", "Inno Setup installer (needs innoextract)"),
        (b"WinRAR SFX", "WinRAR self-extracting archive"),
        (b"7-Zip SFX", "7-Zip self-extracting archive"),
        (b"python-", "possible PyInstaller/embedded CPython"),
        (b"nuitka", "Nuitka-compiled python"),
        (b"_MEIPASS", "PyInstaller runtime marker"),
        (b"installshield", "InstallShield installer"),
        (b"AutoIt", "AutoIt script"),
        (b"AutoHotkey", "AutoHotkey script"),
        (b"py2exe", "py2exe bundle"),
    ]
    low = data.lower()
    for marker, label in checks:
        if marker.lower() in low:
            out.append(label)
    return sorted(set(out))


# --------------------------------------------------------------------------- #
# indicators
# --------------------------------------------------------------------------- #

IOC_PATTERNS = [
    ("url", re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,200}")),
    ("ipv4", re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("domain", re.compile(rb"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                          rb"(?:com|net|org|ru|cn|top|xyz|info|biz|io|me|onion|su|pw)\b")),
    ("email", re.compile(rb"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("registry_run", re.compile(rb"(?:SOFTWARE\\)?Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce)")),
    ("registry_path", re.compile(rb"\bHK(?:LM|CU|CR|U|EY_[A-Z_]+)\\[ -~]{4,120}")),
    ("scheduled_task", re.compile(rb"schtasks(?:\.exe)?[ -~]{0,80}", re.I)),
    ("powershell", re.compile(rb"powershell(?:\.exe)?[ -~]{0,120}", re.I)),
    ("cmd_shell", re.compile(rb"cmd(?:\.exe)?\s*/c[ -~]{0,80}", re.I)),
    ("service_install", re.compile(rb"(?:sc|net)\s+(?:create|start|stop)\s+[A-Za-z0-9_.-]{2,40}", re.I)),
    ("named_pipe", re.compile(rb"\\\\\.\\pipe\\[A-Za-z0-9_.-]{2,60}")),
    ("mutex_like", re.compile(rb"(?:Global|Local)\\[A-Za-z0-9_.{}() -]{4,60}")),
    ("user_agent", re.compile(rb"Mozilla/[45]\.0[ -~]{0,80}")),
    ("defender_exclusion", re.compile(rb"(?:Add-MpPreference|ExclusionPath)[ -~]{0,60}", re.I)),
    ("dns_query", re.compile(rb"(?:DnsQuery|getaddrinfo|gethostbyname)[ -~]{0,20}")),
]

NOISE_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.0.0.0"}
# Well-known documentation and schema hosts. Reporting these as indicators is noise:
# every MSVC binary carries the same XML namespace URLs.
NOISE_DOMAINS = (
    "schemas.microsoft.com", "schemas.openxmlformats.org", "schemas.xmlsoap.org",
    "www.w3.org", "example.com", "example.org", "localhost", "microsoft.com",
    "verisign.com", "digicert.com", "globalsign.com", "sectigo.com", "thawte.com",
    "windowsupdate.com", "msftconnecttest.com", "msftncsi.com",
)
NOISE_URL_PREFIXES = ("http://schemas.", "https://schemas.", "http://www.w3.org/")


def extract_iocs(data: bytes, limit: int = 400) -> dict:
    out = {}
    for kind, pat in IOC_PATTERNS:
        seen, vals = set(), []
        for m in pat.finditer(data):
            # A .NET assembly is full of version strings shaped exactly like IPv4 literals:
            # "mscorlib, Version=4.0.0.0" produced five indicator hits on a managed sample whose
            # real network surface is unrelated. The tell is the word before it.
            if kind == "ipv4":
                before = data[max(0, m.start() - 14):m.start()].lower()
                if b"version" in before:
                    continue
            v = m.group(0).decode("latin1", "replace").strip()
            if not v or v in seen:
                continue
            if kind == "ipv4":
                parts = [int(x) for x in v.split(".")]
                if any(x > 255 for x in parts) or v in NOISE_IPS:
                    continue
                # Skip reserved and private ranges (RFC1918, loopback, link-local, multicast,
                # documentation). Note 6.0.0.0/8 is NOT reserved, so it is kept: a version
                # string that looks like an address is a false positive worth seeing rather
                # than one worth silently filtering.
                a, b = parts[0], parts[1]
                if a in (0, 10, 127, 224, 239, 255) or (a == 172 and 16 <= b <= 31)                         or (a == 192 and b == 168) or (a == 169 and b == 254)                         or (a == 203 and b == 0):
                    continue
            low = v.lower()
            if kind == "domain":
                if len(v) < 6 or any(low.endswith(d) for d in NOISE_DOMAINS):
                    continue
            if kind == "url":
                if any(low.startswith(pfx) for pfx in NOISE_URL_PREFIXES):
                    continue
                if any(("//" + d) in low for d in NOISE_DOMAINS):
                    continue
            if kind == "email" and any(low.endswith(d) for d in NOISE_DOMAINS):
                continue
            seen.add(v)
            vals.append(v)
            if len(vals) >= limit:
                break
        if vals:
            out[kind] = vals
    return out


def readable_regions(data: bytes, min_run: int = 24) -> bytes:
    """Keep only stretches that look like readable data, not code.

    Carving printable runs out of machine code produces import names and instruction
    fragments -- "CreateFileW" became a suspicious string because it contains "file". Those
    are noise, and worse than noise, because a file that imports nothing interesting then
    looks like it has a alarming string in it. A genuine string lives in a long readable run;
    code does not contain one.
    """
    out = bytearray()
    run = 0
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D):
            if run == 0:
                start = i
            run += 1
        else:
            if run >= min_run:
                out += data[start:i] + bytes([10])
            run = 0
    if run >= min_run:
        out += data[start:]
    return bytes(out)


def extract_strings(data: bytes, min_len: int = 6, limit: int = 300) -> dict:
    """ASCII and UTF-16LE runs. UTF-16 matters: a .NET or wide-char sample hides here."""
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    wide_re = re.compile((rb"(?:[\x20-\x7e]\x00){%d,}" % min_len))
    text = readable_regions(data)
    ascii_hits = [m.group(0).decode("latin1") for m in ascii_re.finditer(text)]
    wide_hits = [m.group(0).decode("utf-16-le", "replace") for m in wide_re.finditer(data)]
    interesting = [s for s in ascii_hits + wide_hits
                   if any(k in s.lower() for k in (
                       "http", "cmd", ".exe", ".dll", "temp\\", "appdata", "startup",
                       "password", "bitcoin", "wallet", "decrypt", "encrypt", "ransom",
                       "key", "token", "discord", "telegram", "bot", "steam", "cookie"))]
    return {"ascii_count": len(ascii_hits), "wide_count": len(wide_hits),
            "interesting": interesting[:limit]}


def find_embedded_executables(data: bytes, limit: int = 40) -> list:
    """Embedded PE images, found by header, not by hope."""
    out = []
    start = 0
    while len(out) < limit:
        i = data.find(b"MZ", start)
        if i < 0 or i + 0x40 > len(data):
            break
        start = i + 2
        try:
            pe_off = struct.unpack_from("<I", data, i + 0x3C)[0]
        except struct.error:
            continue
        if pe_off > 0x1000 or i + pe_off + 4 > len(data):
            continue
        if data[i + pe_off:i + pe_off + 4] != b"PE\x00\x00":
            continue
        if i == 0:
            continue                                   # this is the file's own header
        out.append({"offset": i,
                    "sha256_of_region": hashlib.sha256(data[i:i + 1 << 20]).hexdigest()[:32]})
    return out


def base64_candidates(strings: dict, limit: int = 25) -> list:
    """Long base64 blobs, most likely to be a config or a second stage."""
    pat = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    found, seen = [], set()
    for s in strings.get("interesting", []):
        for m in pat.finditer(s):
            v = m.group(0)
            if v in seen:
                continue
            seen.add(v)
            try:
                raw = base64.b64decode(v + "=" * (-len(v) % 4))
            except Exception:
                continue
            found.append({"length": len(v), "decoded_length": len(raw),
                          "decoded_preview": raw[:24].hex(),
                          "decoded_is_pe": raw[:2] == b"MZ"})
            if len(found) >= limit:
                return found
    return found


# --- inside-peek: triage the files a wrapper produced, without loading them whole ---- #

# Analysis limit for a single file. The whole file is loaded, so the guard is set where a
# normal analysis host has room: peak memory is roughly twice this. Tunable, with an explicit
# override for the case where the caller really does mean it.
DEFAULT_MAX_BYTES = 768 << 20

PEEK_BYTES = 4 << 20          # 4 MB of each inner file is enough to type it and read its PE header


def find_inner_executables(root: Path, limit: int = 40) -> list:
    """Executable files inside an unpacked tree, most interesting first.

    Only the head of each file is read: a 200 MB inner DLL does not need to be loaded to be typed
    and have its PE header parsed, and reading it whole would defeat the point of a tool that is
    supposed to be cheap to point at anything.

    The order is by interest rather than by name, which it used to be -- and that mattered: sorted
    by path, a real PyInstaller build fills this list with `binary___bz2.pyd` and its neighbours
    while a nested *executable* sitting in the same directory never appears, because 40 alphabetically
    early stdlib extensions crowd it out. The most interesting thing inside a wrapper is another
    wrapper, so size leads (a nested executable is megabytes; a stdlib extension is tens of
    kilobytes) and packed or strong-signal files come before plain ones.
    """
    out = []
    if not root.is_dir():
        return out
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in (".exe", ".dll", ".pyd", ".so", ".sys", ".scr", ".cpl",
                                    ".ocx", ".node", ".dylib", ".elf", ".bin"):
            continue
        try:
            with p.open("rb") as fh:
                head = fh.read(PEEK_BYTES)
            size = p.stat().st_size
        except OSError:
            continue
        if not head:
            continue
        kind = identify(head, p)
        pe = parse_pe(head) if kind["kind"] == "pe" else None
        if kind["kind"] != "pe" and p.suffix.lower() not in (".exe", ".dll", ".pyd", ".sys"):
            continue
        imports = parse_imports(head, pe) if pe else []
        packer = identify_packer(pe, head, imports) if pe else {"verdict": "n/a", "findings": []}
        out.append({
            "path": str(p.relative_to(root)),
            "size": size,
            "sha256_head": hashlib.sha256(head).hexdigest(),
            "kind": kind["kind"],
            "packer": packer["verdict"],
            "packer_findings": packer["findings"],
            "imports": sum(i["count"] for i in imports),
            "suspicious_imports": sorted({
                fn for i in imports for fn in i["functions"]
                if fn.lower() in STRONG_SIGNAL_IMPORTS}),
            "noted_imports": sorted({
                fn for i in imports for fn in i["functions"]
                if fn.lower() in SUSPICIOUS_IMPORTS and fn.lower() not in STRONG_SIGNAL_IMPORTS}),
            "entropy_max": max((s["entropy"] for s in (pe["sections"] if pe else [])), default=0.0),
            "truncated_head": size > PEEK_BYTES,
            # From the file's tail, because the cookie lives at the end and the head above does not
            # contain it for anything larger than PEEK_BYTES.
            "wrapper": (detect_pyinstaller_at(p) or {}).get("wrapper"),
        })
        # The inner files are the point of unpacking -- the wrapper was only the envelope -- so
        # each one gets the same debug treatment as a top-level sample. Driven from the path, not
        # the head: the debug directory of both real samples sat at 95% of the file, well past
        # PEEK_BYTES, so a head-based read would have reported "no debug information" for files
        # that carry it. That is the false negative this must not produce.
        if pe:
            info = analyse_debug_info(p, pe)
            if info.get("available"):
                out[-1]["debug_info"] = {
                    "codeview_pdb_name": (info.get("codeview") or {}).get("pdb_name"),
                    "build_pdb_path": info.get("build_pdb_path"),
                    "build_machine_dirs": info.get("build_machine_dirs"),
                    "sibling_pdb": (info.get("sibling_pdb") or {}).get("format"),
                    "pdb_matches_binary": info.get("pdb_matches_binary"),
                }
    # Rank before truncating, so the limit keeps the entries that matter instead of the ones that
    # happen to sort first.
    out.sort(key=lambda r: (
        -(1 if r.get("packer") not in ("none", "n/a") else 0),
        -(1 if r.get("suspicious_imports") else 0),
        -r["size"],
        r["path"],
    ))
    return out[:limit]


def scan_tree(root: Path, *, limit: int = 200, only=None) -> dict:
    """Torikago every file in a directory: the answer to 'which of these is worth my time?'.

    `only` restricts the walk to a set of lower-case extensions without the dot, which a corpus build
    needs: scanning a drive unfiltered mostly finds archives and images, and a manifest full of those
    says nothing about the detectors. Observed: 1,496 files with exactly *one* PE among them.
    """
    want = {e.lower().lstrip(".") for e in only} if only else None
    rows = []
    considered = 0
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        considered += 1
        if want is not None and p.suffix.lower().lstrip(".") not in want:
            continue
        try:
            with p.open("rb") as fh:
                head = fh.read(PEEK_BYTES)
        except OSError:
            continue
        if not head:
            continue
        kind = identify(head, p)
        pe = parse_pe(head) if kind["kind"] == "pe" else None
        imports = parse_imports(head, head and pe) if pe else []
        packer = identify_packer(pe, head, imports) if pe else {"verdict": "n/a", "findings": []}
        pyinstaller = detect_pyinstaller(head) if kind["kind"] == "pe" else None
        row = {
            "path": str(p.relative_to(root)),
            "size": p.stat().st_size,
            "kind": kind["kind"],
            "label": kind["label"],
            "mismatch": extension_mismatch(kind["kind"], p),
            "packer": packer["verdict"],
            "wrapper": pyinstaller["wrapper"] if pyinstaller else None,
            "entropy_max": max((s["entropy"] for s in (pe["sections"] if pe else [])), default=None),
            "suspicious_imports": sorted({
                fn for i in imports for fn in i["functions"]
                if fn.lower() in STRONG_SIGNAL_IMPORTS}),
            "noted_imports": sorted({
                fn for i in imports for fn in i["functions"]
                if fn.lower() in SUSPICIOUS_IMPORTS
                and fn.lower() not in STRONG_SIGNAL_IMPORTS}),
            # The full set, because the injection triad is judged on it rather than on the
            # strong/weak split: VirtualAlloc is ordinary on its own but is one third of the
            # pattern, so a tier-based check would miss the combination.
            "all_imports": sorted({fn for i in imports for fn in i["functions"]}),
            "note": None,
        }
        reasons = []
        if row["mismatch"]:
            reasons.append(row["mismatch"])
        if row["packer"] not in ("none", "n/a"):
            reasons.append("packed: %s" % row["packer"])
        # The injection triad is the single most meaningful import signal there is: memory
        # allocation plus a write into another process plus a remote thread. Weak signals
        # such as IsDebuggerPresent are recorded but do not raise attention on their own,
        # because CPython's own extension modules import it (sys.gettrace uses it).
        all_imports_lower = {f.lower() for f in (row.get("all_imports") or [])}
        if {"virtualalloc", "writeprocessmemory", "createremotethread"} <= all_imports_lower:
            reasons.append("injection triad (VirtualAlloc + WriteProcessMemory + CreateRemoteThread)")
        elif row["suspicious_imports"]:
            reasons.append("imports: " + ", ".join(row["suspicious_imports"][:4]))
        if row["entropy_max"] and row["entropy_max"] >= HIGH_ENTROPY and pe and any(
                s["executable"] and s["entropy"] >= HIGH_ENTROPY for s in pe["sections"]):
            reasons.append("high-entropy executable section")
        row["note"] = "; ".join(reasons)
        row["attention"] = len(reasons)
        rows.append(row)
        if len(rows) >= limit:
            break
    rows.sort(key=lambda r: (-r["attention"], -r["size"]))
    return {"root": str(root), "scanned": len(rows),
            "interesting": sum(1 for r in rows if r["attention"]), "rows": rows}


def print_tree_report(report: dict, verbose: bool = False) -> None:
    print("scanned     : %d files under %s" % (report["scanned"], report["root"]))
    print("interesting : %d" % report["interesting"])
    print()
    interesting = [r for r in report["rows"] if r["attention"]]
    shown = interesting if interesting or verbose else []
    if not shown:
        print("  nothing flagged")
    for r in shown:
        print("  [%d] %-52s %9d B  %s" % (r["attention"], r["path"], r["size"], r["kind"]))
        if r["note"]:
            print("        %s" % r["note"])
    if interesting:
        print()
        print("  full list of flagged files is in report.json")


# --------------------------------------------------------------------------- #
# handing the evidence to something that decides
# --------------------------------------------------------------------------- #
#
# The division of labour this file exists to serve: this tool unpacks and reports, and
# something with maintained signatures makes the call. Two targets cover most of the
# world -- ClamAV for a verdict on the files, MISP for the indicators worth sharing.
#
# Both are read-only, and neither executes the target: a scanner reading a file is not the
# same thing as the file running. That distinction is what lets the safety guarantee of
# "never execute" survive integration.

CLAMAV_CANDIDATES = (
    r"C:\Program Files\ClamAV\clamscan.exe",
    r"C:\Program Files (x86)\ClamAV\clamscan.exe",
    "/usr/bin/clamscan",
    "/usr/local/bin/clamscan",
)


DEFENDER_PLATFORM_DIR = Path(r"C:\ProgramData\Microsoft\Windows Defender\Platform")


def find_defender() -> str | None:
    """Locate MpCmdRun.exe, newest platform build first, or None.

    Absence is reported rather than worked around, the same rule as ClamAV: on a machine where
    Defender has been removed or disabled there is nothing to ask, and pretending otherwise would
    be worse than saying so.
    """
    env = os.environ.get("MPCMDRUN_PATH")
    if env and Path(env).is_file():
        return env
    if not DEFENDER_PLATFORM_DIR.is_dir():
        return None
    # Platform builds are version-named directories and only one is current; the newest is the one
    # whose engine the service is using.
    builds = sorted((d for d in DEFENDER_PLATFORM_DIR.iterdir() if d.is_dir()),
                    key=lambda d: d.name, reverse=True)
    for build in builds:
        exe = build / "MpCmdRun.exe"
        if exe.is_file():
            return str(exe)
    return None


def defender_owner() -> dict:
    """Which antivirus products Windows Security Center has registered.

    Exists because "Defender found nothing" is only meaningful if Defender is the engine doing the
    watching. Where a third-party product owns the registration, Defender's engine can still run a
    scan while real-time protection is somebody else's -- so the answer is reported rather than
    assumed, and never smoothed over.
    """
    if os.name != "nt":
        return {"available": False, "reason": "not Windows"}
    import subprocess
    try:
        proc = subprocess.run(
            # The console output encoding is forced to UTF-8 first. Without it PowerShell emits
            # product names in the system code page -- cp936 on a Chinese Windows -- and reading
            # them as UTF-8 turns "Tencent PC Manager" into mojibake. Product names are exactly
            # the thing being asked for here, so getting them wrong is getting the answer wrong.
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
             "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
             "Select-Object -ExpandProperty displayName"],
            capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "reason": "could not query Security Center: %s" % exc}
    names = [l.strip() for l in proc.stdout.decode("utf-8", "replace").splitlines() if l.strip()]
    return {"available": True, "products": names,
            "third_party": [n for n in names if "defender" not in n.lower()]}


def scan_with_defender(paths, *, mpcmdrun: str | None = None, timeout: int = 900) -> dict:
    """Ask Windows Defender for a verdict on `paths`. Reads the files; runs nothing.

    **`-DisableRemediation` is load-bearing.** Without it this call removes or quarantines whatever
    it dislikes, so asking for an opinion would silently destroy the thing being asked about. With
    it, the call is a question.
    """
    exe = mpcmdrun or find_defender()
    if not exe:
        return {"ok": False, "engine": "windows-defender", "executed": False,
                "reason": "MpCmdRun.exe was not found; Defender may not be installed",
                "hint": "set MPCMDRUN_PATH to a specific MpCmdRun.exe"}
    import subprocess
    targets = [(p if isinstance(p, Path) else Path(p)) for p in paths]
    verdicts, errors = [], []
    for target in targets:
        cmd = [exe, "-Scan", "-ScanType", "3", "-File", str(target), "-DisableRemediation"]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append({"file": target.name, "error": str(exc)})
            continue
        out = (proc.stdout or b"").decode("utf-8", "replace")
        err = (proc.stderr or b"").decode("utf-8", "replace")
        text = out + err
        # `-DisableRemediation` also stops the exit code from carrying the verdict, so the verdict
        # has to come from the text. "found no threats" is the clean answer; anything else that
        # mentions a threat is treated as one, and the raw line is kept so the reading can be
        # checked rather than trusted.
        clean = "found no threats" in text.lower()
        line = next((l.strip() for l in text.splitlines()
                     if "threat" in l.lower()), "")
        verdicts.append({
            "file": target.name,
            "path": str(target),
            "clean": clean,
            "line": line or None,
            "returncode": proc.returncode,
        })
    # `ok` means a verdict was actually obtained, matching scan_with_clamav. Returning ok=True with
    # an empty verdict list because the engine path was wrong would read as "it found nothing" --
    # the single most dangerous way this function can fail, since the reader concludes the file is
    # clean when in fact nobody looked at it.
    if not verdicts:
        return {"ok": False, "engine": "windows-defender", "executed": False,
                "reason": ("no verdict was obtained from %s" % exe),
                "errors": errors, "verdicts": [], "owner": defender_owner()}
    return {"ok": True, "engine": "windows-defender", "executed": False,
            "remediation_disabled": True, "verdicts": verdicts, "errors": errors,
            "owner": defender_owner(),
            # Said every time, because the temptation to read this as our own conclusion is the
            # whole risk of having it.
            "note": ("This is Defender's verdict, not this tool's. Torikago reaches no conclusion "
                     "about whether a file is malicious, and nothing here is a detection.")}


def find_clamav() -> str | None:
    """Locate clamscan, or None. Absence is reported, never worked around."""
    env = os.environ.get("CLAMSCAN_PATH")
    if env and Path(env).is_file():
        return env
    for cand in CLAMAV_CANDIDATES:
        if Path(cand).is_file():
            return cand
    import shutil
    return shutil.which("clamscan")


def scan_with_clamav(paths, *, clamscan: str | None = None, timeout: int = 900) -> dict:
    """Run clamscan over the given files and return its verdicts.

    A signature engine reading the files is not execution; nothing here starts the sample.
    """
    exe = clamscan or find_clamav()
    if not exe:
        return {
            "ok": False,
            "available": False,
            "executed": False,
            "reason": "clamscan was not found; install ClamAV or set CLAMSCAN_PATH",
            "install": "https://www.clamav.net/",
        }
    files = [str(p) for p in paths if Path(p).is_file()]
    if not files:
        return {"ok": True, "available": True, "executed": False, "scanned": 0,
                "infected": 0, "verdicts": [], "reason": "nothing to scan"}

    import subprocess
    cmd = [exe, "--no-summary", "--infected", "--stdout"] + files
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "available": True, "executed": False,
                "reason": "clamscan timed out after %ds" % timeout}
    except OSError as exc:
        return {"ok": False, "available": True, "executed": False,
                "reason": "could not run clamscan: %s" % exc}

    # Only accept a verdict whose file part is one of the files we asked about. ClamAV's
    # line is "<path>: <signature> FOUND", and a Windows path contains colons of its own, so
    # splitting on the last colon is right -- but matching against the known set is what
    # makes it safe against a stray line that merely ends in FOUND.
    known = {str(Path(f).resolve()).lower(): str(f) for f in files}
    verdicts = []
    for line in (proc.stdout or "").splitlines():
        line = line.rstrip()
        if not line.endswith("FOUND") or ":" not in line:
            continue
        head, _, sig = line.rpartition(":")
        candidate = head.strip()
        matched = known.get(str(Path(candidate).resolve()).lower())
        if matched is None:
            base = Path(candidate).name.lower()
            matched = next((orig for key, orig in known.items()
                            if Path(key).name == base), None)
        if matched is None:
            continue
        verdicts.append({"file": matched,
                         "signature": sig.replace("FOUND", "").strip()})
    return {
        "ok": True,
        "available": True,
        "executed": False,
        "clamscan": exe,
        "scanned": len(files),
        "infected": len(verdicts),
        "verdicts": verdicts,
        "reason": None,
    }


# --- MISP ------------------------------------------------------------------ #

MISP_TYPE_FOR = {
    "url": "url",
    "domain": "domain",
    "ipv4": "ip-dst",
    "email": "email-src",
    "registry_path": "regkey",
    "registry_run": "regkey",
    "named_pipe": "text",
    "scheduled_task": "text",
    "powershell": "text",
    "cmd_shell": "text",
    "service_install": "text",
    "defender_exclusion": "text",
    "mutex_like": "text",
    "user_agent": "user-agent",
    "dns_query": "text",
}

def build_misp_event(report: dict, *, info: str | None = None, distribution: int = 0,
                     threat_level: int = 2, analysis: int = 1) -> str:
    """A MISP event as XML, so the indicators can actually be shared.

    XML rather than JSON because it is what MISP itself produces for an event: a JSON blob
    that merely resembles one tends to import as an empty event and waste an analyst's time.

    published=false on purpose -- whether this becomes shared intelligence is a human
    decision about their own data, not something a triage tool should assume.
    """
    import xml.etree.ElementTree as ET

    h = report["hashes"]
    # No namespace declaration: MISP's own importer keys off the element names, and
    # ElementTree cannot emit a prefixed namespace attribute cleanly (it mangles the
    # declaration and leaves the tag unreachable by that name).
    root = ET.Element("misp")
    event = ET.SubElement(root, "Event")
    ET.SubElement(event, "info").text = info or (
        "Static triage: %s" % Path(report["file"]).name)
    ET.SubElement(event, "date").text = time.strftime("%Y-%m-%d")
    ET.SubElement(event, "threat_level_id").text = str(threat_level)
    ET.SubElement(event, "analysis").text = str(analysis)
    ET.SubElement(event, "distribution").text = str(distribution)
    ET.SubElement(event, "published").text = "false"

    def add_attr(etype, value, category, to_ids=False):
        if value is None or value == "":
            return
        a = ET.SubElement(event, "Attribute")
        ET.SubElement(a, "type").text = etype
        ET.SubElement(a, "category").text = category
        ET.SubElement(a, "to_ids").text = "true" if to_ids else "false"
        ET.SubElement(a, "distribution").text = str(distribution)
        ET.SubElement(a, "value").text = str(value)

    add_attr("sha256", h["sha256"], "Payload delivery", True)
    add_attr("sha1", h["sha1"], "Payload delivery", True)
    add_attr("md5", h["md5"], "Payload delivery", True)
    add_attr("filename", Path(report["file"]).name, "Payload delivery")
    add_attr("size-in-bytes", h["size"], "Other")

    for kind, values in (report.get("iocs") or {}).items():
        etype = MISP_TYPE_FOR.get(kind)
        if not etype:
            continue
        network = kind in ("url", "domain", "ipv4", "user_agent")
        category = "Network activity" if network else "Artifacts dropped"
        for v in values[:100]:
            add_attr(etype, v, category, to_ids=network)

    for tag_name in ("torikago:static", "torikago:never-executed"):
        ET.SubElement(ET.SubElement(event, "Tag"), "name").text = tag_name
    packer = (report.get("packer") or {}).get("verdict")
    if packer not in (None, "none", "n/a"):
        ET.SubElement(ET.SubElement(event, "Tag"), "name").text = "torikago:packed"
    if report.get("wrapper"):
        ET.SubElement(ET.SubElement(event, "Tag"), "name").text = (
            "torikago:wrapper-%s" % report["wrapper"]["wrapper"].lower())

    try:
        ET.indent(root)                       # pretty output, Python 3.9+
    except AttributeError:                    # pragma: no cover - Python < 3.9
        pass
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


def build_stix_bundle(report: dict) -> dict:
    """A minimal STIX 2.1 bundle: the file, plus one indicator per observable.

    STIX is what TIPs and MISP's own importer consume, so this is a second door into the
    same room as the XML event above.
    """
    h = report["hashes"]
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    file_obj = {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--" + str(uuid.uuid5(uuid.NAMESPACE_URL, h["sha256"])),
        "hashes": {"SHA-256": h["sha256"], "SHA-1": h["sha1"], "MD5": h["md5"]},
        "size": h["size"],
        "name": Path(report["file"]).name,
    }
    objects = [file_obj]
    for kind, values in (report.get("iocs") or {}).items():
        for v in values[:100]:
            if kind == "url":
                pattern = "[url:value = '%s']" % v.replace("'", "\\'")
            elif kind == "domain":
                pattern = "[domain-name:value = '%s']" % v
            elif kind == "ipv4":
                pattern = "[ipv4-addr:value = '%s']" % v
            elif kind == "email":
                pattern = "[email-addr:value = '%s']" % v
            else:
                continue
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_URL, pattern)),
                "created": now,
                "modified": now,
                "name": kind,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now,
                "indicator_types": ["malicious-activity"],
                # The file this was extracted from, in a standard field. It used to be an
                # undeclared `x_torikago_source_file` custom property, which made the object --
                # and therefore the whole bundle -- invalid under STIX 2.1: custom properties have
                # to be declared by an ExtensionDefinition in the same bundle. Verified by parsing
                # the output with the official `stix2` library, which rejected it outright.
                "description": "%s, extracted from %s (%s)" % (
                    kind, Path(report["file"]).name, h["sha256"]),
            })
    return {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": objects}


# --------------------------------------------------------------------------- #
# handing a flagged file to an isolated environment
# --------------------------------------------------------------------------- #
#
# The rule this exists to serve: it stages, it never detonates.
#
#   triage (never executes)  ->  stage into a shuttle directory  ->  a human runs it in a VM
#
# Copying is safe; running is not, and the boundary between them is what keeps this from
# becoming an automatic detonator. So everything here is a file copy plus a written record,
# and the output always includes the manual step rather than performing it.
#
# Beyond that, the reasoning for the pattern: signature-based detection can only recognise
# what it has already seen, and a one-shot destroyer may never be seen twice. Staging a
# flagged file puts a record and a copy in the operator's hand before anything runs, which is
# the only useful thing a tool can do at that moment.

QUARANTINE_MANIFEST = "quarantine.jsonl"

VM_INSTRUCTIONS = (
    "Next step is manual, in an isolated environment:",
    "  1. create a disposable VM with no network and no shared folders",
    "  2. copy ONLY this file in, and treat the copy as hostile",
    "  3. run it there and observe; do not run it on the host",
    "  4. destroy the VM afterwards rather than reusing it",
)


def quarantine_copy(source: Path, quarantine_dir: Path, report: dict, *,
                    reason: str) -> dict:
    """Copy a flagged file into a shuttle directory and record why.

    Deliberately not a move: the original stays where the operator can see it, and a tool
    that silently relocates a file out of a directory someone is working in causes more
    problems than it solves.

    Nothing here executes anything. It writes two files: the copy, and its record.
    """
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S")
    sha = report["hashes"]["sha256"]
    # The name carries the hash tail so two files cannot silently collide in the shuttle.
    staged_name = "%s_%s_%s" % (stamp, sha[:12], source.name)
    staged = quarantine_dir / staged_name

    try:
        with source.open("rb") as src, staged.open("wb") as dst:
            shutil.copyfileobj(src, dst, 1 << 20)
    except OSError as exc:
        return {"ok": False, "reason": "could not copy: %s" % exc, "executed": False}

    # The record travels with the copy: whoever opens the shuttle later needs the verdict and
    # the evidence, not just a file with an opaque name.
    record = {
        "staged_at": stamp,
        "staged_name": staged_name,
        "original_path": str(source),
        "sha256": sha,
        "md5": report["hashes"]["md5"],
        "size": report["hashes"]["size"],
        "identified_as": report["identified_as"]["label"],
        "reason": reason,
        "attention": report["assessment"]["attention"],
        "reasons": report["assessment"]["reasons"],
        "destructive": {
            "highest": (report.get("destructive") or {}).get("highest"),
            "findings": (report.get("destructive") or {}).get("findings", []),
        },
        "iocs": {k: v[:20] for k, v in (report.get("iocs") or {}).items()},
        "executed": False,
        "note": "staged by triage; nothing in the staging step ran this file",
    }
    (quarantine_dir / (staged_name + ".why.json")).write_text(
        json.dumps(record, ensure_ascii=False, indent=1), encoding="utf-8")
    with (quarantine_dir / QUARANTINE_MANIFEST).open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({k: record[k] for k in
                             ("staged_at", "staged_name", "sha256", "reason",
                              "attention", "executed")}, ensure_ascii=False) + "\n")

    return {
        "ok": True,
        "staged": str(staged),
        "why": str(staged) + ".why.json",
        "reason": reason,
        "manifest": str(quarantine_dir / QUARANTINE_MANIFEST),
        "executed": False,
    }


def list_quarantine(quarantine_dir: Path) -> int:
    """Show what is waiting in a shuttle directory, so it does not become a black hole."""
    manifest = quarantine_dir / QUARANTINE_MANIFEST
    if not manifest.is_file():
        print("nothing staged in %s" % quarantine_dir)
        return 0
    rows = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    print("%d staged file(s) in %s" % (len(rows), quarantine_dir))
    for r in rows:
        print("  %s  %s" % (r.get("staged_at", "?"), r.get("staged_name", "?")))
        print("      %s" % (r.get("reason") or "")[:110])
    print()
    for line in VM_INSTRUCTIONS:
        print("  %s" % line)
    return 0


# Reasons that are high-confidence on their own. A weak string keyword match is not one:
# measured over 260 real system and application binaries, 258 reported at least one
# "suspicious string", so that signal has almost no discriminating power and must not by
# itself decide that a file deserves a VM slot.
STRONG_REASON_MARKERS = (
    "injection triad",
    "EMBEDDED BOOT SECTOR",
    "DEVICE CONTROL",
    "input hook plus crypto RNG",
    "high-entropy executable",
    "packed or encrypted",
    "named .",
)


def high_confidence_reasons(report: dict) -> list:
    """The subset of reasons worth acting on without a human reading them first."""
    return [r for r in report["assessment"]["reasons"]
            if any(m.lower() in r.lower() for m in STRONG_REASON_MARKERS)]


def should_stage(report: dict, min_attention: int = 1, min_weak: int = 5) -> tuple:
    """Decide whether a file is worth a VM slot, and say why.

    The gate is about evidence the operator can check, not a score, and it is calibrated on a
    corpus rather than guessed:

    * a destructive finding at high or critical severity always stages -- it is the one
      consequence that cannot be walked back
    * a high-confidence reason stages, and the reason is quoted so the operator can disagree
    * weak signals alone need several of them, because one keyword hit is nearly universal
    """
    destructive = report.get("destructive") or {}
    if destructive.get("highest") in ("high", "critical"):
        return True, "destructive capability reported at %s" % destructive["highest"]
    strong = high_confidence_reasons(report)
    if strong and report["assessment"]["attention"] >= min_attention:
        return True, "attention: %s" % "; ".join(strong)[:240]
    if report.get("wrapper"):
        return True, "%s wrapper: it is a self-extracting program" % \
                     report["wrapper"]["wrapper"]
    weak = report["assessment"]["attention"]
    if weak >= min_weak:
        return True, "%d weak signals: %s" % (
            weak, "; ".join(report["assessment"]["reasons"])[:200])
    return False, "nothing flagged above the staging threshold (weak signals: %d)" % weak


# --------------------------------------------------------------------------- #
# report
NESTED_UNPACK_MAX_DEPTH = 3
NESTED_UNPACK_MAX_TOTAL = 10


def _unpack_nested(inner: list, parent_dest: Path, *, depth: int,
                   max_depth: int = NESTED_UNPACK_MAX_DEPTH,
                   max_total: int = NESTED_UNPACK_MAX_TOTAL,
                   visited: set | None = None) -> dict:
    """Unpack any PyInstaller wrappers among `inner`, and follow what they contain.

    Returns {"unpacked": [...], "skipped": [...]} rather than raising: one broken nested archive
    must not cost the analysis of the others.

    The bounds and why each exists:
      depth    a wrapper in a wrapper is worth following; the cost is files and time
      total    depth alone does not bound the work -- one level can hold thirty archives
      visited  an archive containing a copy of itself would otherwise recurse to the depth limit,
               writing a complete tree at every level
      confinement  unpacking writes files, so an inner path must resolve strictly inside the
               parent's output directory and never somewhere the parent did not already own
    """
    visited = set() if visited is None else visited
    unpacked, skipped = [], []
    if unpack_mod is None or depth > max_depth:
        return {"unpacked": unpacked, "skipped": skipped}

    for row in inner:
        if len(unpacked) >= max_total:
            skipped.append({"path": row.get("path"),
                            "why": "the nested-unpack limit of %d was reached" % max_total})
            continue
        target = (parent_dest / row.get("path", "")).resolve()
        try:
            # The entry name came out of an archive, so it is untrusted like any other.
            target.relative_to(parent_dest.resolve())
        except (ValueError, OSError):
            skipped.append({"path": row.get("path"),
                            "why": "resolves outside the unpack directory"})
            continue
        if not target.is_file():
            continue
        if target in visited:
            skipped.append({"path": row.get("path"), "why": "already unpacked in this run"})
            continue
        # Only another wrapper is worth a second pass; an ordinary inner DLL is already described
        # by the row it came from. The row's `wrapper` field is authoritative because it was read
        # from the file's tail -- re-deriving it from a head peek here is what silently skipped the
        # nested wrapper this function exists to follow.
        if not row.get("wrapper"):
            continue
        visited.add(target)

        child_dest = target.parent / (target.stem + "_unpacked")
        res = unpack_mod.unpack_pyinstaller(target, child_dest, with_pyc=True)
        record = {"path": row.get("path"), "out_dir": str(child_dest), "depth": depth,
                  "ok": bool(res.get("ok"))}
        if res.get("ok"):
            inner2 = find_inner_executables(child_dest)
            record["inside"] = len(inner2)
            unpacked.append(record)
            if inner2:
                deeper = _unpack_nested(inner2, child_dest, depth=depth + 1,
                                        max_depth=max_depth, max_total=max_total - len(unpacked),
                                        visited=visited)
                unpacked.extend(deeper["unpacked"])
                skipped.extend(deeper["skipped"])
        else:
            record["reason"] = res.get("reason") or "the nested unpack failed"
            skipped.append(record)
    return {"unpacked": unpacked, "skipped": skipped}


# --------------------------------------------------------------------------- #

def hashes_of(data: bytes, part: int = 0) -> dict:
    out = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }
    if part:
        out["sha256_first_%d" % part] = hashlib.sha256(data[:part]).hexdigest()
    return out


def assess(pe: dict | None, packer: dict, strings: dict, iocs: dict,
           imports: list, embedded: list, destructive: dict | None = None,
           debug_info: dict | None = None) -> dict:
    """What about this file is unusual, and what is merely true.

    The distinction is measured rather than guessed. Across 298 ordinary binaries from a normal
    drive, a URL appears in 99.7%, the "APIs worth noting" set in 98.7%, debug information in
    84.9%, and a TLS callback in 69.5% -- while a packer verdict fires on 1.0%, an embedded PE on
    0.3%, and a destructive finding on 0.7%.

    `attention` used to be `len(reasons)`, so five facts true of everything weighed the same as one
    destructive finding. Since the job is to surface the rare thing, the ubiquitous observations
    are kept but no longer ranked: `reasons` is the unusual, `notes` is the ordinary.
    """
    reasons, notes = [], []

    # Destructive capability is reported first. It is the one finding whose consequence is
    # unrecoverable, and it is judged on structural evidence rather than on an import that
    # ordinary software also uses.
    if destructive and destructive.get("count"):
        for f in destructive["findings"]:
            if f["severity"] in ("high", "critical"):
                reasons.append("%s [%s]: %s" % (f["capability"].upper(), f["severity"],
                                                f["evidence"]))

    if packer["verdict"] not in ("none",):
        # "data module, not code" is a finding but not a packing, so it does not get that word.
        labels = sorted({f["packer"] for f in packer["findings"]})
        if labels == ["data module, not code"]:
            notes.append("a PE container holding only data: no executable section and no imports")
        else:
            reasons.append("packed or encrypted: " + ", ".join(labels))

    if pe:
        # Not for a managed assembly. IL plus metadata in .text is far less redundant than native
        # machine code, so it sits near the top of the entropy range by construction -- a real
        # .NET sample measured 7.98 and was called packed. The packer finding has known this for a
        # while; this reason had not, so the same file was still described as high-entropy after
        # the packer verdict was corrected.
        if not pe.get("is_dotnet"):
            exec_high = [s["name"] for s in pe["sections"]
                         if s["executable"] and s["entropy"] >= HIGH_ENTROPY]
            if exec_high:
                reasons.append("high-entropy executable section(s): " + ", ".join(exec_high))
        if pe["directories"].get("tls"):
            # 69.5% of ordinary binaries. Real, and not a reason to look twice.
            notes.append("has a TLS callback (runs before the entry point)")

    if embedded:
        reasons.append(f"{len(embedded)} embedded PE image(s)")

    if debug_info and debug_info.get("available"):
        pdb = debug_info.get("sibling_pdb") or {}
        if pdb and pdb.get("format", "").startswith(("msf", "portable")):
            match = debug_info.get("pdb_matches_binary")
            where = ("matches this binary" if match is True
                     else "does NOT match this binary" if match is False
                     else "match unverified")
            # 0% of the corpus: a .pdb that shipped is genuinely rare and worth the top of the list.
            reasons.append("a .pdb shipped beside the binary (%s, %s)"
                           % (pdb.get("format"), where))
        path = debug_info.get("build_pdb_path")
        if path and debug_info.get("build_machine_dirs"):
            # A full path and a bare filename are different disclosures -- but neither is rare.
            # Debug information survives in ordinary release builds: 84.9% of the corpus records a
            # full build path, and an earlier note claiming this was "selective rather than noise"
            # was drawn from a 101-file sample and did not survive a wider one.
            notes.append("built with debug information: the CodeView record names the build-time "
                         ".pdb path (%s)" % path if len(path) < 90 else
                         "built with debug information: the CodeView record names the build-time "
                         ".pdb path")
        elif path:
            notes.append("built with debug information (a .pdb is named, with no path beyond the "
                         "file name)")

    # Imports are a weak signal on their own: any real program resolves APIs dynamically and
    # allocates memory. Only the combination (a notable API in a packed or embedded-PE file) is
    # worth ranking highly, so the wording says what is actually true.
    api_hits, strong = [], []
    for imp in imports:
        for fn in imp["functions"]:
            key = fn.lower()
            if key in SUSPICIOUS_IMPORTS:
                api_hits.append(fn)
                if key in STRONG_SIGNAL_IMPORTS:
                    strong.append(fn)
    # The injection triad is judged first, and on the full import set: it is the single most
    # meaningful import signal there is, and it must fire in single-file triage too, not only in
    # batch scan mode. Escalating on the combination rather than on any one API is what keeps
    # ordinary software -- which uses VirtualAlloc and GetProcAddress constantly -- out of the
    # report.
    low = {fn.lower() for fn in api_hits}
    triad = {"virtualalloc", "writeprocessmemory", "createremotethread"} <= low
    if triad:
        reasons.append("injection triad (VirtualAlloc + WriteProcessMemory + CreateRemoteThread)")
    context = (packer["verdict"] not in ("none", "n/a")) or bool(embedded)
    if strong and context:
        reasons.append("notable imports in a packed or embedded-image file: "
                       + ", ".join(sorted(set(strong))[:8]))
    elif api_hits and not triad:
        # Present in 98.7% of ordinary binaries -- including the ones that turned out to carry the
        # triad, which is why the triad is judged above on the full import set rather than on this
        # line. A fact worth keeping and not worth ranking.
        notes.append("uses APIs worth noting, though common in ordinary programs: "
                     + ", ".join(sorted(set(api_hits))[:6]))

    for kind in ("url", "registry_run", "scheduled_task", "defender_exclusion", "named_pipe"):
        if iocs.get(kind):
            hit = f"{kind}: {len(iocs[kind])} found"
            # A URL is in the string table of 99.7% of binaries; the others are not.
            (notes if kind == "url" else reasons).append(hit)

    if strings.get("interesting"):
        # Measured at 13% of the corpus, so it is not ubiquitous -- but it is a count of a
        # heuristic, and a file with 300 "suspicious strings" is usually an application with 300
        # long string constants. Kept as a note: real, weak, and not a reason to look twice.
        notes.append(f"{len(strings['interesting'])} suspicious strings")

    return {"reasons": reasons, "notes": notes, "attention": len(reasons)}


YARA_TEMPLATE = '''rule {name} {{
    meta:
        description = "draft rule generated by torikago.py from static indicators"
        generated_from = "{sha256}"
        note = "UNREVIEWED: verify against a corpus before use"
    strings:
{strings}
    condition:
        uint16(0) == 0x5A4D and {condition}
}}
'''


def draft_yara(report: dict, max_strings: int = 8) -> str:
    """A starting point, explicitly labelled as unreviewed."""
    picked = []
    for s in report["strings"].get("interesting", []):
        if 6 <= len(s) <= 60 and s.isprintable() and not s.startswith("\\"):
            picked.append(s)
        if len(picked) >= max_strings:
            break
    if not picked:
        return ("// No distinctive strings were found to build a rule from.\n"
                "// The hashes in report.json are the reliable indicator here.\n")
    lines, conds = [], []
    for i, s in enumerate(picked):
        ident = "$s%d" % i
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        lines.append('        %-6s = "%s" ascii wide' % (ident, escaped))
        conds.append(ident)
    name = "torikago_draft_" + report["hashes"]["sha256"][:12]
    return YARA_TEMPLATE.format(name=name, sha256=report["hashes"]["sha256"],
                                strings="\n".join(lines), condition=" and ".join(conds))


def build_report(path: Path, out_dir: Path | None, *, max_bytes: int = DEFAULT_MAX_BYTES,
                 force: bool = False) -> dict:
    # The whole file is loaded, because hashes, strings and indicators need all of it, and
    # peak memory measures at about twice the file size: a 300 MB file cost 600 MB and 62
    # seconds. The cost is linear, so an arbitrarily large input is a cheap way to hang an
    # analysis machine. Refuse by default rather than assuming the caller meant it.
    size = path.stat().st_size
    if not force and max_bytes and size > max_bytes:
        raise SystemExit(
            "%s is %.1f MB, above the %.1f MB analysis limit.\n"
            "  Resource guard, not a refusal to analyse: the whole file is loaded and peak\n"
            "  memory runs about twice its size. Raise it with --max-bytes N, or override\n"
            "  entirely with --force."
            % (path.name, size / (1 << 20), max_bytes / (1 << 20)))
    data = path.read_bytes()
    kind = identify(data, path)
    pe = parse_pe(data) if kind["kind"] == "pe" else None
    imports = parse_imports(data, pe) if pe else []
    if pe:
        pe["is_dotnet"] = is_dotnet(pe, data) is not None
    packer = identify_packer(pe, data, imports) if pe else {"verdict": "n/a", "findings": []}
    strings = extract_strings(data)
    iocs = extract_iocs(data)
    embedded = find_embedded_executables(data)
    pyinstaller = detect_pyinstaller(data)
    wrappers = detect_other_wrappers(data)
    destructive = detect_destructive(pe, data, imports, strings)
    report = {
        "tool": "torikago",
        "version": VERSION,
        "file": str(path),
        "hashes": hashes_of(data, part=4096),
        "identified_as": kind,
        "name_looks_wrong": extension_mismatch(kind["kind"], path),
        "pe": pe,
        "imports": imports,
        "packer": packer,
        "wrapper": pyinstaller,
        "other_wrapper_markers": wrappers,
        "language": detect_language(data, pe=pe),
        # How the binary was built. The CodeView record alone is worth this: it names the .pdb's
        # path on the build machine, and therefore the project and source layout, without the
        # .pdb being present. A .pdb that shipped beside it is reported separately and matched,
        # because a PDB that is not this binary's PDB must not have its names attributed to it.
        # Passed a path, not the bytes: the debug directory sits at ~95% of the file, so a
        # caller holding a head peek would silently see nothing. This seeks instead.
        "debug_info": analyse_debug_info(path, pe),
        "embedded_executables": embedded,
        "destructive": destructive,
        "iocs": iocs,
        "strings": strings,
        "base64_candidates": base64_candidates(strings),
        "assessment": {},
        "unpack_plan": [],
        "executed_target": False,
    }
    report["assessment"] = assess(pe, packer, strings, iocs, imports, embedded, destructive,
                                 report["debug_info"])
    report["unpack_plan"] = plan_unpacking(report)
    report["yara_draft"] = draft_yara(report)
    return report


def build_report_with_unpack(path: Path, out_dir: Path | None, unpack: bool, *,
                             max_bytes: int = DEFAULT_MAX_BYTES, force: bool = False) -> dict:
    """A report, optionally extended with what an actual unpack found inside."""
    report = build_report(path, out_dir, max_bytes=max_bytes, force=force)
    if not unpack:
        return report                       # not asked for: say nothing rather than "failed"
    if unpack_mod is None:
        report["unpack"] = {"ok": False, "executed": False,
                            "reason": "unpack.py is not available next to torikago.py"}
        return report
    kind = report["identified_as"]["kind"]
    if report["wrapper"]:
        dest = (out_dir or path.parent / (path.stem + "_unpacked"))
        res = unpack_mod.unpack_pyinstaller(path, dest, with_pyc=True)
        report["unpack"] = res
        if res.get("ok"):
            report["inside"] = find_inner_executables(dest)
            report["inside_scan"] = scan_tree(dest)
            # A wrapper can hold another wrapper, and stopping at the first level leaves the
            # interesting file one step further in. Bounded, because unpacking writes files.
            # The report shows a readable slice; the recursion looks further, because the wrapper
            # worth following is not necessarily in the first forty names.
            candidates = find_inner_executables(dest, limit=200)
            deeper = _unpack_nested(candidates, dest, depth=1)
            if deeper["unpacked"] or deeper["skipped"]:
                report["nested"] = deeper
        else:
            report["unpack"]["hint"] = ("point %s at nanodesu.py, or install it with "
                                        "pip install nanodesu" % unpack_mod.NANODESU_ENV)
    elif kind == "unknown" and path.suffix.lower() == ".pyz":
        dest = (out_dir or path.parent / (path.stem + "_pyz"))
        res = unpack_mod.unpack_pyz(path, dest)
        report["unpack"] = res
        if res.get("ok"):
            report["inside"] = find_inner_executables(dest)
    else:
        report["unpack"] = {"ok": False, "executed": False,
                            "reason": "no in-process unpacker for %s" % kind}
    return report


def plan_unpacking(report: dict) -> list:
    """What could be done next, and explicitly what requires running the sample."""
    plan = []
    if report["wrapper"]:
        plan.append({
            "step": "unpack the PyInstaller archive",
            "run": "python nanodesu.py extract <file> -o <out> --pyc",
            "needs_execution": False,
        })
    kind = report["identified_as"]["kind"]
    if kind in ("zip", "gzip", "bzip2", "xz", "7z", "cab"):
        plan.append({"step": f"unpack the {kind} container",
                     "run": (f"7z x <file> -o<out>  (any 7-Zip build reads {kind}; "
                             f"Python's own zipfile/tarfile/gzip/bz2/lzma cover most of "
                             f"these when 7-Zip is not installed)"),
                     "needs_execution": False})
    if report["embedded_executables"]:
        plan.append({"step": "carve the embedded PE image(s) out for separate analysis",
                     "run": "extract by offset (see embedded_executables)",
                     "needs_execution": False})
    if "NSIS installer" in " ".join(report.get("other_wrapper_markers") or []):
        plan.append({"step": "unpack the NSIS installer",
                     "run": "7z can list/extract NSIS; if it fails, 7z on the installer body",
                     "needs_execution": False})
    if report["packer"]["verdict"] not in ("none", "n/a"):
        plan.append({
            "step": "unpack the runtime packer",
            "run": "requires running the sample under a debugger or an unpacking tool",
            "needs_execution": True,
            "warning": "This tool will not do it. Use a disposable VM with no network and "
                       "no shared folders, and expect anti-analysis behaviour.",
        })
    if not plan:
        plan.append({"step": "no static unpacking path identified",
                     "run": "treat the hashes and indicators as the finding",
                     "needs_execution": False})
    return plan


def print_human(report: dict) -> None:
    h = report["hashes"]
    print("file        : %s" % report["file"])
    print("size        : %d bytes" % h["size"])
    print("sha256      : %s" % h["sha256"])
    print("md5         : %s" % h["md5"])
    print("identified  : %s (%s)" % (report["identified_as"]["label"],
                                     report["identified_as"]["kind"]))
    if report["name_looks_wrong"]:
        print("name        : !! %s" % report["name_looks_wrong"])
    if report["pe"]:
        pe = report["pe"]
        print("pe          : %s, %d sections, entry RVA %#x, built %d"
              % (pe["machine"], len(pe["sections"]), pe["entry_point_rva"], pe["timestamp"]))
        for s in pe["sections"]:
            flags = ("X" if s["executable"] else "-") + ("W" if s["writable"] else "-")
            print("    %-9s %7d raw  entropy %5.2f  %s"
                  % (s["name"], s["rawsize"], s["entropy"], flags))
    if report["wrapper"]:
        w = report["wrapper"]
        print("wrapper     : PyInstaller (python %s, %s)"
              % (w["python_version"], w["python_library"]))
    if report.get("language", {}).get("likely"):
        lang = report["language"]
        print("language    : %s (%s)%s" % (
            lang["likely"], ", ".join(lang["all"][0]["markers"][:3]),
            " -- symbols appear stripped" if lang["symbols_stripped_hint"] else ""))
    if report["other_wrapper_markers"]:
        print("markers     : %s" % ", ".join(report["other_wrapper_markers"]))
    if report["packer"]["verdict"] not in ("n/a",):
        print("packer      : %s" % report["packer"]["verdict"])
        for f in report["packer"]["findings"]:
            print("    %s -- %s" % (f["packer"], "; ".join(f["evidence"])))
    if report["imports"]:
        total = sum(i["count"] for i in report["imports"])
        print("imports     : %d functions across %d DLL(s)" % (total, len(report["imports"])))
    if report["embedded_executables"]:
        print("embedded PE : %d" % len(report["embedded_executables"]))
    if report["iocs"]:
        print("indicators  :")
        for k, v in report["iocs"].items():
            print("    %-20s %d  %s" % (k, len(v), ", ".join(v[:3])))
    if report["assessment"]["reasons"]:
        print("attention   :")
        for r in report["assessment"]["reasons"]:
            print("    - %s" % r)
    if report.get("destructive", {}).get("count"):
        print("destructive : highest severity %s" % report["destructive"]["highest"])
        for f in report["destructive"]["findings"]:
            print("    [%-8s] %s -- %s" % (f["severity"], f["capability"], f["evidence"]))

    print("next steps  :")
    for step in report["unpack_plan"]:
        mark = "needs execution" if step["needs_execution"] else "safe (no execution)"
        print("    [%s] %s" % (mark, step["step"]))
        print("        %s" % step["run"])
    if report.get("unpack"):
        u = report["unpack"]
        if u.get("ok"):
            print("unpacked    : %d files -> %s" % (u.get("files_written", 0), u.get("out_dir")))
            if report.get("inside"):
                print("inside      : %d executable file(s)" % len(report["inside"]))
                for row in report["inside"][:8]:
                    extra = ""
                    if row["packer"] not in ("none", "n/a"):
                        extra += " packed=%s" % row["packer"]
                    if row["suspicious_imports"]:
                        extra += " imports=%s" % ",".join(row["suspicious_imports"][:3])
                    print("    %-44s %9d B%s" % (row["path"], row["size"], extra))
        else:
            print("unpacked    : not done (%s)" % u.get("reason"))
    av = report.get("antivirus")
    if av:
        if not av.get("available"):
            print("antivirus   : not available (%s)" % av.get("reason"))
        elif av.get("infected"):
            print("antivirus   : %d infected of %d scanned" % (av["infected"], av["scanned"]))
            for v in av["verdicts"][:6]:
                print("    %s -- %s" % (Path(v["file"]).name, v["signature"]))
        else:
            print("antivirus   : %d scanned, nothing detected" % av.get("scanned", 0))
    print("executed    : no (never)")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="torikago",
        description="Static triage for an unknown executable. Never runs the target.")
    ap.add_argument("target", nargs="?", help="file to inspect (or use --scan DIR)")
    ap.add_argument("-o", "--out", help="directory for report.json and rule.yar")
    ap.add_argument("--json", action="store_true", help="print JSON instead of a summary")
    ap.add_argument("--quiet", action="store_true", help="write files only")
    ap.add_argument("--max-bytes", type=float, default=DEFAULT_MAX_BYTES,
                    help="refuse to analyse a file larger than this (default %d; suffix not "
                         "accepted, so give bytes)" % DEFAULT_MAX_BYTES)
    ap.add_argument("--force", action="store_true",
                    help="analyse it regardless of size; peak memory is about twice the file")
    ap.add_argument("--quarantine", metavar="DIR",
                    help="stage a flagged file into this directory for VM analysis "
                         "(a copy plus a written reason; never executes anything)")
    ap.add_argument("--quarantine-list", metavar="DIR",
                    help="list what has been staged in a quarantine directory")
    ap.add_argument("--quarantine-min", type=int, default=1, metavar="N",
                    help="stage when at least N attention signals are present (default 1); "
                         "high or critical destructive findings always stage")
    ap.add_argument("--unpack", action="store_true",
                    help="also unpack a recognised wrapper in-process (never executes it)")
    ap.add_argument("--scan", metavar="DIR",
                    help="triage every file in a directory and report which ones stand out")
    ap.add_argument("--corpus-write", metavar="DIR",
                    help="scan a directory and fold the measurements into corpus/manifest.jsonl "
                         "(structure only; no samples are copied or stored)")
    ap.add_argument("--corpus-file", metavar="PATH",
                    help="manifest to read and write with --corpus-write "
                         "(default: DIR/manifest.jsonl)")
    ap.add_argument("--corpus-check", metavar="PATH",
                    help="load a manifest and report what it holds")
    ap.add_argument("--posture", action="store_true",
                    help="read-only report on what is protecting this machine and where it "
                         "conflicts with itself. Writes no setting")
    ap.add_argument("--scan-limit", type=int, default=200, metavar="N",
                    help="with --scan/--corpus-write, analyse at most N files (default 200)")
    ap.add_argument("--scan-only", metavar="EXT,EXT",
                    help="with --scan/--corpus-write, only look at these extensions "
                         "(e.g. exe,dll); a corpus of archives says nothing about the detectors")
    ap.add_argument("--scan-av", action="store_true",
                    help="also ask ClamAV for a verdict (reads files, never runs them)")
    ap.add_argument("--handoff", choices=("defender", "clamav", "both"),
                    help="hand the file to a real judgement engine and report ITS verdict. "
                         "Reads the file; runs nothing; removes nothing")
    ap.add_argument("--feed", choices=("misp", "stix", "both"),
                    help="write threat-intelligence output for sharing (misp=xml, stix=json)")
    args = ap.parse_args(argv)

    path = Path(args.target) if args.target else None
    if path is not None and not path.exists():
        print("no such file: %s" % path, file=sys.stderr)
        return 1
    if path is not None and path.is_dir():
        print("that is a directory: %s -- did you mean --scan %s ?" % (path, path), file=sys.stderr)
        return 1

    if args.quarantine_list:
        return list_quarantine(Path(args.quarantine_list))

    if args.posture:
        import security_posture as sp

        state = sp.posture()
        if args.json:
            print(json.dumps(state, ensure_ascii=False, indent=1))
            return 0
        d = state["defender"]
        print("defender")
        for label, key in (("engine enabled", "antivirus_enabled"),
                           ("service enabled", "service_enabled"),
                           ("real-time", "realtime"),
                           ("behaviour monitor", "behavior_monitor"),
                           ("signature age", "signature_age_days")):
            print("  %-18s %s" % (label, d.get(key)))
        print()
        print("registered with Security Center")
        for prod in state["registered"].get("products", []):
            print("  %-28s state=%s" % (prod["name"], prod["state"]))
        print()
        print("scanning exclusions  <- silent protection loss that outlives its reason")
        ex = state["exclusions"]
        for label, key in (("paths", "paths"), ("extensions", "extensions"),
                           ("processes", "processes")):
            print("  %-11s %s" % (label, ", ".join(ex.get(key, [])) or "(none)"))
        print()
        ra = state.get("registration_audit") or {}
        if ra.get("ok"):
            print()
            print("declared vs observed  <- the registration is self-declared and nothing verifies it")
            for prod in ra.get("products", []):
                print("  %s" % prod["name"])
                print("     productState %#07x   declares real-time: %s"
                      % (prod.get("product_state") or 0, prod.get("declares_realtime")))
                svc = prod.get("observed_service") or {}
                print("     running service: %s" % (svc.get("matched") or "none matched"))
            for c in ra.get("contradictions") or []:
                print("  [CONTRA] %s: %s" % (c["product"], c["what"]))
            for o in ra.get("observations") or []:
                print("  [note]   %s: %s" % (o["product"], o["what"]))
            if not ra.get("contradictions") and not ra.get("observations"):
                print("  no contradiction found -- which means nothing, see the limits below")
            for limit in (ra.get("limits") or [])[:1]:
                print("  %s" % limit)

        print()
        print("findings")
        found = sp.findings(state)
        for f in found:
            print("  [%-8s] %s" % (f["level"], f["what"]))
        if not found:
            print("  nothing to flag")
        print()
        print(state["note"])
        print()
        # The boundary travels with the result in the data; it is printed here too, because the
        # reader of a console report is exactly who would otherwise take it as reassurance.
        print("boundary")
        for line in state.get("boundary_notice", []):
            print("  - %s" % line)
        return 0

    if args.corpus_write or args.corpus_check:
        import corpus as corpus_mod

        if args.corpus_check:
            path = Path(args.corpus_check)
            if not path.is_file():
                print("no such manifest: %s" % path, file=sys.stderr)
                return 1
            entries = corpus_mod.read_manifest(path)
            stats = corpus_mod.summarize(entries)
            if args.json:
                print(json.dumps(stats, ensure_ascii=False, indent=1))
                return 0
            print("%s" % path)
            print("  files        : %d" % stats["files"])
            print("  attention    : %d" % stats["attention"])
            print("  by packer    : %s" % ", ".join(
                "%s=%d" % kv for kv in sorted(stats["packer"].items(),
                                              key=lambda kv: -kv[1])[:6]))
            print("  by kind      : %s" % ", ".join(
                "%s=%d" % kv for kv in sorted(stats["kind"].items(), key=lambda kv: -kv[1])[:6]))
            return 0

        root = Path(args.corpus_write)
        if not root.is_dir():
            print("not a directory: %s" % root, file=sys.stderr)
            return 1
        manifest_path = Path(args.corpus_file) if args.corpus_file \
            else root / corpus_mod.MANIFEST_NAME
        before = corpus_mod.read_manifest(manifest_path)

        # scan_tree caps how many files it walks (its own default is a guard against being pointed at
        # a whole drive by accident). A corpus build wants the whole sample, so the cap is explicit
        # and adjustable -- the first run silently stopped at 200 of 1232 candidates.
        only = None
        if args.scan_only:
            only = [e.strip() for e in args.scan_only.split(",") if e.strip()]
            print("filtering to: %s" % ", ".join(only))
        tree = scan_tree(root, limit=args.scan_limit, only=only)
        entries, skipped = [], []
        for row in tree.get("rows", []):
            # `scan_tree` rows carry a relative path; the hash has to come from the file itself.
            full = root / row["path"]
            if not full.is_file():
                continue
            # The manifest must not measure itself. Left in, the first run adds it and every later
            # run adds a *new* entry for the file that just changed, so the corpus grows by one
            # spurious record per sweep -- observed: 3 files became 4 on the second pass.
            if full.resolve() == manifest_path.resolve():
                skipped.append(row["path"])
                continue
            entries.append(corpus_mod.entry_from_row(
                row, sha=corpus_mod.sha256_file(full)))

        merged = corpus_mod.merge_manifest(before, entries)
        corpus_mod.write_manifest(manifest_path, merged["entries"])

        print("scanned  : %d file(s)" % tree.get("scanned", 0))
        if skipped:
            print("skipped  : %s (the manifest does not measure itself)" % ", ".join(skipped))
        print("manifest : %s" % manifest_path)
        print("  added   : %d" % len(merged["added"]))
        print("  updated : %d" % len(merged["updated"]))
        print("  total   : %d" % len(merged["entries"]))
        if merged["changed"]:
            # Printed rather than filed away: a verdict that moved is the thing a corpus is kept to
            # notice, and burying it in a JSON file nobody opens would waste the whole exercise.
            print("  verdict changes since the last run:")
            for c in merged["changed"][:15]:
                print("     %s  %s: %r -> %r"
                      % (c["sha256"][:12], c["field"], c["was"], c["now"]))
            if len(merged["changed"]) > 15:
                print("     ... and %d more" % (len(merged["changed"]) - 15))
        return 0

    if args.scan:
        # --scan stands alone: no positional file is needed. Checked before anything else
        # touches args.target.
        root = Path(args.scan)
        if not root.is_dir():
            print("not a directory: %s" % root, file=sys.stderr)
            return 1
        tree = scan_tree(root)
        if args.out:
            o = Path(args.out)
            o.mkdir(parents=True, exist_ok=True)
            (o / "report.json").write_text(json.dumps(tree, ensure_ascii=False, indent=1),
                                           encoding="utf-8")
            if not args.quiet:
                print("report -> %s" % (o / "report.json"))
        if args.json:
            print(json.dumps(tree, ensure_ascii=False, indent=1))
        elif not args.quiet:
            print_tree_report(tree)
        return 0

    if not args.target:
        print("give me a file to inspect, or --scan DIR for a whole directory", file=sys.stderr)
        return 2

    report = build_report_with_unpack(path, Path(args.out) if args.out else None, args.unpack,
                                      max_bytes=int(args.max_bytes), force=args.force)

    if args.scan_av:
        targets = [path]
        if report.get("unpack", {}).get("ok"):
            targets += [Path(r["path"]) for r in (report.get("inside") or [])]
            base = Path(report["unpack"]["out_dir"])
            targets = [path] + [base / r["path"] for r in (report.get("inside") or [])]
        report["antivirus"] = scan_with_clamav(targets)
    if args.handoff:
        # Same target set as --scan-av: the file, plus whatever an unpack found inside it. The inner
        # executables are usually the ones worth asking about -- the outer wrapper is an envelope.
        targets = [path]
        if report.get("unpack", {}).get("ok"):
            base = Path(report["unpack"]["out_dir"])
            targets += [base / r["path"] for r in (report.get("inside") or [])]
        engines = {}
        if args.handoff in ("defender", "both"):
            engines["defender"] = scan_with_defender(targets)
        if args.handoff in ("clamav", "both"):
            engines["clamav"] = scan_with_clamav(targets)
        report["handoff"] = {
            "engines": engines,
            "executed": False,
            "note": ("These are the engines' verdicts, not this tool's. Torikago reaches no "
                     "conclusion about whether a file is malicious."),
        }
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
        (out / "rule.yar").write_text(report["yara_draft"], encoding="utf-8")
        if not args.quiet:
            print("report -> %s" % (out / "report.json"))
            print("yara   -> %s" % (out / "rule.yar"))
    if args.quarantine and path is not None:
        stage, why = should_stage(report, min_attention=args.quarantine_min)
        if stage:
            res = quarantine_copy(path, Path(args.quarantine), report, reason=why)
            report["quarantine"] = res
            if not args.quiet:
                if res.get("ok"):
                    print("staged      : %s" % res["staged"])
                    print("   reason   : %s" % why)
                    for line in VM_INSTRUCTIONS:
                        print("   %s" % line)
                else:
                    print("staged      : failed (%s)" % res.get("reason"))
        else:
            report["quarantine"] = {"ok": True, "staged": None, "reason": why,
                                    "executed": False}
            if not args.quiet:
                print("staged      : no -- %s" % why)

    if args.feed:
        out = Path(args.out) if args.out else Path.cwd()
        out.mkdir(parents=True, exist_ok=True)
        wrote = []
        if args.feed in ("misp", "both"):
            (out / "event.xml").write_text(build_misp_event(report), encoding="utf-8")
            wrote.append("event.xml")
        if args.feed in ("stix", "both"):
            (out / "stix.json").write_text(
                json.dumps(build_stix_bundle(report), ensure_ascii=False, indent=1),
                encoding="utf-8")
            wrote.append("stix.json")
        if not args.quiet:
            print("intel       : %s" % ", ".join(wrote))

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=1))
    elif not args.quiet:
        print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
