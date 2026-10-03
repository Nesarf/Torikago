#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""triage.py - static triage for an unknown executable.

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
    python triage.py <file> [--out DIR] [--json] [--quiet]

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
import struct
import sys
import zlib
from collections import Counter
from pathlib import Path

VERSION = "0.1.0"

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
    binary_exts = {"exe", "dll", "scr", "com", "sys", "ocx", "cpl"}
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
STRONG_SIGNAL_IMPORTS = {
    "writeprocessmemory", "createremotethread", "setwindowshookex", "checkremotedebuggerpresent",
    "ntqueryinformationprocess", "cryptencrypt", "urldownloadtofile", "createservice",
    "shellexecute", "winexec", "virtualprotect",
}


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

    exec_sections = [s for s in pe["sections"] if s["executable"]]
    high = [s for s in pe["sections"] if s["entropy"] >= HIGH_ENTROPY]
    if exec_sections and len(high) == len(pe["sections"]):
        findings.append({"packer": "unknown (all sections high-entropy)",
                         "evidence": f"{len(high)} sections at entropy >= {HIGH_ENTROPY}"})
    if exec_sections and high and any(s["executable"] for s in high):
        findings.append({"packer": "likely packed",
                         "evidence": "executable section is high-entropy (encrypted or compressed code)"})
    # An import table with one or two entries is the classic packer stub.
    total_imports = sum(i["count"] for i in imports)
    if imports and total_imports <= 5:
        findings.append({"packer": "likely packed",
                         "evidence": f"only {total_imports} imported functions"})
    if not imports:
        findings.append({"packer": "likely packed or delay-loaded",
                         "evidence": "no import directory"})

    dedup = {}
    for f in findings:
        dedup.setdefault(f["packer"], set()).add(f["evidence"])
    return {"verdict": sorted(dedup)[0] if len(dedup) == 1 else ("multiple" if dedup else "none"),
            "findings": [{"packer": k, "evidence": sorted(v)} for k, v in dedup.items()]}


# --------------------------------------------------------------------------- #
# wrappers we can unpack without running anything
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


def extract_strings(data: bytes, min_len: int = 6, limit: int = 300) -> dict:
    """ASCII and UTF-16LE runs. UTF-16 matters: a .NET or wide-char sample hides here."""
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    wide_re = re.compile((rb"(?:[\x20-\x7e]\x00){%d,}" % min_len))
    ascii_hits = [m.group(0).decode("latin1") for m in ascii_re.finditer(data)]
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


# --------------------------------------------------------------------------- #
# report
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
           imports: list, embedded: list) -> dict:
    """A short list of reasons this file deserves attention. Not a verdict."""
    reasons = []
    if packer["verdict"] not in ("none",):
        reasons.append("packed or encrypted: " + ", ".join(
            f["packer"] for f in packer["findings"]))
    if pe:
        exec_high = [s["name"] for s in pe["sections"]
                     if s["executable"] and s["entropy"] >= HIGH_ENTROPY]
        if exec_high:
            reasons.append("high-entropy executable section(s): " + ", ".join(exec_high))
        if pe["directories"].get("tls"):
            reasons.append("has a TLS callback (runs before the entry point)")
    if embedded:
        reasons.append(f"{len(embedded)} embedded PE image(s)")
    # Imports are a weak signal on their own: any real program resolves APIs dynamically and
    # allocates memory. Only the combination (a notable API in a packed or embedded-PE file)
    # is worth ranking highly, so the wording says what is actually true.
    api_hits, strong = [], []
    for imp in imports:
        for fn in imp["functions"]:
            key = fn.lower()
            if key in SUSPICIOUS_IMPORTS:
                api_hits.append(fn)
                if key in STRONG_SIGNAL_IMPORTS:
                    strong.append(fn)
    context = (packer["verdict"] not in ("none", "n/a")) or bool(embedded)
    if strong and context:
        reasons.append("notable imports in a packed or embedded-image file: "
                       + ", ".join(sorted(set(strong))[:8]))
    elif api_hits:
        reasons.append("uses APIs worth noting, though common in ordinary programs: "
                       + ", ".join(sorted(set(api_hits))[:6]))
    for kind in ("url", "registry_run", "scheduled_task", "defender_exclusion", "named_pipe"):
        if iocs.get(kind):
            reasons.append(f"{kind}: {len(iocs[kind])} found")
    if strings.get("interesting"):
        reasons.append(f"{len(strings['interesting'])} suspicious strings")
    return {"reasons": reasons, "attention": len(reasons)}


YARA_TEMPLATE = '''rule {name} {{
    meta:
        description = "draft rule generated by triage.py from static indicators"
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
    name = "triage_draft_" + report["hashes"]["sha256"][:12]
    return YARA_TEMPLATE.format(name=name, sha256=report["hashes"]["sha256"],
                                strings="\n".join(lines), condition=" and ".join(conds))


def build_report(path: Path, out_dir: Path | None) -> dict:
    data = path.read_bytes()
    kind = identify(data, path)
    pe = parse_pe(data) if kind["kind"] == "pe" else None
    imports = parse_imports(data, pe) if pe else []
    packer = identify_packer(pe, data, imports) if pe else {"verdict": "n/a", "findings": []}
    strings = extract_strings(data)
    iocs = extract_iocs(data)
    embedded = find_embedded_executables(data)
    pyinstaller = detect_pyinstaller(data)
    wrappers = detect_other_wrappers(data)
    report = {
        "tool": "triage",
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
        "embedded_executables": embedded,
        "iocs": iocs,
        "strings": strings,
        "base64_candidates": base64_candidates(strings),
        "assessment": {},
        "unpack_plan": [],
        "executed_target": False,
    }
    report["assessment"] = assess(pe, packer, strings, iocs, imports, embedded)
    report["unpack_plan"] = plan_unpacking(report)
    report["yara_draft"] = draft_yara(report)
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
                     "run": "use 7zr.exe (present at E:\\DaShaoHuo\\tools\\7zr.exe)",
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
    print("next steps  :")
    for step in report["unpack_plan"]:
        mark = "needs execution" if step["needs_execution"] else "safe (no execution)"
        print("    [%s] %s" % (mark, step["step"]))
        print("        %s" % step["run"])
    print("executed    : no (never)")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="triage",
        description="Static triage for an unknown executable. Never runs the target.")
    ap.add_argument("target", help="file to inspect")
    ap.add_argument("-o", "--out", help="directory for report.json and rule.yar")
    ap.add_argument("--json", action="store_true", help="print JSON instead of a summary")
    ap.add_argument("--quiet", action="store_true", help="write files only")
    args = ap.parse_args(argv)

    path = Path(args.target)
    if not path.exists():
        print("no such file: %s" % path, file=sys.stderr)
        return 1
    if path.is_dir():
        print("that is a directory: %s" % path, file=sys.stderr)
        return 1

    report = build_report(path, Path(args.out) if args.out else None)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
        (out / "rule.yar").write_text(report["yara_draft"], encoding="utf-8")
        if not args.quiet:
            print("report -> %s" % (out / "report.json"))
            print("yara   -> %s" % (out / "rule.yar"))
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=1))
    elif not args.quiet:
        print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
