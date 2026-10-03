# -*- coding: utf-8 -*-

"""Tests for triage.py.



Every fixture is a tiny synthetic file, so the suite runs in well under a second and

needs no real malware. A suite that requires samples is a suite that stops being run.



The synthetic PE is assembled by explicit byte offsets rather than by a single struct

format: the optional header is what triage.py parses, so the fixture must put every

field where the parser looks, and hand-counting a 30-field pack string is how fixtures

start lying.



Verified against real binaries as well (not part of the suite, just the baseline that

says the parser is right): kernel32.dll reports 104 DLLs / 1274 functions,

advapi32.dll 35 / 656, shell32.dll 79 / 1087.



Run:

    python -m unittest discover -s test -v

"""

from __future__ import annotations



import base64 as b64

import importlib.util

import json

import struct

import sys

import tempfile

import unittest

from pathlib import Path



HERE = Path(__file__).resolve().parent

spec = importlib.util.spec_from_file_location("triage", HERE.parent / "triage.py")

tri = importlib.util.module_from_spec(spec)

sys.modules["triage"] = tri

spec.loader.exec_module(tri)



SEC_EXEC = 0x20000000

SEC_READ = 0x40000000

SEC_WRITE = 0x80000000

SEC_CODE = 0x00000020

SEC_INIT_DATA = 0x00000040





def build_pe(*, sections=((".text", b"\x90" * 512, SEC_CODE | SEC_EXEC | SEC_READ),),

             imports=None, is64=True, dll=False, entry=0x1000) -> bytes:

    """Assemble a structurally valid PE.



    `imports` is [(dll_name, [function, ...]), ...], written at RVA 0x2000.



    Layout rule that made this fixture wrong once already: every section body is written at

    the offset its own header declares, not at "wherever appending happens to land". The

    header area can be shorter than the declared raw pointer, and appending silently drops

    that gap, shifting every section and hiding the import table from the parser.

    """

    opt_size = 240 if is64 else 224

    header_end = 0x80 + 24 + opt_size + 40 * len(sections)

    align = 0x200

    raw_ptr = (header_end + align - 1) // align * align



    sec_rva = 0x1000

    first_size = max(len(sections[0][1]), align)

    # The first section must span RVA 0x1000..0x2000 so the import table at RVA 0x2000 is

    # inside a mapped region.

    first_size = max(first_size, 0x1400) if imports else first_size



    layout = []

    cursor = raw_ptr

    vaddr = sec_rva

    for i, (name, body, chars) in enumerate(sections):

        raw_size = first_size if i == 0 else max(len(body), align)

        layout.append({"name": name, "body": body, "chars": chars,

                       "vaddr": vaddr, "rawptr": cursor, "rawsize": raw_size})

        vaddr += 0x1000

        cursor += raw_size

    total = cursor



    sec_table = b"".join(

        s["name"].encode().ljust(8, b"\x00")

        + struct.pack("<IIII", s["rawsize"], s["vaddr"], s["rawsize"], s["rawptr"])

        + struct.pack("<IIHHI", 0, 0, 0, 0, s["chars"])

        for s in layout)



    opt = bytearray(opt_size)

    struct.pack_into("<H", opt, 0, 0x20B if is64 else 0x10B)

    struct.pack_into("<I", opt, 16, entry)

    struct.pack_into("<Q" if is64 else "<I", opt, 24, 0x140000000 if is64 else 0x400000)

    struct.pack_into("<II", opt, 32, 0x1000, 0x1000)

    struct.pack_into("<HH", opt, 40, 6, 0)

    struct.pack_into("<II", opt, 56, 0x2000, 0x200)

    struct.pack_into("<H", opt, 68, 3)

    struct.pack_into("<I", opt, 108 if is64 else 92, 16)

    ddir = 112 if is64 else 96

    if imports:

        # The import descriptors sit at the very start of the section, i.e. RVA 0x1000.

        # The table must be described where it actually is: the classic way to build a

        # fixture that parses as "no imports" is to point the directory somewhere empty.

        struct.pack_into("<II", opt, ddir + 8, 0x1000, 0x200)



    characteristics = (0x2102 | (0x2000 if dll else 0)) & 0xFFFF

    coff = struct.pack("<HHIIIHH", 0x8664 if is64 else 0x14C, len(sections), 0x60000000,

                       0, 0, opt_size, characteristics)



    out = bytearray(total)

    out[0:2] = b"MZ"

    struct.pack_into("<I", out, 0x3C, 0x80)

    pos = 0x80

    out[pos:pos + 4] = b"PE\x00\x00"

    out[pos + 4:pos + 4 + len(coff)] = coff

    out[pos + 24:pos + 24 + opt_size] = bytes(opt)

    out[pos + 24 + opt_size:pos + 24 + opt_size + len(sec_table)] = sec_table



    for i, s in enumerate(layout):

        body = bytearray(s["rawsize"])

        body[0:len(s["body"])] = s["body"]

        if i == 0 and imports:

            # Import layout, written the way the loader reads it:

            #   [descriptors][thunk arrays][hint/name entries][dll name strings]

            # The descriptor's FirstThunk points at a thunk ARRAY, and each array entry holds

            # the RVA of a hint/name entry (hint word + name + NUL). Writing the names

            # directly at the thunk RVA instead is the classic way to end up with an import

            # table that parses but yields no function names.

            desc_size = len(imports) * 20 + 20

            thunk_size = sum((len(funcs) + 1) * 8 for _n, funcs in imports)

            cursor_off = desc_size + thunk_size

            descriptors = bytearray()

            thunk_blob = bytearray()

            names_blob = bytearray()

            dll_entries = []

            for name, funcs in imports:

                name_rvas = []

                for f in funcs:

                    name_rvas.append(0x1000 + cursor_off)

                    names_blob += struct.pack("<H", 0) + f.encode() + b"\x00"

                    cursor_off += 2 + len(f) + 1

                dll_entries.append((struct.pack("<IIIII", 0, 0, 0, 0, 0), name_rvas))

            dll_rvas = []

            for name, _funcs in imports:

                dll_rvas.append(0x1000 + cursor_off)

                names_blob += name.encode() + b"\x00"

                cursor_off += len(name) + 1

            # thunk arrays follow the descriptors

            # tcur is an RVA (section base 0x1000 + body offset); the body writes below use

            # the bare offset. Mixing the two spaces is what left FirstThunk pointing at 0x28,

            # i.e. outside any mapped region.

            tcur = 0x1000 + desc_size

            for (name, funcs), dll_rva, name_rvas in zip(imports, dll_rvas, [e[1] for e in dll_entries]):

                for rva in name_rvas:

                    thunk_blob += struct.pack("<Q" if is64 else "<I", rva)

                thunk_blob += struct.pack("<Q" if is64 else "<I", 0)

                # tcur and dll_rva are already section-relative RVAs (they were built from

                # 0x1000 + offset). Adding sec_rva again is what made the loader-side name

                # pointer land 0x1000 past the string it was supposed to describe.

                descriptors += struct.pack("<IIIII", tcur, 0, 0, dll_rva, tcur)

                tcur += (len(funcs) + 1) * (8 if is64 else 4)

                if not is64:

                    pass

            descriptors += b"\x00" * 20

            body[0:len(descriptors)] = descriptors

            body[desc_size:desc_size + len(thunk_blob)] = thunk_blob

            body[desc_size + thunk_size:desc_size + thunk_size + len(names_blob)] = names_blob

        out[s["rawptr"]:s["rawptr"] + s["rawsize"]] = body

    return bytes(out)



class TestIdentification(unittest.TestCase):

    def test_magic_beats_extension(self):

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "invoice.png"

            p.write_bytes(build_pe())

            r = tri.build_report(p, None)

        self.assertEqual(r["identified_as"]["kind"], "pe")

        self.assertIn("PE executable", r["name_looks_wrong"] or "")



    def test_unknown_bytes_are_not_guessed_from_the_name(self):

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "mystery.exe"

            p.write_bytes(b"\x01\x02\x03\x04" * 64)

            r = tri.build_report(p, None)

        self.assertEqual(r["identified_as"]["kind"], "unknown")

        self.assertIsNone(r["pe"])



    def test_zip_container_is_recognised(self):

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "x.bin"

            p.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

            r = tri.build_report(p, None)

        self.assertEqual(r["identified_as"]["kind"], "zip")





class TestPeAnalysis(unittest.TestCase):

    def test_sections_are_parsed_with_flags(self):

        d = build_pe(sections=((".text", b"\x90" * 512, SEC_CODE | SEC_EXEC | SEC_READ),

                               (".data", b"\x11" * 512, SEC_INIT_DATA | SEC_READ | SEC_WRITE)))

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "a.exe"

            p.write_bytes(d)

            r = tri.build_report(p, None)

        pe = r["pe"]

        self.assertIsNotNone(pe)

        self.assertEqual([s["name"] for s in pe["sections"]], [".text", ".data"])

        self.assertTrue(pe["sections"][0]["executable"])

        self.assertFalse(pe["sections"][0]["writable"])

        self.assertTrue(pe["sections"][1]["writable"])

        self.assertGreaterEqual(min(s["entropy"] for s in pe["sections"]), 0.0)



    def test_uniform_section_has_zero_entropy(self):

        d = build_pe(sections=((".text", b"\x90" * 1024, SEC_CODE | SEC_EXEC | SEC_READ),))

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "z.exe"

            p.write_bytes(d)

            r = tri.build_report(p, None)

        self.assertAlmostEqual(r["pe"]["sections"][0]["entropy"], 0.0, places=3)



    def test_high_entropy_executable_section_is_flagged(self):

        blob = bytes(range(256)) * 8

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "packed.exe"

            p.write_bytes(build_pe(sections=((".text", blob, SEC_CODE | SEC_EXEC | SEC_READ),)))

            r = tri.build_report(p, None)

        self.assertGreater(r["pe"]["sections"][0]["entropy"], 7.2)

        self.assertIn("high-entropy executable", " ".join(r["assessment"]["reasons"]))



    def test_packer_section_names_are_recognised(self):

        d = build_pe(sections=(("UPX0", b"\x00" * 512, SEC_EXEC | SEC_READ),

                               ("UPX1", b"\x00" * 512, SEC_EXEC | SEC_READ)))

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "u.exe"

            p.write_bytes(d)

            r = tri.build_report(p, None)

        self.assertIn("UPX", [f["packer"] for f in r["packer"]["findings"]])



    def test_upx_marker_scan(self):

        d = build_pe() + b"UPX!" + b"\x00" * 32 + b"UPX!"

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "u2.exe"

            p.write_bytes(d)

            r = tri.build_report(p, None)

        self.assertIn("UPX", [f["packer"] for f in r["packer"]["findings"]])



    def test_imports_are_parsed(self):

        d = build_pe(imports=[("KERNEL32.dll", ["CreateFileW", "VirtualAlloc"])])

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "i.exe"

            p.write_bytes(d)

            r = tri.build_report(p, None)

        self.assertTrue(r["imports"], "the import table should have been parsed")

        self.assertIn("KERNEL32.dll", [i["dll"] for i in r["imports"]])

        got = {f for i in r["imports"] for f in i["functions"]}

        self.assertIn("CreateFileW", got)



    def test_embedded_pe_is_carved(self):

        d = build_pe() + build_pe()

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "dropper.exe"

            p.write_bytes(d)

            r = tri.build_report(p, None)

        self.assertTrue(r["embedded_executables"])

        self.assertGreater(r["embedded_executables"][0]["offset"], 0)





class TestInjectionTriad(unittest.TestCase):

    """The triad must fire in single-file triage, not only in batch scan mode."""



    def test_triad_is_reported_for_a_single_file(self):

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "svchost.exe"

            p.write_bytes(build_pe(imports=[("KERNEL32.dll", [

                "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"])]))

            r = tri.build_report(p, None)

        joined = " ".join(r["assessment"]["reasons"])

        self.assertIn("injection triad", joined)



    def test_virtualalloc_alone_is_not_the_triad(self):

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "jit.dll"

            p.write_bytes(build_pe(imports=[("KERNEL32.dll", ["VirtualAlloc"])]))

            r = tri.build_report(p, None)

        joined = " ".join(r["assessment"]["reasons"])

        self.assertNotIn("injection triad", joined)





class TestResourceGuard(unittest.TestCase):

    """The whole file is loaded, so size has to be bounded somewhere the caller can see."""



    def test_oversized_input_is_refused_with_a_usable_message(self):

        with tempfile.TemporaryDirectory() as t:

            big = Path(t) / "big.bin"

            big.write_bytes(b"MZ" + bytes(2 << 20))
            with self.assertRaises(SystemExit) as ctx:

                tri.build_report(big, None, max_bytes=1 << 20)

            msg = str(ctx.exception)

        self.assertIn("analysis limit", msg)

        self.assertIn("--max-bytes", msg)

        self.assertIn("--force", msg)



    def test_force_overrides_the_guard(self):

        with tempfile.TemporaryDirectory() as t:
            big = Path(t) / "big.bin"
            big.write_bytes(build_pe() + bytes(2 << 20))
            r = tri.build_report(big, None, max_bytes=1 << 20, force=True)

        self.assertEqual(r["identified_as"]["kind"], "pe")



    def test_a_file_within_the_limit_is_not_refused(self):

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "ok.bin"

            p.write_bytes(build_pe())

            r = tri.build_report(p, None, max_bytes=1 << 20)

        self.assertEqual(r["identified_as"]["kind"], "pe")



    def test_the_default_limit_is_finite_and_generous(self):

        self.assertGreater(tri.DEFAULT_MAX_BYTES, 64 << 20)

        self.assertLess(tri.DEFAULT_MAX_BYTES, 8 << 30)



    def test_cli_exposes_both_controls(self):

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "x.bin"

            p.write_bytes(build_pe() + bytes(2 << 20))
            # Over the limit the CLI exits rather than returning, so a caller cannot miss the
            # refusal by ignoring a return value.
            with self.assertRaises(SystemExit):
                tri.main([str(p), "--max-bytes", str(1 << 20), "--quiet"])
            self.assertEqual(
                tri.main([str(p), "--max-bytes", str(1 << 20), "--force", "--quiet"]), 0)





class TestWrappers(unittest.TestCase):

    def _pyinstaller(self) -> bytes:

        pkg_len, toc_len = 500, 64

        cookie = struct.pack("!8sIIII64s", tri.MEI_COOKIE, pkg_len, 100, toc_len, 312,

                             b"python312.dll".ljust(64, b"\x00"))

        return build_pe() + b"PYZ\x00" + b"\xcb\r\r\n" + b"\x00" * pkg_len + cookie



    def test_pyinstaller_cookie_is_found_and_read(self):

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "frozen.exe"

            p.write_bytes(self._pyinstaller())

            r = tri.build_report(p, None)

        w = r["wrapper"]

        self.assertIsNotNone(w)

        self.assertEqual(w["wrapper"], "PyInstaller")

        self.assertEqual(w["python_version"], "3.12")

        self.assertEqual(w["python_library"], "python312.dll")

        self.assertTrue(w["has_pyz"])



    def test_unpack_plan_says_pyinstaller_needs_no_execution(self):

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "frozen2.exe"

            p.write_bytes(self._pyinstaller())

            r = tri.build_report(p, None)

        steps = [s for s in r["unpack_plan"] if "PyInstaller" in s["step"]]

        self.assertTrue(steps)

        self.assertFalse(steps[0]["needs_execution"])



    def test_packer_plan_refuses_to_run_the_sample(self):

        d = build_pe(sections=(("UPX0", b"\x00" * 512, SEC_EXEC | SEC_READ),

                               ("UPX1", b"\x00" * 512, SEC_EXEC | SEC_READ)))

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "packed.exe"

            p.write_bytes(d)

            r = tri.build_report(p, None)

        runtime = [s for s in r["unpack_plan"] if s["needs_execution"]]

        self.assertTrue(runtime, "a runtime packer should produce an execution-required step")

        self.assertIn("will not do it", runtime[0]["warning"])



    def test_never_executes_the_target(self):

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "whatever.exe"

            p.write_bytes(build_pe())

            r = tri.build_report(p, None)

        self.assertIs(r["executed_target"], False)





class TestIndicators(unittest.TestCase):

    def test_noise_domains_and_private_ips_are_filtered(self):

        blob = (b"http://schemas.microsoft.com/SMI/2016/WindowsSettings "

                b"https://evil-c2.top/gate.php "

                b"10.0.0.5 192.168.1.1 203.0.113.9 45.77.12.9 version=6.0.0.0 "

                b"admin@evil-c2.top")

        got = tri.extract_iocs(blob)

        self.assertNotIn("http://schemas.microsoft.com/SMI/2016/WindowsSettings",

                         got.get("url", []))

        self.assertIn("https://evil-c2.top/gate.php", got.get("url", []))

        for private in ("10.0.0.5", "192.168.1.1"):

            self.assertNotIn(private, got.get("ipv4", []))

        self.assertIn("45.77.12.9", got.get("ipv4", []))

        self.assertIn("evil-c2.top", got.get("domain", []))

        self.assertIn("admin@evil-c2.top", got.get("email", []))



    def test_persistence_strings_are_extracted(self):

        blob = (b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater "

                b"HKLM\\SYSTEM\\CurrentControlSet\\Services\\BadSvc "

                b"schtasks /create /tn Evil /tr evil.exe "

                b"Add-MpPreference -ExclusionPath C:\\")

        got = tri.extract_iocs(blob)

        for kind in ("registry_run", "registry_path", "scheduled_task", "defender_exclusion"):

            self.assertIn(kind, got, "missing %s" % kind)



    def test_wide_strings_are_read(self):

        got = tri.extract_strings("C:\\Users\\Public\\evil.dll".encode("utf-16-le"))

        self.assertIn("evil.dll", " ".join(got["interesting"]))



    def test_base64_blob_is_decoded(self):

        token = b64.b64encode(b"MZ" + b"\x00" * 30).decode()

        got = tri.base64_candidates({"interesting": ["config=" + token]})

        self.assertTrue(got)

        self.assertTrue(got[0]["decoded_is_pe"], "a base64 PE should be recognisable")





class TestReportAndCli(unittest.TestCase):

    def test_yara_draft_is_labelled_unreviewed(self):

        with tempfile.TemporaryDirectory() as t:

            p = Path(t) / "s.exe"

            p.write_bytes(build_pe() + b"http://evil-c2.top/gate http://evil-c2.top/gate")

            r = tri.build_report(p, None)

        self.assertIn("UNREVIEWED", r["yara_draft"])

        self.assertIn("uint16(0) == 0x5A4D", r["yara_draft"])



    def test_cli_writes_report_and_rule(self):

        with tempfile.TemporaryDirectory() as t:

            src = Path(t) / "sample.bin"

            src.write_bytes(build_pe(imports=[("KERNEL32.dll", ["VirtualAlloc"])]))

            out = Path(t) / "out"

            self.assertEqual(tri.main([str(src), "-o", str(out), "--quiet"]), 0)

            report = json.loads((out / "report.json").read_text(encoding="utf-8"))

            self.assertEqual(report["identified_as"]["kind"], "pe")

            self.assertTrue((out / "rule.yar").is_file())



    def test_cli_rejects_missing_path(self):

        self.assertEqual(tri.main(["no-such-file-xyz.bin"]), 1)





if __name__ == "__main__":

    unittest.main(verbosity=2)