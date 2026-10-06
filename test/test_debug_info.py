# -*- coding: utf-8 -*-

"""Debug information: the PE debug directory, and a .pdb beside the binary.



Two findings live here, and they are different in kind.



**The CodeView record** is in the PE itself. It names the .pdb's absolute path *on the build

machine*, which gives away the project, the source layout and the build configuration with no

second file involved at all. A real sample yielded the whole

`...\\PowerfulWindSlickedBackHairCS-LX_Improve\\...\\obj\\Debug\\....pdb` path.



**The .pdb**, when it shipped, is a disclosure: type names, method names, source paths. On that

same sample the type and method names were recoverable in seconds.



The bug that shaped these tests: the stream directory of a real native PDB resolved several

streams to the same wrong block, and the code still produced a GUID-shaped value from it. That

became a confident **"this .pdb does NOT match this binary"** -- on the .pdb that was, in fact,

its .pdb. A false denial is worse than no answer, so the information stream is now located by the

version marker it must begin with, and an unvalidated stream yields `None` rather than a number.



Run:

    python -m unittest discover -s test -v

"""

from __future__ import annotations



import importlib.util

import shutil

import struct

import sys

import tempfile

import unittest

from pathlib import Path



HERE = Path(__file__).resolve().parent

sys.path.insert(0, str(HERE))





def _load_module():

    spec = importlib.util.spec_from_file_location("torikago_dbg", HERE.parent / "torikago.py")

    mod = importlib.util.module_from_spec(spec)

    sys.modules["torikago_dbg"] = mod

    spec.loader.exec_module(mod)

    return mod





tk = _load_module()





def build_pe_with_codeview(pdb_path: str, guid: bytes, age: int = 1,

                           codeview=b"RSDS") -> bytes:

    """A minimal but structurally valid PE carrying one CodeView debug directory entry.



    Layout is computed from the declared sizes rather than discovered by appending, because

    appending is precisely how a fixture like this ends up lying about its own structure. With

    align = 1 the file offset equals the RVA, which makes the arithmetic checkable by hand:



        pe_off   = 0x80

        opt_size = 240 (PE32+)

        nsec     = 1

        sec_table= pe_off + 24 + 240           = 0x188

        sec_raw  = sec_table + 40              = 0x1B0

        cv_rva   = 0x1000                      -> cv_off  = 0x1B0

        dd_rva   = cv_rva + len(debug record)  -> dd_off  = 0x1B0 + len(cv)

    """

    cv = codeview + guid + struct.pack("<I", age) + pdb_path.encode("utf-8") + b"\x00"

    debug_dir = struct.pack("<IIHHIIII",

                            0,            # characteristics

                            0x5F5E1000,   # timestamp

                            0, 0,         # version

                            2,            # type = IMAGE_DEBUG_TYPE_CODEVIEW

                            len(cv),      # size of data

                            0,            # address of raw data

                            0)            # pointer to raw data -- patched below

    align = 1

    pe_off = 0x80

    opt_size = 240

    sec_table = pe_off + 24 + opt_size

    raw_ptr = sec_table + 40

    cv_off = raw_ptr

    dd_off = cv_off + len(cv)

    dd_rva = 0x1000 + len(cv)



    total = dd_off + len(debug_dir)



    # DOS header

    out = bytearray(b"\x00" * total)

    out[0:2] = b"MZ"

    struct.pack_into("<I", out, 0x3C, pe_off)

    out[pe_off:pe_off + 4] = b"PE\x00\x00"

    struct.pack_into("<HHIIIHH", out, pe_off + 4,

                     0x8664,      # machine = x64

                     1,           # sections

                     0x5F5E1000,  # timestamp

                     0, 0,        # symbol table

                     opt_size,    # size of optional header

                     0x22)        # characteristics (executable | large address aware)

    opt = pe_off + 24

    struct.pack_into("<H", out, opt, 0x20B)          # PE32+

    struct.pack_into("<I", out, opt + 16, 0x1000)    # entry point

    struct.pack_into("<Q", out, opt + 24, 0x140000000)  # image base

    # How many data directories this file claims. Needed since parse_pe started obeying it: without
    # it the field reads as zero, no directories are parsed, and the fixture looks like a PE with no
    # debug directory at all -- which is a pass for the wrong reason rather than a failure.
    struct.pack_into("<I", out, opt + 108, 16)       # NumberOfRvaAndSizes (PE32+ offset)
    struct.pack_into("<I", out, opt + 56, align)     # section alignment

    struct.pack_into("<I", out, opt + 60, align)     # file alignment

    # data directory 6 = debug

    struct.pack_into("<II", out, opt + 112 + 6 * 8, dd_rva, len(debug_dir))

    # section header

    out[sec_table:sec_table + 8] = b".rdata\x00\x00"

    struct.pack_into("<IIII", out, sec_table + 8,

                     total - raw_ptr,   # virtual size

                     0x1000,            # virtual address

                     total - raw_ptr,   # size of raw data

                     raw_ptr)           # pointer to raw data

    struct.pack_into("<I", out, sec_table + 36, 0x40000040)  # initialized data | read



    out[cv_off:cv_off + len(cv)] = cv

    struct.pack_into("<II", out, dd_off, 0, 0x5F5E1000)

    struct.pack_into("<HHIIII", out, dd_off + 8, 0, 0, 2, len(cv), 0, cv_off)

    return bytes(out)





def build_msf(info: bytes, extra_streams=()) -> bytes:
    """A small MSF container for the marker tests.

    Deliberately minimal: it places the given stream and a directory, and it is used only by tests
    that exercise *validation* -- whether a stream that begins with the PDB version marker is read,
    and whether one that does not is refused. Nothing here asserts that the reader agrees with this
    builder about a real container's layout, because a fixture cannot establish that.
    """
    block_size = 512
    streams = [info] + list(extra_streams)

    sized, nxt = [], 1
    for data in streams:
        count = max(1, (len(data) + block_size - 1) // block_size)
        sized.append((data, list(range(nxt, nxt + count))))
        nxt += count

    directory = struct.pack("<I", len(streams))
    for data, blocks in sized:
        directory += struct.pack("<II", 0, len(data))
        directory += struct.pack("<%dI" % len(blocks), *blocks)
    dir_blocks = (len(directory) + block_size - 1) // block_size
    dir_start = nxt
    nxt += dir_blocks

    map_start = nxt
    total = map_start + 1
    while True:
        need = (total * 4 + block_size - 1) // block_size
        if map_start + need == total:
            break
        total = map_start + need

    out = bytearray()
    out += tk.MSF_MAGIC
    out += struct.pack("<IIIIII", block_size, 0xFFFFFFFF, total, dir_blocks * block_size,
                       0, map_start)
    out += bytes(block_size - len(out))
    for data, blocks in sized:
        out += data + bytes(len(blocks) * block_size - len(data))
    out += directory + bytes(dir_blocks * block_size - len(directory))

    locations = list(range(map_start))
    locations.append(dir_start)
    locations += [map_start] * (total - map_start - 1)
    mapping = b"".join(struct.pack("<I", b) for b in locations)
    mapping += bytes((total - map_start) * block_size - len(mapping))
    out += mapping
    return bytes(out)


class TestMarkerValidation(unittest.TestCase):
    """The bug fix these tests exist for, tested without depending on a container layout.

    The real PDB this was found on had a stream directory that resolved several streams to the
    same wrong block, and the reader produced a GUID-shaped value out of it anyway -- which became
    a confident "this .pdb does NOT match this binary" about the .pdb that did. So the information
    stream is located by the marker it must begin with, and an unvalidated one yields None.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="tk-marker-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_a_stream_with_the_marker_is_found(self):
        guid = bytes.fromhex("0b39e64e375b421496d0c2fd5d14b79b")
        blob = struct.pack("<III", 20000404, 0x1234, 1) + guid
        found = tk._find_pdb_info_stream(blob)
        self.assertIsNotNone(found)
        self.assertEqual(found[2], 1)                 # age
        self.assertEqual(found[3], guid)

    def test_an_implausible_age_is_refused(self):
        blob = struct.pack("<III", 20000404, 0x1234, 0x7FFFFFFF) + bytes(range(16))
        self.assertIsNone(tk._find_pdb_info_stream(blob))

    def test_an_all_zero_guid_is_refused(self):
        blob = struct.pack("<III", 20000404, 0x1234, 1) + bytes(16)
        self.assertIsNone(tk._find_pdb_info_stream(blob))

    def test_a_wrong_version_is_refused(self):
        blob = struct.pack("<III", 20000405, 0x1234, 1) + bytes(range(16))
        self.assertIsNone(tk._find_pdb_info_stream(blob))

    def test_a_truncated_marker_is_refused(self):
        self.assertIsNone(tk._find_pdb_info_stream(struct.pack("<III", 20000404, 1, 1)))

    def test_the_marker_is_found_later_in_a_larger_blob(self):
        """The stream sits at an arbitrary offset in the file, which is the whole point of
        locating it by content rather than by trusting the directory."""
        guid = bytes.fromhex("ff" * 16)
        blob = b"\x00" * 3000 + struct.pack("<III", 20000404, 9, 5) + guid
        found = tk._find_pdb_info_stream(blob)
        self.assertIsNotNone(found)
        self.assertEqual(found[3], guid)

    def test_no_marker_anywhere_gives_none(self):
        self.assertIsNone(tk._find_pdb_info_stream(b"\x00" * 5000 + b"nothing here"))

    def test_read_pdb_on_a_container_without_a_marker_reports_unknown(self):
        pdb = self.tmp / "nopdb.pdb"
        pdb.write_bytes(build_msf(bytes(64)))
        got = tk.read_pdb(pdb)
        self.assertEqual(got["format"], "msf-native-pdb")
        self.assertIsNone(got.get("guid"))
        self.assertIn("not located", got.get("info_stream", ""))


class TestCodeViewRecord(unittest.TestCase):

    """The PE-side finding needs no second file."""



    def setUp(self):

        self.tmp = Path(tempfile.mkdtemp(prefix="tk-dbg-"))



    def tearDown(self):

        shutil.rmtree(self.tmp, ignore_errors=True)



    def test_the_build_time_pdb_path_is_recovered(self):

        path = r"D:\Development\SomeProject\obj\Debug\SomeProject.pdb"

        f = self.tmp / "a.exe"

        f.write_bytes(build_pe_with_codeview(path, bytes(range(16))))

        data = f.read_bytes()

        info = tk.analyse_debug_info(data, tk.parse_pe(data), f)

        self.assertTrue(info["available"])

        self.assertEqual(info["build_pdb_path"], path)



    def test_the_guid_and_age_are_recovered(self):

        guid = bytes.fromhex("0b39e64e375b421496d0c2fd5d14b79b")

        f = self.tmp / "a.exe"

        f.write_bytes(build_pe_with_codeview(r"C:\x\y.pdb", guid, age=7))

        data = f.read_bytes()

        info = tk.analyse_debug_info(data, tk.parse_pe(data), f)

        cv = info["codeview"]

        self.assertEqual(cv["age"], 7)

        self.assertEqual(cv["guid"], "0b39e64e-375b-4214-96d0-c2fd5d14b79b")



    def test_the_build_machine_directories_are_listed(self):

        path = r"D:\Development\OpenSource\Proj\obj\Debug\Proj.pdb"

        f = self.tmp / "a.exe"

        f.write_bytes(build_pe_with_codeview(path, bytes(range(16))))

        data = f.read_bytes()

        info = tk.analyse_debug_info(data, tk.parse_pe(data), f)

        self.assertIn("Development", info["build_machine_dirs"])

        self.assertIn("Debug", info["build_machine_dirs"])



    def test_a_binary_without_a_debug_directory_is_not_claimed_to_have_one(self):

        f = self.tmp / "plain.exe"

        f.write_bytes(b"MZ" + b"\x00" * 0x40 + b"\x00" * 512)

        info = tk.analyse_debug_info(f.read_bytes(), tk.parse_pe(f.read_bytes()), f)

        self.assertFalse(info["available"])



    def test_a_non_pe_does_not_crash(self):

        f = self.tmp / "x.txt"

        f.write_bytes(b"just text")

        info = tk.analyse_debug_info(f.read_bytes(), None, f)

        self.assertFalse(info["available"])





class TestItReachesTheReport(unittest.TestCase):



    def setUp(self):

        self.tmp = Path(tempfile.mkdtemp(prefix="tk-rep-"))



    def tearDown(self):

        shutil.rmtree(self.tmp, ignore_errors=True)



    def test_a_common_observation_is_not_a_reason(self):

        """The separation the sweep forced: `reasons` is what is unusual, `notes` is what is merely

        true, and `attention` counts only the first. Without this, five facts true of everything

        weigh the same as one destructive finding."""

        f = self.tmp / "a.exe"

        f.write_bytes(build_pe_with_codeview("C:" + chr(92) + "p" + chr(92) + "a.pdb",

                                             bytes(range(16))))

        report = tk.build_report(f, None)

        a = report["assessment"]

        self.assertEqual(a["attention"], len(a["reasons"]))

        for note in a["notes"]:

            self.assertNotIn(note, a["reasons"])



    def test_debug_info_appears_in_the_report(self):

        f = self.tmp / "a.exe"

        f.write_bytes(build_pe_with_codeview(r"D:\Proj\obj\Debug\a.pdb", bytes(range(16))))

        report = tk.build_report(f, None)

        self.assertIn("debug_info", report)

        self.assertTrue(report["debug_info"]["available"])



    def test_the_codeview_path_is_reported_as_an_ordinary_fact(self):

        """It belongs in `notes`, not `reasons`, and the placement is measured rather than

        stylistic: across 298 real binaries, 84.9% record a full build-machine path, because debug

        information survives in ordinary release builds. An earlier claim in this project that the

        signal was "selective rather than noise" came from a 101-file sample and did not survive a

        wider one."""

        f = self.tmp / "a.exe"

        f.write_bytes(build_pe_with_codeview("D:" + chr(92) + "Proj" + chr(92) + "obj"

                                             + chr(92) + "Debug" + chr(92) + "a.pdb",

                                             bytes(range(16))))

        report = tk.build_report(f, None)

        a = report["assessment"]

        self.assertIn("build-time .pdb path", " ".join(a["notes"]))

        self.assertNotIn("build-time .pdb path", " ".join(a["reasons"]),

                         "84.9% of ordinary binaries have this; it must not be ranked")



    def test_a_managed_assembly_is_not_called_high_entropy(self):

        """The same correction the packer verdict already had. A .NET sample's IL sits near the

        top of the entropy range by construction, and this reason had not learned that."""

        data = bytearray(build_pe_with_codeview(r"C:\p\a.pdb", bytes(range(16))))

        report = {"pe": {"sections": [{"name": ".text", "executable": True, "entropy": 7.98}],

                         "directories": {}, "is_dotnet": True},

                  "imports": [], "embedded_executables": []}

        a = tk.assess(report["pe"], {"verdict": "none", "findings": []},

                      {"suspicious": [], "total": 0}, {}, [], [], None, None)

        self.assertNotIn("high-entropy", " ".join(a["reasons"]))

        report["pe"]["is_dotnet"] = False

        b = tk.assess(report["pe"], {"verdict": "none", "findings": []},

                      {"suspicious": [], "total": 0}, {}, [], [], None, None)

        self.assertIn("high-entropy", " ".join(b["reasons"]))





class TestTheDebugDirectoryIsReachable(unittest.TestCase):
    """A head peek cannot see it, and must not be mistaken for absence.

    Measured on both real samples: the debug directory sits at **95% of the file**, because the
    sections carrying it are linked late. The inner-file scan reads only the first 4 MB, so a
    reader driven by that head would have answered "no debug information" -- not an error, a
    silent false negative, on the most informative thing in the directory.
    """

    def setUp(self):
        self.sample = Path(r"D:\PWSBHv1.5.0\PowerfulWindSlickedBackHair.exe")
        if not self.sample.is_file():
            self.skipTest("the real sample is not present on this machine")

    def test_a_head_peek_misses_it(self):
        """Not a defect to fix -- a limitation to be aware of, and the reason the reader seeks."""
        with open(self.sample, "rb") as fh:
            head = fh.read(tk.PEEK_BYTES)
        got = tk.analyse_debug_info(head, tk.parse_pe(head), self.sample)
        self.assertFalse(got.get("available"),
                         "if this ever passes, the head is large enough and the seek is merely "
                         "an optimisation rather than a correctness requirement")

    def test_a_seek_finds_it(self):
        got = tk.analyse_debug_info(self.sample, tk.parse_pe(self.sample.read_bytes()))
        self.assertTrue(got["available"])
        self.assertIn("obj", got["build_pdb_path"].lower())

    def test_the_two_answers_differ_on_the_same_file(self):
        """The whole point, stated as one assertion."""
        with open(self.sample, "rb") as fh:
            head = fh.read(tk.PEEK_BYTES)
        from_head = tk.analyse_debug_info(head, tk.parse_pe(head), self.sample).get("available")
        from_seek = tk.analyse_debug_info(self.sample,
                                          tk.parse_pe(self.sample.read_bytes())).get("available")
        self.assertNotEqual(from_head, from_seek,
                            "the head and the seek must not agree here: that is the bug")
        self.assertFalse(from_head)
        self.assertTrue(from_seek)

    def test_the_debug_directory_really_is_late_in_the_file(self):
        """Keeps the reason for the seek honest: if a future sample has it early, this test says
        so rather than letting the seek look like an arbitrary preference."""
        data = self.sample.read_bytes()
        pe = tk.parse_pe(data)
        dd = (pe.get("directories") or {}).get("debug")
        self.assertIsNotNone(dd)
        off = tk.rva_to_offset(pe, dd["rva"])
        self.assertGreater(off / len(data), 0.5,
                           "the debug directory is not late in this file after all")




if __name__ == "__main__":

    unittest.main(verbosity=2)

