# -*- coding: utf-8 -*-
"""`FORMAT_MATRIX.md` and the `MAGIC` table in `torikago.py`, kept from drifting apart.

The pairing is what makes the document worth reading: a table nothing checks is a table somebody
edited a year ago, and the failure mode of a hand-maintained format list is not a crash -- it is a
list that is quietly missing the entry you need, with every test still green because no test ever
looked at the list.

Three things are asserted, and they fail in three different ways:

* **the same entries.** The document's rows and `MAGIC` are compared as multisets, so a row dropped
  from either side goes red, and so does a `kind` changed on one side only. A multiset rather than a
  set, because `MAGIC` legitimately carries two `zip` prefixes and two `macho` ones -- a set
  comparison would let "the document lists `zip` once" pass.
* **the same behaviour.** Every prefix parsed out of the document is fed to `identify()`, which must
  return that row's `kind`. This is the assertion the other two cannot make: the table and the code
  can agree with each other while `identify()` walks a different list.
* **the gaps are written down.** A table of what is accepted, read alone, implies that everything
  outside it is a malformed specimen of something inside it. The document has to say what it does
  not recognise, and that section has to survive editing as well as the table does.

The order of the list is deliberately not asserted. `MAGIC` is read as a set of prefixes and no
prefix is a prefix of another, so order cannot change an answer -- asserting it would be pinning
something that does not matter, which is how a test starts failing for no reason.
"""
from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent

spec = importlib.util.spec_from_file_location("tk_formats", REPO / "torikago.py")
tk = importlib.util.module_from_spec(spec)
sys.modules["tk_formats"] = tk
spec.loader.exec_module(tk)

MATRIX = REPO / "FORMAT_MATRIX.md"

# One row of the table: a backticked hex prefix, then a backticked kind, then two free cells.
# Deliberately strict about the backticks -- the other tables in the document also have cells that
# look like words, and a looser pattern would start reading them as formats.
ROW = re.compile(r"^\|\s*`([0-9A-Fa-f ]+)`\s*\|\s*`([a-z0-9]+)`\s*\|", re.M)


def documented_rows() -> list:
    """The table as the document states it: [(prefix as bytes, kind)]."""
    text = MATRIX.read_text(encoding="utf-8")
    rows = []
    for hex_digits, kind in ROW.findall(text):
        clean = hex_digits.replace(" ", "")
        if len(clean) % 2:
            raise AssertionError(
                "the prefix `%s` in FORMAT_MATRIX.md has an odd number of hex digits, which means "
                "it was written without its spaces or with one missing" % hex_digits)
        rows.append((bytes.fromhex(clean), kind))
    return rows


class TestTheDocumentExistsAndIsReadable(unittest.TestCase):
    def test_the_matrix_document_exists(self):
        self.assertTrue(MATRIX.is_file(), "FORMAT_MATRIX.md is missing from the repository root")

    def test_the_table_can_be_parsed_at_all(self):
        """A regex that matches nothing would make every comparison below vacuously true."""
        rows = documented_rows()
        self.assertGreater(len(rows), 10,
                           "only %d rows parsed out of FORMAT_MATRIX.md -- the table changed shape "
                           "and this file stopped reading it" % len(rows))


class TestTheDocumentAndTheTableAgree(unittest.TestCase):
    """The two directions, as multisets.

    Dropping a row from one side, adding one to the other, or changing a `kind` in one place are
    three different mistakes and all three land here.
    """

    def test_the_same_entries_in_both_directions(self):
        documented = Counter(documented_rows())
        in_code = Counter((prefix, kind) for prefix, _label, kind in tk.MAGIC)
        self.assertEqual(documented, in_code,
                         "FORMAT_MATRIX.md and MAGIC disagree.\n"
                         "  documented but not in code: %s\n"
                         "  in code but not documented: %s" % (
                             sorted(k for k in documented if documented[k] > in_code.get(k, 0)),
                             sorted(k for k in in_code if in_code[k] > documented.get(k, 0))))

    def test_the_documented_count_is_the_real_count(self):
        """The summary says how many prefixes there are; a stale summary is the same defect."""
        text = MATRIX.read_text(encoding="utf-8")
        stated = re.search(r"\|\s*prefixes in the table\s*\|\s*\*\*(\d+)\*\*\s*\|", text)
        self.assertIsNotNone(stated, "the summary no longer states how many prefixes there are")
        self.assertEqual(int(stated.group(1)), len(tk.MAGIC))

    def test_the_documented_kind_count_is_the_real_count(self):
        text = MATRIX.read_text(encoding="utf-8")
        stated = re.search(r"\|\s*distinct kinds\s*\|\s*\*\*(\d+)\*\*", text)
        self.assertIsNotNone(stated, "the summary no longer states how many kinds there are")
        self.assertEqual(int(stated.group(1)), len({kind for _p, _l, kind in tk.MAGIC}))


class TestIdentifyFollowsTheTable(unittest.TestCase):
    """Not a comparison of two lists -- a comparison of the list against the behaviour."""

    def test_every_documented_prefix_is_identified_as_its_kind(self):
        for prefix, kind in documented_rows():
            with self.subTest(prefix=prefix.hex(" ").upper()):
                got = tk.identify(prefix + b"\x00" * 32, Path("sample.bin"))
                self.assertEqual(got["kind"], kind,
                                 "%s is documented as %s but identify() says %s" % (
                                     prefix.hex(" ").upper(), kind, got["kind"]))
                self.assertEqual(got["by"], "magic")

    def test_the_reported_prefix_is_the_one_that_matched(self):
        """`identify` reports the prefix, so a wrong-but-shorter entry would be visible rather than
        silently matching a longer documented one first."""
        for prefix, kind in documented_rows():
            with self.subTest(prefix=prefix.hex(" ").upper()):
                got = tk.identify(prefix + b"\x00" * 32, Path("sample.bin"))
                self.assertEqual(got["prefix"], prefix.hex())

    def test_something_with_no_prefix_is_unknown_rather_than_guessed(self):
        """The fallthrough, which is the half a table of matches never covers."""
        got = tk.identify(b"\x00\x01\x02\x03" * 8, Path("sample.unknown"))
        self.assertEqual(got["kind"], "unknown")
        self.assertEqual(got["label"], "unrecognised")


class TestTheGapsAreWrittenDown(unittest.TestCase):
    """A list of what is accepted, alone, reads as a list of everything that exists."""

    def setUp(self):
        self.text = MATRIX.read_text(encoding="utf-8")
        self.flat = " ".join(self.text.split())

    def test_the_unrecognised_section_exists(self):
        self.assertIn("What this tool does not recognise", self.text)

    def test_it_says_which_formats_needs_an_offset(self):
        """The structural limit is the one a reader would otherwise read as an oversight."""
        for name in ("WebP", "MP4", "tar"):
            with self.subTest(format=name):
                self.assertIn(name, self.text)

    def test_it_names_the_formats_measured_at_the_wrong_offset(self):
        self.assertIn("RIFF", self.text)
        self.assertIn("ftyp", self.text)

    def test_it_records_the_shared_prefixes(self):
        """A prefix that identifies a family is not a wrong answer, but a reader has to know."""
        self.assertIn("Shared prefixes", self.text)
        self.assertIn("Java class", self.text)

    def test_it_records_the_measured_mz_versus_broken_pe_table(self):
        """The F-2 measurement: not a claim, a table with a `None` in it."""
        self.assertIn("parse_pe()", self.flat)
        self.assertIn("damaged PE", self.text)

    def test_it_says_the_mz_entry_is_not_an_identification(self):
        """`MZ` is the only row that says where to look rather than what is there."""
        self.assertIn("is **not** an identification", self.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
