# -*- coding: utf-8 -*-
"""The check that reads the corpus, which nothing did.

`corpus/manifest.jsonl` holds 1,161 measurements of real installed software, and until this existed
the only thing reading it was a test suite exercising the data structures with synthetic input. So a
detector edit could change verdicts on a thousand real files and the only way to learn that was to
remember to re-sweep a drive by hand.

## What is asserted, and the rule that is deliberately not

**It does not assert that verdicts are unchanged.** A change caused by a detector edit is *expected*;
a change nobody expected is a bug. Software cannot tell those apart, and a check that tried would
either fail on every intentional change or pass on every accidental one.

    the check makes differences visible; a person decides whether they were intended

The tests below therefore assert that differences are **found and reported**, not that they are absent.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

spec = importlib.util.spec_from_file_location("cv", HERE.parent / "corpus_verify.py")
cv = importlib.util.module_from_spec(spec)
sys.modules["cv"] = cv
spec.loader.exec_module(cv)

cspec = importlib.util.spec_from_file_location("cvm", HERE.parent / "corpus.py")
cvm = importlib.util.module_from_spec(cspec)
sys.modules["cvm"] = cvm
cspec.loader.exec_module(cvm)


def entry(sha="a" * 64, **over):
    """A manifest entry, built the same way the writer builds one.

    The first version hand-wrote `import_count: 10` while the corresponding row had two imports, so
    every "unchanged" test reported a change -- a fixture that did not match the shape of the real
    artefact, which is the same class of mistake as a fixture written from the code's assumptions
    rather than from its output.
    """
    base = {
        "schema": 1, "sha256": sha, "path_hint": "x.dll", "first_seen": "t", "last_seen": "t",
        "times_seen": 1,
    }
    base.update(cv._row_to_entry(row()))
    base.update(over)
    return base


def row(**over):
    base = {
        "path": "x.dll", "size": 100, "kind": "pe", "label": "PE executable (DOS/PE)",
        "mismatch": None, "packer": "none", "wrapper": None, "entropy_max": 6.0,
        "suspicious_imports": [], "noted_imports": [], "attention": 0,
        "all_imports": ["a", "b"],
    }
    base.update(over)
    return base


class TestDifferencesAreFound(unittest.TestCase):
    """The whole point: drift must be visible."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cv-"))
        self.manifest = self.tmp / "manifest.jsonl"
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def _write(self, entries):
        self.manifest.write_text(
            "\n".join(json.dumps(e, ensure_ascii=False, sort_keys=True) for e in entries) + "\n",
            encoding="utf-8")

    def _fake_measure(self, measured):
        """Replace the real scanner so the comparison logic is tested without a drive."""
        original = cv.collect_now
        cv.collect_now = lambda root, **kw: {"ok": True, "measured": measured, "scanned": len(measured)}
        self.addCleanup(lambda: setattr(cv, "collect_now", original))
        return original

    def test_a_changed_verdict_is_reported(self):
        self._write([entry()])
        self._fake_measure({"a" * 64: (cv._row_to_entry(row(packer="UPX")), "x.dll")})
        result = cv.verify(self.manifest, self.tmp)
        self.assertEqual(len(result["changed"]), 1)
        self.assertEqual(result["changed"][0]["field"], "packer")
        self.assertEqual(result["changed"][0]["was"], "none")
        self.assertEqual(result["changed"][0]["now"], "UPX")

    def test_an_unchanged_verdict_is_not_reported(self):
        self._write([entry()])
        self._fake_measure({"a" * 64: (cv._row_to_entry(row()), "x.dll")})
        self.assertEqual(cv.verify(self.manifest, self.tmp)["changed"], [])

    def test_a_file_the_manifest_lacks_is_reported_as_added(self):
        self._write([])
        self._fake_measure({"b" * 64: (cv._row_to_entry(row()), "new.dll")})
        result = cv.verify(self.manifest, self.tmp)
        self.assertEqual(len(result["added"]), 1)

    def test_a_manifest_entry_not_measured_is_reported_as_missing(self):
        self._write([entry()])
        self._fake_measure({})
        result = cv.verify(self.manifest, self.tmp)
        self.assertEqual(len(result["missing"]), 1)

    def test_every_verdict_field_is_compared(self):
        """A field left out of the comparison is a class of drift that can never be noticed.

        `import_count` is driven through `all_imports` rather than set directly: `_row_to_entry`
        derives it, so assigning the field is silently overwritten and the test would pass without
        comparing anything -- a fake that proves nothing about the thing it names.
        """
        for field in cv.VERDICT_FIELDS:
            with self.subTest(field=field):
                self._write([entry()])
                changed_row = row()
                if field == "import_count":
                    changed_row["all_imports"] = ["a", "b", "c", "d", "e"]
                else:
                    changed_row[field] = "CHANGED"
                self._fake_measure({"a" * 64: (cv._row_to_entry(changed_row), "x.dll")})
                result = cv.verify(self.manifest, self.tmp)
                self.assertTrue(any(c["field"] == field for c in result["changed"]),
                                "%s drift was not compared" % field)


class TestItReportsRatherThanJudges(unittest.TestCase):
    """A check that decided whether a change was intended would be wrong half the time."""

    def test_the_result_carries_its_limits(self):
        tmp = Path(tempfile.mkdtemp(prefix="cv-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        (tmp / "manifest.jsonl").write_text("", encoding="utf-8")
        result = cv.verify(tmp / "manifest.jsonl", tmp)
        text = " ".join(result["limits"]).lower()
        self.assertIn("does not judge", text)
        self.assertIn("cannot measure false negatives", text)

    def test_no_verdict_word_appears_in_the_result(self):
        tmp = Path(tempfile.mkdtemp(prefix="cv-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        (tmp / "manifest.jsonl").write_text("", encoding="utf-8")
        result = cv.verify(tmp / "manifest.jsonl", tmp)
        blob = json.dumps(result).lower()
        for word in ('"pass"', '"fail"', '"regression"', '"ok_to_ship"'):
            with self.subTest(word=word):
                self.assertNotIn(word, blob)

    def test_the_summary_says_nothing_changed_rather_than_all_good(self):
        out = cv.summarise({"in_manifest": 1, "measured": 1, "changed": [], "added": [],
                            "missing": []})
        self.assertIn("no verdict changed", out)
        for reassurance in ("all good", "no problems", "safe"):
            with self.subTest(word=reassurance):
                self.assertNotIn(reassurance, out.lower())


class TestTheManifestDoesNotMeasureItself(unittest.TestCase):
    """`--corpus-write` learned this and the verifier did not: `--corpus-write` skips its own
    manifest, but the first verifier run reported one extra file -- its own output."""

    def test_the_manifest_is_excluded_from_the_measurement(self):
        tmp = Path(tempfile.mkdtemp(prefix="cv-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        manifest = tmp / "manifest.jsonl"
        manifest.write_text("", encoding="utf-8")
        # A real file next to it, so there is something to measure and something to skip.
        (tmp / "real.dll").write_bytes(b"MZ" + bytes(1024))
        result = cv.collect_now(tmp, skip=[manifest])
        self.assertTrue(result["ok"])
        for _sha, (_entry, path_hint) in result["measured"].items():
            self.assertNotEqual(Path(path_hint or "").name, "manifest.jsonl",
                                "the manifest measured itself, which shows up as a phantom addition")


class TestTheScannerIsTheShippingOne(unittest.TestCase):
    def test_it_calls_the_tool_rather_than_a_second_analyser(self):
        """A parallel analyser would be a second thing to keep correct, and this file exists to make
        drift visible rather than to add somewhere for it to hide."""
        import inspect
        src = inspect.getsource(cv.collect_now)
        self.assertIn("import torikago", src)
        self.assertIn("tk.scan_tree", src)


class TestTheDocstringMatchesTheCode(unittest.TestCase):
    def test_it_does_not_claim_a_size_and_mtime_guard(self):
        """An earlier draft described a size/mtime fast path that was never implemented -- the
        documentation promising something the code does not do."""
        src = (HERE.parent / "corpus_verify.py").read_text(encoding="utf-8")
        flat = " ".join(src.split())
        self.assertIn("was never implemented", flat,
                      "the correction is what stops the claim coming back")
        self.assertIn("Every file is read, on purpose", flat)


if __name__ == "__main__":
    unittest.main(verbosity=2)
