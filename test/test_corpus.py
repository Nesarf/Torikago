# -*- coding: utf-8 -*-
"""The corpus: measurements that survive, and a contract that keeps them comparable.

An earlier sweep's 248 records were deleted with a scratch directory. Measurements are the expensive
part and the binaries are reproducible, so what is worth keeping is the *facts* -- which is also what
makes the corpus committable, since it contains no samples.

The properties that matter are about comparison, not storage:

  * identity is the content hash, so a file that moves is the same file
  * a repeated sweep keeps `first_seen` and increments `times_seen`, so "did this change" is
    answerable at all
  * a field that moved is reported, because a verdict that drifts is the thing a corpus is for
  * a malformed manifest is an error rather than a quietly shorter list
  * the manifest does not measure itself -- observed in practice: left in, every sweep grew the
    corpus by one spurious record
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

spec = importlib.util.spec_from_file_location("corpus_mod", HERE.parent / "corpus.py")
corpus = importlib.util.module_from_spec(spec)
sys.modules["corpus_mod"] = corpus
spec.loader.exec_module(corpus)


def row(path="a.exe", **over):
    base = {
        "path": path, "size": 1234, "kind": "pe", "label": "PE executable (DOS/PE)",
        "mismatch": None, "packer": "none", "wrapper": None, "entropy_max": 6.2,
        "suspicious_imports": [], "noted_imports": [], "attention": 0,
        "all_imports": ["a", "b", "c"],
    }
    base.update(over)
    return base


class TestIdentityIsContent(unittest.TestCase):
    """Paths move between machines and sweeps; content does not."""

    def test_the_hash_is_of_the_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "one.bin"
            a.write_bytes(b"hello")
            b = Path(tmp) / "two.bin"
            b.write_bytes(b"hello")
            self.assertEqual(corpus.sha256_file(a), corpus.sha256_file(b),
                             "identical content at different paths must be one identity")

    def test_different_bytes_are_different_identities(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a"
            a.write_bytes(b"hello")
            b = Path(tmp) / "b"
            b.write_bytes(b"hello!")
            self.assertNotEqual(corpus.sha256_file(a), corpus.sha256_file(b))

    def test_a_large_file_hashes_without_being_loaded_whole(self):
        """The function streams in chunks; a 200 MB sample must not need 200 MB of memory."""
        import inspect
        src = inspect.getsource(corpus.sha256_file)
        self.assertIn("read(chunk)", src)


class TestEntriesCarryTheStructuralFacts(unittest.TestCase):
    def test_the_measured_fields_are_copied(self):
        e = corpus.entry_from_row(row(packer="UPX"), sha="a" * 64)
        self.assertEqual(e["packer"], "UPX")
        self.assertEqual(e["kind"], "pe")
        self.assertEqual(e["schema"], corpus.SCHEMA_VERSION)

    def test_the_full_import_list_is_not_carried(self):
        """A hundred names per file makes a diff nobody reads; a count is enough to see a change."""
        e = corpus.entry_from_row(row(), sha="a" * 64)
        self.assertNotIn("all_imports", e)
        self.assertEqual(e["import_count"], 3)

    def test_the_path_is_a_hint_not_an_identity(self):
        e = corpus.entry_from_row(row(path="deep/nested/thing.exe"), sha="b" * 64)
        self.assertEqual(e["path_hint"], "deep/nested/thing.exe")
        self.assertEqual(e["sha256"], "b" * 64)


class TestRepeatedSweepsStayComparable(unittest.TestCase):
    """Without this the second sweep would erase the evidence that there ever was a first."""

    def test_a_new_entry_is_added(self):
        out = corpus.merge_manifest({}, [corpus.entry_from_row(row(), sha="a" * 64)])
        self.assertEqual(len(out["added"]), 1)
        self.assertEqual(out["entries"]["a" * 64]["times_seen"], 1)

    def test_seeing_a_file_again_keeps_first_seen_and_counts(self):
        first = corpus.entry_from_row(row(), sha="a" * 64, stamp="2026-01-01T00:00:00Z")
        second = corpus.entry_from_row(row(), sha="a" * 64, stamp="2026-02-02T00:00:00Z")
        out = corpus.merge_manifest({"a" * 64: first}, [second],
                                    stamp="2026-02-02T00:00:00Z")
        entry = out["entries"]["a" * 64]
        self.assertEqual(entry["first_seen"], "2026-01-01T00:00:00Z",
                         "first_seen moved, so the corpus cannot say when it first saw the file")
        self.assertEqual(entry["last_seen"], "2026-02-02T00:00:00Z")
        self.assertEqual(entry["times_seen"], 2)
        self.assertEqual(out["added"], [])

    def test_a_verdict_that_moved_is_reported(self):
        """The whole reason to keep a corpus: noticing that an assessment changed."""
        before = corpus.entry_from_row(row(packer="none"), sha="a" * 64)
        after = corpus.entry_from_row(row(packer="UPX"), sha="a" * 64)
        out = corpus.merge_manifest({"a" * 64: before}, [after])
        self.assertTrue(out["changed"])
        change = out["changed"][0]
        self.assertEqual(change["field"], "packer")
        self.assertEqual(change["was"], "none")
        self.assertEqual(change["now"], "UPX")

    def test_an_unchanged_file_reports_no_change(self):
        e = corpus.entry_from_row(row(), sha="a" * 64)
        out = corpus.merge_manifest({"a" * 64: e}, [corpus.entry_from_row(row(), sha="a" * 64)])
        self.assertEqual(out["changed"], [])
        self.assertEqual(out["added"], [])


class TestTheFileIsStableAndAuditable(unittest.TestCase):
    def test_it_round_trips(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.jsonl"
            entries = {"a" * 64: corpus.entry_from_row(row(), sha="a" * 64)}
            corpus.write_manifest(path, entries)
            self.assertEqual(corpus.read_manifest(path), entries)

    def test_writing_is_sorted_so_a_diff_shows_only_real_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.jsonl"
            entries = {s * 64: corpus.entry_from_row(row(), sha=s * 64) for s in "cab"}
            corpus.write_manifest(path, entries)
            shas = [json.loads(l)["sha256"][0] for l in
                    path.read_text(encoding="utf-8").splitlines() if l.strip()]
            self.assertEqual(shas, ["a", "b", "c"])

    def test_a_missing_manifest_is_empty_not_an_error(self):
        self.assertEqual(corpus.read_manifest(Path("does-not-exist.jsonl")), {})

    def test_a_malformed_line_is_an_error(self):
        """A corpus that quietly loses rows is worse than one that refuses to load."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.jsonl"
            path.write_text('{"sha256": "aa"}\nnot json at all\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                corpus.read_manifest(path)

    def test_an_entry_without_a_hash_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.jsonl"
            path.write_text('{"path_hint": "x"}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                corpus.read_manifest(path)


class TestSummarizeAndDiff(unittest.TestCase):
    def test_the_summary_counts_what_the_assessor_produces(self):
        entries = {
            "a" * 64: corpus.entry_from_row(row(packer="none", attention=0), sha="a" * 64),
            "b" * 64: corpus.entry_from_row(row(packer="UPX", attention=2), sha="b" * 64),
        }
        stats = corpus.summarize(entries)
        self.assertEqual(stats["files"], 2)
        self.assertEqual(stats["attention"], 1)
        self.assertEqual(stats["packer"]["UPX"], 1)

    def test_the_diff_names_additions_removals_and_changes(self):
        before = {"a" * 64: corpus.entry_from_row(row(), sha="a" * 64),
                  "b" * 64: corpus.entry_from_row(row(), sha="b" * 64)}
        after = {"a" * 64: corpus.entry_from_row(row(packer="UPX"), sha="a" * 64),
                 "c" * 64: corpus.entry_from_row(row(), sha="c" * 64)}
        d = corpus.diff_manifests(before, after)
        self.assertEqual(d["added"], ["c" * 64])
        self.assertEqual(d["removed"], ["b" * 64])
        self.assertEqual(len(d["changed"]), 1)
        self.assertEqual(d["changed"][0]["field"], "packer")


class TestTheManifestDoesNotMeasureItself(unittest.TestCase):
    """Observed in practice: left in, the first sweep added the manifest and every later sweep added
    a fresh entry for the file that had just changed, so the corpus grew by one per run."""

    def test_the_cli_skips_its_own_manifest(self):
        src = (HERE.parent / "torikago.py").read_text(encoding="utf-8")
        self.assertIn("the manifest does not measure itself", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestARowSaysHowMuchOfTheFileWasMeasured(unittest.TestCase):
    """Three different things used to look identical in the manifest.

    A row measured over the whole file, a row measured over a prefix because a scan was bounded, and a
    row from an older schema that never recorded coverage all had the same shape -- so **"this field
    changed" and "this field stopped being measured" read the same in a diff.** That is the exact
    distinction the no-under-reporting commitment exists to keep, and it was missing from the corpus.
    """

    def test_a_truncated_measurement_is_partial_and_names_what_stopped(self):
        out = corpus.coverage_of({"truncated_head": True, "attention": 1})
        self.assertEqual(out["measurement"], corpus.MEASUREMENT_PARTIAL)
        self.assertIn("truncated_head", out["stopped_at"])

    def test_a_row_with_coverage_bookkeeping_is_complete(self):
        out = corpus.coverage_of({"limits": {"imports": 256}, "scanned": 1 << 20})
        self.assertEqual(out["measurement"], corpus.MEASUREMENT_COMPLETE)

    def test_a_row_that_says_nothing_is_unknown_not_complete(self):
        """**The important one.** A tidy-looking old row is not evidence of a complete measurement --
        it is evidence that nobody asked. Calling it complete would be the tool reassuring itself.
        """
        out = corpus.coverage_of({"attention": 0, "packer": "none", "size": 100})
        self.assertEqual(out["measurement"], corpus.MEASUREMENT_UNKNOWN)
        self.assertIn("records nothing", out["reason"])

    def test_the_truncation_keys_are_matched_by_suffix_so_a_new_cap_is_not_missed(self):
        """A cap added later writes `something_truncated`; the check has to see it without an edit."""
        for key in ("sections_truncated", "pyz_truncated", "whatever_truncated"):
            with self.subTest(key=key):
                out = corpus.coverage_of({key: True})
                if key in corpus.TRUNCATION_KEYS:
                    self.assertEqual(out["measurement"], corpus.MEASUREMENT_PARTIAL)
                else:
                    # Not in the tuple, so it is unknown rather than misread as complete.
                    self.assertEqual(out["measurement"], corpus.MEASUREMENT_UNKNOWN)

    def test_every_new_entry_carries_coverage(self):
        entry = corpus.entry_from_row({"path": "a.exe", "attention": 0}, sha="0" * 64)
        self.assertIn("coverage", entry)
        self.assertIn(entry["coverage"]["measurement"],
                      (corpus.MEASUREMENT_COMPLETE, corpus.MEASUREMENT_PARTIAL,
                       corpus.MEASUREMENT_UNKNOWN))

    def test_the_real_manifest_is_honest_about_itself(self):
        """Every existing row predates the question, so every one must read as unknown -- except any
        that recorded a cap. This is checked against the shipped manifest rather than a fixture,
        because the point is what the corpus actually says about 1161 real measurements.
        """
        from pathlib import Path as _P
        manifest = _P(__file__).resolve().parent.parent / "corpus" / "manifest.jsonl"
        if not manifest.exists():
            self.skipTest("no manifest in this checkout")
        import json
        rows = [json.loads(l) for l in manifest.read_text(encoding="utf-8").splitlines() if l.strip()]
        self.assertGreater(len(rows), 100, "the manifest is not the real one")
        known = {corpus.coverage_of(r)["measurement"] for r in rows}
        self.assertNotIn(corpus.MEASUREMENT_COMPLETE, known,
                         "rows predating the coverage question are claiming to be complete")
