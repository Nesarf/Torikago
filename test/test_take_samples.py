# -*- coding: utf-8 -*-
"""Batching the decision, without making it.

Taking twenty samples one hash at a time is twenty deliberate acts, and the friction pushes toward
taking fewer or taking carelessly. This removes the friction **without** removing the deliberation.

**It does not decide whether to take samples.** That is the machine owner's call and running it is
that call being made. What it decides is only how: which types are worth taking, how to avoid taking
the same thing twice, and how to leave a record.

The tests below are about the refusals and the bookkeeping, because those are what a batch tool is
most likely to get wrong in a way nobody notices until a corpus is quietly worthless — the first
corpus built by hand had **1,496 records and exactly one PE among them**.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import _fixtures                                      # noqa: E402

spec = importlib.util.spec_from_file_location("ts", HERE.parent / "take_samples.py")
ts = importlib.util.module_from_spec(spec)
sys.modules["ts"] = ts
spec.loader.exec_module(ts)


def row(sha, ftype="exe", name="x.exe"):
    return {"sha256_hash": sha, "file_type": ftype, "file_name": name, "file_size": 100}


class TestSelectionFiltersWhatWouldBeUseless(unittest.TestCase):
    def test_only_the_given_types_are_taken(self):
        rows = [row("a" * 64, "exe"), row("b" * 64, "zip"), row("c" * 64, "py"),
                row("d" * 64, "dll")]
        chosen, skipped = ts.select(rows, types={"exe", "dll"}, have=set(), limit=10)
        self.assertEqual([c["sha256_hash"][0] for c in chosen], ["a", "d"])
        self.assertEqual({s["kind"] for s in skipped}, {"type"})

    def test_the_default_is_the_types_a_pe_unpacker_can_read(self):
        self.assertIn("exe", ts.PE_TYPES)
        self.assertIn("dll", ts.PE_TYPES)
        self.assertNotIn("zip", ts.PE_TYPES)
        self.assertNotIn("py", ts.PE_TYPES)

    def test_already_sealed_is_skipped_and_labelled(self):
        rows = [row("a" * 64), row("b" * 64)]
        chosen, skipped = ts.select(rows, types={"exe"}, have={"a" * 64}, limit=10)
        self.assertEqual(len(chosen), 1)
        self.assertEqual(skipped[0]["kind"], "sealed")

    def test_a_row_without_a_hash_is_skipped_and_labelled(self):
        chosen, skipped = ts.select([{"file_type": "exe"}], types={"exe"}, have=set(), limit=10)
        self.assertEqual(chosen, [])
        self.assertEqual(skipped[0]["kind"], "nohash")

    def test_the_limit_is_respected(self):
        rows = [row(chr(97 + i) * 64) for i in range(10)]
        chosen, _ = ts.select(rows, types={"exe"}, have=set(), limit=3)
        self.assertEqual(len(chosen), 3)

    def test_types_of_none_takes_everything(self):
        rows = [row("a" * 64, "zip"), row("b" * 64, "py")]
        chosen, skipped = ts.select(rows, types=None, have=set(), limit=10)
        self.assertEqual(len(chosen), 2)
        self.assertEqual(skipped, [])

    def test_skips_carry_a_category_not_just_prose(self):
        """The first version counted skips by asking whether "type" appeared in the reason text,
        which matches far more than it should."""
        _, skipped = ts.select([row("b" * 64, "zip")], types={"exe"}, have=set(), limit=10)
        self.assertIn("kind", skipped[0])
        self.assertEqual(skipped[0]["kind"], "type")


class TestWhatIsAlreadySealed(unittest.TestCase):
    def test_the_vault_is_read_from_its_filenames(self):
        """Every artifact is named by its own content hash, which is why this is a directory listing
        rather than a database lookup -- a sealed artifact identifies itself."""
        base = _fixtures.tmpdir("ts-")
        self.addCleanup(lambda: __import__("shutil").rmtree(base, ignore_errors=True))
        (base / ("a" * 64 + ".zip")).write_bytes(b"PK")
        (base / "not-a-hash.zip").write_bytes(b"PK")
        (base / "readme.txt").write_text("x")
        self.assertEqual(ts.sealed_hashes(base), {"a" * 64})

    def test_a_missing_vault_is_empty_not_an_error(self):
        self.assertEqual(ts.sealed_hashes(Path("does-not-exist-vault")), set())


class TestTheBatchRefusesWhatTheSinglePathRefuses(unittest.TestCase):
    """A batch must not be a way around the destination rules."""

    def test_both_destinations_are_checked(self):
        import inspect
        src = inspect.getsource(ts.main)
        # Two calls, one for the vault and one for the work directory: the loose download is also a
        # place a sample sits, so it is subject to the same rules.
        self.assertEqual(src.count("sf.check_destination"), 2)

    def test_the_rules_come_from_the_single_sample_path(self):
        """Reused rather than reimplemented, so the two cannot drift apart."""
        import inspect
        src = inspect.getsource(ts.main)
        self.assertIn("import sample_fetch as sf", src)


class TestItNeverRunsAnything(unittest.TestCase):
    def test_no_execution_call_appears(self):
        src = (HERE.parent / "take_samples.py").read_text(encoding="utf-8")
        for forbidden in ("subprocess", "os.system", "Popen", "CreateProcess", "os.exec"):
            with self.subTest(call=forbidden):
                self.assertNotIn(forbidden, src,
                                 "%s would mean this tool runs something, which it must not" % forbidden)

    def test_it_unpacks_nothing(self):
        """Fetching and unpacking are separate acts; this performs only the first."""
        src = (HERE.parent / "take_samples.py").read_text(encoding="utf-8")
        self.assertNotIn("unpack_pyinstaller", src)
        self.assertNotIn("nanodesu", src)


class TestTheStagedCopyIsHashedAfterCopying(unittest.TestCase):
    """The staged name carries the hash of the file that was *analysed*.

    The report was built from the source at one moment and the bytes were read at another, so a file
    replaced in between produces a shuttle entry whose name says one sample while the file holds
    another. **That needs no attacker, only a directory something else writes to** -- and a
    mislabelled sample is worse than a missing one, because every later measurement inherits the
    label.
    """

    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("tri", HERE.parent / "torikago.py")
        self.tri = importlib.util.module_from_spec(spec)
        sys.modules["tri"] = self.tri
        spec.loader.exec_module(self.tri)
        self.tmp = _fixtures.tmpdir("qc-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def _report(self, sha, size=0):
        """A fragment of the real report, shaped by reading it rather than guessing.

        **Two rounds of KeyError before this was right** -- md5 and then size -- both because the
        fixture was written from assumption. The real report keeps all of these under `hashes`,
        including `size`, which is not where a reader would look for it; a test standing in for
        another object has to be copied from that object.
        """
        return {"hashes": {"sha256": sha, "sha1": "0" * 40, "md5": "0" * 32, "size": size},
                "assessment": {"attention": [], "reasons": []},
                "identified_as": {"label": "test"}, "executed": False}

    def test_a_matching_copy_is_staged(self):
        import hashlib
        src = self.tmp / "sample.exe"
        src.write_bytes(b"content\n")
        sha = hashlib.sha256(b"content\n").hexdigest()
        r = self.tri.quarantine_copy(src, self.tmp / "shuttle", self._report(sha), reason="test")
        self.assertTrue(r["ok"], r)

    def test_a_mismatched_copy_is_removed_not_left_mislabelled(self):
        """The report says one hash and the file has another. The entry must not survive."""
        src = self.tmp / "sample.exe"
        src.write_bytes(b"content\n")
        wrong = "0" * 64
        shuttle = self.tmp / "shuttle"
        r = self.tri.quarantine_copy(src, shuttle, self._report(wrong), reason="test")
        self.assertFalse(r["ok"])
        self.assertEqual(r["stage"], "verify")
        self.assertIn("does not hash to the file that was analysed", r["reason"])
        left = list(shuttle.glob("*")) if shuttle.is_dir() else []
        self.assertEqual(left, [], "a mislabelled copy was left in the shuttle: %s" % left)

    def test_the_failure_names_both_hashes(self):
        """Without both, a reader cannot tell a race from a collision without redoing the work."""
        src = self.tmp / "s.exe"
        src.write_bytes(b"x")
        r = self.tri.quarantine_copy(src, self.tmp / "s2", self._report("a" * 64), reason="t")
        self.assertEqual(r["expected"], "a" * 64)
        self.assertNotEqual(r["got"], r["expected"])

    def test_the_verification_happens_after_the_copy(self):
        """Checked by position, so reordering the function cannot silently disarm this."""
        import inspect
        body = inspect.getsource(self.tri.quarantine_copy)
        self.assertLess(body.index("copyfileobj"), body.index("staged_sha"))
