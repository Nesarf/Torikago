# -*- coding: utf-8 -*-
"""The sample channels: fetching evidence, and keeping it where an antivirus cannot delete it.

Two tools, one job, and both exist because of something observed rather than imagined.

**The fetch tool.** `abuse.ch` requires an Auth-Key now, and the first version of the error handling
conflated three different failures — `401` (no key given), `403` (a key was given and refused), and
`hash_not_found` (the key worked and the corpus does not have that hash). Each sends the reader in a
different direction, and **one of them sent the reader to generate a key that had just been proven
to work.**

**The vault.** An EICAR test file was written to a quarantine directory, `ls` showed it, and **reading
it returned `Errno 22`** — Windows refusing a file it had judged, with Defender's history holding two
detections of that path. The sample existed and was unreadable, removed from usefulness by the
protection that is supposed to be on your side.

The tests below are mostly about **not claiming things**: not claiming encryption that was never
verified, not claiming a missing key when the key was refused, not claiming a sample is absent when
the query never ran.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

fspec = importlib.util.spec_from_file_location("sf", HERE.parent / "sample_fetch.py")
sf = importlib.util.module_from_spec(fspec)
sys.modules["sf"] = sf
fspec.loader.exec_module(sf)

vspec = importlib.util.spec_from_file_location("sv", HERE.parent / "sample_vault.py")
sv = importlib.util.module_from_spec(vspec)
sys.modules["sv"] = sv
vspec.loader.exec_module(sv)

HAVE_PYZIPPER = sv.pyzipper is not None


def tmpdir():
    """A temporary directory outside every path the tool refuses.

    Neither obvious base works here, which took a diagnostic to establish rather than a guess:
    `tempfile.mkdtemp()` resolves to `TEMP`, which on this machine is the refused cache area, and
    `Path.home()` is on `C:`. **Both candidates were forbidden**, so the fixtures failed no matter
    how they were written, and the failures looked like the check being wrong rather than the
    fixture being in the wrong place.

    The path is assembled from `chr(92)` because writing it literally through a shell heredoc has
    corrupted this repository repeatedly -- the two characters before `triage` become a tab.
    """
    bs = chr(92)
    default = "E:" + bs + "triage-test-tmp"
    base = Path(os.environ.get("TRIAGE_TEST_TMP") or default)
    base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="channels-", dir=str(base)))


class TestRefusalsComeBeforeAnyNetworkCall(unittest.TestCase):
    """A mistake should cost nothing, which means being caught locally."""

    def test_the_workspace_is_refused(self):
        with self.assertRaises(SystemExit):
            sf.check_destination(Path(r"E:\~Sayori~Sleeping~\samples"))

    def test_the_system_drive_is_refused(self):
        with self.assertRaises(SystemExit):
            sf.check_destination(Path(r"C:\samples"))

    def test_the_cache_area_is_refused(self):
        with self.assertRaises(SystemExit):
            sf.check_destination(Path(r"E:\DaShaoHuo\samples"))

    def test_a_git_repository_is_refused(self):
        """A sample in a repository gets committed eventually."""
        tmp = tmpdir()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        (tmp / ".git").mkdir()
        with self.assertRaises(SystemExit) as ctx:
            sf.check_destination(tmp / "samples")
        self.assertIn("repository", str(ctx.exception))

    def test_a_quarantine_directory_is_allowed(self):
        tmp = tmpdir()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        sf.check_destination(tmp / "samples")            # must not raise

    def test_a_hash_that_is_not_a_hash_is_refused_locally(self):
        for bad in ("", "xyz", "abc123", "0" * 31, "0" * 65):
            with self.subTest(value=bad[:12]):
                with self.assertRaises(SystemExit):
                    sf.classify_hash(bad)

    def test_each_hash_length_is_recognised(self):
        self.assertEqual(sf.classify_hash("a" * 32), "md5")
        self.assertEqual(sf.classify_hash("a" * 40), "sha1")
        self.assertEqual(sf.classify_hash("a" * 64), "sha256")

    def test_the_destination_default_is_described_as_a_suggestion(self):
        """The tool has no idea where samples are kept; the default is a convenience, not a belief."""
        src = (HERE.parent / "sample_fetch.py").read_text(encoding="utf-8")
        flat = " ".join(src.split())
        self.assertIn("suggestion, not an assumption", flat)


class TestEachFailureSaysWhichFailureItWas(unittest.TestCase):
    """Conflating them sends the reader the wrong way, which happened."""

    def test_the_three_outcomes_have_three_different_messages(self):
        src = (HERE.parent / "sample_fetch.py").read_text(encoding="utf-8")
        self.assertIn("HTTP 401", src)
        self.assertIn("HTTP 403", src)
        self.assertIn("does not have that hash", src)

    def test_a_refused_key_is_not_reported_as_a_missing_key(self):
        """Observed: a stale placeholder produced 403 and the message told the reader to register
        for a key they already had."""
        src = (HERE.parent / "sample_fetch.py").read_text(encoding="utf-8")
        flat = " ".join(src.split())
        i = flat.index("HTTP 403")
        window = flat[i:i + 600]
        self.assertIn("the key was rejected", window)
        self.assertNotIn("no key was accepted", window)

    def test_an_absent_hash_says_the_key_worked(self):
        """`hash_not_found` is proof of successful authentication -- the service answered."""
        src = (HERE.parent / "sample_fetch.py").read_text(encoding="utf-8")
        flat = " ".join(src.split())
        i = flat.index("does not have that hash")
        self.assertIn("the key worked", flat[i:i + 400])

    def test_the_rate_limit_is_mentioned_where_it_matters(self):
        """abuse.ch limits accounts for up to 72 hours after high query volume, which is a plausible
        cause of a rejected key and would otherwise be invisible."""
        src = (HERE.parent / "sample_fetch.py").read_text(encoding="utf-8")
        self.assertIn("72 hours", src)

    def test_the_key_is_never_read_from_the_declared_destination(self):
        """A key lying beside the samples is one more thing a later cleanup has to remember."""
        src = (HERE.parent / "sample_fetch.py").read_text(encoding="utf-8")
        self.assertIn("Do not put the key in this directory", src)


class TestTheVaultNeverClaimsUnverifiedEncryption(unittest.TestCase):
    """The defect found by listing a vault on an interpreter without pyzipper: every artifact
    reported `encrypted=False` -- a confident statement that a sealed file was plaintext."""

    def setUp(self):
        self.tmp = tmpdir()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def test_an_unanswerable_check_returns_none_not_false(self):
        if HAVE_PYZIPPER:
            self.skipTest("pyzipper is installed, so the unanswerable path is unreachable here")
        self.assertIsNone(sv.is_encrypted_zip(self.tmp / "anything.zip"))

    def test_a_non_zip_is_false_not_unknown(self):
        p = self.tmp / "plain.bin"
        p.write_bytes(b"MZ" + bytes(64))
        self.assertFalse(sv.is_encrypted_zip(p))

    @unittest.skipUnless(HAVE_PYZIPPER, "needs pyzipper to write a real AES archive")
    def test_a_sealed_archive_round_trips_and_proves_itself(self):
        src = self.tmp / "benign.bin"
        src.write_bytes(b"a harmless stand-in\n")
        sealed = sv.store(src, self.tmp / "vault")
        self.assertTrue(sealed["ok"], sealed)
        self.assertTrue(sealed["encrypted"])
        self.assertIs(sv.is_encrypted_zip(Path(sealed["path"])), True)

    @unittest.skipUnless(HAVE_PYZIPPER, "needs pyzipper")
    def test_the_content_hash_and_the_archive_hash_are_different_and_both_kept(self):
        """Conflating them files a sample under a name describing the container."""
        src = self.tmp / "benign.bin"
        src.write_bytes(b"content\n")
        sealed = sv.store(src, self.tmp / "vault")
        self.assertNotEqual(sealed["sha256"], sealed["archive_sha256"])
        self.assertEqual(sealed["sha256"], sv.sha256_file(src))

    @unittest.skipUnless(HAVE_PYZIPPER, "needs pyzipper")
    def test_a_sealed_archive_cannot_be_read_without_the_password(self):
        import zipfile
        src = self.tmp / "benign.bin"
        src.write_bytes(b"secret\n")
        sealed = sv.store(src, self.tmp / "vault")
        with self.assertRaises(Exception):
            zipfile.ZipFile(sealed["path"]).read(zipfile.ZipFile(sealed["path"]).namelist()[0])

    @unittest.skipUnless(HAVE_PYZIPPER, "needs pyzipper")
    def test_storing_twice_does_not_make_a_second_archive(self):
        """A second archive for the same content would give one sample two identities."""
        src = self.tmp / "benign.bin"
        src.write_bytes(b"same\n")
        first = sv.store(src, self.tmp / "vault")
        second = sv.store(src, self.tmp / "vault")
        self.assertFalse(second["stored"])
        self.assertEqual(first["path"], second["path"])

    def test_extraction_refuses_a_non_encrypted_archive(self):
        p = self.tmp / "plain.zip"
        p.write_bytes(b"PK" + bytes(64))
        result = sv.extract(p, self.tmp / "work")
        self.assertFalse(result["ok"])

    def test_the_vault_refuses_rather_than_substituting_plaintext(self):
        """The standard library sets the encrypted bit on plaintext. A silent fallback to that would
        be the exact failure this module exists to prevent."""
        src = (HERE.parent / "sample_vault.py").read_text(encoding="utf-8")
        self.assertIn("there is no fallback", src)

    @unittest.skipUnless(HAVE_PYZIPPER, "needs pyzipper")
    def test_extraction_warns_that_the_work_directory_is_now_readable(self):
        src = self.tmp / "benign.bin"
        src.write_bytes(b"x\n")
        sealed = sv.store(src, self.tmp / "vault")
        result = sv.extract(Path(sealed["path"]), self.tmp / "work")
        self.assertTrue(result["ok"])
        self.assertIn("delete", result["note"].lower())


class TestTheToolsAreReachableFromTheTool(unittest.TestCase):
    def test_the_cli_offers_both_channels(self):
        import io
        from contextlib import redirect_stdout
        import torikago as tk
        buf = io.StringIO()
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit):
                tk.main(["--help"])
        text = " ".join(buf.getvalue().split())
        for flag in ("--fetch-sample", "--fetch-bytes", "--vault-store", "--vault-list",
                     "--vault-extract"):
            with self.subTest(flag=flag):
                self.assertIn(flag, text)

    def test_vault_list_uses_the_directory_it_was_given(self):
        """It did not, and fell back to the default -- so listing one vault described another."""
        src = (HERE.parent / "torikago.py").read_text(encoding="utf-8")
        flat = " ".join(src.split())
        self.assertIn("target = args.vault_list or args.dest", flat)

    def test_metadata_is_the_default_and_bytes_are_opt_in(self):
        import io
        from contextlib import redirect_stdout
        import torikago as tk
        buf = io.StringIO()
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit):
                tk.main(["--help"])
        text = " ".join(buf.getvalue().split())
        self.assertIn("Metadata cannot execute", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestBrowsingIsSeparateFromTaking(unittest.TestCase):
    """A listing that could download would make browsing and acquiring the same act."""

    def test_tag_listing_downloads_nothing(self):
        import inspect
        src = inspect.getsource(sf._list_by_tag)
        self.assertIn("get_taginfo", src)
        # Checked against the calls that download, not against the string "--fetch". The listing
        # prints "--fetch" as instructions, and an earlier version of this test failed on its own
        # help text -- the same "measuring the prose instead of the behaviour" mistake in a new
        # costume.
        for forbidden in ("get_file", "getfile", "urlretrieve", "urlopen(url"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, src,
                                 "the listing path can download, so browsing is not separate")

    def test_the_listing_says_how_to_take_one(self):
        import inspect
        src = inspect.getsource(sf._list_by_tag)
        self.assertIn("--fetch", src, "the listing must say how to act on what it shows")

    def test_a_hash_is_not_required_for_a_browsing_command(self):
        parser_src = Path(HERE.parent / "sample_fetch.py").read_text(encoding="utf-8")
        self.assertIn('nargs="?"', parser_src)

    def test_no_hash_and_no_browsing_command_says_so_plainly(self):
        src = Path(HERE.parent / "sample_fetch.py").read_text(encoding="utf-8")
        self.assertIn("no browsing command asked for", src)


class TestTheSecondProviderFollowsTheSameRules(unittest.TestCase):
    """Adding a provider must not route around the checks the first one is subject to."""

    def test_its_key_comes_from_the_environment_and_can_be_overridden(self):
        import provider_malshare as ms
        old = os.environ.get("MALSHARE_TOKEN")
        try:
            os.environ["MALSHARE_TOKEN"] = "abc"
            self.assertEqual(ms.find_auth_key(None), "abc")
            self.assertEqual(ms.find_auth_key("explicit"), "explicit")
        finally:
            if old is None:
                os.environ.pop("MALSHARE_TOKEN", None)
            else:
                os.environ["MALSHARE_TOKEN"] = old

    def test_a_hash_mismatch_deletes_the_download(self):
        """MalShare serves samples raw rather than zipped, so the hash is directly checkable -- and
        a file filed under a hash it does not have is worse than no file."""
        import inspect
        import provider_malshare as ms
        src = inspect.getsource(ms.fetch_bytes)
        self.assertIn("do not match the hash", src)
        self.assertIn("unlink", src)

    def test_it_reports_that_a_download_is_still_executable(self):
        import inspect
        import provider_malshare as ms
        src = inspect.getsource(ms.fetch_bytes)
        self.assertIn("still executable", src,
                      "MalwareBazaar serves a password-protected zip; MalShare does not, and the "
                      "difference matters to whoever handles the file next")

    def test_quota_is_readable_before_spending_an_attempt(self):
        import provider_malshare as ms
        self.assertTrue(hasattr(ms, "quota"))

    def test_the_destination_check_still_runs_first(self):
        """Every refusal happens before a provider is consulted, so a second provider cannot be a
        way around them."""
        import inspect
        src = inspect.getsource(sf.main)
        self.assertLess(src.index("check_destination"),
                        src.index("provider_malshare"),
                        "the destination check moved after the provider is reached")


class TestTheKeyFollowsTheProvider(unittest.TestCase):
    """Observed: `--source malshare` sent the abuse.ch key to MalShare and got a bare HTTP 400.

    The wrong credential went to the wrong service and the error said nothing about why, which is the
    same class of failure as reporting a missing key when a key was refused.
    """

    def test_each_provider_reads_its_own_variable(self):
        src = (HERE.parent / "sample_fetch.py").read_text(encoding="utf-8")
        self.assertIn("MALSHARE_TOKEN", src)
        self.assertIn("MALWAREBAZAAR_AUTH_KEY", src)
        flat = " ".join(src.split())
        self.assertIn('args.source == "malshare"', flat,
                      "the key is not chosen by provider")

    def test_the_provider_choice_comes_before_the_key_is_read(self):
        """Ordering matters: the key default depends on which collection was asked for.

        Searched from the resolution rather than from the first mention. `MALSHARE_TOKEN` also appears
        in the argparse block, which is earlier in the function but not where the reading happens --
        so an index comparison against the first occurrence failed on the definitions.
        """
        src = (HERE.parent / "sample_fetch.py").read_text(encoding="utf-8")
        i = src.index("if not args.auth_key:")
        window = src[i:i + 300]
        self.assertIn("args.source", window,
                      "the key is resolved without consulting which provider was asked for")


class TestQuotaParsingWasMeasured(unittest.TestCase):
    """MalShare returns JSON; an earlier version parsed space-separated numbers and reported
    neither -- so `--quota` printed the raw blob and no figures."""

    def test_it_parses_the_json_shape_malshare_returns(self):
        import provider_malshare as ms
        src = (HERE.parent / "provider_malshare.py").read_text(encoding="utf-8")
        self.assertIn('"LIMIT"', src)
        self.assertIn('"REMAINING"', src)

    def test_the_measurement_is_recorded(self):
        src = (HERE.parent / "provider_malshare.py").read_text(encoding="utf-8")
        flat = " ".join(src.split())
        self.assertIn("Measured, not assumed", flat)


class TestTheTwoProvidersAreGoodAtDifferentThings(unittest.TestCase):
    """The measurement that corrected the design rationale."""

    def test_the_module_records_that_malshare_had_no_pe(self):
        """The assumption was that a second provider fills the first's blind spot. For Windows work
        it does not: MalShare's recent feed was 24 samples with zero PE."""
        src = (HERE.parent / "provider_malshare.py").read_text(encoding="utf-8")
        flat = " ".join(src.split())
        self.assertIn("24 samples, zero PE", flat)
        # The docstring wraps, so the phrase is split across lines in the file. Normalised rather
        # than quoted exactly, which is the difference between checking the sentence and checking
        # the line breaks.
        self.assertIn("being large is not the same as a source being relevant", flat)

    def test_the_recent_listing_says_it_is_not_a_targeted_source(self):
        import inspect
        src = inspect.getsource(sf.main)
        self.assertIn("bulk source, not a targeted one", " ".join(src.split()))
