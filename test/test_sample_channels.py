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

import _fixtures                                      # noqa: E402

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
    """Delegated, because the root has to be chosen per machine -- see `_fixtures`."""
    return _fixtures.tmpdir("channels-")


def require_root():
    return _fixtures.require_root()


@unittest.skipUnless(os.name == "nt",
                     "the destination rules are Windows rules -- `C:`, drive letters, and the "
                     "workspace/cache convention they name. Asserting them on POSIX would either "
                     "pass vacuously or test something other than what ships, and a skip says which.")
class TestRefusalsComeBeforeAnyNetworkCall(unittest.TestCase):
    """A mistake should cost nothing, which means being caught locally.

    **The refusals are platform-specific on purpose.** `C:` is not a path, it is a class of mistake --
    a sample on the system drive outliving the machine it was collected for. On a host where that
    concept does not exist there is nothing to assert, so these skip rather than pretend.
    """

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
        """A sample in a repository gets committed eventually.

        The repository is built **at an allowed root**, because the refusal that fires first is
        whichever one the path violates first -- and on a host where everything is under a refused
        root, this assertion would be measuring that instead of the repository rule.
        """
        root = require_root()
        tmp = Path(__import__("tempfile").mkdtemp(prefix="git-", dir=str(root)))
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        (tmp / ".git").mkdir()
        with self.assertRaises(SystemExit) as ctx:
            sf.check_destination(tmp / "samples")
        self.assertIn("repository", str(ctx.exception))

    def test_a_quarantine_directory_is_allowed(self):
        tmp = tmpdir()          # skips, with a reason, if this host has no allowed location
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


class TestTheHandoffVerdictIsVisible(unittest.TestCase):
    """Found by exercising the download path for the first time, which is also when `--handoff` was
    run without `--out`.

    The results went **only** into `report.json`, and that file is written **only** when `--out` is
    given. So for anyone who did not pass `--out`, asking for a handoff produced no output at all and
    looked like a broken flag. A capability nobody can see is one nobody has.
    """

    def test_the_verdict_is_printed_after_the_file_details(self):
        """Printed *before* the details, an output tail showed only the static working -- and people
        read the end. A conclusion belongs at the end."""
        src = (HERE.parent / "torikago.py").read_text(encoding="utf-8")
        i = src.index("        print_human(report)")
        j = src.index("_print_handoff(report.get(\"handoff\"))")
        self.assertGreater(j, i, "the handoff verdict is printed before the file details")

    def test_printing_cannot_break_the_command(self):
        """The analysis has already succeeded by the time anything is printed."""
        import io
        from contextlib import redirect_stdout
        import torikago as tk

        class Hostile:
            def get(self, _k, _d=None):
                raise RuntimeError("boom")

        buf = io.StringIO()
        with redirect_stdout(buf):
            tk._print_handoff(Hostile())          # must not raise
        self.assertEqual(buf.getvalue(), "")

    def test_nothing_asked_prints_nothing(self):
        import io
        from contextlib import redirect_stdout
        import torikago as tk
        buf = io.StringIO()
        with redirect_stdout(buf):
            tk._print_handoff(None)
        self.assertEqual(buf.getvalue(), "")

    def test_an_unavailable_engine_is_reported_not_hidden(self):
        import io
        from contextlib import redirect_stdout
        import torikago as tk
        buf = io.StringIO()
        with redirect_stdout(buf):
            tk._print_handoff({"engines": {"defender": {"ok": False, "reason": "not installed"}}})
        self.assertIn("not installed", buf.getvalue())

    def test_the_note_says_the_verdict_is_not_ours(self):
        import io
        from contextlib import redirect_stdout
        import torikago as tk
        buf = io.StringIO()
        with redirect_stdout(buf):
            tk._print_handoff({"engines": {"defender": {"ok": True, "verdicts": [
                {"file": "x.exe", "clean": True, "line": "found no threats"}]}}})
        text = buf.getvalue()
        self.assertIn("not this tool's", text)
        self.assertIn("not the same as the file being safe", text)


class TestUnsealingRefusesToWriteOutsideTheWorkDirectory(unittest.TestCase):
    """The vault unsealed with `extractall()`, which does exactly what the member names say.

    The check before it confirmed the *container* was encrypted and said nothing about the contents.
    A zip slip needs no encryption weakness at all -- it is a normal feature of the format, and
    `../../x` writes wherever the user has permission.

    **The names are untrusted even though the container is ours**, because the container was built by
    whoever uploaded the sample. Verified against the old code: every case below wrote the file.
    """

    def setUp(self):
        self.tmp = _fixtures.tmpdir("slip-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.work = self.tmp / "work"

    def _sealed(self, *names):
        """An AES archive holding the given names, placed where the vault would put one.

        **Written directly rather than through `store()`.** `store()` seals a file as a single member
        named after that file, so routing the fixture through it produced an archive whose only member
        was `payload.zip` -- and the traversal names inside it were then never opened, so every test
        below passed vacuously against the bug it was written to catch.
        """
        import pyzipper
        vault = self.tmp / "vault"
        vault.mkdir(parents=True, exist_ok=True)
        out = vault / ("f" * 64 + ".zip")
        with pyzipper.AESZipFile(out, "w", compression=pyzipper.ZIP_DEFLATED,
                                 encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(sv.SAMPLE_PASSWORD)
            for n in names:
                zf.writestr(n, b"HOSTILE\n")
        return out

    @unittest.skipUnless(HAVE_PYZIPPER, "needs pyzipper to build the fixture")
    def test_a_parent_segment_is_refused_and_nothing_escapes(self):
        archive = self._sealed("../../escape.txt")
        self.assertIsNotNone(archive)
        result = sv.extract(archive, self.work)
        self.assertTrue(result["ok"], result)
        self.assertFalse((self.tmp / "escape.txt").exists(),
                         "a member escaped the work directory")
        self.assertEqual([r["why"] for r in result["refused"]],
                         ["contains a parent-directory segment"])

    @unittest.skipUnless(HAVE_PYZIPPER, "needs pyzipper")
    def test_a_backslash_traversal_is_refused_too(self):
        """Windows reads either separator, and zip stores forward slashes -- so both are checked."""
        archive = self._sealed("..\..\escape2.txt")
        self.assertTrue(sv.extract(archive, self.work)["ok"])
        self.assertFalse((self.tmp / "escape2.txt").exists())

    @unittest.skipUnless(HAVE_PYZIPPER, "needs pyzipper")
    def test_an_absolute_path_is_refused(self):
        archive = self._sealed("/tmp/escape3.txt")
        result = sv.extract(archive, self.work)
        self.assertTrue(result["ok"])
        self.assertEqual(result["refused"][0]["why"], "absolute path")

    @unittest.skipUnless(HAVE_PYZIPPER, "needs pyzipper")
    def test_a_drive_absolute_path_is_refused(self):
        archive = self._sealed("C:/escape4.txt")
        self.assertTrue(sv.extract(archive, self.work)["ok"])
        self.assertEqual(sv.extract(archive, self.work)["refused"][0]["why"], "absolute path")

    @unittest.skipUnless(HAVE_PYZIPPER, "needs pyzipper")
    def test_a_harmless_member_is_still_written(self):
        """Over-refusing is its own failure: a vault that refuses everything is unusable."""
        archive = self._sealed("sample.exe")
        result = sv.extract(archive, self.work)
        self.assertTrue(result["ok"], result)
        self.assertIn("sample.exe", result["members"])
        self.assertEqual((self.work / "sample.exe").read_bytes(), b"HOSTILE\n")
        self.assertNotIn("refused", result)

    @unittest.skipUnless(HAVE_PYZIPPER, "needs pyzipper")
    def test_a_refusal_is_reported_not_dropped(self):
        """A member dropped without a word is indistinguishable from one never present."""
        archive = self._sealed("../x.txt", "keep.exe")
        result = sv.extract(archive, self.work)
        self.assertIn("refused", result)
        self.assertEqual(len(result["refused"]), 1)
        self.assertIn("keep.exe", result["members"])

    @unittest.skipUnless(HAVE_PYZIPPER, "needs pyzipper")
    def test_a_device_name_does_not_address_a_device(self):
        """`NUL` is not a filename. Writing to it either fails or does not create a file, and a corpus
        entry recorded as extracted when nothing was written is worse than a refusal."""
        archive = self._sealed("NUL")
        result = sv.extract(archive, self.work)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["members"], ["_NUL"])
        self.assertTrue((self.work / "_NUL").is_file())

    @unittest.skipUnless(HAVE_PYZIPPER, "needs pyzipper")
    def test_a_member_bomb_is_refused_from_the_header(self):
        """Refused before decompressing, so the disk is not filled first and reported after."""
        archive = self._sealed("big.bin")
        result = sv.extract(archive, self.work, max_member_bytes=4)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["members"], [])
        self.assertIn("per-member cap", result["refused"][0]["why"])

    @unittest.skipUnless(HAVE_PYZIPPER, "needs pyzipper")
    def test_the_member_count_is_capped(self):
        archive = self._sealed(*["m%d.bin" % i for i in range(10)])
        result = sv.extract(archive, self.work, max_members=3)
        self.assertFalse(result["ok"])
        self.assertIn("over the cap", result["reason"])

    def test_the_sanitiser_is_pure_and_checkable(self):
        for name, expected in (("a/b.exe", "a/b.exe"), ("NUL", "_NUL"), ("CON.txt", "_CON.txt"),
                               ("a/../b", None), ("../x", None), ("/x", None), ("C:/x", None)):
            with self.subTest(name=name):
                why = sv._is_absolute_or_escaping(name)
                if expected is None:
                    self.assertIsNotNone(why)
                else:
                    self.assertIsNone(why)
                    self.assertEqual(sv._safe_member_name(name), expected)


class TestTheDownloadVerifiesTheSampleNotTheContainer(unittest.TestCase):
    """The code said "verify it against the hash we asked for" and verified the wrong object.

    The collection site serves a zip whose *member* is the sample, so the archive's hash is not the
    sample's hash. The old code computed the former and described it as verification of the latter --
    **a claim in a comment the code did not support**, which is worse than no claim, because it is
    the kind of thing a reader stops checking.
    """

    def test_the_result_names_the_sample_hash_separately(self):
        src = (HERE.parent / "sample_fetch.py").read_text(encoding="utf-8")
        flat = " ".join(src.split())
        self.assertIn("sha256_of_sample", flat)
        self.assertIn("sha256_of_archive", flat)
        self.assertNotIn("sha256_of_download", flat,
                         "the ambiguous name is back; it was the source of the wrong claim")

    def test_a_mismatch_is_refused_and_named(self):
        src = (HERE.parent / "sample_fetch.py").read_text(encoding="utf-8")
        flat = " ".join(src.split())
        self.assertIn("is not the sample that was asked for", flat)
        # The failure must carry both values, or the reader cannot tell a corrupt download from a
        # collision without redoing the work.
        self.assertIn('"expected": meta["sha256_hash"], "got": got', flat)

    def test_the_file_takes_its_final_name_only_after_verification(self):
        """A name that says "complete and checked" must not be reachable by a partial download."""
        src = (HERE.parent / "sample_fetch.py").read_text(encoding="utf-8")
        i = src.index("def fetch_malwarebazaar")
        j = src.index("def _list_by_tag")
        body = src[i:j]
        self.assertIn(".zip.part", body)
        # The commit must come after the hash comparison. Checked against the comparison itself
        # rather than a marker variable, so renaming an internal does not silently disarm the test.
        self.assertLess(body.index('result["sha256_of_sample"]'), body.index("os.replace"),
                        "the file is renamed before its sample hash has been compared")
        # And the write target during download must be the part file, never the final name.
        self.assertNotIn('open(final, "wb")', body)

    def test_a_partial_download_cannot_be_left_behind(self):
        for reason in ("download failed", "over the cap"):
            with self.subTest(reason=reason):
                src = (HERE.parent / "sample_fetch.py").read_text(encoding="utf-8")
                self.assertIn(reason, src)


class TestTheThirdStateIsNotTreatedAsFalse(unittest.TestCase):
    """`is_encrypted_zip` returns None when it cannot check, and `not None` is True.

    A caller that treated the three-state result as a boolean concluded "not encrypted" from "could
    not check" -- **the same substitution the third state was introduced to prevent, made one layer
    down.** It was found by a real fetch behaving differently under two interpreters.
    """

    def test_a_dependency_free_check_exists(self):
        self.assertTrue(hasattr(sv, "is_encrypted_zip_cheaply"))

    def test_the_cheap_check_reads_the_central_directory(self):
        src = (HERE.parent / "sample_vault.py").read_text(encoding="utf-8")
        i = src.index("def is_encrypted_zip_cheaply")
        body = src[i:i + 1400]
        self.assertIn("flag_bits", body)
        self.assertIn("99", body, "WinZip AES is compression method 99 and must be recognised")

    def test_the_fetch_path_uses_the_check_that_cannot_return_none(self):
        src = (HERE.parent / "sample_fetch.py").read_text(encoding="utf-8")
        flat = " ".join(src.split())
        self.assertIn("is_encrypted_zip_cheaply", flat)
        self.assertNotIn("upstream_encrypted = is_encrypted_zip(", flat,
                         "the fetch path is back to a check that answers None without pyzipper")

    def test_the_cheap_check_never_answers_none(self):
        """It has no dependency, so "cannot check" is not one of its outcomes -- which is the whole
        reason the fetch path uses it. The strict check **does** answer None without pyzipper, and
        that is correct; the bug was a caller reading that None as False.
        """
        import zipfile
        tmp = _fixtures.tmpdir("enc-")
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        plain = tmp / "plain.zip"
        with zipfile.ZipFile(plain, "w") as zf:
            zf.writestr("a.txt", b"x")
        self.assertIs(sv.is_encrypted_zip_cheaply(plain), False)
        # Deliberately not asserted equal: without pyzipper the strict check cannot answer at all,
        # and requiring agreement here would demand the very conflation being guarded against.
        if sv.pyzipper is not None:
            self.assertIs(sv.is_encrypted_zip(plain), False)
        else:
            self.assertIsNone(sv.is_encrypted_zip(plain))

    def test_an_aes_archive_is_seen_by_the_cheap_check_without_pyzipper(self):
        """The real case that exposed this: a genuinely sealed sample read as unencrypted because the
        interpreter could not open it."""
        import zipfile
        tmp = _fixtures.tmpdir("aes-")
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        # Hand-built central directory: flag bit 0 set, compression method 99 (WinZip AES).
        raw = tmp / "claims-aes.zip"
        raw.write_bytes(b"PK")
        self.assertIs(sv.is_encrypted_zip_cheaply(raw), False)   # not a readable zip, so no claim
        if sv.pyzipper is not None:
            import pyzipper
            real = tmp / "real-aes.zip"
            with pyzipper.AESZipFile(real, "w", compression=pyzipper.ZIP_DEFLATED,
                                     encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(sv.SAMPLE_PASSWORD)
                zf.writestr("x.bin", b"y")
            self.assertTrue(sv.is_encrypted_zip_cheaply(real))


class TestASampleIsNeverLeftAtRestReadable(unittest.TestCase):
    """The old code warned and left a plaintext sample on disk. A warning nobody reads is not a
    control, and the container exists precisely so the sample cannot be read."""

    def test_an_unsealed_download_is_sealed_here(self):
        src = (HERE.parent / "sample_fetch.py").read_text(encoding="utf-8")
        flat = " ".join(src.split())
        self.assertIn("sealed_by", flat)
        self.assertIn('"source"', flat)
        self.assertIn('"torikago"', flat)

    def test_refusing_outright_is_not_the_answer(self):
        """Turning the protection into a denial of service would be the other failure: the sample
        becomes unobtainable rather than unreadable."""
        src = (HERE.parent / "sample_fetch.py").read_text(encoding="utf-8")
        self.assertNotIn("the downloaded archive is not encrypted, so it was not kept", src)

    def test_the_plaintext_extraction_does_not_trust_the_member_name(self):
        src = (HERE.parent / "sample_fetch.py").read_text(encoding="utf-8")
        i = src.index("def _extract_one_plainly")
        body = src[i:i + 1800]
        self.assertIn("_is_absolute_or_escaping", body)
        self.assertIn("_safe_member_name", body)
        self.assertNotIn("zf.extract(", body,
                         "ZipFile.extract is as trusting as extractall")

    def test_there_is_a_download_cap(self):
        self.assertTrue(hasattr(sf, "MAX_DOWNLOAD_BYTES"))
        self.assertLessEqual(sf.MAX_DOWNLOAD_BYTES, 1 << 30)
