# -*- coding: utf-8 -*-
"""Handing evidence to a real engine, without becoming one.

Torikago reaches no conclusion about whether a file is malicious. That is the whole reason it is
useful, and the handoff is where the discipline is easiest to lose -- because once you can call an
antivirus engine, "it found nothing" starts to feel like "it is safe", and it is not.

The three rules this file defends:

**`-DisableRemediation` must stay.** Without it `MpCmdRun -Scan` deletes or quarantines the file as a
side effect of being asked for an opinion. A diagnostic tool must never destroy what it is reporting
on, and the flag is the difference between a question and an action.

**The verdict is the engine's.** `Defender says clean` and `this is clean` are different sentences.

**A third-party antivirus owning the Security Center registration is reported.** Defender's engine
can answer a scan while something else does the watching, and saying "Defender found nothing" then
would be a false reassurance.

The engine may not be installed. These tests skip rather than fail there, and one checks the
absence path deliberately.
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

spec = importlib.util.spec_from_file_location("tk_handoff", HERE.parent / "torikago.py")
tk = importlib.util.module_from_spec(spec)
sys.modules["tk_handoff"] = tk
spec.loader.exec_module(tk)

HAVE_DEFENDER = tk.find_defender() is not None


class TestTheHandoffNeverRemediates(unittest.TestCase):
    """The flag that makes this a question instead of an action."""

    def test_the_command_disables_remediation(self):
        """Checked by reading the command the function builds, not by running it: running the
        remediating version would be the experiment that deletes a file."""
        import inspect
        src = inspect.getsource(tk.scan_with_defender)
        self.assertIn("-DisableRemediation", src,
                      "without this flag, asking Defender for an opinion removes the file")
        self.assertIn('"-ScanType", "3"', src)

    def test_it_reports_that_remediation_was_disabled(self):
        """A caller must be able to tell which mode ran, from the result alone."""
        if not HAVE_DEFENDER:
            self.skipTest("Defender is not installed here")
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "harmless.txt"
            f.write_text("nothing to see\n", encoding="utf-8")
            r = tk.scan_with_defender([f])
        self.assertTrue(r["ok"])
        self.assertTrue(r["remediation_disabled"],
                        "the result does not say whether the engine was allowed to change files")

    def test_the_file_is_still_there_afterwards(self):
        """The concrete consequence, asserted rather than assumed."""
        if not HAVE_DEFENDER:
            self.skipTest("Defender is not installed here")
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "harmless.txt"
            f.write_text("nothing to see\n", encoding="utf-8")
            tk.scan_with_defender([f])
            self.assertTrue(f.is_file(), "the scan removed the file it was asked about")


class TestTheVerdictIsTheEnginesNotOurs(unittest.TestCase):
    """Nothing in the output may read as this tool's own conclusion."""

    def test_the_result_carries_the_attribution_note(self):
        if not HAVE_DEFENDER:
            self.skipTest("Defender is not installed here")
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "harmless.txt"
            f.write_text("x\n", encoding="utf-8")
            r = tk.scan_with_defender([f])
        self.assertIn("not this tool", r["note"])
        self.assertFalse(r["executed"], "the handoff must report that nothing was run")

    def test_a_clean_result_is_marked_as_the_engines(self):
        if not HAVE_DEFENDER:
            self.skipTest("Defender is not installed here")
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "harmless.txt"
            f.write_text("x\n", encoding="utf-8")
            r = tk.scan_with_defender([f])
        v = r["verdicts"][0]
        self.assertIn("file", v)
        self.assertIn("clean", v)
        # The raw line is kept, so the reading can be checked instead of trusted.
        self.assertTrue(v["line"], "the engine's raw words were discarded")

    def test_no_field_is_named_like_our_own_detection(self):
        """A key called `malicious` or `detected` would be this tool claiming a verdict."""
        import inspect
        src = inspect.getsource(tk.scan_with_defender)
        for forbidden in ('"malicious"', '"detected"', '"is_virus"', '"safe"'):
            self.assertNotIn(forbidden, src,
                             "%s reads as this tool's verdict rather than the engine's" % forbidden)


class TestAbsenceIsReportedNotWorkedAround(unittest.TestCase):
    """The same rule as ClamAV: no engine means say so."""

    def test_a_missing_engine_is_reported(self):
        r = tk.scan_with_defender([Path("nothing.exe")],
                                  mpcmdrun=r"C:\does\not\exist\MpCmdRun.exe")
        self.assertFalse(r["ok"])
        self.assertIn("reason", r)
        self.assertFalse(r["executed"])

    def test_a_finding_engine_reports_none(self):
        if tk.find_defender() is None:
            self.assertIsNone(tk.find_defender())
        else:
            self.assertTrue(Path(tk.find_defender()).is_file())


class TestSecurityCenterRegistrationIsReported(unittest.TestCase):
    """`Defender found nothing` is only meaningful if Defender is the engine watching."""

    def test_the_owner_query_returns_a_shape(self):
        o = tk.defender_owner()
        self.assertIn("available", o)
        if o["available"]:
            self.assertIn("products", o)
            self.assertIn("third_party", o)
            self.assertIsInstance(o["third_party"], list)

    def test_a_third_party_product_is_not_counted_as_defender(self):
        o = tk.defender_owner()
        if not o.get("available"):
            self.skipTest("Security Center is not queryable here")
        for name in o["third_party"]:
            self.assertNotIn("defender", name.lower())

    def test_product_names_are_decoded_not_mojibake(self):
        """PowerShell emits in the system code page unless told otherwise, so a Chinese product
        name read as UTF-8 arrives as garbage -- and a garbled name is a wrong answer."""
        o = tk.defender_owner()
        if not o.get("available") or not o.get("products"):
            self.skipTest("no products registered here")
        for name in o["products"]:
            self.assertNotIn("\ufffd", name, "product name arrived as replacement characters: %r"
                             % name)


class TestTheCliExposesIt(unittest.TestCase):
    def test_the_flag_is_offered(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit):
                tk.main(["--help"])
        self.assertIn("--handoff", buf.getvalue())

    def test_the_help_says_it_does_not_run_or_remove_anything(self):
        """argparse wraps help to the terminal width, so a phrase can be split across lines and a
        naive substring search fails. Whitespace is collapsed before checking -- and the wrapping is
        itself worth knowing about, since the promises have to survive an 80-column terminal."""
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit):
                tk.main(["--help"])
        flat = " ".join(buf.getvalue().split())
        self.assertIn("runs nothing", flat)
        self.assertIn("removes nothing", flat)
        self.assertIn("Reads the file", flat)


if __name__ == "__main__":
    unittest.main(verbosity=2)
