# -*- coding: utf-8 -*-
"""Auditing a self-declared registration against facts that can actually be checked.

The mechanism is self-declared by design: a product registers with Security Center, states that it is
enabled and protecting, and **Windows turns Defender off in response**. That is how any third-party
antivirus takes over, and it is documented behaviour rather than a flaw. What is not verified is the
declaration — which two public tools abuse:

  * `no-defender` registered a fake antivirus that protected nothing; Defender stood down
  * `Defendnot` injected its fake DLL into `Taskmgr.exe`, a signed process the system trusts, to get
    past the registration checks

The second one is why "declares itself the protection product while pointing at a signed Microsoft
component that is not security software" is a contradiction worth naming: it is what injection looks
like from the outside.

**The asymmetry is the whole design, and it is asserted here**: finding a contradiction means
something, finding none means nothing. A convincing fake declares a plausible path that exists and
runs and passes every check. Two regressions found while building this are also covered below.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

spec = importlib.util.spec_from_file_location("pr", HERE.parent / "product_registration.py")
pr = importlib.util.module_from_spec(spec)
sys.modules["pr"] = pr
spec.loader.exec_module(pr)


class TestContradictionsAreFound(unittest.TestCase):
    def test_a_product_pointing_at_taskmgr_is_a_contradiction(self):
        """The Defendnot shape: signed, trusted, and not a security product."""
        found = pr.check_declaration({
            "name": "Totally Real Antivirus",
            "declared_executable": r"C:\Windows\System32\taskmgr.exe",
            "declares_realtime": True,
        })
        self.assertTrue(found["contradictions"])
        self.assertIn("taskmgr.exe", found["contradictions"][0])

    def test_every_trusted_but_not_security_binary_is_caught(self):
        for binary in pr.TRUSTED_BUT_NOT_SECURITY:
            with self.subTest(binary=binary):
                found = pr.check_declaration({
                    "name": "X", "declared_executable": r"C:\Windows\System32\%s" % binary,
                    "declares_realtime": True,
                })
                # Some may not exist on this machine; those are reported as missing instead, which
                # is also a finding. Neither outcome may be silence.
                self.assertTrue(found["contradictions"] or found["checks"])

    def test_declaring_realtime_with_a_missing_executable_is_a_contradiction(self):
        found = pr.check_declaration({
            "name": "X", "declared_executable": r"C:\nowhere\gone.exe",
            "declares_realtime": True,
        })
        self.assertTrue(any("missing" in c for c in found["contradictions"]))

    def test_a_missing_executable_without_a_realtime_claim_is_not_a_contradiction(self):
        """Observed on this machine: Tencent's registered path does not exist while its state has
        no real-time flag. The fact is worth recording; it does not prove a false declaration."""
        found = pr.check_declaration({
            "name": "X", "declared_executable": r"C:\nowhere\gone.exe",
            "declares_realtime": False,
        })
        self.assertEqual(found["contradictions"], [])
        self.assertIn("declared executable does not exist", found["checks"])


class TestWhatIsNotAContradiction(unittest.TestCase):
    def test_a_uri_is_not_treated_as_a_missing_file(self):
        """Defender declares `windowsdefender://`. A naive existence check would call the one
        certainly-real product broken."""
        found = pr.check_declaration({
            "name": "Windows Defender", "declared_executable": "windowsdefender://",
            "declares_realtime": True,
        })
        self.assertEqual(found["contradictions"], [])
        self.assertIn("URI", found["checks"][0])

    def test_nothing_declared_is_noted_not_flagged(self):
        found = pr.check_declaration({"name": "X", "declared_executable": ""})
        self.assertEqual(found["contradictions"], [])
        self.assertIn("no executable declared", found["checks"])


class TestServiceMatchingDoesNotCryWolf(unittest.TestCase):
    """The first version matched "Windows Defender" against a service called Appinfo, because both
    contain "windows". That is a false positive produced by the matcher, not by the machine."""

    SERVICES = [
        {"name": "Appinfo", "path": r"C:\Windows\System32\svchost.exe -k netsvcs"},
        {"name": "QQPCMgr", "path": r"C:\Program Files (x86)\Tencent\QQPCMgr\QQPCMgr.exe"},
    ]

    def test_a_generic_word_does_not_match(self):
        result = pr.matching_service(
            {"name": "Windows Defender", "declared_executable": "windowsdefender://"},
            self.SERVICES)
        self.assertIsNone(result["matched"],
                          "matched on a generic word, which is how Appinfo got attributed to Defender")

    def test_the_vendor_directory_matches(self):
        result = pr.matching_service(
            {"name": "Tencent PC Manager",
             "declared_executable": r"C:\Program Files (x86)\Tencent\QQPCMgr\17.0\QQPCMgr.exe"},
            self.SERVICES)
        self.assertEqual(result["matched"], "QQPCMgr")

    def test_nothing_to_match_on_is_said_rather_than_guessed(self):
        result = pr.matching_service({"name": "X", "declared_executable": "://"},
                                     self.SERVICES)
        self.assertIsNone(result["matched"])
        self.assertIn("reason", result)


class TestTheAsymmetryIsStatedInTheOutput(unittest.TestCase):
    """A report that finds nothing must not read as reassurance."""

    def test_the_result_carries_its_limits(self):
        result = pr.audit_registrations()
        self.assertIn("limits", result)
        if result.get("ok"):
            text = " ".join(result["limits"]).lower()
            self.assertIn("finding none means nothing", text)
            self.assertIn("no signature database", text)

    def test_a_missing_service_is_not_reported_as_proof(self):
        result = pr.audit_registrations()
        if not result.get("ok"):
            self.skipTest("no products registered here")
        text = " ".join(result["limits"]).lower()
        self.assertIn("not proof of absence", text)

    def test_the_module_docstring_names_both_abusing_tools(self):
        """The finding is only meaningful with the reason it exists."""
        doc = (HERE.parent / "product_registration.py").read_text(encoding="utf-8")
        for name in ("no-defender", "Defendnot"):
            with self.subTest(tool=name):
                self.assertIn(name, doc)


class TestTheBitLayoutIsMeasuredNotLookedUp(unittest.TestCase):
    def test_the_real_time_flag_is_bit_twelve(self):
        self.assertEqual(pr.STATE_REALTIME_ON, 1 << 12)

    def test_the_measurement_that_derived_it_is_recorded(self):
        """The comment is load-bearing: the layout is undocumented, and the next reader needs to
        know where the number came from or they will not be able to re-check it."""
        src = (HERE.parent / "product_registration.py").read_text(encoding="utf-8")
        self.assertIn("0x61100", src)
        self.assertIn("RealTimeProtectionEnabled", src)

    def test_an_absent_flag_is_reported_as_ambiguous_not_as_off(self):
        """Asserted against the runtime value, not against the source text.

        The source-text version of this test failed for a reason worth keeping: adjacent string
        literals are quoted and line-broken in the file, so searching it measures the spelling of
        the literal rather than the sentence it builds. Asserting the constant is the same check
        without the false negative.
        """
        self.assertIn("cannot tell the two apart", pr.REALTIME_FLAG_ABSENT)
        self.assertIn("may mean", pr.REALTIME_FLAG_ABSENT,
                      "the message must not decide between the two readings")


if __name__ == "__main__":
    unittest.main(verbosity=2)
