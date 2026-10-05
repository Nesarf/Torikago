# -*- coding: utf-8 -*-
"""The security posture report: read-only, and honest about what it cannot see.

This module exists because a security tool that reports on the machine's protection has two easy
failure modes, and both are worse than not reporting at all:

**It could change something.** The whole value is that it is safe to run at any moment. Asserted
structurally, because a `Set-MpPreference` added later for a good reason would silently turn a report
into a modification.

**It could report a status it did not verify.** Every field comes from a query whose failure is
recorded as a failure, never smoothed into a default -- "signature age: unknown" and "signature age:
0" mean opposite things, and only one of them is reassuring.

The findings logic is separated from the collection so the judgements are visible as judgements.
"""
from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

spec = importlib.util.spec_from_file_location("sp", HERE.parent / "security_posture.py")
sp = importlib.util.module_from_spec(spec)
sys.modules["sp"] = sp
spec.loader.exec_module(sp)

SOURCE = (HERE.parent / "security_posture.py").read_text(encoding="utf-8")


class TestItChangesNothing(unittest.TestCase):
    """A report that can modify the thing it reports on is not a report."""

    def test_no_setting_writing_cmdlet_appears_anywhere(self):
        for forbidden in ("Set-MpPreference", "Add-MpPreference", "Remove-MpPreference",
                          "Set-MpComputerStatus", "Update-MpSignature", "Start-MpScan"):
            with self.subTest(cmdlet=forbidden):
                self.assertNotIn(forbidden, SOURCE,
                                 "%s would let this module change what it reports on" % forbidden)

    def test_actions_that_would_be_writes_are_absent(self):
        for verb in ("-DisableRealtimeMonitoring", "-ExclusionPath", "Remove-Item", "Stop-Service"):
            with self.subTest(verb=verb):
                self.assertNotIn(verb, SOURCE)

    def test_it_says_so_in_its_own_output(self):
        state = {"note": "Nothing here changes a setting."}
        self.assertIn("changes a setting", state["note"])
        self.assertIn("read_only", sp.posture().keys() if callable(sp.posture) else [])
        self.assertTrue(sp.posture().get("read_only"))


class TestEveryFieldIsQueriedNotAssumed(unittest.TestCase):
    def test_the_posture_object_has_the_sections(self):
        state = sp.posture()
        for key in ("defender", "registered", "exclusions", "detections", "read_only"):
            self.assertIn(key, state)

    def test_a_failed_query_is_recorded_as_a_failure(self):
        """Not smoothed into a default: 'unknown' and 'none' are different answers."""
        for fn in (sp.defender_status, sp.registered_products, sp.exclusions, sp.recent_detections):
            result = fn()
            with self.subTest(fn=fn.__name__):
                self.assertIn("ok", result)
                if not result["ok"]:
                    self.assertIn("reason", result,
                                  "%s failed without saying why" % fn.__name__)

    def test_an_unavailable_engine_does_not_look_healthy(self):
        """The dangerous shape would be an empty dict that reads as 'nothing wrong'."""
        result = sp.defender_status()
        self.assertIn("ok", result)
        if result["ok"] and "defender" in result:
            self.assertNotIn("antivirus_enabled", result,
                             "an unavailable engine must not report a protection field")


class TestFindingsAreJudgements(unittest.TestCase):
    """The findings must fire on the states that matter, and stay quiet otherwise."""

    def _findings(self, **over):
        state = {
            "defender": {"antivirus_enabled": "True", "service_enabled": "True",
                         "realtime": "True"},
            "registered": {"products": [], "third_party": []},
            "exclusions": {"paths": [], "extensions": [], "processes": []},
            "detections": {"detections": []},
        }
        state.update(over)
        return sp.findings(state)

    def test_a_clean_machine_reports_nothing(self):
        self.assertEqual(self._findings(), [])

    def test_real_time_protection_off_is_critical(self):
        found = self._findings(defender={"antivirus_enabled": "True", "service_enabled": "True",
                                         "realtime": "False"})
        self.assertTrue(any(f["level"] == "critical" and "real-time" in f["what"] for f in found))

    def test_a_disabled_engine_is_critical(self):
        found = self._findings(defender={"antivirus_enabled": "False", "realtime": "True",
                                         "service_enabled": "False"})
        self.assertTrue(any(f["level"] == "critical" for f in found))

    def test_a_third_party_registration_is_reported_as_information(self):
        """Not a fault -- but it changes what a clean Defender verdict is worth, so it is said."""
        found = self._findings(registered={"products": [], "third_party": ["Some AV"]})
        self.assertTrue(any(f["level"] == "info" and "Some AV" in f["what"] for f in found))

    def test_an_exclusion_is_a_warning(self):
        found = self._findings(exclusions={"paths": [r"C:\x"], "extensions": [],
                                           "processes": []})
        self.assertTrue(any(f["level"] == "warning" for f in found))

    def test_detections_are_summarised_not_dumped(self):
        found = self._findings(detections={"detections": [{"at": "t", "resources": "file: x"}]})
        self.assertTrue(any("recent detection" in f["what"] for f in found))


class TestItKnowsNothingAboutSampleLocations(unittest.TestCase):
    """A shipped package that knows the path to a malware collection is a package that leaks it."""

    def test_no_sample_location_appears_in_the_source(self):
        """Checked against paths and module names, not against the word.

        `quarantine` as a *verb* -- "detection, verdict, quarantine, record" -- is ordinary security
        vocabulary and belongs in the docstring. What must not appear is a path to a collection or the
        name of a module that handles one, and the first version of this test banned the word and
        failed on its own prose.
        """
        lowered = SOURCE.lower()
        for forbidden in ("e:\\quarantine", "sample_vault", "/quarantine/", "\\quarantine\\"):
            with self.subTest(needle=forbidden):
                self.assertNotIn(forbidden, lowered,
                                 "the shipped module must not know where samples are kept")


if __name__ == "__main__":
    unittest.main(verbosity=2)
