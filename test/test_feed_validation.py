"""Validate the feed output against the official libraries, when they are available.

The eighteen existing feed tests check the shape this tool *intends* to produce: is the event
well-formed, do the hashes carry the right attribute types, is it unpublished. None of them asks
whether a consumer would accept the result -- and for STIX the answer was no:

    InvalidValueError: Unexpected properties for Indicator: (x_torikago_source_file)

An undeclared custom property made one object invalid, which made the whole bundle invalid, so every
TIP importing it would have failed. Every existing test passed.

`stix2` is not a dependency of this project and will not become one, so these tests skip when it is
absent. That is the right trade: the check runs where it can, and the package stays dependency-free
where it cannot.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

spec = importlib.util.spec_from_file_location("tk_feedval", HERE.parent / "torikago.py")
tk = importlib.util.module_from_spec(spec)
sys.modules["tk_feedval"] = tk
spec.loader.exec_module(tk)

HAVE_STIX2 = importlib.util.find_spec("stix2") is not None


def sample_report():
    """A report with indicators of every kind the STIX path handles."""
    return {
        "file": r"C:\samples\example.exe",
        "hashes": {"sha256": "a" * 64, "sha1": "b" * 40, "md5": "c" * 32, "size": 1234},
        "iocs": {
            "url": ["https://example.invalid/one", "http://example.invalid/two"],
            "domain": ["evil.invalid", "also-evil.invalid"],
            "ipv4": ["203.0.113.7"],
            "email": ["bad@example.invalid"],
        },
        "identified_as": {"kind": "pe", "label": "PE executable (DOS/PE)"},
        "assessment": {"reasons": ["something"], "notes": [], "attention": 1},
    }


class TestStixIsValid(unittest.TestCase):
    """Requires stix2; skipped rather than failing where it is not installed."""

    def setUp(self):
        if not HAVE_STIX2:
            self.skipTest("stix2 is not installed; this check needs an official consumer")
        import stix2
        self.stix2 = stix2

    def test_the_bundle_parses_with_the_official_library(self):
        bundle = tk.build_stix_bundle(sample_report())
        obj = self.stix2.parse(json.dumps(bundle))
        self.assertEqual(obj.type, "bundle")

    def test_every_object_parses_individually(self):
        """A bundle parse can mask which object was at fault; this names it."""
        bundle = tk.build_stix_bundle(sample_report())
        for o in bundle["objects"]:
            with self.subTest(type=o["type"]):
                self.stix2.parse(json.dumps(o))

    def test_there_are_no_undeclared_custom_properties(self):
        """The defect this file was written for: an `x_` property nothing declares invalidates the
        object, and one invalid object invalidates the bundle."""
        bundle = tk.build_stix_bundle(sample_report())
        declared = {o.get("id") for o in bundle["objects"]
                    if o.get("type") == "extension-definition"}
        for o in bundle["objects"]:
            for key in o:
                if key.startswith("x_"):
                    self.assertIn(o.get("id"), declared,
                                  "object %s carries custom property %r with no "
                                  "ExtensionDefinition declaring it" % (o["id"], key))

    def test_indicators_carry_the_source_in_a_standard_field(self):
        bundle = tk.build_stix_bundle(sample_report())
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        self.assertTrue(indicators)
        for ind in indicators:
            self.assertIn("description", ind)
            self.assertIn("example.exe", ind["description"])

    def test_the_patterns_are_valid_stix_patterns(self):
        """A malformed pattern is another way a bundle fails on import, and the library checks it."""
        bundle = tk.build_stix_bundle(sample_report())
        for ind in (o for o in bundle["objects"] if o["type"] == "indicator"):
            with self.subTest(pattern=ind["pattern"]):
                self.stix2.parse(json.dumps(ind))


class TestStixShapeWithoutTheLibrary(unittest.TestCase):
    """The checks that hold whether or not a consumer is installed."""

    def test_every_object_has_a_type_a_spec_version_and_an_id(self):
        bundle = tk.build_stix_bundle(sample_report())
        for o in bundle["objects"]:
            self.assertIn("type", o)
            self.assertIn("id", o)
            self.assertEqual(o["spec_version"], "2.1")

    def test_the_bundle_is_json_serialisable(self):
        json.dumps(tk.build_stix_bundle(sample_report()))

    def test_ids_are_deterministic_for_the_same_pattern(self):
        """The same indicator extracted twice must not appear as two different objects."""
        a = tk.build_stix_bundle(sample_report())
        b = tk.build_stix_bundle(sample_report())
        ids_a = sorted(o["id"] for o in a["objects"] if o["type"] == "indicator")
        ids_b = sorted(o["id"] for o in b["objects"] if o["type"] == "indicator")
        self.assertEqual(ids_a, ids_b)


class TestMispEventIsWellFormedXml(unittest.TestCase):
    """MISP takes XML for its import path; the parser here is the standard library's."""

    def test_the_event_parses_as_xml(self):
        xml = tk.build_misp_event(sample_report())
        root = ET.fromstring(xml)
        self.assertEqual(root.tag, "misp")

    def test_attributes_carry_the_fields_misp_requires(self):
        root = ET.fromstring(tk.build_misp_event(sample_report()))
        attrs = root.findall("./Event/Attribute")
        self.assertTrue(attrs)
        for a in attrs:
            for field in ("type", "category", "value", "to_ids"):
                self.assertIsNotNone(a.find(field),
                                     "attribute %r has no <%s>" % (a.findtext("value"), field))

    def test_to_ids_survives_the_round_trip(self):
        root = ET.fromstring(tk.build_misp_event(sample_report()))
        flag = {a.findtext("value"): a.findtext("to_ids")
                for a in root.findall("./Event/Attribute")}
        self.assertIn("true", set(flag.values()))

    def test_the_event_is_not_published(self):
        """Generating an event is a statement of intent, not a disclosure to every MISP peer."""
        root = ET.fromstring(tk.build_misp_event(sample_report()))
        self.assertEqual(root.findtext("./Event/published"), "false")


if __name__ == "__main__":
    unittest.main(verbosity=2)
