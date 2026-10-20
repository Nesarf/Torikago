# -*- coding: utf-8 -*-
"""The rating's stated basis must be the basis that produced it.

`assess` explains its division of unusual from ordinary with seven rates measured on 298 real binaries.
Those rates used to live only in that docstring -- so when the corpus grows, or a detector changes, the prose
would keep making the old claim and nothing would notice. They are data now (`CALIBRATION`), and this test
holds the two together in both directions:

* every percentage quoted in the prose must exist in the table;
* every rate in the table must be quoted in the prose.

One direction catches a docstring left behind by a re-measurement; the other catches a rate added to the
table whose justification nobody wrote down.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

spec = importlib.util.spec_from_file_location("torikago_cal", ROOT / "torikago.py")
tri = importlib.util.module_from_spec(spec)
sys.modules["torikago_cal"] = tri
spec.loader.exec_module(tri)


def quoted_percentages():
    doc = tri.assess.__doc__ or ""
    return sorted({round(float(x), 1) for x in re.findall(r"(\d+\.\d+)%", doc)})


def table_percentages():
    rates = dict(tri.CALIBRATION["ubiquitous"], **tri.CALIBRATION["rare"])
    return sorted({round(100 * v, 1) for v in rates.values()})


class TestTheStatedBasisMatchesTheData(unittest.TestCase):

    def test_the_prose_quotes_exactly_the_measured_rates(self):
        quoted, table = quoted_percentages(), table_percentages()
        self.assertEqual(len(quoted), 7,
                         "the docstring should quote all seven rates; found %r" % (quoted,))
        self.assertEqual(quoted, table,
                         "the docstring and CALIBRATION disagree: quoted %r, table %r"
                         % (quoted, table))

    def test_the_sample_is_named_not_assumed(self):
        self.assertIn("298", tri.CALIBRATION["sample"],
                      "the sample size a reader is asked to trust is not stated in CALIBRATION")
        self.assertIn("298", tri.assess.__doc__ or "",
                      "the docstring no longer names the sample the rates came from")

    def test_the_version_is_a_positive_integer(self):
        """A version that cannot be ordered cannot be used to say "this rating is older than that one"."""
        self.assertIsInstance(tri.CALIBRATION["version"], int)
        self.assertGreaterEqual(tri.CALIBRATION["version"], 1)

    def test_every_rate_is_a_fraction(self):
        for kind in ("ubiquitous", "rare"):
            for name, value in tri.CALIBRATION[kind].items():
                self.assertTrue(0.0 <= value <= 1.0,
                                "%s/%s is %r, which is not a fraction" % (kind, name, value))

    def test_the_ubiquitous_rates_are_actually_ubiquitous(self):
        """The table's two halves have to mean what their names say, or the division stops explaining
        anything: everything under `ubiquitous` must be commoner than everything under `rare`."""
        commonest_rare = max(tri.CALIBRATION["rare"].values())
        rarest_ubiquitous = min(tri.CALIBRATION["ubiquitous"].values())
        self.assertGreater(rarest_ubiquitous, commonest_rare,
                           "a 'ubiquitous' rate is rarer than a 'rare' one: the split is a label, not a "
                           "measurement")


class TestTheCorpusCheckCarriesTheBasis(unittest.TestCase):
    """The command a reader runs when the corpus has grown must say what the rating rests on."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.manifest = Path(self.tmp.name) / "manifest.jsonl"
        self.manifest.write_text("", encoding="utf-8")

    def _run(self, argv):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = tri.main(argv)
        return rc, buf.getvalue()

    def test_json_carries_the_calibration(self):
        rc, out = self._run(["--corpus-check", str(self.manifest), "--json"])
        self.assertEqual(rc, 0)
        body = json.loads(out)
        self.assertIn("calibration", body)
        self.assertEqual(body["calibration"]["version"], tri.CALIBRATION["version"])
        self.assertEqual(body["calibration"]["ubiquitous"], tri.CALIBRATION["ubiquitous"])

    def test_the_human_output_names_the_version_and_the_sample(self):
        rc, out = self._run(["--corpus-check", str(self.manifest)])
        self.assertEqual(rc, 0)
        self.assertIn("CALIBRATION v%d" % tri.CALIBRATION["version"], out)
        self.assertIn("298", out)
        self.assertIn("99.7%", out)


if __name__ == "__main__":
    unittest.main()
