# -*- coding: utf-8 -*-
"""The window: a panel painted from two files this repository embeds.

**Why these tests never open a window.** Opening one needs a display and blocks in `mainloop`, so a
suite that opened one would hang rather than fail -- measured once already in a sibling project, where
the run simply never returned and looked like slowness. Everything worth asserting is upstream of that
call: the layout validates its own checksum, the page arithmetic counts rows the layout derives rather
than rows somebody wrote down, a title that does not fit is refused instead of cut, and the lines the
panel holds are the lines the terminal printed.

Run:
    python -m unittest discover -s test -v
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

spec = importlib.util.spec_from_file_location("torikago", ROOT / "torikago.py")
tri = importlib.util.module_from_spec(spec)
sys.modules["torikago"] = tri
spec.loader.exec_module(tri)

import panel_window as pw                                          # noqa: E402


LAYOUT = pw.load(ROOT / "panel.json")
GLYPH = pw.load_font(ROOT / "font.json")

# `pillow` is an extra, and a suite that errors on its absence cannot be run on the machine that is
# only checking the analysis. The pixels are still checked everywhere the extra is installed, and the
# release workflow installs it so the gate that publishes sees them.
try:
    import PIL                                                       # noqa: F401
    HAVE_PILLOW = True
except ImportError:
    HAVE_PILLOW = False

needs_pillow = unittest.skipUnless(HAVE_PILLOW, "pillow is the `window` extra and is not installed")


class TestTheEmbeddedLayout(unittest.TestCase):
    """The layout has to be the one Ichiwatashi exported, and it has to say so itself."""

    def test_it_validates_its_own_checksum(self):
        body = json.loads((ROOT / "panel.json").read_text(encoding="utf-8"))
        self.assertEqual(body["format"], pw.FORMAT)
        self.assertEqual(body["tier"], "console")
        self.assertEqual(tuple(body["size"]), (716, 385))
        # Nine since `content_text` joined the table: the bar's ink and the body's are two jobs, and all
        # three renderers used to do both with one colour.
        self.assertEqual(len(body["roles"]), 9)
        self.assertIn("content_text", body["roles"])
        want = body["checksum"]
        got = hashlib.sha256(pw.canonical({k: v for k, v in body.items() if k != "checksum"}
                                          ).encode("utf-8")).hexdigest()
        self.assertEqual(want, got)

    def test_the_content_geometry_is_derived_from_the_rectangles(self):
        """118 by 46 is also the character grid Volcano Separator lays out, which is the point.

        Both numbers come from the content rectangle divided by the cell size. A tool that wrote
        either one down would page wrongly on any other size tier.
        """
        cx0, cy0, cx1, cy1 = LAYOUT.layout["content"]
        self.assertEqual(LAYOUT.body_cols, (cx1 - cx0) // pw.CELL_W)
        self.assertEqual(LAYOUT.body_rows, (cy1 - cy0) // pw.CELL_H)
        self.assertEqual((LAYOUT.body_cols, LAYOUT.body_rows), (118, 46))

    def test_a_tampered_layout_is_refused_rather_than_drawn(self):
        body = json.loads((ROOT / "panel.json").read_text(encoding="utf-8"))
        body["size"] = [700, 385]                      # one field, checksum now wrong
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "panel.json"
            p.write_text(json.dumps(body), encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                pw.load(p)
        self.assertIn("checksum", str(ctx.exception))

    @needs_pillow
    def test_the_pixels_come_from_the_file_not_from_this_reader(self):
        """**Nothing here is a second opinion about the panel.** Change a colour, re-sign the file,
        and the rendered pixel follows -- so the frame cannot be recomputed locally without a test
        noticing."""
        body = json.loads((ROOT / "panel.json").read_text(encoding="utf-8"))
        body["colours"]["cm"] = [1, 2, 3, 4]
        body["checksum"] = hashlib.sha256(
            pw.canonical({k: v for k, v in body.items() if k != "checksum"}).encode("utf-8")
        ).hexdigest()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "panel.json"
            p.write_text(json.dumps(body), encoding="utf-8")
            lay = pw.load(p)
        im = pw.image(lay, [], title=None, scale=1)
        self.assertEqual(im.getpixel((708, 4)), (1, 2, 3, 4))

    def test_a_wheel_carries_the_module_and_both_files(self):
        """`py-modules` lists modules one by one and cannot carry data.

        The repository has this defect's shape on record twice already -- `unpack.py` was missing from
        a published wheel, and a sibling project shipped without its `assets/` directory. Both were
        found by installing rather than by testing, and neither showed up locally.
        """
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        modules = re.search(r"^py-modules\s*=\s*\[(.*?)\]", pyproject, re.S | re.M)
        self.assertIsNotNone(modules, "py-modules is missing from pyproject.toml")
        self.assertIn('"panel_window"', modules.group(1))
        files = re.search(r"^\[tool\.setuptools\.data-files\](.*?)(?=^\[|\Z)", pyproject, re.S | re.M)
        self.assertIsNotNone(files, "no data-files table, so the JSON cannot reach a wheel")
        self.assertIn("panel.json", files.group(1))
        self.assertIn("font.json", files.group(1))


    def test_the_window_extra_is_declared(self):
        """`--window` needs an image library and the base install is deliberately empty.

        A clean venv install of this wheel, without the extra, imports `panel_window` happily -- PIL is
        imported inside the drawing call -- and then `open_window` raises. So the dependency is real and
        invisible until someone runs the flag; naming it in an extra is what makes it findable.
        """
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        extra = re.search(r"^window\s*=\s*\[([^\]]*)\]", pyproject, re.M)
        self.assertIsNotNone(extra, "no `window` extra, so a pip install can never draw one")
        self.assertIn("pillow", extra.group(1).lower())


class TestTheBodyInk(unittest.TestCase):
    """Body text used to be drawn in the title bar's ink by all three renderers.

    So a change to the bar's colour silently restyled every report, and nothing anywhere said the body was
    borrowing. The layout names the job now -- and a file exported before the role existed still draws, in
    the colour it always used, so upgrading one side of an embedding does not break the other.
    """

    def test_the_two_inks_are_separate_jobs(self):
        body_key = LAYOUT.key_of["content_text"]
        title_key = LAYOUT.key_of["title_text"]
        self.assertNotEqual(body_key, title_key, "one key for two jobs is the defect this role replaced")
        self.assertEqual(LAYOUT.content_ink, LAYOUT.colours[body_key])
        self.assertNotEqual(LAYOUT.content_ink, LAYOUT.colours[title_key],
                            "both inks are the same colour, so nothing would show the role is being used")

    @needs_pillow
    def test_rendered_body_text_uses_that_ink_and_not_the_bar_s(self):
        """Asserted on pixels rather than on the property: the property could be right while the renderer
        ignored it, which is the shape of every wiring defect this family has found."""
        cx0, cy0, _cx1, _cy1 = LAYOUT.layout["content"]
        _tx0, ty0, _tx1, _ty1 = LAYOUT.layout["title"]
        start, _room = LAYOUT.title_room
        im = pw.image(LAYOUT, ["I"], title="T", scale=1, draw_fn=GLYPH)

        def cell(x, y):
            return [im.getpixel((x + dx, y + dy))
                    for dy in range(pw.CELL_H) for dx in range(pw.CELL_W)]

        body, title = cell(cx0, cy0), cell(start, ty0 + 1)
        self.assertIn(LAYOUT.content_ink, body, "the body was not drawn in the layout's own ink")
        self.assertNotIn(LAYOUT.colours[LAYOUT.key_of["title_text"]], body,
                         "the body is still borrowing the title bar's ink")
        self.assertIn(LAYOUT.colours[LAYOUT.key_of["title_text"]], title)
        self.assertNotIn(LAYOUT.content_ink, title, "the title is drawn in the body's ink")

    def test_a_file_without_the_role_falls_back_to_the_title_ink(self):
        body = json.loads((ROOT / "panel.json").read_text(encoding="utf-8"))
        body["roles"] = [r for r in body["roles"] if r != "content_text"]
        del body["keys"]["content_text"]
        # The colour stays in the table, because that is what an older export looks like: the role is what a
        # reader asks for, and its absence is the question being answered here.
        body["checksum"] = hashlib.sha256(
            pw.canonical({k: v for k, v in body.items() if k != "checksum"}).encode("utf-8")).hexdigest()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "panel.json"
            p.write_text(json.dumps(body), encoding="utf-8")
            old = pw.load(p)
        self.assertNotIn("content_text", old.key_of)
        self.assertEqual(old.content_ink, old.colours[old.key_of["title_text"]])


class TestRefusalsInsteadOfCuts(unittest.TestCase):
    """Three ways a window can lie, and none of them is allowed to happen quietly."""

    def test_a_title_that_does_not_fit_names_both_numbers(self):
        with self.assertRaises(ValueError) as ctx:
            pw.text(LAYOUT, ["x"], title="T" * 200)
        message = str(ctx.exception)
        self.assertIn("1200 px", message)              # what the title needs
        self.assertIn("703", message)                  # what the bar has

    def test_a_body_line_wider_than_the_content_is_refused(self):
        with self.assertRaises(ValueError) as ctx:
            pw.text(LAYOUT, ["x" * 200], title="T")
        message = str(ctx.exception)
        self.assertIn("200 characters", message)
        self.assertIn("118", message)

    def test_wrapping_marks_the_breaks_and_stays_inside_the_width(self):
        line = "file        : " + "C:\\" + "very-long-directory\\" * 12 + "sample.exe"
        wrapped = tri._wrap_lines([line], LAYOUT.body_cols)
        self.assertGreater(len(wrapped), 1, "the fixture did not need wrapping")
        for out in wrapped:
            self.assertLessEqual(len(out), LAYOUT.body_cols, "%r is wider than the panel" % (out,))
        for out in wrapped[:-1]:
            self.assertTrue(out.endswith(" \\"),
                            "a continued line must be marked; %r is not" % (out,))
        self.assertFalse(wrapped[-1].endswith(" \\"))
        # Nothing was lost: the payload survives the break, ignoring the marks and the indent.
        rejoined = "".join(w.rstrip(" \\").rstrip() for w in wrapped).replace("  ", "")
        self.assertIn("sample.exe", rejoined)

    def test_a_line_that_exactly_fits_is_not_touched(self):
        exact = "x" * LAYOUT.body_cols
        self.assertEqual(tri._wrap_lines([exact], LAYOUT.body_cols), [exact])


class TestCaseIsPreserved(unittest.TestCase):
    """**The font carries 88 glyphs and 26 of them are lower-case.** A renderer that upper-cases
    throws those 26 away while every test still passes -- measured in the PowerShell consumer, where
    the table's keys were also case-insensitive, and then found again here."""

    def test_the_font_holds_lower_case_letters(self):
        body = json.loads((ROOT / "font.json").read_text(encoding="utf-8"))
        glyphs = body["glyphs"]
        self.assertEqual(len(glyphs), 88)
        for ch in "abcdefghijklmnopqrstuvwxyz":
            self.assertIn(ch, glyphs, "%r is not in the embedded font" % ch)
        self.assertNotEqual(glyphs["a"], glyphs["A"], "the two cases are the same shape")

    @needs_pillow
    def test_lower_case_is_drawn_as_lower_case(self):
        from PIL import Image

        def drawn(text):
            im = Image.new("RGBA", (32, 16), (0, 0, 0, 0))
            GLYPH(im.load(), 0, 0, text, (255, 255, 255, 255))
            return [im.getpixel((x, y))[3] for y in range(8) for x in range(6)]

        self.assertNotEqual(drawn("a"), drawn("A"),
                            "the renderer upper-cases its input, so the lower-case glyphs are dead")

    def test_the_body_text_of_a_report_keeps_its_case(self):
        _cx0, cy0, cx1, _cy1 = LAYOUT.layout["content"]
        rows = pw.text(LAYOUT, ["sha256 : CE66F800e2c6"], title="T")
        body_row = rows[cy0]
        self.assertIn("e2c6", body_row)
        self.assertIn("CE66", body_row)


class TestPaging(unittest.TestCase):
    """A report longer than the content area is the normal case, not the edge case."""

    def test_one_page_even_when_there_is_nothing(self):
        self.assertEqual(LAYOUT.page_count([]), 1)

    def test_a_page_holds_exactly_what_the_layout_says(self):
        # 200 lines rather than 100 on purpose: with 100 the page count is 3 and page 2 is the last one,
        # which holds 8 rows -- so a fixture that felt big enough would assert the *short* page and call
        # a correct result a failure. Measured: 8 != 46 was the first run of this test.
        lines = ["line %d" % i for i in range(200)]
        rows, page, pages = LAYOUT.page_lines(lines, 2)
        self.assertEqual(len(rows), LAYOUT.body_rows)
        self.assertEqual(rows[0], "line %d" % (2 * LAYOUT.body_rows))
        self.assertEqual((page, pages), (2, 5))

    def test_a_page_number_past_the_end_shows_the_last_page(self):
        lines = ["x"] * 100
        rows, page, pages = LAYOUT.page_lines(lines, 99)
        self.assertEqual(page, pages - 1)
        self.assertEqual(len(rows), 100 - 2 * LAYOUT.body_rows)

    def test_the_marker_is_drawn_only_when_it_is_true(self):
        _tx0, ty0, _tx1, _ty1 = LAYOUT.layout["title"]
        one = pw.text(LAYOUT, ["x"], title="TORIKAGO")
        self.assertNotIn("/", one[ty0 + 1])
        many = pw.text(LAYOUT, ["x"] * 100, title="TORIKAGO", page=0)
        self.assertIn("1/3", many[ty0 + 1])
        last = pw.text(LAYOUT, ["x"] * 100, title="TORIKAGO", page=2)
        self.assertIn("3/3", last[ty0 + 1])


class TestTheWindowShowsWhatTheTerminalSays(unittest.TestCase):
    """**Captured, not re-formatted.** A window with its own formatter would be a second answer to
    "what did this command say", and the two could disagree without either being wrong."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "sample.bin"
        self.path.write_bytes(b"MZ" + b"\x00" * 400)
        self.report = tri.build_report_with_unpack(self.path, None, False,
                                                   max_bytes=int(tri.DEFAULT_MAX_BYTES),
                                                   force=False, yara_corpus=None)

    def _terminal_lines(self, report):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            tri.print_human(report)
            tri._print_handoff(report.get("handoff"))
        lines = buf.getvalue().splitlines()
        while lines and not lines[-1].strip():
            lines.pop()
        return lines

    def test_the_captured_lines_are_the_printed_lines(self):
        self.assertEqual(tri._report_lines(self.report), self._terminal_lines(self.report))

    def test_the_window_is_asked_for_once_with_a_title_and_an_integer_scale(self):
        import unittest.mock as mock

        with mock.patch.object(pw, "open_window") as fake:
            rc = tri._show_report_window(self.report, self.path)
        self.assertEqual(rc, 0)
        self.assertEqual(fake.call_count, 1)
        _layout, lines = fake.call_args[0]
        kwargs = fake.call_args[1]
        self.assertTrue(kwargs["title"].startswith("TORIKAGO - "))
        self.assertIn("sample.bin", kwargs["title"])
        self.assertEqual(kwargs["scale"], 2)
        self.assertEqual(lines, self._terminal_lines(self.report))

    def test_a_long_name_is_elided_rather_than_refused(self):
        import unittest.mock as mock

        long_path = Path(str(self.path.parent)) / (("n" * 200) + ".exe")
        with mock.patch.object(pw, "open_window") as fake:
            tri._show_report_window(self.report, long_path)
        title = fake.call_args[1]["title"]
        self.assertTrue(title.endswith(".."), "%r was not elided" % (title,))
        # And the renderer accepts it, which is the only reason the elision exists.
        pw.text(LAYOUT, ["x"], title=title)

    def test_an_unreadable_panel_prints_the_report_instead(self):
        import unittest.mock as mock

        with mock.patch.object(pw, "load", side_effect=ValueError("checksum")):
            captured = self._catch_stdout(lambda: tri._show_report_window(self.report, self.path))
        self.assertEqual(captured, self._terminal_lines(self.report))

    def test_a_missing_image_library_prints_the_report_instead(self):
        """The measured behaviour of a bare `pip install torikago`: no PIL, so no window.

        **The report still comes out and the exit code is still zero**, because the analysis succeeded
        -- and the failure is said out loud rather than swallowed, so nobody is left wondering whether
        `--window` did anything.
        """
        import unittest.mock as mock

        with mock.patch.object(pw, "open_window",
                               side_effect=ModuleNotFoundError("No module named 'PIL'")):
            captured = self._catch_stdout(lambda: tri._show_report_window(self.report, self.path))
        self.assertEqual(captured, self._terminal_lines(self.report))

    def _catch_stdout(self, fn):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            fn()
        lines = buf.getvalue().splitlines()
        while lines and not lines[-1].strip():
            lines.pop()
        return lines


class TestTheFlagIsRefused(unittest.TestCase):
    """`--window` draws one file's report. Paired with a mode that returns before that report exists,
    accepting the flag and doing nothing is worse than refusing it -- the caller would believe a
    window had opened."""

    def test_each_alternative_mode_is_named_and_refused(self):
        for argv in (["--window", "--json", "x"],
                     ["--window", "--quiet", "x"],
                     ["--window", "--scan", "x"],
                     ["--window", "--posture"],
                     ["--window", "--corpus-check", "x"],
                     ["--window", "--tag", "emotet"]):
            with self.subTest(argv=argv):
                self.assertEqual(tri.main(argv), 2, "%r was not refused" % (argv,))

    def test_it_needs_a_file(self):
        self.assertEqual(tri.main(["--window"]), 2)


if __name__ == "__main__":
    unittest.main()
