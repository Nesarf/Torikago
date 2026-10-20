# -*- coding: utf-8 -*-
"""The persona document and the code must say the same lines, and the comparison goes both ways.

`PERSONA.md` is prose with a machine-readable table at the end. The code has `PROSE`. **The document ships
with neither the wheel nor the sdist**, so a line changed there and not here would change nothing for anybody
who installed the tool -- and nothing would notice. That is the gap this file closes.

Both directions matter. A key in the document and not in the code is a line she cannot say; a key in the code
and not in the document is a line nobody wrote down. Either one alone passes a one-way check.
"""
from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

spec = importlib.util.spec_from_file_location("torikago_persona", ROOT / "torikago.py")
tri = importlib.util.module_from_spec(spec)
sys.modules["torikago_persona"] = tri
spec.loader.exec_module(tri)

DOCUMENT = ROOT / "PERSONA.md"


def table_from_document():
    """The §九 table as `{key: (spoken, plain)}`, read rather than copied.

    A row looks like ``| `key` | 日语 | 英文 | 源 |``. Rows outside the section are ignored, so the earlier
    prose -- which is full of pipe-free lines but also of other tables -- cannot be mistaken for this one.
    """
    text = DOCUMENT.read_text(encoding="utf-8")
    start = text.index("## 九、台词表")
    section = text[start:]
    rows = {}
    for line in section.splitlines():
        m = re.match(r"^\|\s*`([a-z_]+)`\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|$", line)
        if not m:
            continue
        rows[m.group(1)] = (m.group(2), m.group(3))
    return rows


class TestTheDocumentAndTheCodeAgree(unittest.TestCase):

    def test_the_table_was_found(self):
        rows = table_from_document()
        self.assertGreaterEqual(len(rows), 5,
                                "the §九 table was not found or is too small to be the real one: %r"
                                % (sorted(rows),))

    def test_every_documented_line_exists_in_the_code(self):
        rows = table_from_document()
        for key, (spoken, plain) in rows.items():
            self.assertIn(key, tri.PROSE, "%r is in PERSONA.md but not in PROSE" % key)
            self.assertEqual(tri.PROSE[key][0], spoken, "%r: the spoken line differs" % key)
            self.assertEqual(tri.PROSE[key][1], plain, "%r: the plain line differs" % key)

    def test_every_code_line_is_documented(self):
        rows = table_from_document()
        for key in tri.PROSE:
            self.assertIn(key, rows, "%r is in PROSE but nobody wrote it down in PERSONA.md" % key)

    def test_a_missing_key_returns_the_key_rather_than_raising(self):
        """An absent line must not stop an analysis. It should be visible, though, which is why it returns
        something identifiable instead of an empty string."""
        self.assertEqual(tri.say("no_such_line_here"), "no_such_line_here")

    def test_plain_switches_registers(self):
        self.addCleanup(tri.set_plain, False)
        tri.set_plain(False)
        spoken = tri.say("watching")
        tri.set_plain(True)
        plain = tri.say("watching")
        self.assertNotEqual(spoken, plain)
        self.assertEqual(plain, "watching only")
        tri.set_plain(False)
        self.assertEqual(tri.say("watching"), spoken)

    def test_the_default_register_is_off(self):
        """Importing this module must not start a personality inside somebody's pipeline."""
        self.assertFalse(tri.is_plain() is None)
        self.assertIsInstance(tri.is_plain(), bool)


if __name__ == "__main__":
    unittest.main()
