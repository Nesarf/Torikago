# -*- coding: utf-8 -*-
"""Finding Nanodesu!, and what a user is told when it is not there.

`triage` declares no dependencies on purpose: it is a tool meant to be run on a machine you
do not control and do not trust, so every dependency it does not have is one less thing a
reader has to audit. Nanodesu! is therefore discovered at runtime rather than required at
install time, and the discovery has to be both portable and honest.

An earlier version searched two hard-coded absolute paths on the author's own disk. They
could only ever work on one machine, and they published a directory layout in a public
repository, so they are gone -- these tests exist so they do not come back in another form.

Run:
    python -m unittest discover -s test -v
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

import unpack as unp


class _Env:
    """Set NANODESU_PATH for the duration of a test, and put it back."""

    def __init__(self, value):
        self.value = value

    def __enter__(self):
        self.old = os.environ.get(unp.NANODESU_ENV)
        if self.value is None:
            os.environ.pop(unp.NANODESU_ENV, None)
        else:
            os.environ[unp.NANODESU_ENV] = self.value

    def __exit__(self, *exc):
        if self.old is None:
            os.environ.pop(unp.NANODESU_ENV, None)
        else:
            os.environ[unp.NANODESU_ENV] = self.old
        return False


class TestNoHardCodedPaths(unittest.TestCase):
    """The failure this file's docstring promises will not return."""

    def test_no_absolute_paths_are_baked_into_the_module(self):
        source = (HERE.parent / "unpack.py").read_text(encoding="utf-8")
        # A drive-letter path or a home directory in the source is the smell.
        for pattern in ("E:\\", "C:\\", "/home/", "/Users/"):
            self.assertNotIn(pattern, source,
                             "unpack.py carries a machine-specific path (%r); discovery "
                             "must be relative or environment-driven" % pattern)

    def test_the_module_no_longer_exposes_a_candidate_list(self):
        self.assertFalse(hasattr(unp, "CANDIDATE_PATHS"),
                         "a hard-coded candidate list is how the machine-specific paths "
                         "got in; discovery should be computed, not tabulated")


class TestDiscovery(unittest.TestCase):

    def test_an_explicit_file_is_used(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "nanodesu.py"
            p.write_text("VERSION = '9.9.9'\n", encoding="utf-8")
            with _Env(str(p)):
                found = unp.find_nanodesu()
            self.assertEqual(Path(found), p)

    def test_an_explicit_directory_is_searched(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "nanodesu.py"
            p.write_text("VERSION = '9.9.9'\n", encoding="utf-8")
            with _Env(t):
                found = unp.find_nanodesu()
            self.assertEqual(Path(found), p)

    def test_a_checkout_with_the_source_one_level_down_is_found(self):
        """`pip install -e .` layouts and plain checkouts both nest the module."""
        with tempfile.TemporaryDirectory() as t:
            nested = Path(t) / "nanodesu"
            nested.mkdir()
            p = nested / "nanodesu.py"
            p.write_text("VERSION = '9.9.9'\n", encoding="utf-8")
            with _Env(t):
                found = unp.find_nanodesu()
            self.assertEqual(Path(found), p)

    def test_an_explicit_path_that_does_not_exist_is_an_error(self):
        """Not a silent fall-through: using a different build than the caller named is
        exactly the confusion this function exists to prevent."""
        with tempfile.TemporaryDirectory() as t:
            with _Env(str(Path(t) / "nope.py")):
                with self.assertRaises(FileNotFoundError) as ctx:
                    unp.find_nanodesu()
            self.assertIn(unp.NANODESU_ENV, str(ctx.exception))

    def test_an_installed_module_is_preferred_over_a_neighbouring_file(self):
        """If nanodesu is importable, that is the installation the user chose."""
        with tempfile.TemporaryDirectory() as t:
            mod = Path(t) / "nanodesu.py"
            mod.write_text("VERSION = 'installed'\n", encoding="utf-8")
            sys.path.insert(0, t)
            saved = sys.modules.pop("nanodesu", None)
            try:
                with _Env(None):
                    found = unp.find_nanodesu()
                self.assertFalse(isinstance(found, Path),
                                 "an importable nanodesu should be returned as a module")
                self.assertEqual(getattr(found, "VERSION", None), "installed")
            finally:
                sys.path.remove(t)
                sys.modules.pop("nanodesu", None)
                if saved is not None:
                    sys.modules["nanodesu"] = saved


class TestMissingIsDiagnosable(unittest.TestCase):
    """'not found' with no next step is what makes a tool feel broken when it is only
    incomplete, and the fix is one command."""

    def test_the_reason_names_the_install_command(self):
        reason = unp.nanodesu_missing_reason()
        self.assertIn("pip install nanodesu", reason)

    def test_the_reason_names_the_environment_variable(self):
        self.assertIn(unp.NANODESU_ENV, unp.nanodesu_missing_reason())

    def test_a_missing_tool_yields_a_result_dict_not_an_exception(self):
        with tempfile.TemporaryDirectory() as t:
            target = Path(t) / "x.exe"
            target.write_bytes(b"MZ")
            with _Env(str(Path(t) / "absent")):
                res = unp.unpack_pyinstaller(target, Path(t) / "out")
            self.assertIsInstance(res, dict)
            self.assertIs(res["executed"], False)
            self.assertIs(res["ok"], False)

    def test_the_two_kinds_of_not_found_say_different_things(self):
        """'Nothing is installed' and 'the path you named is wrong' have different fixes,
        so they must not share a message. An earlier draft of these tests asserted the
        install hint in both cases, which is how the distinction got flattened."""
        with tempfile.TemporaryDirectory() as t:
            target = Path(t) / "x.exe"
            target.write_bytes(b"MZ")

            # The caller named a path; that path is the problem.
            with _Env(str(Path(t) / "absent")):
                named = unp.unpack_pyinstaller(target, Path(t) / "out-a")
            self.assertIn(unp.NANODESU_ENV, named["reason"])
            self.assertNotIn("pip install", named["reason"])

            # Nothing was named; the install is the fix.
            self.assertIn("pip install nanodesu", unp.nanodesu_missing_reason())

    def test_a_missing_tool_never_claims_to_have_executed_anything(self):
        with tempfile.TemporaryDirectory() as t:
            target = Path(t) / "x.pyz"
            target.write_bytes(b"PYZ\x00")
            with _Env(str(Path(t) / "absent")):
                res = unp.unpack_pyz(target, Path(t) / "out")
            self.assertIs(res["executed"], False)


class TestTheMissingResultIsUsable(unittest.TestCase):
    """A caller should be able to tell 'not installed' from 'installed but failed'."""

    def test_the_result_carries_a_hint_field(self):
        with tempfile.TemporaryDirectory() as t:
            target = Path(t) / "x.exe"
            target.write_bytes(b"MZ")
            with _Env(str(Path(t) / "absent")):
                res = unp.unpack_pyinstaller(target, Path(t) / "out")
            self.assertIn("hint", res)
            self.assertEqual(res["hint"], unp.INSTALL_HINT)

    def test_the_tool_field_is_none_when_nothing_was_found(self):
        with tempfile.TemporaryDirectory() as t:
            target = Path(t) / "x.exe"
            target.write_bytes(b"MZ")
            with _Env(str(Path(t) / "absent")):
                res = unp.unpack_pyinstaller(target, Path(t) / "out")
            self.assertIsNone(res["tool"])

    def test_an_environment_variable_pointing_nowhere_is_reported_plainly(self):
        with tempfile.TemporaryDirectory() as t:
            target = Path(t) / "x.exe"
            target.write_bytes(b"MZ")
            with _Env(str(Path(t) / "absent")):
                res = unp.unpack_pyinstaller(target, Path(t) / "out")
            self.assertIn(unp.NANODESU_ENV, res["reason"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
