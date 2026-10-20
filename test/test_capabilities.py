# -*- coding: utf-8 -*-
"""The capability boundary is a fact about the code, so it is checked against the code.

The README says the analysis is offline. A reader can reasonably take that for the whole repository, and it
is not: fetching a sample, asking a provider, reading Defender's state, registering a product and collecting
samples all reach the network or start a process. The claim worth asserting is narrower, and it took a
measurement to state it correctly:

* **this module's module-level imports** contain nothing that can reach out;
* **five sibling files** may, and they are named;
* **three functions inside this module** may, and they are named -- all three on the `--handoff` path.

The first draft of this test asserted that the file as a whole never starts a process. That was wrong, and
the test said so on its first run: `--handoff` legitimately runs `clamscan`. Correcting the claim rather than
weakening the test is the point of the file.
"""
from __future__ import annotations

import ast
import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

spec = importlib.util.spec_from_file_location("torikago_caps", ROOT / "torikago.py")
tri = importlib.util.module_from_spec(spec)
sys.modules["torikago_caps"] = tri
spec.loader.exec_module(tri)


def _module_names(node):
    names = set()
    if isinstance(node, ast.Import):
        for alias in node.names:
            names.add(alias.name.split(".")[0])
    elif isinstance(node, ast.ImportFrom) and node.module:
        names.add(node.module.split(".")[0])
    return names


def top_level_imports(path):
    """Imports at module scope only -- inside a function is a different claim, and a different test."""
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    names = set()
    for node in tree.body:
        names |= _module_names(node)
    return names


def all_imports(path):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        names |= _module_names(node)
    return names


def functions_with_capability_imports(path):
    """Which functions in `path` import something that can reach out."""
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for sub in ast.walk(node):
            names = _module_names(sub)
            if names & set(tri.NETWORK_OR_SHELL):
                found.add(node.name)
    return found


class TestTheAnalyserStaysOffline(unittest.TestCase):

    def test_module_level_imports_are_exactly_the_declared_ones(self):
        actual = top_level_imports(ROOT / "torikago.py")
        declared = set(tri.CORE_IMPORTS)
        self.assertEqual(actual - declared, set(),
                         "torikago.py imports something the boundary does not declare")
        self.assertEqual(declared - actual, set(),
                         "the boundary declares an import the file does not make")

    def test_nothing_declared_can_reach_out(self):
        for name in tri.CORE_IMPORTS:
            self.assertNotIn(name, tri.NETWORK_OR_SHELL,
                             "%r is declared as a core import and as a capability" % name)

    def test_the_only_functions_that_reach_out_are_the_declared_ones(self):
        found = functions_with_capability_imports(ROOT / "torikago.py")
        self.assertEqual(found, set(tri.SHELL_CAPABLE_FUNCTIONS),
                         "the set of functions that can start a process changed: found %r, declared %r"
                         % (sorted(found), sorted(tri.SHELL_CAPABLE_FUNCTIONS)))

    def test_only_the_delegated_files_reach_out(self):
        """`test/` is exempt: a test may start a subprocess to check one, and this list is about what
        ships rather than what verifies it."""
        found = set()
        for path in sorted(ROOT.glob("*.py")):
            if all_imports(path) & set(tri.NETWORK_OR_SHELL):
                found.add(path.name)
        declared = set(tri.DELEGATED_TO_NETWORK_OR_SHELL) | {"torikago.py"}
        self.assertEqual(found, declared,
                         "the set of files that can reach out changed: found %r, declared %r"
                         % (sorted(found), sorted(declared)))

    def test_the_delegated_files_exist(self):
        for name in tri.DELEGATED_TO_NETWORK_OR_SHELL:
            self.assertTrue((ROOT / name).is_file(), "%s is declared but missing" % name)


if __name__ == "__main__":
    unittest.main()
