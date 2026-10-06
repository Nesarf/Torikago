# -*- coding: utf-8 -*-
"""The one invariant everything else rests on: the target is never run.

Two documents say it and one argparse help string says it, and until now **nothing checked it.** It
held because nobody had written the path — a property of the code as it happens to be, not a property
anyone is defending. The whole tool is auditable only while that stays true, and both personas rest on
it too: she has the eye and the binding and no digestion, and the constraint is where the character's
tension comes from.

## Two failed attempts, kept in the record because they are the lesson

**The first version** inspected only literal argv and skipped computed ones. Injecting
`subprocess.run([str(path)])` — which is exactly what running the target looks like — left the file
green. It audited the easy half.

**The second version** collected assignments file-wide, which merged same-named variables from
different functions: `exe` is a passed-in tool in one function and a path join in another.

**This version resolves per function, because that is where a name means something.** What matters is
not argv[0]'s spelling but whether it can be derived from the target.
"""
from __future__ import annotations

import ast
import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import _fixtures                                              # noqa: E402


# What a process may be. Each of these either answers a question about the machine or reads a file as
# data; none of them takes a program to run.
ALLOWED_PROGRAMS = {
    "powershell.exe", "powershell", "pwsh", "pwsh.exe",
    "MpCmdRun.exe", "mpcmdrun.exe",
    "clamscan", "clamscan.exe", "clamdscan",
}

# Programs found at runtime rather than written literally. Trusted **only** because a test below
# asserts none of them can see the target -- a reassuring name is not evidence.
FINDER_FUNCTIONS = {"find_defender", "find_clamav"}

# The parameters by which a target enters a function. If argv[0] can be derived from one of these, the
# tool is running the sample.
TARGET_PARAMETERS = {"path", "target", "targets", "file", "sample", "paths"}

SPAWN_CALLS = ("run", "Popen", "call", "check_output", "check_call")


class TestNoSubprocessRunsATarget(unittest.TestCase):
    """Every spawning call is inspected, **in the scope it is written in**."""

    FILES = ["torikago.py", "sample_fetch.py", "security_posture.py",
             "product_registration.py", "unpack.py", "sample_vault.py",
             "take_samples.py", "provider_malshare.py"]

    def _calls(self, tree):
        """(call node, enclosing function name) for every process-spawning call."""
        out = []

        def visit(node, func):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func = node.name
            if isinstance(node, ast.Call) and getattr(node.func, "attr", None) in SPAWN_CALLS:
                out.append((node, func))
            for child in ast.iter_child_nodes(node):
                visit(child, func)

        visit(tree, "<module>")
        return out

    def _scope_sets(self, func_node):
        """What each name in this function is assigned: literals, finders, and list expressions.

        **Per function, not per file.** Names are scoped, and a file-wide map conflated an `exe` that
        is a passed-in tool with an `exe` that is a path join.
        """
        literals, finders, lists = {}, {}, {}
        for node in ast.walk(func_node):
            if not (isinstance(node, ast.Assign) and len(node.targets) == 1):
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue
            value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                literals.setdefault(target.id, set()).add(value.value)
            elif isinstance(value, ast.Name):
                literals.setdefault(target.id, set()).add(("alias", value.id))
            elif isinstance(value, ast.BoolOp):
                # `exe = override or find_defender()` -- every leaf counts, so an alternative that is
                # not a finder cannot hide behind a short-circuit.
                for leaf in value.values:
                    if isinstance(leaf, ast.Call) and getattr(leaf.func, "id", None):
                        finders.setdefault(target.id, set()).add(leaf.func.id)
                    elif isinstance(leaf, ast.Constant) and isinstance(leaf.value, str):
                        literals.setdefault(target.id, set()).add(leaf.value)
                    elif isinstance(leaf, ast.Name):
                        literals.setdefault(target.id, set()).add(("alias", leaf.id))
                    else:
                        finders.setdefault(target.id, set()).add("<%s>" % type(leaf).__name__)
            elif isinstance(value, ast.Call) and getattr(value.func, "id", None):
                finders.setdefault(target.id, set()).add(value.func.id)
            elif isinstance(value, ast.List):
                lists.setdefault(target.id, []).append(value)
            elif isinstance(value, ast.BinOp) and isinstance(value.left, ast.List):
                # `[tool, ...] + files` -- the head is still the tool.
                lists.setdefault(target.id, []).append(value.left)
        return literals, finders, lists

    def _head_of_list(self, expr):
        elts = getattr(expr, "elts", None) or []
        if not elts:
            return None
        head = elts[0]
        if isinstance(head, ast.Constant) and isinstance(head.value, str):
            return ("literal", head.value)
        if isinstance(head, ast.Name):
            return ("name", head.id)
        if isinstance(head, ast.Call):
            return ("call", getattr(head.func, "id", "?"))
        return ("other", type(head).__name__)

    def test_every_subprocess_program_resolves_to_an_allowed_tool(self):
        checked, problems = 0, []
        for filename in self.FILES:
            path = HERE.parent / filename
            if not path.exists():
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            funcs = {n.name: n for n in ast.walk(tree)
                     if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
            for node, func_name in self._calls(tree):
                checked += 1
                scope = funcs.get(func_name, tree)
                literals, finders, lists = self._scope_sets(scope)
                where = "%s:%s" % (filename, func_name)

                if not node.args:
                    problems.append("%s passes no argv at all" % where)
                    continue
                argv = node.args[0]
                if isinstance(argv, ast.List):
                    exprs = [argv]
                elif isinstance(argv, ast.Name):
                    exprs = lists.get(argv.id, [])
                else:
                    exprs = []
                if not exprs:
                    problems.append("%s: argv is neither a list literal nor a variable holding one"
                                    % where)
                    continue

                for expr in exprs:
                    head = self._head_of_list(expr)
                    if head is None:
                        problems.append("%s: empty argv" % where)
                    elif head[0] == "literal":
                        if head[1] not in ALLOWED_PROGRAMS:
                            problems.append("%s runs %r" % (where, head[1]))
                    elif head[0] == "name":
                        var = head[1]
                        lits = {v for v in literals.get(var, set()) if isinstance(v, str)}
                        fnds = {f for f in finders.get(var, set()) if not f.startswith("<")}
                        if lits or fnds:
                            for value in lits:
                                if value not in ALLOWED_PROGRAMS:
                                    problems.append("%s runs %s = %r" % (where, var, value))
                            for f in fnds:
                                if f not in FINDER_FUNCTIONS:
                                    problems.append("%s runs %s from %s()" % (where, var, f))
                        else:
                            problems.append("%s: argv[0] is %r and the scope does not say what it "
                                            "holds" % (where, var))
                    elif head[0] == "call":
                        if head[1] not in FINDER_FUNCTIONS:
                            problems.append("%s: argv[0] is %s()" % (where, head[1]))
                    else:
                        problems.append("%s: argv[0] is a %s" % (where, head[1]))

        self.assertGreater(checked, 5, "too few calls inspected to be meaningful (%d)" % checked)
        self.assertEqual(problems, [],
                         "argv[0] could be the target: " + " ; ".join(problems))

    def test_no_finder_can_reach_a_target_parameter(self):
        """The runtime-found programs are trusted for exactly one reason, and this is it.

        `find_defender` and `find_clamav` choose a tool from a path list or an environment variable. If
        either could see the target, argv[0] could be the sample and every other assertion here would
        be decoration.
        """
        source = (HERE.parent / "torikago.py").read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.FunctionDef) or node.name not in FINDER_FUNCTIONS:
                continue
            names = {a.arg for a in node.args.args} | {a.arg for a in node.args.kwonlyargs}
            with self.subTest(function=node.name):
                self.assertEqual(names & TARGET_PARAMETERS, set(),
                                 "%s takes a target parameter, so it could return the sample"
                                 % node.name)

    def test_a_target_is_only_ever_an_argument_not_a_program(self):
        """The scanner case: `defender -Scan -File <target>` is reading it, not running it."""
        src = (HERE.parent / "torikago.py").read_text(encoding="utf-8")
        self.assertIn('cmd = [exe, "-Scan", "-ScanType", "3", "-File", str(target)', src)
        self.assertIn('cmd = [exe, "--no-summary", "--infected", "--stdout"] + files', src)

    def test_the_source_does_not_claim_a_process_it_does_not_make(self):
        src = (HERE.parent / "torikago.py").read_text(encoding="utf-8")
        self.assertIn("Never runs the target", src)


class TestTheReportedFlagIsNeverTrue(unittest.TestCase):
    """`executed_target` appears in every report and is always false. If it ever became true the tool
    would have done the one thing it says it does not, and every verdict in that report would mean
    something else."""

    def test_a_real_report_says_false(self):
        """**The field is `executed_target`, not `executed`** -- read from a real report rather than
        guessed. The first version asserted the guessed name, found nothing, and would have passed a
        report that ran the file in a differently-named field.
        """
        import torikago as tk
        import test_torikago as tt
        tmp = _fixtures.tmpdir("exec-")
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        sample = tmp / "x.exe"
        sample.write_bytes(tt.build_pe())
        report = tk.build_report(sample, None)

        self.assertIn("executed_target", report,
                      "the report no longer states whether the target was run at all")
        self.assertIs(report["executed_target"], False)

        # And nowhere in the document may it claim execution *happened*.
        #
        # **Matched narrowly, on purpose-built evidence.** A bare "execut" substring also caught
        # `sections[0].executable` -- a PE characteristic bit meaning "this region may be executed",
        # which is a format field and not a claim about this tool -- and
        # `unpack_plan[0].needs_execution`, which is the opposite of a violation: it says a step
        # *would* require running the sample and that **this tool will not do it**.
        CLAIMS = ("executed", "did_execute", "was_executed", "has_executed")
        seen = []

        def walk(node, path="report"):
            if isinstance(node, dict):
                for k, v in node.items():
                    if isinstance(v, bool) and any(c in k.lower() for c in CLAIMS):
                        seen.append((path + "." + k, v))
                    walk(v, path + "." + k)
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    walk(item, "%s[%d]" % (path, i))

        walk(report)
        for where, value in seen:
            with self.subTest(field=where):
                self.assertIs(value, False, "%s is %r" % (where, value))

    def test_a_plan_that_would_need_execution_says_the_tool_will_not_do_it(self):
        """The honest half of the same idea, and it is why the broad match was wrong.

        `needs_execution: true` is not a claim to have run anything -- it is a step that *would*
        require running the sample, paired with a statement that this tool refuses and pointing at a
        disposable VM. Removing that pairing would be the actual regression.
        """
        src = (HERE.parent / "torikago.py").read_text(encoding="utf-8")
        i = src.index('"needs_execution": True')
        window = src[max(0, i - 400):i + 500]
        flat = " ".join(window.split())
        self.assertIn("This tool will not do it", flat)
        self.assertIn("disposable VM", flat)

    def test_the_literal_has_no_true_counterpart(self):
        """Cheap, and it catches the obvious regression: a second author adding a mode that runs the
        file. The structural tests above are the real defence; this one is a tripwire."""
        for filename in ("torikago.py", "unpack.py", "sample_fetch.py"):
            path = HERE.parent / filename
            if not path.exists():
                continue
            src = path.read_text(encoding="utf-8")
            with self.subTest(filename=filename):
                self.assertNotIn('"executed": True', src)
                self.assertNotIn("'executed': True", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
