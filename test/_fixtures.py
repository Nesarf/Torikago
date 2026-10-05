# -*- coding: utf-8 -*-
"""A temporary directory that is (a) outside every path the tools refuse and (b) portable.

**Both constraints are real and they pull in opposite directions.** The tools refuse samples under the
workspace, the cache area, a git repository, or `C:` — so a fixture cannot simply use
`tempfile.mkdtemp()`, whose default here is `E:\DaShaoHuo\cache\tmp` (refused) and whose `Path.home()`
is on `C:` (refused). Writing `E:\triage-test-tmp` fixed it locally and **broke CI**, where there is no
`E:` drive at all:

    FileNotFoundError: [WinError 3] The system cannot find the path specified: 'E:\'

So the root is *chosen per machine*: the env override if set, else the first candidate that exists and
is not refused. A test that only passes on the machine it was written on is not a test of the code.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

_BS = chr(92)          # built rather than written literally: a Windows path through a shell heredoc
                       # has corrupted this repository repeatedly, turning `\t` into a tab.


def _refused() -> tuple:
    """Read from the tools themselves, so the fixture cannot drift from the rule it is obeying."""
    try:
        import sample_fetch as sf
        return tuple(Path(r) for r in sf.FORBIDDEN_ROOTS)
    except Exception:                                          # noqa: BLE001
        return ()


def _is_refused(path: Path) -> bool:
    try:
        target = str(path.resolve()).lower()
    except OSError:
        target = str(path).lower()
    for root in _refused():
        try:
            if target.startswith(str(root.resolve()).lower().rstrip("\/")):
                return True
        except OSError:
            continue
    return False


def tmp_root() -> Path:
    """The first acceptable root on this machine, created if missing."""
    override = os.environ.get("TRIAGE_TEST_TMP")
    candidates = [Path(override)] if override else []
    candidates += [Path("E:" + _BS + "triage-test-tmp"), Path(tempfile.gettempdir())]
    for cand in candidates:
        if str(cand).lower().startswith("c:" + _BS) or _is_refused(cand):
            continue
        try:
            cand.mkdir(parents=True, exist_ok=True)
        except OSError:
            continue
        return cand
    # Nothing acceptable: fall back so the failure is a test failure with a message, not an import
    # error that hides which tests never ran.
    return Path(tempfile.gettempdir())


def tmpdir(prefix: str = "triage-") -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix, dir=str(tmp_root())))
