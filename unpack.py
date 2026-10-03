#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""unpack.py - the unpacking half of triage.

Kept separate from the reporting half because unpacking is where the tool touches the
filesystem with a lot of files, and because the target-format knowledge belongs with
Nanodesu!, which already implements it correctly. Nothing here executes the sample:
every path is a byte-level decode.

Nanodesu! is loaded as a module and called in-process rather than through a subprocess,
so there is exactly one implementation of the archive format and no shell in the middle.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

NANODESU_ENV = "NANODESU_PATH"

# Where Nanodesu! is likely to be. Checked in order; the environment variable wins so a
# checkout can be pointed at explicitly.
CANDIDATE_PATHS = (
    r"E:\~Sayori~Sleeping~\nanodesu-release\nanodesu.py",
    r"E:\~Sayori~Sleeping~\pyunpack\nanodesu.py",
)


def find_nanodesu() -> Path | None:
    """Locate nanodesu.py, or None if it is not installed."""
    env = os.environ.get(NANODESU_ENV)
    if env:
        p = Path(env)
        if p.is_file():
            return p
        if p.is_dir() and (p / "nanodesu.py").is_file():
            return p / "nanodesu.py"
    for cand in CANDIDATE_PATHS:
        p = Path(cand)
        if p.is_file():
            return p
    # last resort: alongside this file's parent workspace
    here = Path(__file__).resolve()
    for up in (here.parent, here.parent.parent):
        p = up / "nanodesu.py"
        if p.is_file():
            return p
    return None


def load_nanodesu(path: Path):
    """Import nanodesu.py by path, without requiring it to be installed."""
    spec = importlib.util.spec_from_file_location("nanodesu_embedded", path)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load %s" % path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["nanodesu_embedded"] = module
    spec.loader.exec_module(module)
    return module


def unpack_pyinstaller(target: Path, out_dir: Path, *, with_pyc: bool = True,
                       log=print) -> dict:
    """Unpack a PyInstaller onefile with Nanodesu!. Returns a result dict.

    `executed` is always False and is recorded in the result so a caller never has to
    assume it: this function only decodes bytes and writes files.
    """
    nano_path = find_nanodesu()
    if nano_path is None:
        return {
            "ok": False,
            "tool": None,
            "reason": "nanodesu.py was not found; set %s to its path" % NANODESU_ENV,
            "executed": False,
        }
    try:
        nano = load_nanodesu(nano_path)
    except Exception as exc:                       # pragma: no cover - defensive
        return {"ok": False, "tool": str(nano_path),
                "reason": "could not load nanodesu: %s" % exc, "executed": False}

    out_dir.mkdir(parents=True, exist_ok=True)
    argv = ["extract", str(target), "-o", str(out_dir)]
    if with_pyc:
        argv.append("--pyc")

    before = {p for p in out_dir.rglob("*") if p.is_file()}
    try:
        rc = nano.main(argv)
    except SystemExit as exc:                      # nanodesu exits via SystemExit
        rc = exc.code if isinstance(exc.code, int) else 1
    except Exception as exc:                       # pragma: no cover - defensive
        return {"ok": False, "tool": str(nano_path),
                "reason": "nanodesu failed: %s" % exc, "executed": False}
    after = {p for p in out_dir.rglob("*") if p.is_file()}
    written = sorted(str(p.relative_to(out_dir)) for p in after - before)

    result = {
        "ok": rc == 0,
        "tool": str(nano_path),
        "tool_version": getattr(nano, "VERSION", None),
        "out_dir": str(out_dir),
        "files_written": len(written),
        "executed": False,
    }
    if rc != 0:
        result["reason"] = "nanodesu exited with status %s" % rc
    return result


def unpack_pyz(target: Path, out_dir: Path, *, bare: bool = False, log=print) -> dict:
    """Unpack a standalone PYZ archive to valid .pyc files."""
    nano_path = find_nanodesu()
    if nano_path is None:
        return {"ok": False, "reason": "nanodesu.py was not found", "executed": False}
    try:
        nano = load_nanodesu(nano_path)
    except Exception as exc:                       # pragma: no cover
        return {"ok": False, "reason": str(exc), "executed": False}
    out_dir.mkdir(parents=True, exist_ok=True)
    argv = ["pyz", str(target), "-o", str(out_dir)]
    if bare:
        argv.append("--bare")
    try:
        rc = nano.main(argv)
    except SystemExit as exc:
        rc = exc.code if isinstance(exc.code, int) else 1
    return {"ok": rc == 0, "out_dir": str(out_dir), "executed": False,
            "reason": None if rc == 0 else "nanodesu exited with status %s" % rc}
