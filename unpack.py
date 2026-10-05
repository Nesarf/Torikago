#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""unpack.py - the unpacking half of triage.

Kept separate from the reporting half because unpacking is where the tool touches the
filesystem with a lot of files, and because the target-format knowledge belongs with
Nanodesu!, which already implements it correctly. Nothing here executes the sample:
every path is a byte-level decode.

Nanodesu! is loaded and called in-process rather than through a subprocess, so there is
exactly one implementation of the archive format and no shell in the middle. That matters
for a security tool: a subprocess would put a shell, an argv round-trip, and a PATH
lookup between the sample and the parser.

Finding it, in order:

  1. ``NANODESU_PATH`` -- an explicit file or directory, for a checkout
  2. an installed ``nanodesu`` module (``pip install nanodesu``)
  3. ``nanodesu.py`` next to this file, or one directory up -- the source-tree case,
     where triage and Nanodesu! sit side by side

An earlier version looked at two hard-coded absolute paths on the author's own disk.
Those are gone: they could only ever work on one machine, and they published somebody's
directory layout in a public repository.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
from pathlib import Path

NANODESU_ENV = "NANODESU_PATH"

# Where nanodesu.py should be installed, for the message a user gets when it is missing.
INSTALL_HINT = "pip install nanodesu   (or set %s to a nanodesu.py checkout)" % NANODESU_ENV


def find_nanodesu():
    """Locate Nanodesu!, or None.

    Returns either a module already imported, or a Path to a nanodesu.py on disk.
    """
    env = os.environ.get(NANODESU_ENV)
    if env:
        p = Path(env)
        if p.is_file():
            return p
        if p.is_dir():
            cand = p / "nanodesu.py"
            if cand.is_file():
                return cand
            # A checkout whose source lives in a package directory.
            for sub in sorted(p.glob("*/nanodesu.py")):
                return sub
        # An explicit request that cannot be honoured is an error, not a reason to fall
        # through to a guess: silently using a different build than the caller named is
        # exactly the confusion this function exists to prevent.
        raise FileNotFoundError(
            "%s is set to %r, which is not a nanodesu.py file or a directory containing one"
            % (NANODESU_ENV, env))

    try:
        return importlib.import_module("nanodesu")
    except Exception:
        pass

    here = Path(__file__).resolve().parent
    for candidate in (here / "nanodesu.py", here.parent / "nanodesu.py",
                      here / "nanodesu" / "nanodesu.py"):
        if candidate.is_file():
            return candidate
    return None


def load_nanodesu(found):
    """Return the Nanodesu! module, importing it by path when it is not installed."""
    if not isinstance(found, Path):
        return found
    spec = importlib.util.spec_from_file_location("nanodesu_embedded", found)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load %s" % found)
    module = importlib.util.module_from_spec(spec)
    sys.modules["nanodesu_embedded"] = module
    spec.loader.exec_module(module)
    return module


def nanodesu_missing_reason() -> str:
    """The message a user sees when unpacking is asked for and Nanodesu! is not there.

    Worth being explicit: 'not found' with no next step is the kind of message that makes a
    tool feel broken when it is merely incomplete, and the fix is one command.
    """
    return ("Nanodesu! was not found, so this PyInstaller archive cannot be unpacked. "
            "Install it with: %s" % INSTALL_HINT)


def _describe(found) -> str:
    if isinstance(found, Path):
        return str(found)
    return getattr(found, "__file__", None) or getattr(found, "__name__", "nanodesu")


def _resolve(log=print):
    """Find and load Nanodesu!, or return (None, reason)."""
    try:
        found = find_nanodesu()
    except FileNotFoundError as exc:
        return None, str(exc)
    if found is None:
        return None, nanodesu_missing_reason()
    try:
        return load_nanodesu(found), None
    except Exception as exc:                       # pragma: no cover - defensive
        return None, "could not load Nanodesu! from %s: %s" % (_describe(found), exc)


def unpack_pyinstaller(target: Path, out_dir: Path, *, with_pyc: bool = True,
                       log=print) -> dict:
    """Unpack a PyInstaller onefile with Nanodesu!. Returns a result dict.

    `executed` is always False and is recorded in the result so a caller never has to
    assume it: this function only decodes bytes and writes files.
    """
    nano, reason = _resolve(log)
    if nano is None:
        return {"ok": False, "tool": None, "reason": reason, "executed": False,
                "hint": INSTALL_HINT}

    out_dir.mkdir(parents=True, exist_ok=True)

    # Prefer the library API when it is there. It returns a summary instead of printing one,
    # which means the caller gets a count and a list of confined names rather than having to
    # scrape them back out of prose. The CLI path stays for Nanodesu! versions before 1.3.
    if hasattr(nano, "extract") and hasattr(nano, "PyInstallerError"):
        try:
            res = nano.extract(target, out_dir, pyc=with_pyc)
        except Exception as exc:
            return {"ok": False, "tool": _describe(nano),
                    "reason": "Nanodesu! failed: %s" % exc, "executed": False}
        return {
            "ok": bool(res.get("ok")),
            "tool": _describe(nano),
            "tool_version": getattr(nano, "VERSION", None),
            "out_dir": str(out_dir),
            "files_written": res.get("written", 0),
            "failed": res.get("failed", []),
            "reason": None if res.get("ok") else "%d entr(ies) could not be written"
                                             % len(res.get("failed", [])),
            "executed": False,
        }

    argv = ["extract", str(target), "-o", str(out_dir)]
    if with_pyc:
        argv.append("--pyc")

    before = {p for p in out_dir.rglob("*") if p.is_file()}
    try:
        rc = nano.main(argv)
    except SystemExit as exc:                      # nanodesu exits via SystemExit
        rc = exc.code if isinstance(exc.code, int) else 1
    except Exception as exc:                       # pragma: no cover - defensive
        return {"ok": False, "tool": _describe(nano),
                "reason": "Nanodesu! failed: %s" % exc, "executed": False}
    after = {p for p in out_dir.rglob("*") if p.is_file()}
    written = sorted(str(p.relative_to(out_dir)) for p in after - before)

    result = {
        "ok": rc == 0,
        "tool": _describe(nano),
        "tool_version": getattr(nano, "VERSION", None),
        "out_dir": str(out_dir),
        "files_written": len(written),
        "executed": False,
    }
    if rc != 0:
        result["reason"] = "Nanodesu! exited with status %s" % rc
    return result


def unpack_pyz(target: Path, out_dir: Path, *, bare: bool = False, log=print) -> dict:
    """Unpack a standalone PYZ archive to valid .pyc files."""
    nano, reason = _resolve(log)
    if nano is None:
        return {"ok": False, "reason": reason, "executed": False, "hint": INSTALL_HINT}
    out_dir.mkdir(parents=True, exist_ok=True)
    argv = ["pyz", str(target), "-o", str(out_dir)]
    if bare:
        argv.append("--bare")
    try:
        rc = nano.main(argv)
    except SystemExit as exc:
        rc = exc.code if isinstance(exc.code, int) else 1
    except Exception as exc:                       # pragma: no cover - defensive
        return {"ok": False, "reason": "Nanodesu! failed: %s" % exc, "executed": False}
    return {"ok": rc == 0, "out_dir": str(out_dir), "executed": False,
            "reason": None if rc == 0 else "Nanodesu! exited with status %s" % rc}
