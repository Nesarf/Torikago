"""Second provider: MalShare, reached the same way MalwareBazaar is.

## Why more than one provider

A single source answers one narrow question — *does this hash exist there* — and its collection policy
becomes your horizon. MalwareBazaar indexes what its pipeline ingests; MalShare indexes what the
community uploads, including things nobody has named yet. **For a tool whose value is how much of the
format space it has seen, one source is a blind spot**, and the blind spot is invisible because you
cannot miss what you never had.

The two are also usefully different in shape: MalwareBazaar carries family signatures and tags,
MalShare carries a "recently added" firehose and a daily quota you can read.

## Same rules as the first provider, because they are the rules

Nothing here weakens what `sample_fetch` already enforces. The destination check, the local hash
validation, the metadata-first default and the protection-state recording all happen **before** a
provider is consulted, so adding a provider cannot route around them.

## What it turned out to be good for, measured

The first assumption was that a second provider fills the first one's blind spot. Measured on
2026-10-05, that is **not true for Windows work**: MalShare's recent feed was **24 samples, zero PE** --
dominated by ELF (9) and Mach-O (3), with the rest ASCII, AppleScript, archives and documents. Filtering
by type for `PE32`, `PE32+`, `exe` or `dll` returned nothing, which for a 24-hour window means there was
nothing rather than that the filter failed.

So the two providers are good at different things, and the difference is the reason both are kept:

* **MalwareBazaar is the targeted one** -- indexed by family and by tag, which is how 20 PyInstaller
  samples were found when a tag was asked for.
* **MalShare is the bulk one** -- much larger, a daily firehose, and a type filter that makes sense over
  a longer window than a day.

**A conclusion worth keeping: a source being large is not the same as a source being relevant.** For a
Windows unpacker, the smaller, better-indexed collection is the more useful one -- and an assumption
about complementarity is worth one measurement before it is written down as a design rationale.

## What it does not do

It does not download by default, does not treat a provider's answer as a verdict, and does not
retry aggressively. **MalShare reported quota per key**, and a fetch tool that hammers a free service
is one that gets the account limited — which is the same failure abuse.ch now warns about on its own
front page.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

MALSHARE_API = "https://malshare.com/api.php"
USER_AGENT = "torikago-research/1.0 (malware corpus collection)"


def find_auth_key(explicit: str | None = None) -> str | None:
    """The MalShare API key, from the argument or the environment, or None."""
    return explicit or os.environ.get("MALSHARE_TOKEN") or None


def _call(params: dict, *, timeout: int = 300) -> bytes:
    url = MALSHARE_API + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as fh:
        return fh.read()


def quota(api_key: str) -> dict:
    """How many requests this key has left today.

    Read before a fetch rather than after a failure: MalShare allocates a daily request count, and
    discovering the limit by being rejected wastes the attempt that hit it.
    """
    try:
        raw = _call({"api_key": api_key, "action": "getlimit"}).decode("utf-8", "replace").strip()
    except (urllib.error.URLError, OSError) as exc:
        return {"ok": False, "reason": str(exc)}
    out = {"ok": True, "raw": raw}
    # Measured, not assumed: the endpoint returns JSON ({"LIMIT":2000,"REMAINING":2000}), while an
    # earlier version parsed it as two space-separated numbers and silently reported neither.
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            for key, label in (("LIMIT", "allocated"), ("REMAINING", "remaining")):
                for k, v in parsed.items():
                    if k.upper() == key:
                        out[label] = int(v)
    except (ValueError, TypeError):
        parts = raw.replace(",", " ").split()
        if len(parts) >= 2:
            try:
                out["allocated"], out["remaining"] = int(parts[0]), int(parts[1])
            except ValueError:
                pass
    return out


def recent(api_key: str, *, limit: int = 20) -> dict:
    """Hashes added in the last 24 hours, newest first.

    The "what exists right now" question, which MalwareBazaar answers by tag and this answers by
    recency. Useful for a corpus because it is the cheapest way to see the current variety of file
    types without committing to any of them.
    """
    try:
        raw = _call({"api_key": api_key, "action": "getlist"}).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
        return {"ok": False, "reason": str(exc)}
    try:
        rows = json.loads(raw)
    except ValueError:
        return {"ok": False, "reason": "the list endpoint did not return JSON",
                "raw_head": raw[:200]}
    if isinstance(rows, dict):
        rows = [rows]
    return {"ok": True, "count": len(rows), "samples": rows[:limit]}


def details(api_key: str, sha256: str) -> dict:
    """What MalShare knows about one hash, without downloading it."""
    try:
        raw = _call({"api_key": api_key, "action": "details", "hash": sha256}).decode(
            "utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"ok": False, "reason": "MalShare does not have that hash", "authenticated": True}
        if exc.code in (401, 403):
            return {"ok": False, "reason": "MalShare rejected the key (HTTP %d)" % exc.code,
                    "note": "check MALSHARE_TOKEN; register at https://malshare.com/register.php"}
        return {"ok": False, "reason": "HTTP %d" % exc.code}
    except (urllib.error.URLError, OSError) as exc:
        return {"ok": False, "reason": str(exc)}
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {"ok": True, "raw_head": raw[:400]}
    if not parsed or (isinstance(parsed, dict) and not parsed.get("MD5")):
        return {"ok": False, "reason": "MalShare does not have that hash", "authenticated": True}
    return {"ok": True, "metadata": parsed}


def fetch_bytes(api_key: str, sha256: str, dest: Path, *, timeout: int = 900) -> dict:
    """Download one sample into `dest`. Called only when the caller asked for bytes."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / (sha256 + ".bin")
    url = MALSHARE_API + "?" + urllib.parse.urlencode(
        {"api_key": api_key, "action": "getfile", "hash": sha256})
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as fh, open(out, "wb") as target:
            while True:
                block = fh.read(1 << 20)
                if not block:
                    break
                target.write(block)
    except urllib.error.HTTPError as exc:
        out.unlink(missing_ok=True)
        if exc.code == 404:
            return {"ok": False, "reason": "MalShare does not have that hash", "authenticated": True}
        return {"ok": False, "reason": "MalShare returned HTTP %d" % exc.code}
    except (urllib.error.URLError, OSError) as exc:
        out.unlink(missing_ok=True)
        return {"ok": False, "reason": str(exc)}

    import hashlib
    h = hashlib.sha256()
    with open(out, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    got = h.hexdigest()
    if got.lower() != sha256.lower():
        # MalShare returns samples raw rather than zipped, so unlike MalwareBazaar the hash is
        # directly checkable -- and a mismatch means the file is not what was asked for.
        out.unlink(missing_ok=True)
        return {"ok": False, "reason": "the downloaded bytes do not match the hash asked for",
                "expected": sha256, "got": got}
    return {"ok": True, "path": str(out), "sha256": got, "bytes": out.stat().st_size,
            "note": ("MalShare serves samples raw, not zipped, so this file is still executable "
                     "content. Keep it sealed and do not run it.")}
