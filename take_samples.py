#!/usr/bin/env python3
"""Take many samples at once, from a tag, with every safety rule already applied.

## Why this exists

Taking twenty samples one hash at a time is twenty deliberate acts, and the friction pushes toward
taking fewer or taking carelessly. **A batch tool removes the friction without removing the
deliberation**: the destination is checked once against rules that cannot be waived, every file is
sealed before it stops moving, and the whole run is written to an append-only log.

## The decision this does not make

**It does not decide whether to take samples.** That is the machine owner's call, and running this is
that call being made. What it decides is only *how*, once the decision has been made: which types are
worth taking, how to avoid taking the same thing twice, and how to leave a record.

## What it refuses

* **Destinations that are a specific way of going wrong** — inside a git repository (a sample in a
  repository gets committed eventually), on `C:` (it survives a machine being handed on), in the
  cache area or the workspace.
* **Types the unpacker cannot read.** A zip is not evidence about a PE parser; taking twenty of them
  would produce a corpus that says nothing. This is the lesson from the first corpus built here, which
  had 1,496 records and exactly one PE among them.
* **Duplicates.** Identity is the content hash, so a second copy of something already sealed is not a
  second sample.
* **Remediation of any kind.** Nothing here runs, unpacks, or modifies a sample. It moves bytes into a
  sealed container and stops.

## What it does that a person would otherwise do by hand

Reads the tag listing, filters to the types worth having, checks each hash against the vault, fetches
what is missing, seals it, and prints one line per sample. A failure on one sample does not end the
run — the rest are still worth having, and the failure is reported rather than swallowed.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# The types a Windows PE unpacker can actually do something with. Anything else is worth taking only
# on purpose, never as part of filling a corpus -- so this is the default and `--types` overrides it.
PE_TYPES = ("exe", "dll", "sys", "scr", "cpl")

# Fetched bytes are sealed immediately and never left loose.
MB_API = "https://mb-api.abuse.ch/api/v1/"
USER_AGENT = "torikago-research/1.0 (malware corpus collection)"


def listing(tag: str, auth_key: str | None, *, limit: int) -> dict:
    body = urllib.parse.urlencode({"query": "get_taginfo", "tag": tag, "limit": limit}).encode()
    headers = {"User-Agent": USER_AGENT}
    if auth_key:
        headers["Auth-Key"] = auth_key
    req = urllib.request.Request(MB_API, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=180) as fh:
            payload = json.load(fh)
    except (urllib.error.URLError, ValueError) as exc:
        return {"ok": False, "reason": str(exc)}
    if payload.get("query_status") != "ok":
        return {"ok": False, "reason": "MalwareBazaar said %r" % payload.get("query_status")}
    return {"ok": True, "samples": payload.get("data") or []}


def select(samples: list, *, types, have: set, limit: int) -> tuple:
    """Which samples to take, and what was skipped and why.

    Returns (chosen, skipped). The skips are returned rather than discarded because "I took 4 of 20"
    means something different from "only 4 existed" -- and the difference matters when the corpus
    later looks thin.
    """
    chosen, skipped = [], []
    for s in samples:
        sha = (s.get("sha256_hash") or "").lower()
        if not sha:
            skipped.append({"why": "no hash", "name": s.get("file_name"), "kind": "nohash"})
            continue
        if sha in have:
            skipped.append({"why": "already sealed", "sha256": sha,
                            "name": s.get("file_name"), "kind": "sealed"})
            continue
        ftype = (s.get("file_type") or "").lower()
        if types and ftype not in types:
            skipped.append({"why": "type %r not in %s" % (ftype, ",".join(sorted(types))),
                            "sha256": sha, "name": s.get("file_name"), "kind": "type"})
            continue
        chosen.append(s)
        if len(chosen) >= limit:
            break
    return chosen, skipped


def sealed_hashes(vault: Path) -> set:
    """What is already in the vault, by content hash.

    The vault names every artifact by its own sha256, which is why this is a directory listing
    rather than a database lookup -- a sealed artifact identifies itself.
    """
    vault = Path(vault)
    if not vault.is_dir():
        return set()
    return {p.stem.lower() for p in vault.glob("*.zip") if len(p.stem) == 64}


def take_one(sha: str, *, vault: Path, work: Path, auth_key: str | None,
             log) -> dict:
    """Fetch, verify, seal, delete the loose copy. Returns what happened."""
    import sample_fetch as sf
    import sample_vault as sv

    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    work.mkdir(parents=True, exist_ok=True)

    # Download into the work directory, never the vault: a loose sample and a sealed one should not
    # share a directory, or the sealed one's guarantee is only as good as remembering which is which.
    result = sf.fetch_malwarebazaar(sha, fetch_bytes=True, dest=work, auth_key=auth_key)
    if not result.get("ok"):
        return {"sha256": sha, "at": started, "ok": False, "stage": "fetch",
                "reason": result.get("reason")}

    loose = Path(result["path"])
    if not sv.is_encrypted_zip(loose):
        # The provider serves a password-protected zip. If that is not true of this file, it is
        # readable hostile content sitting in a work directory -- said loudly rather than sealed and
        # forgotten.
        return {"sha256": sha, "at": started, "ok": False, "stage": "verify",
                "reason": "the download is not an encrypted archive",
                "path": str(loose)}

    sealed = sv.store(loose, vault)
    if not sealed.get("ok"):
        return {"sha256": sha, "at": started, "ok": False, "stage": "seal",
                "reason": sealed.get("reason"), "path": str(loose)}

    # Remove the loose copy. Keeping both would leave readable hostile content next to a sealed
    # container that exists precisely to avoid that.
    try:
        loose.unlink()
        removed = True
    except OSError:
        removed = False

    record = {"sha256": sha, "at": started, "ok": True, "stage": "sealed",
              "sealed": sealed["path"], "archive_bytes": sealed.get("archive_bytes"),
              "removed_loose_copy": removed}
    if log:
        sv.record(record, log)
    return record


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="take-samples",
        description="Fetch several samples by tag, seal each one, and stop. Never runs, unpacks or "
                    "modifies a sample. The decision to take samples is yours; this only carries "
                    "it out.")
    ap.add_argument("--tag", required=True, help="MalwareBazaar tag, e.g. pyinstaller")
    ap.add_argument("--dest", required=True,
                    help="vault directory. Refused inside the workspace, the cache area, a git "
                         "repository, or on C:")
    ap.add_argument("--work", required=True,
                    help="a scratch directory, ideally on the same volume, for the loose download")
    ap.add_argument("--count", type=int, default=5, help="how many to take (default 5)")
    ap.add_argument("--types", default=",".join(PE_TYPES),
                    help="file types worth taking, comma separated (default: %s). Pass 'any' to "
                         "take whatever the tag holds" % ",".join(PE_TYPES))
    ap.add_argument("--scan", type=int, default=100, help="how many listing rows to consider")
    ap.add_argument("--log", default=None, help="append-only record of what was taken")
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would be taken, then stop")
    args = ap.parse_args(argv)

    import sample_fetch as sf
    import sample_vault as sv

    vault = Path(args.dest)
    work = Path(args.work)
    # The same refusals as the single-sample path, because a batch must not be a way around them.
    sf.check_destination(vault)
    sf.check_destination(work)

    types = None if args.types.strip().lower() == "any" else {
        t.strip().lower() for t in args.types.split(",") if t.strip()}

    auth_key = os.environ.get("MALWAREBAZAAR_AUTH_KEY")
    listed = listing(args.tag, auth_key, limit=args.scan)
    if not listed.get("ok"):
        print("listing failed: %s" % listed.get("reason"), file=sys.stderr)
        return 1

    have = sealed_hashes(vault)
    chosen, skipped = select(listed["samples"], types=types, have=have, limit=args.count)

    # Counted by an explicit category rather than by substring-matching the reason text. The first
    # version asked whether "type" appeared in the why-string, which matches far more than it should
    # and reported every skip as a type skip.
    by_kind = {}
    for s in skipped:
        by_kind[s.get("kind", "other")] = by_kind.get(s.get("kind", "other"), 0) + 1
    print("tag %r: %d listing row(s)" % (args.tag, len(listed["samples"])))
    for kind, label in (("sealed", "already sealed"), ("type", "wrong type"),
                        ("nohash", "no hash")):
        if by_kind.get(kind):
            print("  %-16s %d" % (label, by_kind[kind]))
    print()
    for s in chosen:
        print("  take  %-18s %-5s %10s  %s"
              % ((s.get("sha256_hash") or "")[:16], s.get("file_type"), s.get("file_size"),
                 (s.get("file_name") or "")[:34]))
    for s in skipped[:8]:
        print("  skip  %-18s %s" % ((s.get("sha256") or "-")[:16], s["why"]))
    if len(skipped) > 8:
        print("  ... and %d more skipped" % (len(skipped) - 8))

    if args.dry_run:
        print()
        print("dry run: nothing was fetched.")
        return 0
    if not chosen:
        print()
        print("nothing to take.")
        return 0

    print()
    results = []
    for s in chosen:
        sha = s["sha256_hash"]
        r = take_one(sha, vault=vault, work=work, auth_key=auth_key, log=args.log)
        results.append(r)
        if r.get("ok"):
            print("  sealed  %s  %s B" % (sha[:16], r.get("archive_bytes")))
        else:
            print("  FAILED  %s  at %s: %s" % (sha[:16], r.get("stage"), r.get("reason")))

    took = sum(1 for r in results if r.get("ok"))
    print()
    print("%d of %d sealed into %s" % (took, len(chosen), vault))
    print("Nothing was run, unpacked or modified. To analyse one, unseal it into a work directory")
    print("you will delete:")
    print("  torikago --vault-extract <zip> --work <a directory you will delete>")
    return 0 if took else 1


if __name__ == "__main__":
    sys.exit(main())
