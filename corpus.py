#!/usr/bin/env python3
"""A committed corpus of structural facts about files, without the files.

An earlier sweep produced 248 measurement records and they were gone a few weeks later, deleted with
a scratch directory -- so "is that medium-severity finding still there" and "were those six false
positives fixed" had no answer. Measurements are the expensive part; the binaries are reproducible or
irrelevant.

So this writes `corpus/manifest.jsonl`: one JSON object per file, keyed by content hash, recording
what was measured. **No samples are stored, which is what makes the corpus committable** -- it can be
diffed in review, used as a regression baseline, and published without shipping anything dangerous.

Deliberate design decisions:

* **Identity is the sha256, not the path.** Paths change between machines and between sweeps; content
  does not. A file reappearing at a new path updates the existing entry rather than adding a
  duplicate, which is what keeps the manifest from growing without bound.
* **`first_seen` and `last_seen`, not a single timestamp.** Re-scanning the same corpus must produce
  the same *rows*; the timestamps are what let a check confirm that it did, rather than overwriting
  the evidence that it was ever measured before.
* **Only the imports that mattered.** Keeping every import makes the manifest large, noisy and
  unreviewable in a diff. The ones the assessor cited are the ones worth reviewing, and a count of the
  rest is enough to notice a change.
* **A judgement, when one exists, is stored with its source.** A clean verdict from an engine is that
  engine's opinion; recording which engine and when is the difference between data and a claim.

Nothing here executes anything: it calls the same static analyser the CLI does.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

MANIFEST_NAME = "manifest.jsonl"
SCHEMA_VERSION = 1

# The fields copied from an assessment row. Everything else is derived or dropped on purpose -- see
# the module docstring on why `all_imports` is not here.
ROW_FIELDS = (
    "size", "kind", "label", "mismatch", "packer", "wrapper",
    "entropy_max", "suspicious_imports", "noted_imports", "attention",
)


def sha256_file(path: Path, *, chunk: int = 1 << 20) -> str:
    """The content hash, streamed so a large sample does not have to fit in memory."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def entry_from_row(row: dict, *, sha: str, stamp: str | None = None) -> dict:
    """One manifest entry from an assessment row.

    `row` is a `--scan` row, whose keys are already the structural facts. The path is kept as a hint
    about where it was found and never as identity.
    """
    stamp = stamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    entry = {
        "schema": SCHEMA_VERSION,
        "sha256": sha,
        "path_hint": row.get("path"),
        "first_seen": stamp,
        "last_seen": stamp,
        "times_seen": 1,
    }
    for field in ROW_FIELDS:
        if field in row:
            entry[field] = row[field]
    # The imported-function count, without the list. Enough to notice that an import table changed
    # without carrying a hundred names into a diff nobody will read.
    if isinstance(row.get("all_imports"), list):
        entry["import_count"] = len(row["all_imports"])
    return entry


def read_manifest(path: Path) -> dict:
    """The manifest as {sha256: entry}. A malformed line is an error, not silently skipped: a corpus
    that quietly loses rows is worse than one that refuses to load."""
    path = Path(path)
    out = {}
    if not path.is_file():
        return out
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError as exc:
            raise ValueError("%s line %d is not JSON: %s" % (path, n, exc))
        sha = item.get("sha256")
        if not sha:
            raise ValueError("%s line %d has no sha256" % (path, n))
        out[sha] = item
    return out


def merge_manifest(existing: dict, fresh: list, *, stamp: str | None = None) -> dict:
    """Fold new entries into the old, returning the merged set plus what changed.

    An entry seen again keeps its `first_seen` and increments `times_seen`; only `last_seen` and the
    measured fields are updated. That is what makes a repeated sweep comparable to the first one
    instead of indistinguishable from it.
    """
    stamp = stamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    merged = dict(existing)
    added, updated, changed = [], [], []

    for entry in fresh:
        sha = entry["sha256"]
        if sha not in merged:
            merged[sha] = entry
            added.append(sha)
            continue
        old = merged[sha]
        new = dict(old)
        new["last_seen"] = stamp
        new["times_seen"] = int(old.get("times_seen", 1)) + 1
        new["path_hint"] = entry.get("path_hint") or old.get("path_hint")
        for field in ROW_FIELDS:
            if field in entry:
                if old.get(field) != entry[field]:
                    changed.append({"sha256": sha, "field": field,
                                    "was": old.get(field), "now": entry[field]})
                new[field] = entry[field]
        if "import_count" in entry:
            new["import_count"] = entry["import_count"]
        if new != old:
            updated.append(sha)
        merged[sha] = new

    return {"entries": merged, "added": added, "updated": updated, "changed": changed}


def write_manifest(path: Path, entries: dict) -> Path:
    """Write sorted by sha256 so the file is stable and a diff shows only real changes."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(entries[sha], ensure_ascii=False, sort_keys=True)
             for sha in sorted(entries)]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return path


def summarize(entries: dict) -> dict:
    """What the corpus holds, by the fields the assessor produces."""
    out = {"files": len(entries), "packer": {}, "kind": {}, "attention": 0}
    for entry in entries.values():
        packer = entry.get("packer") or "unknown"
        packer = packer if isinstance(packer, str) else str(packer)
        out["packer"][packer] = out["packer"].get(packer, 0) + 1
        kind = entry.get("kind") or "unknown"
        out["kind"][kind] = out["kind"].get(kind, 0) + 1
        if entry.get("attention"):
            out["attention"] += 1
    return out


def diff_manifests(before: dict, after: dict) -> dict:
    """What changed between two states of the corpus.

    Exists so a detector adjustment can be judged: run the corpus before and after, and this says
    which files' verdicts moved. Without it, "I fixed the false positives" is unverifiable.
    """
    out = {"added": [], "removed": [], "changed": []}
    for sha in sorted(set(after) - set(before)):
        out["added"].append(sha)
    for sha in sorted(set(before) - set(after)):
        out["removed"].append(sha)
    for sha in sorted(set(before) & set(after)):
        for field in ROW_FIELDS:
            a, b = before[sha].get(field), after[sha].get(field)
            if a != b:
                out["changed"].append({"sha256": sha, "field": field, "was": a, "now": b})
    return out
