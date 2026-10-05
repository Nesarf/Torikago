"""Compare a corpus manifest against what the detectors say about those files now.

## Why this exists, and the gap it closes

`corpus/manifest.jsonl` holds 1,161 measurements of real installed software, and **until now nothing
read it.** The module's own tests exercised the data structures with synthetic input; the real
manifest sat there. So a change to a detector could alter verdicts on a thousand real files and the
only way to find out was to remember to re-sweep the drive by hand.

That matters more here than in most projects because **every false positive this tool has found came
from a real file and none from a fixture** — .NET entropy, version strings parsed as IPs, random code
matching at a sector boundary, data-only modules called packed. Fixtures replay known regressions;
they cannot find a new class. The corpus is the only instrument that can, and an instrument nothing
reads is a pile.

## What it asserts, and what it deliberately does not

**It does not assert that the verdicts are unchanged.** A change caused by a detector edit is
*expected*; a change nobody expected is a bug. Software cannot tell those apart, so it must not try:

    the check makes the differences visible; a person decides whether they were intended

That is the same rule the rest of this project follows — report facts, refuse to conclude.

## Every file is read, on purpose

Identity is the content hash, so a file cannot be recognised without reading it. A size/mtime guard
would make this much faster and was described in an earlier draft of this docstring — **and was never
implemented**, which is its own small lesson about writing the documentation before the code.

It stays unimplemented deliberately: a guard trades a real class of false negatives for speed, and the
whole point of this check is to notice drift. A check that can silently miss a changed file is a check
that will one day report "no verdict changed" about a file whose verdict did.
"""
from __future__ import annotations

import json
from pathlib import Path

# The fields whose movement is a verdict change. `last_seen` and `times_seen` move every run by
# design and would otherwise drown the report in noise.
VERDICT_FIELDS = (
    "kind", "label", "mismatch", "packer", "wrapper",
    "entropy_max", "suspicious_imports", "noted_imports", "attention", "import_count",
)


def _row_to_entry(row: dict) -> dict:
    """The same shape `manifest.jsonl` holds, from a fresh assessment row."""
    entry = {}
    for field in VERDICT_FIELDS:
        if field in row:
            entry[field] = row[field]
    if isinstance(row.get("all_imports"), list):
        entry["import_count"] = len(row["all_imports"])
    return entry


def collect_now(root: Path, *, only=None, limit: int = 100000, skip=None, progress=None) -> dict:
    """Re-measure a tree, keyed by content hash.

    Uses the existing scanner rather than a second implementation of it, so the check exercises the
    code that ships. A parallel analyser would be a second thing to keep correct, and the point of
    this file is to make drift visible, not to add a way for it to hide.
    """
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import torikago as tk
    import corpus as corpus_mod

    tree = tk.scan_tree(Path(root), limit=limit, only=only)
    skip = {Path(x).resolve() for x in (skip or []) if x}
    out = {}
    for row in tree.get("rows", []):
        full = Path(root) / row["path"]
        if not full.is_file():
            continue
        # The manifest must not measure itself. `--corpus-write` learned this already and the
        # verifier did not: left in, every run reports a file the manifest did not have, and that
        # phantom entry is the report's own output rather than a finding.
        if full.resolve() in skip:
            continue
        out[corpus_mod.sha256_file(full)] = (_row_to_entry(row), row.get("path"))
        if progress:
            progress(len(out))
    return {"ok": True, "measured": out, "scanned": tree.get("scanned", 0)}


def verify(manifest_path: Path, root: Path, *, only=None, limit: int = 100000) -> dict:
    """Compare the manifest against a fresh measurement of `root`.

    Returns the differences grouped by what they mean, and never a verdict about them.
    """
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import corpus as corpus_mod

    before = corpus_mod.read_manifest(Path(manifest_path))
    measured = collect_now(Path(root), only=only, limit=limit,
                           skip=[manifest_path])["measured"]

    changed, missing, added = [], [], []
    for sha, (entry, path_hint) in sorted(measured.items()):
        if sha not in before:
            added.append({"sha256": sha, "path_hint": path_hint})
            continue
        old = before[sha]
        for field in VERDICT_FIELDS:
            was, now = old.get(field), entry.get(field)
            if was != now:
                changed.append({
                    "sha256": sha,
                    "path_hint": path_hint or old.get("path_hint"),
                    "field": field,
                    "was": was,
                    "now": now,
                })
    for sha, old in sorted(before.items()):
        if sha not in measured:
            missing.append({"sha256": sha, "path_hint": old.get("path_hint"),
                            "why": "not found under the tree that was measured, or unchanged "
                                   "content that the size/mtime guard skipped"})

    return {
        "ok": True,
        "manifest": str(manifest_path),
        "root": str(root),
        "in_manifest": len(before),
        "measured": len(measured),
        "changed": changed,
        "added": added,
        "missing": missing,
        "limits": [
            "This reports differences; it does not judge them. A change caused by a detector edit is "
            "expected, and a change nobody expected is a bug -- software cannot tell those apart, so "
            "it does not try.",
            "A file listed as missing was not found under the tree that was measured: it may have "
            "moved, changed content, or been deleted.",
            "The manifest holds legitimate software only, so it can show that a detector still does "
            "not cry wolf. It cannot measure false negatives; that needs samples this corpus "
            "deliberately does not contain.",
        ],
    }


def summarise(result: dict) -> str:
    """A short human-readable summary. Separate from `verify` so the data stays usable as data."""
    lines = []
    lines.append("%d in the manifest, %d measured now" % (result["in_manifest"], result["measured"]))
    n_changed = len(result["changed"])
    if n_changed:
        by_field = {}
        for c in result["changed"]:
            by_field.setdefault(c["field"], []).append(c)
        lines.append("%d verdict change(s), by field:" % n_changed)
        for field, items in sorted(by_field.items(), key=lambda kv: -len(kv[1])):
            lines.append("   %-18s %d" % (field, len(items)))
            for c in items[:4]:
                lines.append("      %s  %r -> %r  (%s)"
                             % (c["sha256"][:12], c["was"], c["now"],
                                str(c["path_hint"])[-48:]))
            if len(items) > 4:
                lines.append("      ... and %d more" % (len(items) - 4))
    else:
        lines.append("no verdict changed")
    if result["added"]:
        lines.append("%d file(s) measured that the manifest did not have" % len(result["added"]))
    if result["missing"]:
        lines.append("%d manifest entr(ies) not seen in this measurement" % len(result["missing"]))
    return "\n".join(lines)


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        prog="corpus-verify",
        description="Re-measure a tree and report how the detectors' verdicts differ from the "
                    "manifest. Reports differences; does not judge them.")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--root", required=True, help="the tree the manifest describes")
    ap.add_argument("--scan-only", metavar="EXT,EXT",
                    help="restrict to these extensions, as with --corpus-write")
    ap.add_argument("--limit", type=int, default=100000)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    only = [e.strip() for e in args.scan_only.split(",")] if args.scan_only else None
    result = verify(Path(args.manifest), Path(args.root), only=only, limit=args.limit)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=1))
        return 0
    print(summarise(result))
    print()
    for limit in result["limits"]:
        print("  - %s" % limit)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
