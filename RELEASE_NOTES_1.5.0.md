# Torikago 1.5.0

A corpus of measurements that survives, and the two flags that were needed to build it honestly.

## Why

An earlier sweep of this machine produced **248 measurement records**, and a few weeks later they were
gone — deleted with a scratch directory. With them went the answers to *"is that medium-severity
finding still there?"* and *"were those six false positives fixed?"* **The measurements are the
expensive part; the binaries are reproducible or irrelevant.**

`corpus/manifest.jsonl` keeps the facts and **never the samples**, which is what makes it committable,
diffable and publishable.

Identity is the **content hash**, not the path, so a file that moves is the same file. `first_seen` and
`times_seen` exist so a repeated sweep is *comparable* to the first rather than a replacement for it,
and a field that moved is reported — because a verdict that drifts is the thing a corpus is for.

## The first corpus built was worthless, and the reason is instructive

**1,496 records with exactly one PE among them.** `scan_tree` walks every file, and a drive's shallow
directories are mostly archives and images — so the manifest described zip files and said nothing about
the detectors. Hence `--scan-only exe,dll`.

Then the first *filtered* run **silently stopped at 200 of 1,232 candidates**, because `scan_tree`
defaults to a 200-file cap as a guard against being pointed at a whole drive by accident. Hence
`--scan-limit`.

And the manifest **measured itself**: left in the scanned tree, it added a fresh record for itself
every sweep, because the file had just changed. It is now skipped, and the run says so.

## What the corpus says so far

**1,161 real PE files** from installed commercial software (Adobe, Autodesk, FabFilter, Live2D, game
engines):

| packer verdict | count | share |
|---|---|---|
| `none` | 1001 | **86.2%** |
| `likely packed or delay-loaded` | 153 | 13.2% |
| `data module, not code` | 7 | 0.6% |

**198 files carry attention**, and 153 of those are the packer verdict landing on legitimate signed
software. That number is the point: **this is the false-positive pressure measured on real files**,
rather than inferred from a handful of samples. Every false positive this project has found came from
a real file and none from a fixture, so a corpus of real software is the only instrument that finds
that class — and the only way to answer "did that adjustment break something else?" afterwards.

## Two properties of the corpus itself

**A malformed manifest is an error, not a shorter list.** A corpus that quietly loses rows is worse
than one that refuses to load.

**The file is sorted by hash**, so a diff in review shows real changes and not reordering.

## Testing

**207 tests** (was 189), green on Python 3.9, 3.12, 3.13 and 3.14. `test_corpus.py` adds 18: identity
is content, a repeat sweep keeps `first_seen` and counts up, a verdict that moved is reported, a
malformed line raises, writing is sorted, and the full import list is deliberately not stored (a
count is enough to see a change; a hundred names per file is a diff nobody reads).
