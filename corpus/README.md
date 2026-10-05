# corpus

Measurements about files, **not the files**. One JSON object per line in `manifest.jsonl`.

## Why this exists, and what it cost to learn

An earlier sweep of this machine produced **248 measurement records**. A few weeks later they were
gone — deleted along with a scratch directory — and with them the answers to *"is that
medium-severity finding still there?"* and *"were those six false positives fixed?"*.

**The measurements are the expensive part. The binaries are reproducible or irrelevant.** So what is
kept is the facts, and because no sample is ever stored, this directory can be committed, diffed in
review, and published without shipping anything dangerous.

## What is in a record

| field | meaning |
|---|---|
| `sha256` | **identity.** Paths change between machines and sweeps; content does not |
| `path_hint` | where it was found last — a hint, never an identity |
| `first_seen`, `last_seen`, `times_seen` | so a repeat sweep is *comparable* to the first, not a replacement for it |
| `size`, `kind`, `label` | what it is |
| `mismatch` | extension disagreeing with content |
| `packer` | the packer verdict, or `n/a` when not applicable |
| `wrapper` | a recognised self-extracting wrapper, e.g. PyInstaller |
| `entropy_max` | highest section entropy |
| `suspicious_imports`, `noted_imports` | **only the imports the assessor cited**, plus `import_count` for the rest |
| `attention` | the number of things worth a look |
| `schema` | manifest schema version |

The full import list is deliberately **not** stored: a hundred names per file makes a diff nobody
reads, and `import_count` is enough to notice that an import table changed.

## Rebuilding it

```bash
torikago --corpus-write /d --corpus-file corpus/manifest.jsonl \
         --scan-limit 1200 --scan-only exe,dll
```

Three flags that all exist because the naive version wasted a run:

* **`--scan-only exe,dll`** — without it the walk picks up every file, and a drive's shallow
  directories are mostly archives and images. Observed: **1,496 records with exactly one PE among
  them**, which says nothing about the detectors.
* **`--scan-limit`** — `scan_tree` defaults to 200 as a guard against being pointed at a whole drive
  by accident. The first corpus run **silently stopped at 200 of 1,232 candidates**.
* **`--corpus-file`** — keeps the manifest out of the tree being scanned.

The manifest never measures itself; a run that finds it skips it and says so. Left in, it would add a
fresh record for itself every sweep, because the file had just changed.

## Checking it

```bash
torikago --corpus-check corpus/manifest.jsonl
```

Reports the file count, how many carry attention, and the breakdown by packer and by kind.

## What it is for

**Detector calibration.** Every false positive this project has found came from a real file and none
from a fixture — .NET entropy, version strings parsed as IPs, random boot-sector code, data-only
modules called packed. A corpus of real software is the only thing that finds that class, and it is
the only way to answer *"did that adjustment break something else?"* afterwards.

**False negatives, or the absence of them, are not measurable here.** A corpus of legitimate software
cannot say whether a detector would catch malware. That is what `--handoff` is for: hand the sample to
an engine that judges, and record *whose* verdict it was.
