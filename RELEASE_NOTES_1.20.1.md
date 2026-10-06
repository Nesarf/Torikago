# Torikago 1.20.1

The performance debt from 1.18.0, measured and paid.

## What the measurement says

On a 4.56 GB Windows ISO:

| step | time |
|---|---|
| streamed read of the whole file | 37–78 s (disk-bound, not code) |
| read into memory | 30–36 s (4672 MB resident) |
| boot-sector scan, **per-byte Python loop** | **over four minutes, never finished** |
| boot-sector scan, **`bytes.find`, whole file** | **3.12 s** |
| runtime markers, **one sweep per marker** | **58.24 s** |
| runtime markers, single alternated regex | 51 s (92 MB/s — still too slow) |
| **boot sector, default 64 MiB** | **0.059 s** |
| **runtime markers, default 64 MiB** | **0.702 s** |

## Three findings, and the third is the one that changes the code

**The cost was in the loop, not in the coverage.** Stepping through every byte position in Python took
minutes; asking `bytes.find` for the signature takes 3.1 seconds over the same 4.56 GB. The 18.6
million occurrences of the signature byte did not need to reach the interpreter.

**But covering the whole file has a cost of its own**, and thirty markers mean thirty sweeps. A single
alternated regex is only 4.5× faster and still 51 seconds — not enough.

**So the default is a bounded prefix, and the bound is reported.** `SCAN_COVERAGE = 64 MiB`, which
matches the tool's own default ceiling of 768 MB per file. **Optimising for a 5 GB image was the wrong
call, and truncating it silently would have been worse** — a pattern beyond the prefix is
unlooked-for, which is a different fact from absent. The result now carries `truncated`, `file_size`
and a sentence saying what was read, and it surfaces as a low-severity finding of its own. A caller who
wants everything passes `limit=None` and gets 3.2 seconds.

## Two real bugs found by doing this

**The loop's advance was placed only at the end of the body**, so on the full-file path every
`continue` and every hit re-found the same candidate. It did not terminate. The "over four minutes"
figure was that, not the scan.

**One boot sector was reported twice.** A 512-byte record can contain the signature at its own offset
510 *and* an incidental `0x55AA` elsewhere, and both resolve to the same record start — so a finding
saying "this program brings its own boot code" read as two of them.

## Testing

**375 tests**, green on Python 3.9, 3.12, 3.13 and 3.14. The boot-sector call returns a record rather
than a list now, so its callers were updated to say whether they mean the default coverage or the whole
file — and the tests that exist to prove coverage reaches past the old 8 MB cut now pass `limit=None`
explicitly, because otherwise they would be testing the default.

`tools/bench_full_scan.py` is checked in with the measurements, so the next person can re-run them
rather than take these on trust.
