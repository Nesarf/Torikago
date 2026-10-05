# Torikago 1.8.0

The corpus is now an instrument rather than a pile.

## The gap

`corpus/manifest.jsonl` holds **1,161 measurements of real installed software** — and until this
release **nothing read it**. The module's own tests exercised the data structures with synthetic
input; the real manifest sat there. So a detector edit could change verdicts on a thousand real files
and the only way to find out was to remember to re-sweep a drive by hand.

That matters more here than in most projects, because **every false positive this tool has found came
from a real file and none from a fixture**: .NET entropy, version strings parsed as IPs, random code
matching at a sector boundary, data-only modules called packed. Fixtures replay known regressions; they
cannot find a new class.

## What it does

```bash
python torikago.py --corpus-verify corpus/manifest.jsonl --corpus-root /d --scan-only exe,dll
```

Re-measures a tree and reports how verdicts differ from the manifest, grouped by field, with the
before and after for each.

## And what it refuses to do

**It reports differences; it does not judge them.** A change caused by a detector edit is *expected*; a
change nobody expected is a bug. **Software cannot tell those apart, so it does not try.** The result
carries that sentence, and the summary says `no verdict changed` rather than "all good" — because a
clean comparison means nothing was *detected*, not that nothing is wrong.

The tests assert differences are **found and reported**, never that they are absent. A check that
failed on every intentional change would be turned off; one that passed on every accidental change
would be worse than nothing.

## It also cannot measure false negatives

The corpus is legitimate software, so it can show a detector still does not cry wolf. It says nothing
about what a detector would miss. That needs samples this corpus deliberately does not contain, and
the output says so rather than leaving the reader to assume otherwise.

## Two mistakes of mine, both kept in the code

**The verifier measured its own manifest.** `--corpus-write` had already learned to skip it; the
verifier did not, so every run reported one phantom addition — the report's own output.

**A docstring described a size/mtime fast path that was never implemented.** Writing the documentation
before the code, and leaving the documentation describing the intent. It now says the opposite and
says why: a guard would make this faster and would trade a real class of false negatives for speed,
and **a check that can silently miss a changed file will one day report "no verdict changed" about a
file whose verdict did.**

## Testing

**256 tests** (was 245), green on Python 3.9, 3.12, 3.13 and 3.14. `test_corpus_verify.py` adds 11:
every verdict field is compared (driven through `all_imports` for `import_count`, since assigning the
field is silently overwritten — a fake that would otherwise prove nothing), changes and additions and
removals are all reported, the manifest is excluded from its own measurement, the result carries its
limits, no verdict word appears in it, and the summary offers no reassurance.
