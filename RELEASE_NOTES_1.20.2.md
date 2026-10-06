# Torikago 1.20.2

A corpus row now says how much of the file it measured.

## Three things that used to look identical

A row measured over the whole file, a row measured over a prefix because a scan was bounded, and a row
from an older schema that never recorded coverage **all had the same shape.**

So in a diff — and the manifest exists to be diffed — **"this field changed" and "this field stopped
being measured" read identically.** That is the exact distinction the no-under-reporting commitment
exists to keep, and it was missing from the corpus that feeds every detector decision.

## Derived from the row, not declared by the writer

`coverage_of()` reads the answer out of the row instead of asking the writer to state it, because **a
writer that has to remember will forget** and the evidence is already present: every bounded scan in
this project records that it stopped. Truncation keys are matched so a cap added later is seen without
an edit here.

## And the default is the part that matters

**A row that carries no coverage bookkeeping is `unknown`, not `complete`.**

The absence of a truncation flag and the absence of any bookkeeping are different facts.
**Declaring a tidy-looking old row complete would be the tool reassuring itself** — the failure mode
this whole project is arranged against.

Every one of the **1161 shipped rows** predates the question, so **every one reads as `unknown`**, and
a test asserts that against the real manifest rather than against a fixture. The corpus is honest about
its own history instead of quietly upgrading it.

## Testing

**381 tests** (was 375), green on Python 3.9, 3.12, 3.13 and 3.14. Six new, and the one that matters
reads the shipped manifest and requires that nothing in it claims to be complete.

## A note on the release itself

The first attempt at this tag **failed the release workflow**, because the notes file was not in the
tree. The workflow refuses to publish a version nobody can review later, which is the right behaviour
and is recorded here rather than quietly fixed.
