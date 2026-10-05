# Torikago 1.3.4

`--unpack` now follows a wrapper inside a wrapper. Getting there turned up two ways it had been
silently doing nothing.

## The limit removed the entry it was meant to find

`find_inner_executables` ordered by path and took the first 40. On a real PyInstaller build that
fills with `binary___bz2.pyd`, `binary___decimal.pyd` and their neighbours — alphabetically early,
individually uninteresting — while **a nested executable in the same directory never appeared at
all**. The recursion then iterated an empty set of wrappers, and `--unpack` reported success.

The order is now by interest rather than by name: **the largest first**, then anything packed or
carrying strong-signal imports, with ties broken by path for stability. A nested executable is
megabytes; a stdlib extension is tens of kilobytes, so size is a crude but honest proxy — and a
wrapper is the most interesting thing inside a wrapper.

## And wrapper detection used a head peek, when the cookie is at the end

Same shape of mistake as an earlier one in this project, one function over. A CArchive cookie is the
**last occurrence** of its magic, so reading the first 4 MB of an 8.5 MB inner executable cannot see
it. `detect_pyinstaller` returned `None`, and the recursion skipped exactly the file it was built to
follow.

`detect_pyinstaller_at(path)` reads the tail, where the cookie is. The original function is unchanged
and still correct — the problem was only ever the buffer it was handed.

**Both failures were silent.** Neither raised, neither was reported, and the only reason either was
found is that a **real nested sample was built** — an outer PyInstaller executable with an inner one
carried as data — and the output did not contain what was expected.

## The bounds, and why each exists

Recursion without bounds is a tool that can be told to write an unbounded tree of files:

| bound | the failure it prevents |
|---|---|
| **depth** (3) | a wrapper in a wrapper is worth following; ten is not |
| **total** (10) | depth alone does not bound the work — one level can hold thirty archives |
| **visited resolved paths** | an archive containing a copy of itself would recurse to the depth limit, writing a complete tree at every level |
| **confinement** | unpacking writes files, so an inner path must resolve strictly inside the parent's output directory |

A broken nested archive is recorded as a skipped entry and the walk continues: one failure must not
cost the analysis of the others.

## Testing

**176 tests** (was 165), green on Python 3.9, 3.12, 3.13 and 3.14.

The tests reproduce both silent failures directly: a padded archive whose cookie a head peek cannot
reach, and a directory of small alphabetically-early files alongside one large one, asserting the
large one survives a limit of two.
