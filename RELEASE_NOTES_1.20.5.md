# Torikago 1.20.5

A packaging patch. Nothing in the tool behaves differently.

## The sdist shipped a test suite that could not run

The 1.20.4 sdist carried `test/test_*.py` and nothing else from that directory. Measured by unpacking
the published sdist and running its suite on Linux: **391 tests, 7 errors** — four modules failed at
import on a missing `_fixtures.py`, and five tests errored on files that were never shipped
(`PERSONA.md`, `tools/pixelart.py`).

The cause is what setuptools includes by default: `test/test_*.py` matches, `test/_fixtures.py` does not,
and no document or script from the repository root travels in an sdist unless it is named.

**A file that looks like a test suite and cannot run is the same shape as a wheel that looked installed
and could not find its own font** — and this project has published that shape twice, once as `unpack.py`
in 1.3.0 and once as the two panel files in 1.20.3.

## What changed

`MANIFEST.in` now names what the tests need: the whole `test/` directory, `tools/`, `PERSONA.md`.

`tools/` is included for a second reason: the scripts in it are how the numbers in the documents were
measured. Shipping a claim without the instrument that produced it is the failure this repository keeps
correcting.

## Verified on the artifact, not on the checkout

The check is the one that found the defect: unpack the built sdist somewhere that is **not** the
repository and run the suite there.

    torikago 1.20.5 sdist, Linux: 488 tests, OK (skipped=41)

More tests than before (488 against 391) because four modules can now be collected at all. The skips are
fixtures this host cannot build, the same set the repository run skips.
