# Torikago 1.7.1

Documentation for features that shipped without any.

## The gap

`--handoff` had been released in **three** versions and its flag name appeared **zero** times in the
README. `--posture` had been released in **two** and was not mentioned at all. `--corpus-write`,
`--scan-only` and `--scan-limit` were absent too.

The concepts were often described — there was a whole section called *"Handing the evidence to
something that decides"* — but **the flag was never named**, and a flag nobody can find is a feature
nobody has. The README is the front door; a feature behind it needs a sign.

## What is documented now

* **Every flag in `Usage`**, including a note saying why: three of them shipped unmentioned.
* **A `--posture` section**: what it queries, that it is read-only and asserted to be, the
  declared-vs-observed checks, the two tools that abuse the registration mechanism, and **the
  boundary notice verbatim**, error paths included.
* **The test count corrected** — the README claimed 69; the suite is **245**.
* Two CI-only regressions named, because they are the kind of thing that gets "fixed" by someone who
  never reads why they exist.

## And a small confession in the text

The paragraph explaining the platform bug first spelled the Windows path out, and writing it through
a shell heredoc turned the two characters before `askmgr` into a real tab — **the fifth time that has
happened in this project**, twice corrupting a test fixture. It is described rather than quoted now,
with the reason in the README itself: **a sentence that cannot survive being written down is not
documentation.**

## Testing

**245 tests**, unchanged — this release is documentation, and the suite is the check that nothing else
moved.
