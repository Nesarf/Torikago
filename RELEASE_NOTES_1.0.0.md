# Torikago 1.0.0

The project has a name. The package is `torikago`, the command is `torikago`, the module is
`torikago.py`.

## Why the rename

Not because the old name was ugly — because it was **wrong twice over**.

**It was already taken.** `triage` on PyPI belongs to an unrelated risk-modelling package, which
is why this was published as `triage-static`: a hyphenated compromise that *still* collided,
because the collision was with the word itself. It also was not a good name. `torikago` was free.

**And it named the category rather than the tool.** Triage, in medicine and in incident response,
is *sorting under time pressure and routing things elsewhere*. This does not sort and does not
route: it looks at one unknown file, reports what it is, and **refuses to run it**. What makes it
distinctive is that refusal — and the name for a refusal to run something is a cage.

> **鳥籠** — a birdcage. You put something live and dangerous in a cage so you can **look at it
> from a safe distance.** Held, but in view. That is precisely the relationship this tool has with
> an unknown sample.

## The category word does not disappear

`triage` stays in the description, the keywords, and the prose — because a codename does not do
ambient discovery, and somebody searching for a malware triage tool should still land here. The
name does the distinctive work; the words do the findable work. That split is deliberate.

## Traces, handled two different ways on purpose

**The current tree is renamed completely** — module, package metadata, console entry point, test
file, CI workflow, every user-facing string. The STIX tags and MISP objects this tool produces now
read `torikago:static` and `x_torikago_source_file`, because a producer should label its output
with its own name.

**The historical release notes keep the old name.** They are records of what was true when they
were written. Rewriting them to say Torikago would not be erasing a trace — it would be falsifying
a record. The README states plainly that this was formerly `triage-static`, so anyone arriving
from the old name can find their way.

`Nesarf` appears only in genuine project links to `Nanodesu!`, which are correct and stay.

## Version 1.0.0

A rename that settles the name is the moment the interface settles too. Nothing about the
behaviour changed: the same static analysis, the same refusal to execute, the same evidence
output — 124 tests, unchanged and green on Python 3.9, 3.12, 3.13 and 3.14.

```bash
pip install torikago                 # zero dependencies, by design
pip install torikago[pyinstaller]    # adds the PyInstaller unpacking half
torikago sample.exe
```
