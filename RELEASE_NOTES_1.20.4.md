# Torikago 1.20.4

**What PyPI serves as 1.20.3 is not this tree.** Two commits landed after that tag and kept the
version number: the measured YARA draft, and the window. Everyone who installed rather than cloned
got neither, and nothing said so. This is the first release that carries them.

## The window

`--window` draws the human report in a window this tool paints itself — 716x385 at 2x — from
`panel.json` and `font.json` exported by Ichiwatashi and embedded here, each with a checksum
compared before anything is drawn. A shared layout is only shared if a modified copy can be told
apart from it.

**The lines are captured, not re-formatted.** They are the ones `print_human` prints, so the window
and the terminal cannot disagree about what a command said.

Three refusals, for three ways of asking for a window that could not open: an alternate mode
(`--scan`, `--corpus-write`, `--corpus-verify`, `--posture`, `--handoff`, and the rest — each returns
before a report exists), `--json`, and `--quiet`. Every one of them would have accepted the flag and
done nothing with it.

## Three things that only building it found

| what | how it showed |
|---|---|
| the wrap loop **hung** instead of failing | breaking inside the continuation indent cut the line at index 1 and looped there |
| a flat distribution carries modules, not files | `panel_window.py` and both JSON files were missing from the wheel while the build, `twine check` and the install all reported success |
| a dependency stays invisible until the flag is used | without `pillow` the flag raised `ModuleNotFoundError` out of the report path; it now names the reason and prints the report |

## `--neutralize`: producing the variant this tool could already recognise

Two bytes at offset zero become `XX`. The loader refuses the file and every byte the analysis reads
stays where it was. **Nothing inside is understood, removed or repaired**, and the record says that
before it says where the file is.

## The cross-tool contract agrees on facts, not on bytes

The old contract asked this tool's variant and its sibling's to share a sha256. The two semantics are
opposites: one yields a copy that cannot run by construction, the other a copy that runs with its
modules neutered. Demanding one hash would have meant demanding that one of them stop doing its own
job. What is held now is what both can honestly promise — both call the file `pe`, neither claims it
is a PyInstaller archive, and each states its own limit.

## Every ceiling is answerable

Nine caps used to live where their parsers sat. Read from outside, "512 functions" as a cap and
"512 functions" as a fact are the same sentence. `analysis_budget()` is one object, it travels in the
report as `budget`, and a test holds each field to the constant it names.

## The prose is checked against the code, in both directions

`PERSONA.md` ships with neither the wheel nor the sdist, so a line changed there and nowhere else
changes nothing for anybody who installed the tool — and nothing noticed. A table in §九 of that
document holds seven lines with a source column saying which are quoted and which are written from
its principles, and `test_persona_table.py` compares the table against the strings the code prints:
a line the code stopped saying fails, and so does one the document lost. The four beats are wired to
the four stages they describe, and the boundary sentence lives in one function so two paths cannot
word it differently.

## The corpus keeps both layers, and says which question a number answers

`manifest.jsonl` holds the ten diffable fields; `raw/<sha>.json` holds the scan row, which is the
re-measurable one and the only place `all_imports` survives. The summary counts rows by
`coverage_of` instead of adding complete and partial together, a schema generation is recorded so two
generations are not averaged as one, and a measurement that moved under a hash already in the
manifest is printed as the two events it is: the sample changed, or the detector did.

## YARA: measured, and optionally parsed

The draft rule measures each candidate string's selectivity over a benign corpus and records the
observed hit count in the rule's `meta`. The `yara` extra compiles the rule and **never matches it**;
when the parser is absent the report says so rather than implying the rule is sound.

## The release pipeline was checking less than it looked

The wheel check named two files, and this release adds three. It now takes the module names plus the
two data files by suffix, and fails when any of them is missing. A new step installs the built wheel
into a clean environment and **renders the panel from a directory that is not the checkout**: the
`<prefix>/share/torikago` branch is the one a clone never exercises and the only one a `pip install`
user has.

## Testing

**491 tests** (was 389 at 1.20.3), green on Python 3.9, 3.12, 3.13 and 3.14, with 20 skipped where a
fixture cannot be built on the host. The release itself was verified the way this release asks others
to verify it: the wheel was built, installed into an empty virtual environment, and asked to paint
its panel from a directory that is not the repository — 1432x770 pixels, from
`<venv>/share/torikago`.
