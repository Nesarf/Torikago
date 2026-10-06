# Torikago 1.20.3

The gate now judges capability before harm, and capability has a definition of its own.

## What "strong" means, kept apart from "harmful"

The tool goes after strong things, and the previous ordering could not express that: it led with a
destructive finding at high severity, so **a file carrying one destructive keyword outranked a deeply
layered one that took real work to build.**

Capability is now measured from complexity and reach, using evidence the report already carries:

| signal | what it says |
|---|---|
| a recognised wrapper, **by name** | work went into the packaging |
| additional wrapper markers | more than one layer |
| embedded executables | it carries other programs inside it |
| an unpack step that needs execution | a static read cannot reach the end of it |
| branches, imported-function volume, section count | how much code is there |

It returns `none` / `some` / `high` **with its reasons attached**, because this tool refuses to print a
score without its evidence anywhere else and the gate is not an exception — the operator can disagree
with *"PyInstaller wrapper"*, not with *"present"*.

## The order, and why harm is second rather than removed

**Capability first, harmfulness second, stubbornness third.**

**Harm is intent and capability is fact, and this tool deals in facts** — that is the whole reason it
refuses to reach a verdict. But harm is not removed: **an irreversible consequence still stops
everything**, because that is the one thing worth stopping for regardless of how strong anything is.

**Stubbornness is last on purpose.** Deciding to look at something because it is difficult, rather than
because it is strong or dangerous, is the wrong reason.

## The mistake the new tests pin

`destructive` is deliberately **not** a capability signal. Folding it in is exactly what the old
ordering did — rank by destructiveness and call the result a judgement of the target — and a test now
asserts that a critical destructive finding leaves the capability level at `none`.

## A regression an existing test caught

The first version printed `wrapper: present` for a wrapper, because it handled a string and the report
carries a mapping whose inner key holds the name. **Losing "PyInstaller" loses the only part of the
reason a person can check.**

## Testing

**389 tests** (was 381), green on Python 3.9, 3.12, 3.13 and 3.14. Eight new: capability is named first
and quoted, harm still stops everything, difficulty alone is the weakest reason, a quiet report does not
stage, destructiveness is not capability, a wrapper keeps its name, three signals read as high, and the
judgement is recorded on the report so a reader sees what the gate thought separately from what it did.
