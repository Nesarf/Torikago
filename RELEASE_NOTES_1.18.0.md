# Torikago 1.18.0

Two searches stopped at a fixed offset, and a persona that has to match the behaviour.

## Scans that read as absence

The boot-sector scan stopped at **8 MB** and the runtime-marker search at **6 MB**. Evidence past
either point produced no finding — and **"not found" and "not there" looked identical**, which is the
single distinction this tool exists to keep.

Both now read the whole file, and both regressions are verified against the old code: a 512-byte MBR
shape placed at 9 MB and a runtime marker at 7 MB each fail to be found by the previous version.

The partition-table validator is what makes a full scan affordable here — it is the check that
stopped a 51 MB remote-desktop DLL being reported as carrying boot code, **twice** — and its
strictness is why two rounds of the fixture were rejected before its requirements were read out of
the validator instead of assumed.

The raw-disk pattern scan stopped at **4 MB per section**, which is the same failure in a third
place. It now reads each section in full, and where a shortfall remains it is **reported as a
finding** rather than left implicit.

## An independent persona has to match its behaviour

Both Nanodesu and Torikago were settled as **independent personas**, which — per the rule already
recorded for this work — means **the text and the behaviour must agree across layers, because
behavioural deviation is the persona collapsing.**

So the behaviour was audited before anything was written:

| what she does | what actually happens |
|---|---|
| `sample_fetch` | asks the system's protection, via PowerShell |
| `product_registration` | asks the Security Center, via WMI |
| `security_posture` | reads Defender's settings and history |
| `quarantine_copy` | the only place this tool writes a file — one copy |

**Nothing executes the target.** Every subprocess is a question put to something else — which is
exactly her stated position: she does not believe in any god, and when she quotes one she says whose
words they are. The report already says it in code: *"These are the engines' verdicts, not this
tool's."*

## `CHARACTER_AMARYLLIS.md` and `PERSONA.nsfw.md`

Her sheet, and her adult register kept separate for the reason Nanodesu established: a main file
carrying "she can be lewd" hands that to people who asked for a safety tool and never asked for this.

**The tidy mapping had to be rejected.** Lilith's line rests on *"she does not need to bite to know"*,
where biting is unpacking and knowing is reporting. Carried to Torikago it comes apart — this tool has
no equivalent of taking — and a succubus who feeds maps onto the **acquisition** subsystem, not the
triage engine. Writing it into the engine would be a false statement about the tool.

That mismatch became the design. Lilith's appeal is being able to and not needing to; **Amaryllis is
bound** — she could do a great deal and does one thing. Her chain is written on the sheet itself as
both instrument and restraint, which is the architecture: a core that only looks, and a research layer
that fetches. Her third act is not completion but **handing over**, which is what `--handoff` is.

## Also recorded: a persona does not ship

Measured — Nanodesu 1.7.0's sdist contains no `PERSONA.md`. Only `README.md` and `LICENSE` are
package-data, and `py-modules` decides what code goes out. So the design documents stay in the
repository while the executable lines live in a dictionary in the code, which means **editing the
design changes nothing about behaviour and nothing will report it.** The two will drift, always with
code behind design, because writing design is easier. Noted so the wiring copies rather than
references, and asserts agreement.

## Testing

**364 tests** (was 360), green on Python 3.9, 3.12, 3.13 and 3.14, on two interpreters here with and
without `pyzipper`. Four new, two of which are verified to fail against the previous code.
