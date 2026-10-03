# Triage 0.7.0

Automate everything up to the step that must stay manual — and calibrate a gate on a corpus
rather than on an example.

## Staging a flagged file for a VM

```bash
python triage.py suspicious.exe --quarantine ./shuttle
python triage.py --quarantine-list ./shuttle
```

A flagged file is **copied** into the shuttle with its verdict and the evidence behind it, and
the output states the part that stays manual:

```
staged      : ./shuttle/20261003T215443_8f47b88ba3bf_invoice.png
   reason   : attention: injection triad (VirtualAlloc + WriteProcessMemory + CreateRemoteThread)
   Next step is manual, in an isolated environment:
     1. create a disposable VM with no network and no shared folders
     2. copy ONLY this file in, and treat the copy as hostile
     3. run it there and observe; do not run it on the host
     4. destroy the VM afterwards rather than reusing it
```

**The original is never moved and nothing is ever executed.** A tool that silently relocates a
file out of a directory someone is working in causes more problems than it solves; a tool that
detonates a sample by itself is a launcher, not a triage tool.

Three artifacts land in the shuttle:

| File | Purpose |
|---|---|
| `<timestamp>_<sha256[:12]>_<name>` | the copy; the hash in the name prevents silent collisions |
| the same name + `.why.json` | verdict, evidence, IOCs, and `executed: false` |
| `quarantine.jsonl` | append-only record for auditing |

## The gate is calibrated, not guessed

Measuring first showed that one of the signals is nearly universal: **258 of 260 real system
and application binaries report at least one "suspicious string"**. A keyword hit therefore
cannot decide that a file deserves a VM slot.

| Condition | Stages |
|---|---|
| destructive finding at high or critical severity | always — the one consequence that cannot be walked back |
| a high-confidence reason (injection triad, embedded boot sector, packing, high-entropy executable, a name contradicting its contents) | yes, and the reason is quoted so the operator can disagree |
| weak signals only | needs several together |
| a recognised wrapper | yes: it is a self-extracting program |
| nothing flagged | no — and it says how close it came |

## A real false positive found on the way

Import names were being carved out of machine code and matched as keywords, so a program whose
only notable import was `CreateFileW` reported a suspicious string containing the word
`file`. Strings are now extracted only from **long readable runs** — where a genuine string
lives, and where machine code is not.

Verified in both directions: a plain program reports **attention 0**, and a file carrying a URL
and a `Run` key still reports **4**.

## Testing

109 tests (was 90), green on Python 3.9, 3.12, 3.13 and 3.14, on Linux and Windows.

The tests that matter most here are the negative ones: the original is never moved, nothing is
executed, and a file with no signals is not staged at all.
