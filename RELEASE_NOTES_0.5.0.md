# Triage 0.5.0

A whole class of threat was missing from the report: **files that destroy rather than
infect**.

## The gap

An MBR overwriter needs a raw write to a physical drive and usually carries its own boot
sector. None of that appeared anywhere in the import tiers, so a one-shot destroyer — the
kind of program that wrecks one machine and never spreads, which is exactly why it never
earns an antivirus definition — was reported as an ordinary executable.

## The new tier

Judged on structural evidence, not on imports:

| Finding | Severity |
|---|---|
| Embedded boot sector, verified against the partition-table format | **critical** |
| Raw disk or volume device paths | medium |
| Destructive terminology | low |

The boot sector check verifies the actual format: four 16-byte entries, status `0x00`/`0x80`,
a partition type the format defines, geometry in range, and bounded LBA and sector count.

## Calibrated in both directions, because one direction proves nothing

Three corrections, all from measuring:

**False positives.** The first version keyed on `DeviceIoControl` + `WriteFile` and flagged
**five benign binaries out of seven** — including this tool's own executable and
`kernel32.dll`. Both are ordinary imports that most Windows binaries carry. That rule is gone.

**A three-byte marker is not evidence.** A substring test for `MBR` flagged a Python extension
module, because unicode character data contains the word **UMBRELLA**.

**False negatives.** Tightening the boot-sector check then silenced it on genuine MBRs, and
an off-by-one in the scan loop (`len - 512` instead of `len - 511`) made a 512-byte boot
sector at offset 0 impossible to find at all.

Final calibration:

| Input | Result |
|---|---|
| Synthetic destroyer (MBR + raw device + terminology) | reported **critical** |
| 260 real system and application binaries | **0** findings |

## Testing

82 tests (was 69), green on Python 3.9, 3.12, 3.13 and 3.14, on Linux and Windows.

```bash
python -m unittest discover -s test -v
```
