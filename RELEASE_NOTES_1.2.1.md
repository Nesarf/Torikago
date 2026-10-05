# Torikago 1.2.1

A critical false positive removed, found by sweeping 108 real binaries.

## What the sweep was for

Every calibration before this one used two samples and a system directory. This swept **108
binaries** up to two levels deep on a real drive — games, editors, a remote-desktop client,
installers — which is the population a detector actually has to survive.

## The false positive

An ordinary 51 MB remote-desktop DLL (`ToDesk\zrtc.dll`) was reported as carrying **two embedded
boot sectors, severity critical.**

The bytes said otherwise:

```
offset 0x400624, bytes at slot 510:  e8 55 aa   <- "call rel32" with 55 aa as its immediate
partition table area:               code, not entries
55 AA occurrences in the file:      98
of which at slot 510 of a 512 block: 0
```

It was not a boot sector. It was x86 code that happened to contain the byte pair.

## Why the old rule missed it

It looked for **any** slot that validated and stopped there. So a window whose first slot happened
to carry a known partition type and plausible geometry was a hit, regardless of what the other
three slots held.

A real partition table cannot look like that. An MBR with one partition has **three zeroed slots**,
and the slots sit on a 16-byte grid that arbitrary code does not respect.

The rule now requires **every** slot to be either a well-formed partition or a well-formed empty
slot, and at least one to be a partition.

## Measured on both sides before adopting it

| | before | after |
|---|---|---|
| five genuine boot sectors (CHS variants, four partition types) | detected | **all still detected** |
| the two false positives in `zrtc.dll` | reported **critical** | **not reported** |
| 4 MB of random bytes | 0 | 0 |

**A tightening that also silenced the true positives would have passed a false-positive test
perfectly.** So the regression test asserts both directions: a lookalike window shaped like the real
one must not fire, and one-partition and two-partition boot sectors must.

## Everything else held up

Of **101** binaries scanned:

| | result |
|---|---|
| packer verdict "not packed" | **98** (the other three: two ASPack, one "multiple") |
| critical destructive findings, after the fix | **0** |
| debug information present | 65 — of which **40 carry a full build-machine path** |

That last number is the point of the feature: 40 of 101 have a real layout disclosure, so the
signal is selective rather than noise.

The one remaining destructive finding is `ToDesk.exe` itself, severity **medium**, and its evidence
is accurate — a remote-desktop client really does hook input, use a crypto RNG, and not write to
disk. A finding that is true about a program doing what it advertises is not a false positive.

## Testing

**149 tests** (was 145), green on Python 3.9, 3.12, 3.13 and 3.14.
