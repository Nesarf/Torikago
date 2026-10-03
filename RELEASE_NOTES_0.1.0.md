# Triage 0.1.0

First release. Static triage for a file of unknown provenance: it identifies, unpacks and
reports, so that an engine with maintained signatures can make the call.

## The one rule

**The target is never executed.** Not on any code path; there is no `CreateProcess` call
in this tool and no flag that adds one.

Unpacking is a byte-level reading problem, so a sample that is never allowed to run cannot
act. That is a stronger guarantee than a user-mode sandbox, because it does not depend on
catching behaviour — there is no behaviour to catch.

## What it reports

* **Identification by magic bytes**, because extensions lie: a `.png` that is really a PE
  is reported as such.
* **PE structure** — machine, sections, per-section entropy, executable/writable flags,
  data directories. A TLS callback (which runs before the entry point) is called out.
* **Import table** with per-DLL function lists. Dynamic resolution, injection and
  anti-debug APIs are named, and their weight stated honestly: on their own they are
  ordinary program behaviour, and only the combination with packing or an embedded image
  is ranked high.
* **Packer identification** — UPX (section pair *and* marker scan), Themida, VMProtect,
  ASPack, MPRESS, PECompact, plus generic evidence such as all sections high-entropy or a
  near-empty import table.
* **Wrappers** — PyInstaller cookies are read properly (python version, library, PYZ
  presence) and routed to `nanodesu.py` for unpacking. NSIS, Inno Setup, InstallShield,
  AutoIt and Nuitka are named, never pretended.
* **Indicators** — URLs, IPs, domains, mail addresses, registry `Run` keys, services,
  scheduled tasks, PowerShell/cmd lines, named pipes, Defender exclusion paths.
  Documentation hosts and RFC1918 ranges are filtered; a version string like `6.0.0.0` is
  kept deliberately, because a false positive you can see beats one hidden from you.
* **Strings** in ASCII and UTF-16LE, base64 blobs with decoded heads (flagged when they
  decode to a PE), and embedded PE images located by header for carving.
* **Output**: `report.json`, a human summary, and a YARA draft labelled `UNREVIEWED`.

Every entry in the suggested next steps is marked either `safe (no execution)` or
`needs execution`. Anything in the second category comes with the instruction to do it in
a disposable VM, and this tool does not do it for you.

## What it refuses to do

* **Unpack runtime packers.** Themida, VMProtect and custom stubs only reveal themselves
  by running. It names them, records the evidence, and stops.
* **Detect or remove anything.** Detection means fixing a definition of "malicious", and
  any definition can be bypassed — bypass tools for reference engines appear within days.
  The durable division of labour is: this tool unpacks and reports, an engine with
  maintained signatures decides.
* **Talk to the network.** No reputation lookups, no telemetry. It works on an air-gapped
  machine by design.
* **Contain an adversary.** A user-mode process cannot contain a kernel-level attacker.
  Real isolation comes from a VM, and this tool tells you so rather than implying
  otherwise.

## Testing

21 tests, no samples required — every fixture is a small synthetic file, including a
hand-assembled PE. A suite that needs real malware is a suite that stops being run.

```bash
python -m unittest discover -s test -v
```

Green on Python 3.9, 3.12, 3.13 and 3.14.

The PE parser is additionally validated against real system binaries, which is the
baseline that says the fixtures are not merely self-consistent:

| Binary | DLLs | Imported functions |
|---|---|---|
| `kernel32.dll` | 104 | 1274 |
| `advapi32.dll` | 35 | 656 |
| `shell32.dll` | 79 | 1087 |

## Verified on

* A PyInstaller onefile build (Windows x64) — identified, wrapper read correctly, unpack
  routed to `nanodesu.py`.
* `7zr.exe`, `winmm.dll` and the three system DLLs above — structure and import tables
  parsed, `packer: none` for unpacked binaries (no false packer verdicts).
* A synthetic trojan-shaped file — misnamed extension, injection imports, a registry `Run`
  key, a hidden PowerShell line, a Defender exclusion and a C2 address all reported in one
  pass.

## Install

No third-party dependencies, Python 3.9+.

```bash
pip install .
python triage.py suspicious.exe
```
