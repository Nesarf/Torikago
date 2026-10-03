# Triage

Static triage for an unknown executable. It tells you what a file really is, whether it
is packed, what is inside it, which indicators it carries, and hands you a draft YARA
rule — **without ever running it**.

The name is provisional; the project follows the same naming habit as `Nanodesu!` and
`Volcano Separator`, and is easy to rename.

## The safety model, stated up front

**It never executes the target.** Not once, not on any code path. There is no
`CreateProcess` call in this tool, and there is no flag that adds one.

That is not a limitation, it is the entire safety argument. Unpacking is a byte-level
reading problem: a sample cannot act on a machine it is never allowed to run on. This is
a stronger guarantee than any user-mode sandbox, because it does not depend on catching
the sample's behaviour — there is no behaviour to catch.

Three things this tool therefore does **not** claim:

1. **It is not a sandbox.** A user-mode process cannot contain a kernel-level or
   administrator-level adversary. If a sample must be *run* to be understood, do it in a
   disposable VM with no network and no shared folders. `triage` prints that instruction
   and refuses to take that step itself.
2. **It is not an antivirus.** Detection means fixing a definition of "malicious", and
   any definition can be bypassed — the reference implementations get bypass tools written
   against them within days. The durable division of labour is: *this tool unpacks and
   reports; an engine with maintained signatures decides.*
3. **It cannot defeat a runtime packer.** Themida, VMProtect and custom stubs only reveal
   themselves by running. `triage` names them, records the evidence, and stops.

## What it does

| Stage | Detail |
|---|---|
| **Identify** | magic bytes first, because extensions lie. A `invoice.png` that is really a PE is reported as such. |
| **PE structure** | machine, section table, per-section entropy, writable/executable flags, data directories (a TLS callback runs before the entry point and is called out). |
| **Imports** | full import table with per-DLL function lists. Dynamic resolution, injection and anti-debug APIs are flagged, and their weight is stated honestly: on their own they are ordinary program behaviour. |
| **Packer** | UPX (section pair and marker scan), Themida, VMProtect, ASPack, MPRESS, PECompact and friends, plus generic evidence (all sections high-entropy, a near-empty import table). |
| **Wrappers** | PyInstaller cookies are read properly (python version, library, PYZ presence) and routed to `nanodesu.py` for unpacking. NSIS, Inno Setup, InstallShield, AutoIt, Nuitka and others are named, not pretended. |
| **Indicators** | URLs, IPs, domains, mail addresses, registry `Run` keys, services, scheduled tasks, PowerShell/cmd lines, named pipes, Defender exclusions. Documentation hosts and RFC1918 ranges are filtered; a version string like `6.0.0.0` is deliberately kept, because a false positive you can see beats one hidden from you. |
| **Strings** | ASCII and UTF-16LE (wide strings matter: a .NET or wide-char sample hides there), plus base64 blobs with their decoded heads, flagged when they decode to a PE. |
| **Embedded images** | PE files inside the file, located by header, offered for carving. |
| **Report** | `report.json` (machine-readable), a human summary, and `rule.yar` labelled `UNREVIEWED`. |

## Install

No third-party dependencies, Python 3.9+.

```bash
pip install .                 # provides the `triage` command
python triage.py --help       # or run it directly
```

For PyInstaller targets, put `nanodesu.py` on the same machine — `triage` detects the
archive and tells you the exact command to unpack it.

## Usage

```bash
python triage.py suspicious.exe
python triage.py suspicious.exe -o ./out        # also writes report.json and rule.yar
python triage.py suspicious.exe --json          # machine-readable on stdout
```

Example summary:

```
identified  : PE executable (DOS/PE) (pe)
pe          : x64, 7 sections, entry RVA 0xdcf0
    .text      210432 raw  entropy  6.49  X-
    .rsrc       61440 raw  entropy  7.35  --
wrapper     : PyInstaller (python 3.12, python312.dll)
packer      : none
imports     : 132 functions across 3 DLL(s)
attention   : uses APIs worth noting, though common in ordinary programs: ...
next steps  :
    [safe (no execution)] unpack the PyInstaller archive
        python nanodesu.py extract <file> -o <out> --pyc
executed    : no (never)
```

Every entry in `next steps` is marked either `safe (no execution)` or
`needs execution`; anything in the second category comes with the instruction to do it in
a VM, and this tool does not do it for you.

## Testing

```bash
python -m unittest discover -s test -v
```

21 tests, no samples required: every fixture is a small synthetic file, including a
hand-assembled PE. A suite that needs real malware is a suite that stops being run.

The PE parser is additionally validated against real binaries, which is the baseline that
says the fixtures are not just self-consistent: `kernel32.dll` → 104 DLLs / 1274
functions, `advapi32.dll` → 35 / 656, `shell32.dll` → 79 / 1087.

## Verified on

* A PyInstaller onefile build (windows x64) — identified, wrapper read correctly,
  unpack routed to `nanodesu.py`.
* `7zr.exe`, `winmm.dll`, `kernel32.dll`, `advapi32.dll`, `shell32.dll` — structure and
  import tables parsed, `packer: none` for unpacked binaries (no false packer verdicts).
* A `.png`-named PE — the naming contradiction is reported.

## What was deliberately left out

* **Unpacking runtime packers.** Needs execution.
* **Network lookups.** No VirusTotal, no hash reputation, no telemetry. The tool works
  on an air-gapped machine by design.
* **A detection engine.** See the safety model above.
* **Auto-removal of anything.** Left to engines that maintain signatures and to the
  operator who knows the machine.

## License

MIT.
