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
| **Language runtime** | Names what built it: Rust (rustc markers), Go (build ID, runtime symbols), C#/.NET (decided structurally — COM descriptor → CLI header → `BSJB` metadata root, not by scanning for a four-byte signature), AutoIt, Delphi, Nim, Electron/Node, frozen Python. A Rust or Go binary whose symbols are gone is flagged, because stripping is normal and also removes the analyst's best tool. |
| **Wrappers** | PyInstaller cookies are read properly (python version, library, PYZ presence) and routed to `nanodesu.py` for unpacking. NSIS, Inno Setup, InstallShield, AutoIt, Nuitka and others are named, not pretended. |
| **Indicators** | URLs, IPs, domains, mail addresses, registry `Run` keys, services, scheduled tasks, PowerShell/cmd lines, named pipes, Defender exclusions. Documentation hosts and RFC1918 ranges are filtered; a version string like `6.0.0.0` is deliberately kept, because a false positive you can see beats one hidden from you. |
| **Strings** | ASCII and UTF-16LE (wide strings matter: a .NET or wide-char sample hides there), plus base64 blobs with their decoded heads, flagged when they decode to a PE. |
| **Embedded images** | PE files inside the file, located by header, offered for carving. |
| **Unpack (in-process)** | `--unpack` calls [Nanodesu!](https://github.com/Nesarf/Nanodesu) as a module — no subprocess, no shell — to actually unpack a PyInstaller archive, then triages the executables it produced. Set `NANODESU_PATH` if it is not in a known location. |
| **Batch scan** | `--scan DIR` triages every file in a directory and reports only the ones that stand out, ranked. On a real 200-file Python distribution it reports **0**; on a file carrying the injection triad it reports that file first. |
| **Verdict** | `--scan-av` asks ClamAV; `--feed misp\|stix\|both` writes an importable MISP event and/or a STIX 2.1 bundle. |
| **Report** | `report.json` (machine-readable), a human summary, and `rule.yar` labelled `UNREVIEWED`. |

## Install

No third-party dependencies, Python 3.9+.

```bash
pip install .                 # provides the `triage` command
python triage.py --help       # or run it directly
```

For PyInstaller targets, either install the extra — `pip install triage-static[pyinstaller]` —
or put `nanodesu.py` somewhere `triage` can find it:

1. `NANODESU_PATH`, pointing at a file or a directory
2. an installed `nanodesu` module
3. `nanodesu.py` next to `triage`, or one directory up

`triage` itself declares **no dependencies**, deliberately: it is meant to run on a machine you
do not trust, so every dependency it does not have is one less thing a reader has to audit. The
PyInstaller half is an extra rather than a requirement for that reason.

If it is absent, the failure says so and names the fix rather than leaving you to work it out:

```
Nanodesu! was not found, so this PyInstaller archive cannot be unpacked.
Install it with: pip install nanodesu   (or set NANODESU_PATH to a nanodesu.py checkout)
```

It calls Nanodesu! through its library API when that is available, and falls back to the CLI for
versions before 1.3. Either way there is no subprocess and no shell in the middle.

## Usage

```bash
python triage.py suspicious.exe
python triage.py suspicious.exe -o ./out        # also writes report.json and rule.yar
python triage.py suspicious.exe --json          # machine-readable on stdout
python triage.py suspicious.exe --unpack        # actually unpack it, then triage the inside
python triage.py --scan ./downloads             # which of these files deserves my time?
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

## Handing the evidence to something that decides

The durable division of labour: this tool unpacks and reports; something with maintained
signatures makes the call. Two targets cover most of the world, and both are read-only —
a scanner *reading* a file is not the file running, which is what lets the "never execute"
guarantee survive integration.

### ClamAV

```bash
python triage.py suspicious.exe --scan-av --unpack
```

`--scan-av` runs `clamscan` over the sample and anything the unpack produced, and reports
signature verdicts. It finds ClamAV on `PATH`, in the usual install locations, or via
`CLAMSCAN_PATH`. **If ClamAV is not installed, it says so and moves on** — a missing
scanner never turns into a broken feature.

### MISP and STIX

```bash
python triage.py suspicious.exe --feed both -o ./out
```

| File | Format | Purpose |
|---|---|---|
| `event.xml` | MISP event XML | import into MISP; hashes are `to_ids`, network indicators land in *Network activity*, persistence strings in *Artifacts dropped* |
| `stix.json` | STIX 2.1 bundle | for a TIP or MISP's STIX importer |

The MISP event is written as `published=false` on purpose: whether your indicators become
shared intelligence is a decision about your own data, not one a triage tool should make
for you.

## Signals are graded, and the grading is the point

An import is not a verdict. `IsDebuggerPresent` is how CPython implements `sys.gettrace`;
`GetProcAddress` is how every delay-load stub works; `VirtualAlloc` is used by any JIT. A
scanner that flags those produces a list nobody reads.

So attention is raised by:

* the **injection triad** — `VirtualAlloc` + `WriteProcessMemory` + `CreateRemoteThread`
  together, which is what process injection actually looks like
* a **packer verdict** built from section names, marker scans, or a genuinely empty import
  table — not from "few imports", and not for an API-set forwarder
  (`api-ms-win-*`), which has almost no imports by design
* a **high-entropy executable section**
* a **name that contradicts the contents**

Weak signals are recorded (`noted_imports`) without raising attention.

This is a calibration, not a heuristic: on a real 200-file Python distribution the scan
reports **zero** interesting files, and the same build of the tool still flags a synthetic
trojan carrying the injection triad and a misnamed extension. Both directions are tested.

## Testing

```bash
python -m unittest discover -s test -v
```

69 tests, no samples required: every fixture is a small synthetic file, including a
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

## Where this sits, and where it does not

Several curated "top open-source security tools" lists were reviewed while building this
(secrss, eet-china, Tencent Cloud, Pa55w0rd/Enterprise_-Security_tools, and others). Across
all of them, **one tool does the same job and it works the opposite way**: Cuckoo Sandbox
("constructs an isolated environment to *run* the malware and generates a behaviour log").
Everything else in the malware-adjacent categories is host-side or network-side detection —
Wazuh, OSSEC, whids, yulong-hids, Maltrail, Falco.

That is not a gap in those lists, it is the shape of the field:

```
unknown file
  -> [static]   triage + Nanodesu! unpack      <- never executes; this tool
  -> [dynamic]  Cuckoo / CAPEv2 detonation     <- executes, in isolation
  -> [verdict]  ClamAV / YARA / reputation
  -> [intel]    MISP / Maltrail
```

This tool is the stage *before* detonation: see what is inside safely, then decide whether
it is worth a sandbox slot. It deliberately does **not** become a sandbox, because that
requires running the sample, which is the one thing it will not do.

One useful pointer found in those lists: Microsoft's **RIFT**, for analysing **Rust**
malware. That is why language identification was added here — it is cheap, static, and Rust
binaries are harder to read on purpose.

## Staging a flagged file for a VM

```bash
python triage.py suspicious.exe --quarantine ./shuttle
python triage.py --quarantine-list ./shuttle
```

A flagged file is **copied** into the shuttle directory with its verdict and the evidence
that produced it, and the output states the part that stays manual. Nothing is executed and
nothing is moved: the original stays where you can see it.

```
staged      : ./shuttle/20261003T215443_8f47b88ba3bf_invoice.png
   reason   : attention: injection triad (VirtualAlloc + WriteProcessMemory + CreateRemoteThread)
   Next step is manual, in an isolated environment:
     1. create a disposable VM with no network and no shared folders
     2. copy ONLY this file in, and treat the copy as hostile
     3. run it there and observe; do not run it on the host
     4. destroy the VM afterwards rather than reusing it
```

The reasoning: signature-based detection only recognises what it has already seen, and a
one-shot destroyer may never be seen twice. Staging puts a record and a copy in the
operator's hand **before** anything runs — and detonation stays a human decision, because the
alternative is a tool that launches malware by itself.

Three files land in the shuttle, and the name carries the hash so two files cannot silently
collide:

| File | Purpose |
|---|---|
| `<timestamp>_<sha256[:12]>_<name>` | the copy |
| the same name + `.why.json` | verdict, evidence, IOCs, and `executed: false` |
| `quarantine.jsonl` | append-only record for auditing |

### What stages, and what does not

Calibrated on a corpus rather than guessed, because one signal turned out to be nearly
universal: **258 of 260 real system and application binaries report at least one "suspicious
string"**, so a keyword hit cannot decide anything on its own.

| Condition | Stages |
|---|---|
| destructive finding at high or critical severity | always |
| a high-confidence reason (injection triad, embedded boot sector, packing, high-entropy executable, a name that contradicts its contents) | yes, and the reason is quoted |
| weak signals only | needs several (`--quarantine-min`, default 1 for the strong gate) |
| a recognised wrapper | yes: it is a self-extracting program |
| nothing flagged | no — `nothing flagged above the staging threshold (weak signals: N)` |

## Hardened as an attack surface, not only used as a tool

A tool that opens untrusted files is itself an attack surface, so it was audited as one.

| Area | State |
|---|---|
| **Never executes the target** | no `CreateProcess` anywhere, and no flag that adds one |
| **Resource bounds** | a single analysis loads the whole file, so a size guard refuses anything above **768 MB** by default (peak memory runs about twice the file size — a 300 MB file measured 600 MB and 62 seconds). `--max-bytes` raises it, `--force` overrides it, both explicit. Inside a directory scan only the first **4 MB** of each file is read. |
| **Subprocess** | ClamAV is invoked as an argument list, never through a shell. It is the only subprocess in the tool. |
| **Integration output** | the MISP event and STIX bundle embed attacker-controlled strings and are emitted through the standard serialisers, not by string concatenation |
| **Paths** | output paths come from the tool's own control, never from a name inside a sample — the one place a sample's names become paths is the unpack step, delegated to Nanodesu, where a path traversal bug was found and fixed in 1.1.0 |
| **Supply chain** | no third-party dependencies, no network access, CI actions pinned to commit SHAs, read-only CI token |

`SECURITY.md` states all of this, including what the tool explicitly does **not** defend
against, and private vulnerability reporting is enabled on the repository.

## What was deliberately left out

* **Unpacking runtime packers.** Needs execution.
* **Network lookups.** No VirusTotal, no hash reputation, no telemetry. The tool works
  on an air-gapped machine by design.
* **A detection engine.** See the safety model above. The signature engine is ClamAV; the
  sharing formats are MISP and STIX. This tool's job is to make the sample legible to them.
* **Auto-removal of anything.** Left to engines that maintain signatures and to the
  operator who knows the machine.

## License

MIT.
