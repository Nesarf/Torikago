# Triage 0.4.0

Language identification, prompted by reviewing curated open-source security tool lists.

## Why

Several of those lists were checked (secrss, eet-china, Tencent Cloud,
Pa55w0rd/Enterprise_-Security_tools and others). Two things came out of it.

**One useful pointer:** Microsoft's **RIFT**, for analysing **Rust** malware. Rust is on the
rise in malware precisely because its binaries are harder to read — mangled symbols, a large
runtime, scattered strings. The static half of that is cheap: the runtime is identifiable
without running anything.

**One confirmation of the field's shape:**

```
unknown file
  -> [static]   triage + Nanodesu! unpack      <- never executes; this tool
  -> [dynamic]  Cuckoo / CAPEv2 detonation     <- executes, in isolation
  -> [verdict]  ClamAV / YARA / reputation
  -> [intel]    MISP / Maltrail
```

Cuckoo Sandbox is the one tool in those lists that does a comparable job, and it does it the
opposite way: it *constructs an isolated environment and runs the malware*. Everything else
in the malware-adjacent categories is host-side or network-side detection (Wazuh, OSSEC,
whids, yulong-hids, Maltrail, Falco). This tool is the stage **before** detonation, and it
deliberately does not become a sandbox.

## What was added

* **Rust** — rustc markers, `core::panicking`, `RUST_BACKTRACE`, `/rustc/` paths
* **Go** — build ID, `runtime.gopanic`, `GOROOT`
* **C#/.NET** — decided structurally
* **AutoIt, Delphi/Pascal, Nim, Electron/Node, frozen Python**
* A Rust or Go binary whose symbols are gone is flagged: stripping is normal, and it also
  removes the analyst's best tool.

## Two corrections the .NET path needed

Both were caught by testing against real binaries rather than by reasoning:

1. Keying on `mscoree.dll` and `_CorExeMain` reported **kernel32.dll as .NET**. Those appear
   as mere references inside ordinary Win32 libraries.
2. Switching to a `BSJB` signature scan **still** misidentified kernel32.dll — a four-byte
   signature occurs by chance inside a large binary.

It is now decided by following the COM descriptor directory to the CLI header and then to
the metadata root. Verified against a real `dotnet build` output: `cb=72`, runtime 2.5,
metadata `v4.0.30319`.

Testing both directions is what makes the claim worth anything: the genuine assembly is
recognised, `kernel32.dll` and `mscoree.dll` are not, and a chance `BSJB` in the middle of a
file identifies nothing.

## Testing

69 tests (was 61), no samples required. Green on Python 3.9, 3.12, 3.13 and 3.14, on Linux
and Windows.

```bash
python -m unittest discover -s test -v
```
