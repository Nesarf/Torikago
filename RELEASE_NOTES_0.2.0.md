# Triage 0.2.0

Three changes, in the order they matter: it now actually unpacks, it can scan a whole
directory, and its signals are graded — which is what makes it usable rather than noisy.

## Unpack for real

The tool used to print the command to unpack a PyInstaller archive and stop there. Now
`--unpack` loads [Nanodesu!](https://github.com/Nesarf/Nanodesu) as a module — no
subprocess, no shell, so there is exactly one implementation of the archive format — and
unpacks the archive, then triages the executables that came out of it.

Set `NANODESU_PATH` to a checkout if it is not in a known place. Without it, the step
reports a hint rather than failing.

Still never executes the target: every path is a byte-level decode, and `executed: false`
is recorded in the result so no caller has to assume it.

## Batch scan

`--scan DIR` answers the question a directory of unknown files actually poses: *which of
these deserves my time?*

Files are ranked by attention, and a clean directory says `nothing flagged` instead of
printing two hundred rows. Only the head of each file is read, so pointing it at a large
tree stays cheap.

## Signals are graded, and the grading is the point

A first run against a real 200-file Python distribution reported 19 interesting files.
All 19 were false: every CPython extension imports `IsDebuggerPresent` — that is how
`sys.gettrace` works — and every `api-ms-win-*` forwarder has almost no imports by design.

Fixes:

* The **injection triad** (`VirtualAlloc` + `WriteProcessMemory` + `CreateRemoteThread`)
  replaced the tier-based import check, and is judged on the full import set, because
  `VirtualAlloc` is ordinary on its own but is one third of the pattern.
* `IsDebuggerPresent`, `GetProcAddress`, `VirtualProtect` and `NtQueryInformationProcess`
  moved to a *noted* tier: recorded, without raising attention.
* "Few imports" no longer implies packing. Only a genuinely empty import table does.
* API-set forwarders and small exporting images are not reported as packed.
* `.pyd`, `.so`, `.node`, `.dylib` and friends are treated as conventional binary names,
  not as disguises.

## Calibrated in both directions, and tested that way

| Input | Result |
|---|---|
| A real 200-file Python distribution | **0** files flagged |
| A synthetic trojan with the injection triad | flagged first, `injection triad (…)` |
| A synthetic PE named `.png` | flagged, `named .png but is a PE executable` |

A tool that cries wolf on every system DLL is not used twice, so the quiet direction is
tested as carefully as the loud one.

## Testing

41 tests (was 21), no samples required — every fixture is synthetic, including a
hand-assembled PE. Green on Python 3.9, 3.12, 3.13 and 3.14, on Linux and Windows.

```bash
python -m unittest discover -s test -v
```
