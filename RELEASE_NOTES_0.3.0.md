# Triage 0.3.0

The tool unpacked and reported but left the calling to the reader. This release closes that:
it can ask a signature engine for a verdict, and it can write intelligence in formats
something else can import.

All three additions are read-only. A scanner **reading** a file is not the file running,
which is what lets the "never execute the target" guarantee survive integration.

## ClamAV

```bash
python triage.py suspicious.exe --scan-av --unpack
```

Runs `clamscan` over the sample and everything the unpack produced, and reports signature
verdicts. It finds the binary on `PATH`, in the usual install locations, or via
`CLAMSCAN_PATH`.

**If ClamAV is not installed, it says so and moves on** — a missing scanner must never turn
into a broken feature. That path is tested.

Verdict lines are matched against the files we actually asked about, because a Windows path
contains colons of its own and a stray line ending in `FOUND` must not become a verdict.
The parser is tested against a stand-in that prints ClamAV's documented format.

## MISP and STIX

```bash
python triage.py suspicious.exe --feed both -o ./out
```

| File | Format | Notes |
|---|---|---|
| `event.xml` | MISP event | hashes are `to_ids`; network indicators land in *Network activity*; persistence strings in *Artifacts dropped* |
| `stix.json` | STIX 2.1 bundle | file object with all three hashes, one indicator per observable, stable ids |

Two deliberate choices:

* **XML for MISP**, not JSON. XML is what MISP itself emits for an event; a JSON blob that
  merely resembles one tends to import as an empty event and waste an analyst's time.
* **`published=false`.** Whether your indicators become shared intelligence is a decision
  about your own data, not one a triage tool should make for you.

## Also fixed

An unrequested `--unpack` was reported as a failure. It now says nothing.

## Testing

59 tests (was 41), no samples required. Green on Python 3.9, 3.12, 3.13 and 3.14, on Linux
and Windows.

```bash
python -m unittest discover -s test -v
```
