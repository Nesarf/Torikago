# Triage 0.6.0

The tool was audited as an **attack surface**, not only used as a tool. The tool's whole job
is to open files someone else built, which means every input it reads is hostile by
definition.

## Resource bound added

A single analysis loads the whole file — hashes, strings and indicators all need all of it —
and peak memory measures at about **twice the file size**. Measured on a 300 MB input:

```
300 MB file → 600 MB peak memory, 62 seconds
```

The cost is linear, so an arbitrarily large file is a cheap way to hang an analysis machine.

| Control | Behaviour |
|---|---|
| default | refuse anything above **768 MB**, with a message that says why and what to do |
| `--max-bytes N` | raise the limit |
| `--force` | override entirely; the message warns that peak memory is about twice the file |

Refusal **exits** rather than returning, so a caller cannot miss it by ignoring a return
value. A directory scan already read only the first 4 MB of each file; that is unchanged.

## Repository hardening

* **CI actions pinned to commit SHAs**, not movable tags — a tag can be retagged upstream and
  a workflow referencing `@v4` would run whatever it then pointed at. `persist-credentials`
  is disabled and the workflow token is read-only.
* **`SECURITY.md`** states the safety property, how to report privately, the untrusted-input
  classes worth attacking (parser robustness, resource bounds, paths, subprocess handling,
  integration output), and — as importantly — **what the tool explicitly does not defend
  against**.
* **Private vulnerability reporting enabled.**

Every claim in `SECURITY.md` was checked against the code before it was written. The
resource-bound claim was **wrong when first drafted**, and checking it is how the missing
guard was found rather than shipped.

## Unchanged, and re-verified

The safety property: **the target is never executed**, on any path. ClamAV is the only
subprocess and is invoked as an argument list, never through a shell. No third-party
dependencies, no network access.

## Testing

87 tests (was 82), green on Python 3.9, 3.12, 3.13 and 3.14, on Linux and Windows.

```bash
python -m unittest discover -s test -v
```
