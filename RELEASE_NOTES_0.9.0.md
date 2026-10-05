# Triage 0.9.0

The PyInstaller half is now declared as an extra, and the tool stopped shipping a directory layout.

## An external review, and the one recommendation worth declining

A review concluded that `triage` and `Nanodesu!` are correctly two projects with an adapter
between them, and should stay separate. Verification confirmed it: `unpack.py` is 132 lines with
no parser in it, and the format work lives where it belongs.

Its own recommendation — make `nanodesu` a hard dependency — is the part to decline, and the
reason is the reason this tool exists. **`triage` declares no dependencies deliberately:** it is
meant to run on a machine you do not control, so every dependency it does not have is one less
thing a reader has to audit. A tool you hand to someone during an incident should not need a
package tree. So the PyInstaller half is an optional extra:

```bash
pip install triage-static[pyinstaller]
```

and the base install stays empty. The metadata now says so instead of leaving it to prose.

## Discovery was carrying a directory layout, in a public repository

The candidate list held two absolute paths on the author's own disk — one of which named a
personal workspace directory. They could only ever work on one machine, and they published
somebody's filesystem to everyone who read the source.

Replaced with a real chain:

1. `NANODESU_PATH` — an explicit file or directory
2. an installed `nanodesu` module
3. `nanodesu.py` next to `triage`, or one directory up

An explicit `NANODESU_PATH` that does not resolve is now an **error** rather than a silent
fall-through to a guess: using a different build than the caller named is exactly the confusion
that function exists to prevent. A test asserts that no drive-letter or home-directory path
appears in the module, so this cannot come back in another form.

The same class of leak was swept out of `triage.py`, where an advice string pointed at a specific
`7zr.exe` on one machine.

## "Not found" now names the fix

Two different absences have two different remedies, and they no longer share a message:

```
Nanodesu! was not found, so this PyInstaller archive cannot be unpacked.
Install it with: pip install nanodesu   (or set NANODESU_PATH to a nanodesu.py checkout)
```

*"Not found"* with no next step is what makes a tool feel broken when it is merely incomplete.

`unpack.py` now prefers Nanodesu's library API (1.3.0) and falls back to the CLI for earlier
versions, so the result carries a structured count rather than one scraped out of prose. Still no
subprocess and no shell in the middle.

## Testing

124 tests (was 109), green on Python 3.9, 3.12, 3.13 and 3.14.
