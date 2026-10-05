# Torikago 1.2.0

Debug information now comes from the files **inside** an unpacked wrapper, and building that
exposed a real defect in 1.1.0.

## The defect: a silent false negative

**The debug directory sits at 95% of the file.** Measured on both real samples — **95.5%** and
**95.0%** — because the sections carrying it are linked late.

The inner-file scan reads only the first **4 MB** of each file. So a reader driven by that head
would have answered, for a file that has debug information:

```
available: False
```

Not an error. A silent false negative, on the single most informative thing in the directory —
and it would have been invisible, because "no debug information" is a perfectly ordinary answer.

Demonstrated on the real sample rather than argued:

| read | result |
|---|---|
| a 4 MB head read | `available=False` |
| a seek | `available=True`, with the build-time path |

## The fix

The reader no longer takes a buffer. `analyse_debug_info` and `parse_debug_directory` now work from
a **path and a reader callable**: they read the headers to learn the layout, seek to the directory,
and read only what they must.

Two things follow. A 100 MB inner DLL no longer has to be loaded to find out how it was built, and
a head peek can no longer be mistaken for absence.

## Verified

All six binaries in a real Electron directory report their CodeView record, including the 104 MB
one:

```
ffmpeg.dll              ffmpeg.dll.pdb
libEGL.dll              libEGL.dll.pdb
libGLESv2.dll           libGLESv2.dll.pdb
TeachingFeeling.exe     electron.exe.pdb
```

They name the PDB as a **bare filename**, which is Chromium's habit and not a layout disclosure —
and the report says so rather than crying wolf. That distinction was already in place: a bare name
and a full `D:\...\obj\Debug\...` path are not the same finding.

## Testing

**145 tests** (was 141), green on Python 3.9, 3.12, 3.13 and 3.14.

The regression test states the bug as a single assertion — that a head read and a seek **must
disagree** on that file — and a companion test asserts the directory really is late, so the seek
does not read as an arbitrary preference if a future sample has it early.
