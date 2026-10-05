# Torikago 1.1.0

Reads the PE debug directory, and a `.pdb` when one shipped.

## The CodeView record needs no second file

The PE debug directory holds the `.pdb`'s **absolute path on the build machine**. A real sample
yielded:

```
D:\Development\OpenSource\PowerfulWindSlickedBackHairCS-LX_Improve\...\obj\Debug\....pdb
```

That names the project, the source layout and the build configuration, and it is readable from the
executable alone — it was the fastest route to understanding what the sample was.

## A shipped .pdb is a disclosure

Type names, method names, source paths. On the same sample: **20 namespaces, 118 type names, 77
source paths**, recoverable in seconds where disassembling to the same understanding would have
taken far longer. Shipping it is itself worth reporting.

```
a .pdb shipped beside the binary (msf-native-pdb, matches this binary)
debug build: the CodeView record names the full build-time .pdb path, so the build
             machine's directory layout is in the binary
```

What this does **not** do is parse PDB symbol records. The MSF container is read as the structure it
is; the identifier extraction is labelled as *extraction*, because a half-written record reader
would produce confident nonsense.

## A false denial, found and fixed while building it

The first version read the PDB information stream **by index**. On a real PDB the stream directory
resolved several streams to the same wrong block, so it produced a GUID-shaped value that was not a
GUID — and reported:

> `pdb_matches_binary: False` — this .pdb does **not** match this binary

about the `.pdb` that did.

A false denial is worse than no answer. The stream is now located by the **version marker it must
begin with**, and an unvalidated one yields `None`, which now means something different from
`False`: *could not be established*, not *does not match*.

## Two levels of disclosure

Chromium's official builds record just `electron.exe.pdb` — nothing beyond the fact of a debug
build. A compiled-for-this-project sample recorded the whole path. The reason says which, because
they are not the same finding.

## Also corrected

The assessment still called a **.NET assembly** "high-entropy". IL plus metadata in `.text` sits
near the top of the entropy range by construction, so the same file was described as packed, and
then — after that was fixed — as high-entropy instead. Both now know.

## Testing

**141 tests** (was 124), green on Python 3.9, 3.12, 3.13 and 3.14.

A lesson recorded in the tests themselves: a synthetic container written from the same
understanding as the reader proves only that the two share assumptions. The container tests were
replaced by checks against a **real** `.pdb`, which skip when the sample is absent.
