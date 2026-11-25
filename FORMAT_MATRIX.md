# File format identification

What this tool recognises from a file's first bytes, on what evidence, and what it deliberately
does not. The table below is `MAGIC` in `torikago.py`; `test/test_format_matrix.py` reads this
document and compares the two in both directions, so a table nobody checks cannot fall a year
behind the code.

| | |
|---|---|
| prefixes in the table | **22** |
| distinct kinds | **20** (`macho` and `zip` each have two prefixes) |
| what decides | the **first** prefix that matches, read from offset 0 |
| what it cannot decide | anything that does not live at offset 0, and anything whose prefix is shared |

Extensions decide nothing here. `invoice.png` that opens with `MZ` is reported as a PE executable,
because the bytes are the file and the name is a claim about it.

---

## The table

Each row's evidence is the specification that defines the prefix, or the shape of a real file where
no single document owns the format. No row is here because the format is famous.

| prefix (hex) | kind | what the bytes are | evidence |
|---|---|---|---|
| `4D 5A` | `pe` | DOS/PE executable | PE format spec, DOS header `e_magic` = `0x5A4D`; `MZ` are the initials of Mark Zbikowski |
| `7F 45 4C 46` | `elf` | ELF executable or object | ELF spec, `e_ident[EI_MAG0..3]` = `0x7F 'E' 'L' 'F'` |
| `CA FE BA BE` | `macho` | Mach-O universal binary | `FAT_MAGIC`, big-endian fat header. **Also the Java class-file magic** — see *Shared prefixes* |
| `CF FA ED FE` | `macho` | Mach-O 64-bit | `MH_MAGIC_64` (`0xFEEDFACF`) stored little-endian |
| `50 4B 03 04` | `zip` | ZIP container | APPNOTE.TXT, local file header signature |
| `50 4B 05 06` | `zip` | empty ZIP | APPNOTE.TXT, end-of-central-directory signature. An archive with no entries has no local header at all |
| `37 7A BC AF 27 1C` | `7z` | 7-Zip archive | 7-Zip's own signature bytes, six of them |
| `52 61 72 21 1A 07` | `rar` | RAR archive | RAR 4 and RAR 5 share these six bytes; RAR 5 adds `01 00` |
| `1F 8B` | `gzip` | gzip stream | RFC 1952 §2.2, `ID1` = `0x1F`, `ID2` = `0x8B` |
| `42 5A 68` | `bzip2` | bzip2 stream | `BZh`, followed by the block-size digit |
| `FD 37 7A 58 5A 00` | `xz` | xz stream | xz file format spec §2.1.1, six-byte magic |
| `25 50 44 46` | `pdf` | PDF document | ISO 32000-1 §7.5.2, `%PDF-` header |
| `D0 CF 11 E0 A1 B1 1A E1` | `ole` | OLE compound file | MS-CFB §2.2, the eight-byte header signature. Legacy `.doc`/`.xls`/`.msi` |
| `4D 53 43 46` | `cab` | Microsoft Cabinet | `MSCF`, cabinet header signature |
| `49 54 53 46` | `chm` | CHM help file | `ITSF`, the compiled-HTML header |
| `89 50 4E 47 0D 0A 1A 0A` | `png` | PNG image | PNG spec §5.2, eight-byte signature chosen to catch line-ending corruption |
| `FF D8 FF` | `jpeg` | JPEG image | `SOI` (`0xFFD8`) followed by the first marker (`0xFF`) |
| `47 49 46 38` | `gif` | GIF image | `GIF8`, shared by 87a and 89a |
| `23 21` | `script` | script with a shebang | `#!`, the two bytes a kernel reads to pick an interpreter |
| `7B 5C 72 74 66` | `rtf` | RTF document | `{\rtf`, the opening group |
| `21 3C 61 72 63 68 3E` | `ar` | ar archive | `!<arch>`, the Unix archives `.a` and `.lib` use |
| `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` | `sqlite` | SQLite database | `SQLite format 3\0`, sixteen bytes including the terminating NUL |

Order matters only where one prefix is a prefix of another. No row here is, which is why the list
can be read as a set rather than as a sequence.

---

## Where the prefix and the structure disagree: `MZ` but not PE

`MZ` is the only row in this table that is **not** an identification. It is a claim that something
DOS-shaped lives here; whether a PE image lives here is decided further down, by `parse_pe()`.

That separation is right, and it currently costs a distinction the report does not make. Three
samples, run through `identify()` and `parse_pe()`:

| sample | `kind` | `parse_pe()` | `packer` | `imports` |
|---|---|---|---|---|
| a real PE32 header | `pe` | a dict | `likely packed or delay-loaded` | 0 |
| `MZ`, and no `PE\0\0` at `e_lfanew` | `pe` | **`None`** | `n/a` | 0 |
| plain text | `unknown` | `None` | `n/a` | 0 |

The second sample is a **damaged PE** and the report describes it as a **PE with no features** —
`packer: n/a`, `imports: 0`, `entropy_max: 0.0` is what a clean, boring executable also looks like.
Nothing anywhere says the header failed to parse. The third sample is honestly `unknown`, so the
two are distinguishable by `kind` — but the one that is wrong about itself is the one that claims
to be an executable.

**This is measured, not assumed** (`TODO.md` §零之七 F-2). The fix is not decided yet; what is
decided is that a report must be able to say "the header did not parse" rather than "nothing here".

The same prefix swallows three other executables that are not PE: **NE** (16-bit Windows),
**LE** and **LX** (OS/2). All three start with `MZ` and all three fail `parse_pe()`, so all three
land in the same indistinguishable row as a damaged PE.

---

## Shared prefixes

A prefix identifies a family, not a species. Three rows are worth knowing about:

| prefix | what it also matches | what the report says |
|---|---|---|
| `CA FE BA BE` | a **Java class file** | `macho`. The fat-header and class-file magics are the same four bytes; nothing in the first four distinguishes them |
| `50 4B 03 04` | JAR, APK, DOCX/XLSX/PPTX, WAR, EPUB, and every other ZIP container | `zip`. The container is what the bytes say; the payload is a question for the unpacker |
| `52 61 72 21 1A 07` | both RAR 4 and RAR 5 | `rar`. The six shared bytes are enough to say RAR, not enough to say which |

Being able to say `zip` about a `.docx` is not a failure — it is the correct reading of the bytes.
The failure to avoid is a report that says `docx` because the name did.

---

## What this tool does not recognise

A table of what is accepted, read alone, implies that everything outside it is a malformed
specimen of something inside it. The gaps come in three kinds and only the first is an oversight.

### Not at offset 0, and therefore out of reach for a prefix table

| format | signature | why it is not in the table |
|---|---|---|
| WebP | `RIFF` at 0, `WEBP` at 8 | `RIFF` alone is also WAV, AVI, and WebP; adding `RIFF` would be a wrong answer for two of the three |
| MP4 / MOV | `ftyp` at 4 | the box size comes first, so offset 0 is variable |
| WAV / AVI | `RIFF` at 0, `WAVE`/`AVI ` at 8 | as above |
| tar | `ustar` at 257 | there is no signature at the start at all |
| ISO 9660 | `CD001` at 32769 | outside the bytes a head read would fetch, and not a format this tool handles |
| OOXML and ODF | a ZIP container | reported as `zip`, correctly; the payload is decided by the unpacker |

`MAGIC` is a list of prefixes, so a format whose signature is not at the start needs a different
mechanism, not a longer list. Adding `RIFF` to this table would trade one wrong answer for two.

### Two bytes is too short to be worth it

`BM` opens every BMP and also opens a large share of arbitrary binary data. A two-byte entry with
that hit rate does not identify anything; it labels. BMP is therefore absent on purpose.

### Formats nobody has brought yet

The comment on `MAGIC` says the list grows from real misses rather than from imagination. These are
the misses it has not received: FLAC, OGG, MP3, PE's own **NE/LE/LX** relatives, Apple disk images,
Java class files (see *Shared prefixes* — they are matched, as the wrong thing), and 32-bit
little-endian Mach-O (`CE FA ED FE`, which would be a one-line addition if anything ever asks).

An absent row here is not a promise to add it. It is a record of the question not having been asked.

---

## Reproducing this table

```
python -c "import sys; sys.path.insert(0,'.'); import torikago; \
  [print(p.hex(' ').upper(), k, l) for p, l, k in torikago.MAGIC]"
```

The prefixes above were taken from that output and each one was matched to its specification by
hand. That step is not automatable, and no test here checks whether `4D 5A` really is the DOS magic
— what the tests check is narrower and still worth having: that this document, the `MAGIC` table and
what `identify()` actually does all say the same thing.

**This file passed on its first run, which is not evidence that it works.** Three deliberate drifts
were made afterwards to find out whether it would fail, and each one was made in a different place:

| drift | assertions that turned red |
|---|---|
| a `kind` changed to `gifs` | 2 — the multiset comparison, and the behavioural one, which named the prefix |
| a summary count changed to 21 | 1 — the count comparison |
| an entry deleted from `MAGIC` | 5 — count, kind count, multiset, behaviour, and the reported prefix |

Two of the tests written in the same sitting were wrong before they were right: a skip condition
that could never fire (it tested the truth of a path object in a way that is always true), and an
assertion that only checked whether the phrase it was looking for was already in the text. Both are
corrected above, and neither would have been caught by the tests themselves — which is the reason
the drifts in the table are worth more than the green run.

## Why this document exists

`identify()` had a `MAGIC` table and no document. The table was correct; nothing said what it
accepted, on what evidence, or what it refused. The cost of that is not documentation debt — it is
that the consistency layer between this tool and Nanodesu stops at "both call this file a `pe`"
and cannot compare what variants each side accepts. One repository had a matrix with sources and a
test; the other had a list in code.

Nanodesu's matrix is the shape this one follows: every row points at an origin, a test compares the
document to the code in both directions, and the formats that are not recognised are written down
next to the ones that are.
