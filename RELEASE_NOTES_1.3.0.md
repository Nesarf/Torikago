# Torikago 1.3.0

Rank what is unusual; keep what is merely true.

## The attention list was mostly noise

A sweep of **298 real binaries** from an ordinary drive, measured rather than guessed:

| reason | fired on |
|---|---|
| `url` | **99.7%** — in the string table of nearly everything |
| `uses APIs worth noting` | **98.7%** — by construction |
| `debug build` | **84.9%** — debug info survives in ordinary release builds |
| `has a TLS callback` | **69.5%** — standard in modern software |

And `attention` was `len(reasons)`. So **five facts true of every file counted the same as one
destructive finding** — in a tool whose entire job is to surface the rare thing.

## This corrected a claim made an hour earlier

From a 101-file sample, 1.2.0's notes reported that 40 with a full build path meant the debug
signal was *"selective rather than noise"*. At 298 files it is **84.9%** — the opposite of
selective. **A wider corpus changed the conclusion**, which is the argument for sweeping wider
corpora.

## The fix

`assess` now separates the two:

* **`reasons`** — what is unusual. Ranked, counted by `attention`, fed to the high-confidence path.
* **`notes`** — what is true but ordinary. Still reported, never ranked.

Nothing is hidden: *"this binary has a TLS callback"* is a fact a reader may legitimately want.

The same 248 files, before and after:

```
before   99.7% url · 98.7% APIs · 84.9% debug · 69.5% TLS ...
after     0.8% packed or encrypted      2  icudt71.dll, icudt73.dll
          0.8% named_pipe               2  unins000.exe, crashpad_handler.exe
          0.4% embedded PE image(s)     1  unins000.exe
          0.4% registry_run             1  unins000.exe
          0.4% EMBEDDED BOOT SECTOR     1  AS_Storage_w64.dll
```

**The loudest signal is now the boot sector, which is what it should be.**

## A second false positive, from the same sweep

ICU's data DLLs — `icudt71.dll` at 30 MB and `icudt73.dll` at 37 MB, each one `.rdata` section and
nothing else — were reported as **"likely packed, evidence: no imported functions"**.

They import nothing **because they call nothing**. The rule assumed a file with no imports must be
a packer stub. It now checks whether the file contains any code at all, and names a data-only
module as exactly that — *"a 30 MB data blob"* is the more useful statement about such a file, and
"packed" is not true of it.

Tested in both directions: a codeless PE must not be called packed, and a code-bearing PE with no
imports must still be.

## What rebuilding `assess` cost me

I read the first 46 lines of the function and rewrote the whole of it — so the part after them,
**including the injection triad**, the single most meaningful import signal the tool has,
disappeared. The quarantine tests caught it.

Reading part of a function and rewriting the whole of it is how working logic vanishes. It is
restored verbatim, and the triad is still judged on the **full import set** rather than on the
filtered list.

## Testing

**152 tests** (was 149), green on Python 3.9, 3.12, 3.13 and 3.14.
