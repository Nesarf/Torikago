# Torikago 1.12.0

The download path was exercised for the first time, and `--handoff` turned out to be invisible.

## What found this

`--fetch-bytes` had **never actually been run.** Every fetch through this provider had been metadata
only, so the code that downloads, verifies and seals had never been executed — and the first person to
press it would have been the user, on a real sample. Exercising it on a harmless one showed it works
(**1967 bytes downloaded, hash verified, sealed into the vault**), and it also surfaced the next bug.

## `--handoff` produced no output

The verdicts went **only** into `report.json`, and that file is written **only** when `--out` is
given. So for anyone who did not pass `--out`, asking for a handoff printed nothing and **looked like
a broken flag.** A capability nobody can see is one nobody has.

**And the first fix was still wrong.** It printed the verdict *before* the file's own details, so an
output tail — and people read the end — showed only the static working, which is how this was missed
twice in a row. **A conclusion belongs at the end, not buried under the working.** It now prints last,
and two tests pin the order.

## What the output says

```
defender:
    bb81437b7c77f0a7...              no threats reported
        Scanning E:\...\bb81437b....bin.
    note: 腾讯电脑管家系统防护 also holds the Security Center registration, so
          this verdict is not the whole picture

These are the engines' verdicts, not this tool's. A clean result means the engine did
not detect anything, which is not the same as the file being safe.
```

The Security Center note is the point of `--posture` appearing where it is load-bearing: on this
machine a third-party product holds the registration, so **a clean Defender verdict is weaker than it
sounds**, and saying so at the moment of the verdict is when it matters.

Printing is wrapped and cannot raise: the analysis has already succeeded by then.

## And a mistake of my own worth recording

While moving that print, I cut a twenty-line block out of `main` with string slicing and **corrupted
the file** — the `--out` writer and part of the `--feed` block went with it. Three tests caught it
immediately, which is what they are for, and the repair was `git checkout` plus a single precise edit
rather than another slice.

**String-slicing a source file to move a block is the same class of mistake as writing Windows paths
through a shell heredoc**, which has now happened seven times in this project: an edit that looks
surgical and removes more than it says.

## Testing

**301 tests** (was 296), green on Python 3.9, 3.12, 3.13 and 3.14. Five new: the verdict is printed
after the details, printing survives a hostile report and an absent one, an unavailable engine is
reported rather than hidden, and the note that the verdict is not this tool's is present.
