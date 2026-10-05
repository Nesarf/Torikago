# Torikago 1.10.0

A second sample provider, and browsing separated from taking.

## `--tag`: see what a collection holds before committing to anything

```bash
torikago --fetch-sample --tag pyinstaller --limit 20
```

A table of what MalwareBazaar holds under a tag: hash, type, size, first-seen, name, plus a type
breakdown. **It downloads nothing, and there is no flag that turns it into a download** — browsing a
collection and taking from it are different acts.

That separation is not decoration. Building the corpus meant choosing hashes one at a time from search
results, and several turned out to be archives the unpacker cannot read. A listing makes that visible
before anything is taken.

First use, on the tag that matters most for this project: **20 PyInstaller samples, 18 of them `exe`,
spanning 0.34 MB to 63 MB.** Size spread is the point — a 342 KB PyInstaller onefile is unusual
(typical is 6–60 MB), so it reaches branches in the parser that a synthetic sample never would.
Meanwhile **this tool has only ever been verified against one PyInstaller archive it built itself.**

## A second provider, for the reason a blind spot is invisible

`--source malshare` (needs `MALSHARE_TOKEN`; register at malshare.com). MalwareBazaar indexes what its
pipeline ingests; MalShare indexes what the community uploads, including things nobody has named yet.
**For a tool whose value is how much of the format space it has seen, one source is a blind spot — and
a blind spot is invisible, because you cannot miss what you never had.**

`--quota` reports the key's remaining daily requests. Read **before** spending an attempt, because
discovering a limit by being rejected wastes the attempt that hit it — the same failure abuse.ch now
warns about on its own front page with a 72-hour rate limit.

## One difference between the two providers that matters to whoever handles the file

**MalwareBazaar serves a password-protected zip. MalShare serves the sample raw.** So a MalShare
download is **still executable content**, and the tool says so. Its hash is also directly checkable —
and a mismatch **deletes the file**, because a sample filed under a hash it does not have is worse than
no sample.

## The rules did not move

Destination checks, local hash validation, metadata-first, protection-state recording — all of them
run **before** any provider is consulted, and a test asserts the ordering. **Adding a provider cannot
be a way around a check.**

## Testing

**290 tests** (was 281), green on Python 3.9, 3.12, 3.13 and 3.14, run on two interpreters here with
and without `pyzipper`. Nine new: the listing path contains no download call (checked against the
calls, not against the string `--fetch` — the first version failed on its own help text), a hash is
optional for a browsing command, the second provider reads its key from the environment, a hash
mismatch deletes, and the destination check still runs first.
