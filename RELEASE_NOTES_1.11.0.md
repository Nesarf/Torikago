# Torikago 1.11.0

Two providers wired end to end, and a design rationale corrected by measuring it.

## The key follows the provider

`--source malshare` was sending the **abuse.ch** key to MalShare and getting a bare `HTTP 400`. The
wrong credential went to the wrong service and the error said nothing about why — the same class of
failure as reporting a missing key when a key was refused. Each provider now reads its own variable,
and the choice is made from `args.source` rather than assumed.

## `--quota` parsed the wrong shape

MalShare returns JSON (`{"LIMIT":2000,"REMAINING":2000}`). The first version parsed two
space-separated numbers and therefore **reported neither** — it printed the raw blob and no figures,
which looks like a working command. Measured on the real response and fixed; the parser accepts both
shapes now.

## The design rationale was wrong, and one measurement showed it

The assumption written into the module was that a second provider fills the first one's blind spot.
**For Windows work it does not.** MalShare's recent feed, measured:

```
24 samples: ELF 9 · Mach-O 3 · ASCII 3 · AppleScript 2 · data 1 · Zip 1 · PDF 1
            · RAR 1 · JavaScript 1 · ISO 1 · Unicode 1
```

**Zero PE.** Filtering by type for `PE32`, `PE32+`, `exe` or `dll` returned nothing — which for a
24-hour window means there was nothing, not that the filter failed.

So the two are good at different things, and that is why both stay:

* **MalwareBazaar is the targeted one** — indexed by family and tag, which is how **20 PyInstaller
  samples (18 `exe`, 0.34–63 MB)** were found when a tag was asked for.
* **MalShare is the bulk one** — much larger, a daily firehose, and a type filter that only makes
  sense over a longer window than a day.

**A source being large is not the same as a source being relevant.** For a Windows unpacker the
smaller, better-indexed collection is the more useful one, and the complementarity assumption was
worth one measurement before it became a design rationale. That sentence is now in the module, because
the next person to have the same sensible idea deserves to find the result.

## `--recent`, and it says what it is not

```bash
torikago --fetch-sample --source malshare --recent
```

Lists the last 24 hours, and **prints that this feed is a bulk source rather than a targeted one** —
so nobody reads a thin day as an empty collection.

## Testing

**296 tests** (was 290), green on Python 3.9, 3.12, 3.13 and 3.14, on two interpreters here. Six new:
each provider reads its own variable, the provider is known before the key is resolved, the quota
parser matches the JSON MalShare actually returns, and the module records the measurement that
contradicted its own rationale.

Two of the new tests failed first for instructive reasons — one because `MALSHARE_TOKEN` appears
earlier in the file than where it is read, and one because a wrapped docstring split the phrase being
searched for. **Both were measuring the text rather than the behaviour**, which is the third time
that has happened in this project.
