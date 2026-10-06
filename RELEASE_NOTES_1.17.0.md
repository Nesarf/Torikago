# Torikago 1.17.0

The three remaining P0s from the code review. **All three are the same shape, and it is the worst
shape available to a triage tool: not a crash, not an exception, just wrong evidence in the report.**

## The directory count was ignored, so section headers became directories

`parse_pe` iterated its own list of fifteen directory names unconditionally, so a PE declaring
`NumberOfRvaAndSizes = 2` had **everything after the optional header parsed as directories — which is
the section table.** The invented entries were built from section headers, and the fields invented are
exactly the ones a report leans on: import, TLS, debug, COM descriptor.

**A fabricated import table reads as a finding.** That is the worst instance of this shape in the
review, because the output is not obviously wrong — it looks like a file with an import directory.

The declared count is now read first, clamped to what the file actually has room for, and recorded so
two reports can be compared on it.

## Virtual size and file-backed size were treated as one

```python
if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
```

`vsize > rawsize` is **normal**: the tail is zero-filled at load time and simply absent from the file.
An RVA in that tail produced an offset past the section's real bytes, and the caller read **whatever
happened to be at that file position** — a wrong import name, a wrong string, a fabricated indicator.

Now `rva_to_offset` answers **file bytes only** and returns `None` for a virtual-only tail, which every
caller already treated as "not readable". `rva_is_virtual_only` reports the other fact separately,
because "inside the section but no file bytes" and "no such RVA" are different claims.

**This also exposed a broken fixture**, and how it was broken is the point: `with_dotnet_layout` wrote
`VirtualSize = 0x1000` while its own comment said the header had to cover `0x1400`, and then wrote
`0x1400` to the section header's `VirtualAddress` field. **The old `max(vsize, rawsize)` mapping covered
the target anyway, which is why a fixture with two wrong fields passed for as long as it did.**

## The staged copy was never hashed after being copied

The shuttle entry's name carries the hash of the file that was *analysed*; the bytes were read at a
different moment. A file replaced in between produces an entry whose name says one sample while the
file holds another — **and that needs no attacker, only a directory something else writes to.** A
mislabelled sample is worse than a missing one, because every later measurement inherits the label.

The copy is now re-hashed and **removed** on a mismatch, with both hashes reported so a reader can tell
a race from a collision.

## Testing

**360 tests** (was 348), green on Python 3.9, 3.12, 3.13 and 3.14, on two interpreters here with and
without `pyzipper`.

Twelve new, and the regressions are written to fail against the old code: a virtual tail must have no
file offset, a short directory table must not invent entries, and a mismatched staged copy must not
survive.

**Three of the new tests were wrong before they were right** — the PE fixture omitted
`NumberOfRvaAndSizes`, and the report fragment omitted `md5` and then `size`, each surfacing as a
`KeyError` that looked like a defect in the code rather than a gap in the fixture. A test standing in
for another object has to be **copied from** that object, and twice here it was written from
assumption instead.
