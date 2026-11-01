# Torikago 1.21.0

The fifth beat, on the copy and never on the original.

## `--purge`

```bash
python torikago.py --purge shuttle/20260101T000000_abc123def456_sample.exe \
                   --purge-confirm <sha256>
```

The six beats this family aims at are: see, interrogate, force into view, deactivate, execute, purify. Four of
them were here. The fifth was handed to an engine through `--handoff`, which meant the tool that found the file
could not do anything about it. Now it can, with the smallest surface that is still an action: one staged copy
at a time, named by its hash, confirmed by that hash, recorded in the same append-only manifest staging writes
to.

**Three refusals, because the failure mode of a delete is not a wrong answer but a missing one.**

The file must sit in a directory that already holds `quarantine.jsonl` — not a path the caller names from
memory, and not the original's own directory. The caller must paste the sha256 it expects, so a mistyped or
stale path removes nothing. Nothing outside a shuttle is ever removed: the original stays where the operator
can see it, which is the rule `quarantine_copy` was built on.

**The record keeps the difference that matters afterwards.** An empty shuttle and a shuttle that never held
that file look the same unless something says which. Each purge appends when, which name, which hash, how many
bytes — and the sentence that the original was not touched.

## What this is not

It is not a cleanup of an infected machine, and it is not a repair of an infected binary. `--purge` removes a
copy that was already set aside. Repairing a host file that a virus wrote into is a different job with a
different precondition: without a clean copy of the same version there is nothing to restore, only something to
report.

## Testing

**467 tests** (was 462). The five new ones are about refusal except the first: the hash that does not match,
the path that is not a shuttle, the confirmation that is missing, and the original that must survive the purge
that succeeds.
