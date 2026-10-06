# Torikago 1.19.0

The handoff now asks about the variant. It is a one-link fix and the link was load-bearing.

## The chain stopped one short of its own reason for existing

Neutralising a sample produces a second artifact **whose entire purpose is to be handed to an engine**
— and `--handoff` only ever looked at the original and the unpacked contents.

**So the one file the repair was for was the one file nobody asked about.** A person could repair a
sample, hand it over, and read a verdict that said nothing about it.

That made `--handoff` and the repair mutually useless: the repair produced something designed to be
judged, and the judging step could not see it.

## What it does now

Targets are the file, whatever an unpack found inside it, **and any variant**:

* **declared first** — a caller that ran a repair can name its outputs
* **detected second** — a sibling `<stem>_defanged*` beside the target, because somebody who has just
  repaired a file should not have to name it again
* **marked in the output row as `[variant]`** — a modified copy and the original produce rows of
  identical shape, and a reader skimming a long list will not go back to read a paragraph at the end

## And the report says what a verdict on a variant is worth

```
These are modified copies. Editing a binary changes its hash and invalidates its signature, so a
clean verdict on one means the engine did not recognise it -- not that it is clean. The original is
unchanged and remains the thing an engine can actually judge.
```

**A verdict on a modified file says something different from a verdict on the original**, so the two
are never folded together silently — and the sentence that says why travels with the claim.

**No variant means no extra keys.** A note about variants that do not exist is noise, and a test pins
that.

## Testing

**368 tests** (was 364), green on Python 3.9, 3.12, 3.13 and 3.14, and run here on two interpreters
with and without `pyzipper`. Four new, three of which are **verified to fail against the previous
code** — the variant is not handed over, the report does not name it, and a declared output is not
honoured.

## Checklist

`P1-1` and `N-2` move to done. The remaining parity work is `N-1`/`N-3` (Torikago's own `neutralize`)
and `X-2`/`X-3`/`N-4` on both sides, since aligning two artifacts requires first saying what the
artifact is.
