# Torikago 1.13.0

`take_samples.py`: filling a corpus in one command, with the refusals already applied.

## Why a batch tool

**Taking twenty samples one hash at a time is twenty deliberate acts**, and the friction pushes
toward taking fewer, or taking carelessly. This removes the friction **without** removing the
deliberation: the destination is checked once against rules that cannot be waived, every file is
**sealed before it stops moving**, and the run is written to an append-only log.

```bash
python take_samples.py --tag pyinstaller --count 6 \
    --dest /your/vault --work /a/scratch/dir
```

```bash
tag 'pyinstaller': 72 listing row(s)
  take  78c76827458897e4   exe     13601651  tkdbfype_160948.exe
  take  5702cb05be590956   exe     12967960  ForniteFix.exe
  ...
```

`--dry-run` shows the selection and fetches nothing.

## What it decides, and what it does not

**It does not decide whether to take samples.** That is the machine owner's call, and running this is
that call being made. What it decides is only *how*, once the decision exists.

## The filters exist for a specific failure

**Only PE types by default** (`exe`, `dll`, `sys`, `scr`, `cpl`; `--types any` overrides). A zip is
not evidence about a PE parser, and the failure this prevents is measured: **the first corpus built
here had 1,496 records and exactly one PE among them.** Twenty archives would have produced a corpus
that says nothing about the detectors.

**Already-sealed samples are skipped**, because the vault names every artifact by its own content
hash — a second copy is not a second sample.

**Skips carry a category, not prose.** The first version counted them by asking whether the string
`type` appeared in the reason text, which matches far more than it should and reported every skip as
a type skip.

## The refusals are the single-sample ones, reused

The destination rules are called from `sample_fetch`, not reimplemented, so the batch cannot drift
away from the single path — and **both** the vault and the work directory are checked, because the
loose download is also somewhere a sample sits.

**The loose copy is deleted once sealed.** Keeping both would leave readable hostile content next to
the container that exists precisely to avoid that.

**Nothing here runs, unpacks or modifies a sample.** A test asserts that no execution call appears in
the file at all, and that the unpacker is not referenced: fetching and unpacking are separate acts and
this performs only the first.

## On the decision itself

The tool carries the decision out; it does not make it. That is why the entry point requires
`--dest` and `--work` explicitly rather than defaulting: **a default destination would turn a
deliberate act into a convenient one.** The safety of an action like this rests on somebody having
chosen it, and a tool that chooses on your behalf has removed the only guarantee it had.

## Testing

**314 tests** (was 301), green on Python 3.9, 3.12, 3.13 and 3.14. Thirteen new: type filtering takes
only what a PE unpacker can read, sealed and hash-less rows are skipped and labelled, skips carry a
category rather than relying on substring matching, the vault is read from its filenames, both
destinations are checked, the rules are reused rather than reimplemented, and **no execution call
appears anywhere in the file.**
