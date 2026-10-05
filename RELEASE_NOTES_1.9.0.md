# Torikago 1.9.0

The sample channels move in: a fetcher and a vault, both of which existed only in a scratch directory
that gets cleaned.

## Why they needed a home

The fetch tool and the vault had been written and used, and lived **only** at `E:\Quarantine\` — a
directory that exists to be deleted. That is the same situation that lost an earlier sweep's 248
measurement records, and the reason the corpus exists at all. A tool that is the only copy of itself
in a scratch directory is one `clean` away from not existing.

They now ship in this package, reachable from the same CLI:

```bash
torikago --fetch-sample <sha256>          # metadata only; --fetch-bytes to download
torikago --vault-store sample.bin --dest /your/vault
torikago --vault-list /your/vault
torikago --vault-extract <zip> --work /a/dir/you/will/delete
```

## `pip install torikago[vault]`

The vault needs real AES and **there is no fallback.** The Python standard library cannot write
encrypted zip members — it will cheerfully set the encrypted bit and write plaintext, which is why
every archive is **verified by failing to read it back without the password**. A container that only
looks encrypted is worse than none, because the operator leaves a readable sample lying about
believing it sealed. Absence of `pyzipper` is a reported failure, not a silent downgrade.

## Four defects found while moving them

**The vault reported a sealed archive as unencrypted.** `--vault-list` on an interpreter without
`pyzipper` said `encrypted=False` for a genuinely AES-encrypted file — a confident statement produced
by an inability to read it. `is_encrypted_zip` now returns **`None`** when the question cannot be
answered, and the listing says `unknown`; a store that cannot verify deletes rather than keeping an
unconfirmed container.

**`--vault-list DIR` ignored the DIR** and listed the default vault instead: a wrong answer to the
question asked, which is worse than no answer.

**Three different failures shared one message.** `401` (no key), `403` (a key was given and refused)
and `hash_not_found` (the key worked, the corpus lacks that hash) all reported "you may need a key" —
and **one of them told the reader to go and generate a key that had just been proven to work.** They
are now distinguished, and `403` names the plausible causes including **abuse.ch's new rate limit of
up to 72 hours**.

**A fixture lived in a forbidden path.** The tests created temporary directories under `TEMP`
(`E:\DaShaoHuo\cache\tmp`) and under `Path.home()` (`C:\`) — **both of which the tool refuses on
purpose** — so the fixtures failed in a way that looked exactly like the check being wrong. Neither
obvious base works on this machine, which a diagnostic established rather than a guess.

## Destinations are refused, not sanitised

Never inside the workspace, the cache area, a git repository, or on `C:`. Each refusal is a specific
way this goes wrong: **a sample in a repository gets committed eventually**, and one on the system
drive survives a machine being handed on. The default destination is described in the tool itself as
**a suggestion rather than an assumption** — the fetcher has no idea where you keep samples, while the
posture module deliberately knows nothing about it at all.

## Testing

**280 tests** (was 256), green on Python 3.9, 3.12, 3.13 and 3.14, and run on **two interpreters here**
— with and without `pyzipper` — because the interesting behaviour differs between them. The 24 new
tests are mostly about **not claiming things**: not encryption that was never verified, not a missing
key when the key was refused, not a sample absent when the query never ran.
