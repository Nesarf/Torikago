# Torikago 1.16.0

Three P0s from a code-level review, all confirmed against the source — plus one defect the fixes
themselves introduced, which is the part worth reading.

## The vault unsealed with `extractall()`

`sample_vault.extract()` checked that the container was encrypted and then did exactly what the
member names said. **A zip slip needs no encryption weakness at all** — it is a normal feature of the
format, and `../../x` writes wherever the user has permission. The check was of the container and
said nothing about the contents, and the names are untrusted even though the container is ours,
because the container was built by whoever uploaded the sample.

Members are now written one at a time after checking the name: both separators, a resolve-and-confirm
belt behind the sanitiser, member and size caps **enforced from the headers and again while writing**
because a header can lie, and Windows device names neutralised — `NUL` is not a filename, and a corpus
entry recorded as extracted when nothing was written is worse than a refusal. Refusals are reported,
never dropped.

**Verified against the old code: seven of the new tests fail there.**

## The download verified the wrong object

The comment said *"verify it against the hash we asked for"* and the code verified the **archive**.
The site serves a zip whose member is the sample, so the archive's hash is not the sample's hash — and
**a claim in a comment the code does not support is worse than no claim, because it is the kind of
thing a reader stops checking.**

The sample inside is now extracted, hashed and compared **before the file may take its final name**.
Downloads go to `.part` and are committed with `os.replace`, so an interrupted transfer cannot leave
something whose name says it is complete. A download cap now exists — streaming solved the memory
problem and did nothing about the disk.

## And the fetch path treated a three-state result as a boolean

`is_encrypted_zip` returns `None` when it cannot check, and `not None` is `True`. So **a genuinely
AES-sealed sample was routed down the plaintext path** — the same substitution the third state was
introduced to prevent, made one layer down by a caller that ignored it. Found because a real fetch
behaved differently under two interpreters.

There is now a dependency-free check that reads the archive's own central directory, so the decision
no longer depends on what happens to be installed. A test asserts the strict check **still** answers
`None` without `pyzipper` and deliberately does not require the two to agree, because demanding
agreement would be demanding the very conflation being guarded against.

## Which exposed a design conflict worth naming

The old code warned that an archive was unencrypted and **left the plaintext sample in place**. A
warning nobody reads is not a control, and the container exists precisely so the sample cannot be
read. Refusing outright would turn the protection into a denial of service — the sample becomes
unobtainable rather than unreadable. So an unsealed download is **sealed here instead**, and the
result records who sealed it.

## CI

**It had never passed on this branch.** Failing since 1.13.0 — the fixture paths hard-coded a drive
that does not exist on a runner — and the failures were misread as queueing more than once. Green now,
which is what fixing the fixture roots was for. The gap between the release list and the source was a
symptom of that, not of forgetting to publish.

## Testing

**348 tests** (was 325), green on Python 3.9, 3.12, 3.13 and 3.14, and run here on two interpreters
with and without `pyzipper` because the interesting behaviour differs between them.
