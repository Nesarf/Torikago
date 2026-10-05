# Torikago 1.14.0

`WORKFLOW_ISOLATED.md`: the procedure for handling what `take-samples` fetches.

## Why a workflow document is part of the product

**A sealed artifact is inert** — an AES-encrypted zip, nothing double-clicks into execution — so the
residual risk is not *"the sample will run"*. It is **what happens at the moment somebody unseals one
to look at it**, and that moment had no documented procedure behind it.

The document is short because the tools make it short: **~316 KB of Python, standard library only**,
with `pyzipper` as the single exception for real AES. **Verified portable** — copied into a clean
directory and run, no installer, no environment.

## Two tempting mistakes it names rather than assumes away

**A sandbox with network lets the sample phone home.** That is not hypothetical for these collections:
a RAT's entire function is reaching a command server, and an isolated-but-online run reports your IP to
whoever is listening. The document supplies a `.wsb` with no `<Networking>` element **and** a
verification step — `Test-NetConnection` and `ipconfig` **before** unsealing anything, because a
containment assumption that turns out to be wrong is worse than none.

**WSL is not an isolation boundary.** It shares the host filesystem and network namespace, so a sample
inside it reaches the host through `/mnt/c`. It is named explicitly because it is the convenient-looking
option: fine for Linux malware analysis, wrong for containing something.

## The shape of the workflow

    acquire   on the host   -> lands SEALED. Not executable, not readable by a scanner.
    unseal    in isolation  -> the only moment readable hostile bytes exist
    analyse   in isolation  -> nanodesu / torikago
    judge     in isolation  -> --handoff
    discard   the sandbox   -> closed, not cleaned

**Acquire stays on the host deliberately.** Moving it into the sandbox would put the sample where there
is no way to get it back out, and the thing being protected — the host's own antivirus — is what the
sealed form already handles. What needs isolation is the unsealing.

**"Discard, not clean"** is the reason Windows Sandbox is the recommendation: closing the window
deletes everything, so there is no wiping step to get wrong and no folder to forget. A full VM gets the
same treatment — revert the snapshot rather than deleting files, because a revert cannot miss
something.

## What the document says it does not do

* Does not make the sample safe to **run** — it makes it safe to *look at*
* Does not protect against a mistake made **on the host**, outside the sandbox
* Does not survive a read-write mount or a clipboard, both of which are switched off for that reason
* **Does not replace judgement about which samples to take** — that decision is the machine owner's,
  and no amount of isolation makes it for them

## Testing

**314 tests**, unchanged — this release is documentation. The portability claim was verified by
copying the ten files into a clean directory and running them.
