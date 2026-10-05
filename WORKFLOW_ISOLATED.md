# Working with samples in an isolated environment

This is the procedure for handling what `take-samples` fetches. It exists because the residual risk
after sealing is not *"the sample will run"* — a sealed artifact is an AES-encrypted zip and nothing
double-clicks into execution — it is **what happens at the moment somebody unseals one to look at it.**

**The tools are portable by design**, which is what makes this practical:

| | size | dependencies |
|---|---|---|
| `nanodesu.py` (+ `boundary`, `neutralize`, `boundary_voice`) | ~200 KB | **none — standard library only** |
| `torikago.py`, `sample_fetch.py`, `take_samples.py`, `corpus.py` | ~180 KB | none |
| `sample_vault.py` | 11 KB | `pyzipper` — for real AES |

The whole toolkit is **~316 KB of Python**. Nothing here needs an installer.

---

## Where each step happens, and why

    acquire   on the host    -> lands as a SEALED artifact. Not executable, not readable by a scanner.
    unseal    in isolation   -> this is the only moment readable hostile bytes exist.
    analyse   in isolation   -> nanodesu / torikago
    judge     in isolation   -> --handoff
    destroy   the isolation  -> the sandbox is discarded, not cleaned

**The acquire step stays on the host deliberately.** Moving it into the sandbox would put the sample
somewhere with no way back out, and the thing being protected — the host's own antivirus — is what the
sealed form already handles. What needs isolation is the unsealing.

---

## 1. Pick an isolation that is actually disposable

| option | disposable | host filesystem | needs an ISO | notes |
|---|---|---|---|---|
| **Windows Sandbox** | **yes** — closed window deletes everything | **no** (read-only mounts at best) | **no** | Windows Pro/Enterprise; best fit here |
| Hyper-V VM | yes, with a snapshot discipline | no, if you disable checkpoints/shared folders | yes | more control, more setup |
| WSL | **no** | **shares the host filesystem** | no | convenient, **not an isolation boundary** |
| A folder | no | — | — | it is a folder |

**WSL is named here because it is the tempting mistake**: it shares the network and the filesystem, so
a sample inside it reaches the host through `/mnt/c` and through the network namespace. It is a fine
place to run Linux malware analysis; **it is not a place to run something you are containing.**

Check what this machine has:

```powershell
Get-WindowsOptionalFeature -Online -FeatureName WindowsSandbox
```

`Enabled` and you are done. Otherwise it needs the feature turned on **and a reboot** — a system change
worth making deliberately rather than as a side effect of wanting to look at one file.

---

## 2. Take the network away — this is the step people skip

**A sandbox with network is a sandbox that lets the sample phone home.** That is not hypothetical for
the families in these collections: a RAT's entire function is to reach a command server, and an
isolated-but-online run reports your IP to whoever is listening.

Windows Sandbox: create `sample.wsb` next to the `.exe`:

```xml
<Configuration>
  <!-- No networking at all. A <Networking> element is what ENABLES it; omitting it is the default
       and is still worth writing down, because "it felt fine" is how this gets lost. -->
  <MappedFolders>
    <!-- Exactly one folder in, mapped read-only. The samples go here; nothing else is visible. -->
    <MappedFolder>
      <HostFolder>E:\samples-for-review</HostFolder>
      <SandboxFolder>C:\review</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <ClipboardRedirection>false</ClipboardRedirection>
  <VGpu>Disable</VGpu>
</Configuration>
```

**Verify the network is really off before unsealing anything.** Inside the sandbox:

```powershell
Test-NetConnection 1.1.1.1 -InformationLevel Quiet     # expect: fails or times out
ipconfig                                                # expect: no usable adapter, or APIPA only
```

**Checked before the sample is opened, not after.** A containment assumption that turns out to be
wrong is worse than none, because it changes how carefully the rest is done.

---

## 3. Get the tools in

They are small and dependency-free, so a second read-only mount is enough — or copy them onto the
sandbox's desktop at start-up, since a sandbox that has not yet opened a sample is still clean.

Inside the sandbox, the sample arrives **sealed**:

```powershell
python sample_vault.py list --dest C:\review\vault
python sample_vault.py extract <sealed.zip> --work C:\work
```

`pyzipper` is the one dependency. If it is missing, the vault **refuses and says so** rather than
falling back — the standard library cannot write encrypted zip members and will set the encrypted bit
on plaintext, which is why there is no fallback to have.

---

## 4. What to run, in order

```powershell
# what is it, structurally
python nanodesu.py info    C:\work\sample.exe

# unpack it. The extracted tree is readable hostile content -- it lives and dies with the sandbox.
python nanodesu.py extract C:\work\sample.exe -o C:\work\out --pyc

# what stands out, and hand the evidence to an engine
python torikago.py C:\work\sample.exe --handoff defender
```

**Use `--plain` if you want the tool to say nothing but the facts**: the persona is silenced and the
boundary notice stays, because the boundary is data rather than register.

**Read the boundary notice the first time.** It is four lines and one of them says that a clean
extraction proves nothing about safety, which is exactly the assumption a tidy-looking output invites.

---

## 5. Discard, do not clean

**Close the sandbox window.** Everything in it is deleted, including the unsealed sample and the
extracted tree. There is no wiping step to get wrong and no folder to forget.

If a full VM was used instead: **revert to the snapshot** rather than deleting files. The difference
matters because a snapshot revert cannot miss something.

**The sealed artifact on the host is untouched by any of this**, and it is the copy that stays: named
by its own hash, unreadable to a scanner, inert.

---

## What this procedure does not do

* **It does not make the sample safe to run.** It makes it safe to *look at*. Behaviour analysis —
  which means executing it — needs a disposable VM with no network and no shared folders, and that is a
  different exercise with a different risk profile.
* **It does not protect against a mistake made on the host.** If a sealed artifact is unsealed outside
  the sandbox, this procedure was not applied.
* **It does not survive carelessness with the mapping.** A read-write mount of a host folder, or a
  clipboard, is a path out. Both are switched off above for that reason.
* **It does not replace judgement about which samples to take.** That decision is the machine owner's,
  and no amount of isolation makes it for them.
