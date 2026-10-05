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
| **Windows Sandbox** | **yes** — closed window deletes everything | **no** (read-only mounts at best) | **no** | **Pro / Enterprise / Education only** |
| Hyper-V VM | yes, with snapshot discipline | no, if checkpoints and shared folders are off | yes | **also Pro and above** |
| VirtualBox / VMware | yes, with snapshot discipline | no, if shared folders are off | yes | **works on Home** — the pragmatic answer here |
| WSL | **no** | **shares the host filesystem** | no | **not an isolation boundary, by Microsoft's own statement** |
| A folder | no | — | — | it is a folder |

### Measured on this machine, 2026-10-06

**The table above is generic. This machine's actual situation is narrower:**

* **Windows 11 Home, build 26200.** `Get-WindowsOptionalFeature -Online -FeatureName
  Containers-DisposableClientVM` returns **nothing at all** — not an error, not a state. On Home the
  feature does not exist, so there is nothing to enable and no reboot that would help. **Windows
  Sandbox and Hyper-V are both unavailable for that reason**, not for a lack of privilege.
* **Virtualisation itself is fine**: `HypervisorPresent: True`, and WSL2 runs a distro
  (`wsl --status` → version 2). So the hardware and the platform are capable; only the
  disposable-Windows component is missing.
* **WSL is present and is therefore the temptation.** It has its own network namespace
  (`eth1 172.21.236.218/24`) — so the isolation is more real than "a folder" — but three things rule
  it out for this purpose, and the third is decisive:

  1. **Microsoft states WSL is not a security boundary**, and does not service vulnerabilities that
     cross it. An isolation the vendor will not stand behind is one you are relying on alone.
  2. **`/mnt/c` maps the host filesystem**, and interop can start Windows programs from the Linux side.
  3. **This WSL is a working environment** — a named distro with systemd running and development
     configuration. A container for samples should be one that has never held anything else.

**Conclusion for this machine: there is no available disposable isolation for Windows PE samples.**
The workflow below still describes the shape; the container it needs has to come from somewhere else.

---

## 1b. If no disposable isolation is available

**Do not unseal.** A sealed artifact is inert and useful — `nanodesu` cannot read inside it, but
`--handoff` can be pointed at the sealed zip, and the corpus can record its metadata. What is given up
is the static unpacking, which is real but is not worth doing on a machine you also browse from.

**The options that would restore it**, roughly in order of effort:

* **VirtualBox or VMware Workstation Player** — both work on Home, both are free for this use, and
  both give a snapshot to revert rather than files to delete. This is the shortest path from here.
* **A second physical machine**, or a spare SSD in this one, with a clean Windows install. Nothing
  beats a genuinely separate computer, and an offline one is better still.
* **Windows Pro** — the upgrade that makes Sandbox and Hyper-V exist. Worth stating plainly that it
  costs money, because "enable a feature" and "buy a licence" are different decisions.

**What is not an option, however convenient:** unsealing on the host and being careful. Care is not a
containment mechanism, and the failure mode is a single double-click.

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
