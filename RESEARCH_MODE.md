# Research mode: the one part of a security product's job this can honestly take on

## What a security centre does, and what it therefore cannot do

Real-time monitoring, behavioural interception, kernel-level components, a sample feed. None of that
is here and none of it is claimed. But one of its properties is structural rather than a matter of
capability:

> **A security centre detects and destroys. It has no research mode.**

Destroying detected malware is the correct behaviour for an antivirus. It is exactly wrong for
research, and the conflict is not theoretical — it was observed on this machine:

| observed | evidence |
|---|---|
| an EICAR test file was written to the quarantine directory | `ls` showed it, 70 bytes |
| **reading it failed** | `OSError: [Errno 22] Invalid argument` — Windows does this to files it has judged |
| **Defender had logged it twice** | `Get-MpThreatDetection` held two entries for that exact path, 23:43:11 and 23:43:24 |

**The sample existed and was unreadable.** The protection removed it from usefulness at the moment it
became interesting — not through malice or error, but because that is what it is for.

## The missing function, stated plainly

    security centre:  detect  ->  destroy  ->  done
    research mode:    detect  ->  preserve ->  judge -> a person decides

Research mode is not a weaker antivirus. It is the step that antiviruses are built to skip, and a
tool that unpacks unknown files is the right place for it because **the bytes are the whole point of
what it does**.

So this project does not replace a security centre. It **coexists with one**, by keeping samples in a
shape the protection cannot reach into:

* **Sealed at rest.** AES-encrypted zip, named by the sample's own sha256. A scanner cannot read inside
  one, so the bytes survive as a *candidate* until somebody deliberately opens it.
* **Unsealed on purpose, into a directory you delete.** Never in place — in place would put readable
  hostile bytes exactly where the protection is watching.
* **Judged by an engine, not by this.** `--handoff` asks Defender or ClamAV and reports **whose**
  verdict it is.
* **Recorded either way.** Fetch attempts, protection state at the time, and verdicts, in an
  append-only log. A failed fetch is a fact about the run too.

## The verification that is not optional

**An archive that only *looks* encrypted is worse than no archive**, because the operator leaves a
readable sample lying around believing it is sealed. The Python standard library makes this mistake
easy:

```python
info.flag_bits |= 0x1          # ask for encryption
zf.writestr(info, b"hello")    # ...and the data is written in PLAINTEXT
read back without a password: b"hello"
```

So every archive is **proved encrypted by failing to read it back without the password**. A write that
does not encrypt is reported as a failure and the file is deleted rather than left looking protected.

## Why this needs samples, which needs care

The judgement a research mode exists to preserve is only as good as the samples it sees, and this
project's own record is the argument: **every false positive it has found came from a real file and
none from a fixture** — .NET entropy, version strings parsed as IPs, random code matching at a sector
boundary, data-only modules called packed.

So samples are collected, under rules that exist for specific failures:

| rule | the failure it prevents |
|---|---|
| never inside a git repository | a sample in a repository gets committed eventually |
| never on `C:` | a sample survives a machine being handed on |
| never in the workspace or the cache area | it is one `git add -A` away from being published |
| sealed before it is stored | the protection removes it, which is how this section started |
| never executed, at any point | this tool does not run anything, and that is not negotiable |

`E:\Quarantine\` holds the tooling: `fetch/fetch_sample.py` (metadata by default, bytes only with
`--fetch`) and `fetch/sample_vault.py` (seal, list, unseal).

## What is still not claimed

* **A defanged variant is a variant, never a cure.** Editing a sample changes its hash and invalidates
  its signature, so it stops matching threat intelligence and AV caches — **it will always scan clean,
  not because it is clean but because nobody has seen it.**
* **Repair is per-sample, not a capability.** Cutting a malicious module out and supplying a working
  stub means knowing its exports, its calling convention and what the host expects. That is research
  on one sample by somebody who has studied it. Offered as a general feature it would be a lie about
  coverage.
* **A corpus of legitimate software cannot measure false negatives.** It can only show that detectors
  do not cry wolf on real, signed, ordinary files — which is 1,161 files' worth of evidence so far.
