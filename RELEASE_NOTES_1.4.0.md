# Torikago 1.4.0

Hand the evidence to the engine that is actually running, and never claim its verdict as your own.

## `--handoff`

```bash
torikago suspect.exe --handoff defender          # or clamav, or both
```

Torikago reaches no conclusion about whether a file is malicious — that is the whole reason it is
useful — but "we do not judge; we hand it to something that does" is only real if the something is
reachable. ClamAV was already wired up; this adds **Windows Defender**, the engine genuinely installed
on the machine most users of this tool are on.

Three decisions, each the difference between a tool and a liability:

**`-DisableRemediation` is not optional.** Without it, `MpCmdRun -Scan -ScanType 3` deletes or
quarantines the file as a side effect of being asked for an opinion. A diagnostic tool must never
destroy what it is reporting on. That flag is the difference between a question and an action, and it
is asserted by a test rather than trusted.

**The verdict is reported as the engine's.** `Defender says clean` and `this is clean` are different
sentences, and a test checks that no result field is named as though it were our own detection.

**A third-party antivirus owning the Security Center registration is reported, not worked around.**
On this machine that is not hypothetical — **Tencent PC Manager** holds the registration alongside
Defender, so "Defender found nothing" would be a false reassurance about what is actually watching.
The product list is queried and stated.

## Two defects found while building it

**A missing engine returned `ok: True`.** Pointing `--handoff` at an MpCmdRun that does not exist
produced a successful-looking result with an empty verdict list — **which a reader would take as "it
found nothing."** That is the single most dangerous way this function can fail: the reader concludes a
file is clean when in fact nobody looked at it. It now returns `ok: False` unless a verdict was
actually obtained, matching `scan_with_clamav`.

**Product names arrived as mojibake.** PowerShell emits in the system code page — cp936 on a Chinese
Windows — so `腾讯电脑管家系统防护` was read as replacement characters. A garbled name is a wrong
answer about which engine is watching, so the console output encoding is forced to UTF-8 first.

## The boundary, written into SECURITY.md

This release also adds the claims the tool will not make, because a capability like `--handoff` is
exactly where discipline erodes:

* **It will never say a file is safe** — including on the strength of a clean verdict from an engine
  it handed the file to. That is the engine's opinion about a sample, not a property of your machine.
* **It does not replace your antivirus.** Real-time monitoring, behavioural interception and a sample
  feed are not things a Python unpacker has. A user who believes otherwise ends up less protected.
* **A defanged variant is a variant, never a cure.** Editing a sample changes its hash and invalidates
  its signature, so it stops matching threat intelligence and AV caches — **it will always scan clean,
  not because it is clean but because nobody has seen it.**

## Testing

**189 tests** (was 176), green on Python 3.9, 3.12, 3.13 and 3.14. `test_handoff.py` adds 13, and they
skip cleanly where no engine is installed: remediation stays disabled, the file still exists
afterwards, the attribution note is present, a missing engine is reported rather than reported as
clean, and product names decode rather than turning into garbage.
