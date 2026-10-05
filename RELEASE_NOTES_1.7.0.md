# Torikago 1.7.0

`--posture` now audits the endpoint-protection registration itself: **contradictions between what a
product declares and what can be observed**.

## The mechanism, and why it is worth auditing

A product registers with Windows Security Center, states that it is enabled and protecting in real
time, and **Windows turns Defender off in response**. That is documented behaviour and it is how any
third-party antivirus takes over — **what is not verified is the declaration.**

Two public tools abuse exactly that:

* **`no-defender`** (2024) registered a fake antivirus that protected nothing. Defender stood down and
  the machine was left with no protection at all. Removed after a DMCA claim.
* **`Defendnot`** (2025) rebuilt it without third-party code and **injected its fake DLL into
  `Taskmgr.exe`** — a Microsoft-signed process the system already trusts — to get past the
  registration checks. Defender switched off.

The second is why *"declares itself the protection product while pointing at a signed Microsoft
component that is not security software"* is a named contradiction: **it is what injection looks like
from the outside.**

## What it checks, and the asymmetry it states every time

| check | what it catches |
|---|---|
| declared executable missing **while claiming real-time protection** | the declaration is contradicted by the filesystem |
| declared executable is a signed non-security component (`taskmgr.exe`, `svchost.exe`, …) | the `Defendnot` shape |
| no running service matches the product's vendor directory | recorded as a note, **never as proof** |

**Finding a contradiction means something. Finding none means nothing.** A convincing fake declares a
plausible signed path that exists and runs and passes every check. That sentence is in the output, not
only in the docs — the same rule the rest of this project follows.

## Four things this got wrong first, all kept in the code

**The path was parsed with the host's rules, not Windows'.** CI is a Linux runner, where
`pathlib.Path(r"C:\Windows\System32	askmgr.exe").name` is **the entire string** — a backslash is
not a separator there. So the trusted-component check could never fire, and **it worked perfectly on
Windows, which is precisely why it shipped**. Registration always holds a Windows path, so parsing
now uses `PureWindowsPath` regardless of platform. This is the second bug CI found and the development
machine could not.

**The vendor directory was the immediate parent.** In the common layout
(`…\Tencent\QQPCMgr.11.28973.206\QQPCMgr.exe`) that is the *version* folder, so no service could
ever match. It now walks up to the first non-version, non-generic component — caught by a test, not by
the machine.

**The name check depended on the file existing.** `C:\Windows\System32	askmgr.exe` is not a file
on a Linux runner, so the existence branch returned early and **the Defendnot shape was never
reached** — CI failed on the assertion and was right to. The defect was in the check rather than only
in the test: an injected fake *must* point at a trusted component, and that is visible in the **name**
whatever the platform thinks of the path. The name check now runs first and independently.

**The productState bit layout was guessed.** The format is not officially documented. The flag is now
**derived by measurement**: Defender's `0x61100` has bit 12 set and Defender's own API reports
`RealTimeProtectionEnabled = True`, so bit 12 is the real-time flag. **An absent flag is reported as
ambiguous, never as "off"** — a product may simply not report that bit, and this cannot tell the
difference. Tencent's entry on this machine is exactly that case.

**The service matcher cried wolf.** It matched "Windows Defender" against a service called `Appinfo`
because both contain "windows". That is a false positive produced by the matcher, not by the machine.

**A source-text assertion measured quoting, not meaning.** One test searched the module's own text for
a sentence that is assembled from adjacent string literals; the quotes between them became tokens and
the search failed on the file's formatting. The message is now a module constant and the test asserts
its **value**.

## Observed on this machine

**Tencent PC Manager holds the Security Center registration alongside Defender**, and its declared
executable (`…\QQPCMgr\17.11.28973.206\QQPCMgr.exe`) **does not exist**. It carries no real-time flag,
so this is recorded as an **observation** and not as a contradiction — the fact is worth having, and it
does not prove a false declaration. Keeping that distinction is the difference between a report that is
cautious and one that is useless.

## Read-only, still asserted

No setting is written by any of this. It queries WMI, the filesystem and a service list.

## Testing

**242 tests** (was 227), green on Python 3.9, 3.12, 3.13 and 3.14. `test_product_registration.py` adds
15: every trusted-but-not-security binary is caught, a URI is not mistaken for a missing file, a
missing executable without a real-time claim is not a contradiction, the generic-word matcher
regression is covered, and the asymmetry is asserted to be present in the output rather than only in
the documentation.
