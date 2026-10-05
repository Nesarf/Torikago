# Torikago 1.6.0

`--posture`: a read-only report on what is actually protecting this machine, and where it conflicts
with itself. It changes nothing.

## Why this and not something else

There is a real argument that security tooling should be able to **replace what a security centre
decides and does** — detection, verdict, quarantine, record. That is a competitor, not a
circumvention, and in one respect a tool can do it better: **it is auditable.**

What a tool cannot do is the other half. Real-time behavioural interception, kernel-level components
and a per-file-open hook are not things a static analyser has. **Claiming that role would promise
coverage that does not exist, and a user who believes it ends up less protected than one who never
heard the claim.** So this reports instead, and the boundary is written down rather than left implied.

## What it reports, and why each item is worth a line

* **Whether Defender's engine is watching, and whether it is the one doing the watching.** A
  third-party product can hold the Security Center registration while Defender's engine still answers
  scans — observed here: **Tencent PC Manager is registered alongside Defender**, so a clean
  "Defender found nothing" is weaker than it sounds.
* **Whether real-time protection is on**, across the separate fields that disagree with each other.
* **What is excluded from scanning.** An exclusion is *silent, permanent* protection loss that
  outlives the reason for it. Reported whether or not anyone remembers adding it.
* **What the machine has actually caught**, newest first — a machine described by its own history is
  more informative than one described by its current quiet.

## Read-only, and that is asserted

`Set-MpPreference`, `Add-MpPreference`, `Remove-MpPreference`, `Set-MpComputerStatus`, `Stop-Service`
— **none of them appear in the source**, and a test fails if one is added. A report that can modify
what it reports on is not a report, and a `Set-MpPreference` added later "for a good reason" would
silently turn this into something else.

A failed query is recorded as a failure, never smoothed into a default: **`signature age: unknown` and
`signature age: 0` mean opposite things**, and only one of them is reassuring.

## One thing it deliberately does not know

**It has no idea where samples are kept.** The vault check stayed beside the vault, because a shipped
package that knows the path to a malware collection is a package that leaks it. A test enforces the
absence — and the first version of that test banned the *word* "quarantine" and failed on its own
docstring prose, which is its own small lesson about testing words instead of facts.

## Testing

**220 tests** (was 207), green on Python 3.9, 3.12, 3.13 and 3.14. `test_posture.py` adds 13: no
setting-writing cmdlet anywhere, every section records its own failure, real-time protection off is
critical, a third-party registration is information rather than a fault, and an exclusion is a
warning.
