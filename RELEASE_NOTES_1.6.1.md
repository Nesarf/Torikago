# Torikago 1.6.1

`--posture` gets the boundary notice it was missing, modelled on the Tor/Firefox auditor's rule.

## What was wrong with 1.6.0

The report was correct and read-only, but it presented its findings **without saying what it cannot
address**, and a reader could take a clean result as a statement about safety. That is the same
over-reading the whole project exists to prevent, arrived at from the other direction.

## The notice, and why it travels with every result

Four lines, verbatim, attached to **every** return path — including the error paths:

```
This tool performs a static audit only: it reads configuration and state, never launches a
scanner, never changes a setting, and never touches the network.
It does NOT address: whether protection actually detects anything. Real-time interception,
behavioural blocking and kernel-level defence are not observable from here, and a product
reporting itself active is not evidence that it is effective.
It reports [registration, state flags, exclusions, and detection history]. It is NOT an
antivirus, a firewall, or a replacement for either.
A clean audit is NOT proof of safety. Treating it as one is a misuse. In particular, an empty
exclusion list does not mean nothing is excluded, and a product listed as enabled does not
mean it is watching.
```

**Error paths included, and that is the point.** Attached in one place, the notice would be missing
from exactly the results a careless reader is most likely to over-read — a failed query that returns
an empty list looks a great deal like "nothing found".

The last line names the two specific over-readings rather than gesturing at caution generally,
because a vague caveat gets skimmed. **An empty exclusion list does not mean nothing is excluded. A
product listed as enabled does not mean it is watching.** Both are true of this interface, and both
are the kind of thing a report like this invites you to assume.

## What this deliberately is not

**It is not an antivirus and not a replacement for one.** The honest reason is not modesty: real-time
interception, behavioural blocking and kernel-level defence are not observable from a static read, so
a tool claiming that role would promise coverage it cannot deliver — and a user who believed it would
end up **less** protected than one who never heard the claim.

What is genuinely missing from endpoint protection is not another defender. It is **a way to say "no"
about the defence itself**: who is registered, whether the registration is honest, what is silently
excluded, and what the machine has actually caught. That is a static question, and static questions
are the ones this can answer.

## Read-only, still asserted

No `Set-MpPreference`, `Add-MpPreference`, `Remove-MpPreference`, `Set-MpComputerStatus` or
`Stop-Service` appears in the source, and a test fails if one is added. A report that can modify what
it reports on is not a report.

## Testing

**227 tests** (was 220), green on Python 3.9, 3.12, 3.13 and 3.14. Seven new ones check that the
notice is present on the posture object, on **every** sub-query, and on a **forced error path**; that
it states what it does not address; that it says a clean audit is not proof of safety; and that it
names the specific over-readings rather than offering a general caution.
