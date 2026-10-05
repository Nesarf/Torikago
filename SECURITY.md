# Security policy

## The one rule

**The target is never executed.** Not on any code path; there is no `CreateProcess` call in
this tool and no flag that adds one. Unpacking and parsing are byte-level reads, so a sample
that is never allowed to run cannot act on the machine doing the analysis.

That is the whole safety argument, and it is also the thing to attack. **If you find any
path that runs, or could be made to run, the file under analysis, that is the most serious
bug this project can have.** Report it privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting (**Security → Report a vulnerability**). Please
do not open a public issue for something exploitable.

Useful in a report:

* what an attacker controls (the sample, a file name, an environment variable, the command line)
* the smallest input that demonstrates it
* what the tool does that it should not — executes something, writes outside its output
  directory, allocates or reads without bound, discloses data, hangs

I aim to acknowledge within a few days and to ship a fix with a test that fails without it.

## Untrusted input, and what that means here

Everything this tool reads is untrusted by definition: the sample, its file name, the strings
and structures inside it, and anything a wrapper produced when unpacked. The classes worth
attacking:

* **Parser robustness.** Every structure is attacker-shaped. A malformed PE, a declared
  section size larger than the file, an import table pointing at itself, a boot sector with
  impossible geometry — none of these should crash, hang, or read out of bounds.
* **Resource bounds.** No input should cause unbounded memory use or an unbounded loop. A
  single-file analysis loads the whole file, so a size guard refuses anything above 768 MB by
  default (peak memory runs about twice the file size; a 300 MB file measured 600 MB and 62
  seconds). `--max-bytes` raises the limit and `--force` overrides it, both deliberately
  explicit. Inside a directory scan, only the first 4 MB of each file is read. A crafted input
  that defeats either bound is a finding.
* **Paths.** Output paths are derived from names in the tool's own control, never from a name
  inside a sample. The one place a sample's names become paths is the unpack step, which
  delegates to Nanodesu — where a path traversal bug was found and fixed in 1.1.0 (nine
  vectors, regression-tested). If you find another route by which a sample's contents decide
  where something is written, that is a bug of the same class.
* **Subprocess handling.** ClamAV is invoked as an argument list, never through a shell, and
  the tool has no other subprocess. A sample name containing shell metacharacters must not
  become a command.
* **Integration output.** The MISP event and STIX bundle embed attacker-controlled strings.
  They are emitted as XML and JSON through the standard library's serialisers, not by string
  concatenation; a sample that can inject structure into either output is a finding.

## Claims this tool will not make, even if asked to

These are not limitations to be worked around later. They are the properties that make the tool
trustworthy, and weakening one would make it worse rather than more capable.

### It will never say a file is safe

It reports what is **in** a file. It does not conclude that the file is **harmless**, and no result
it produces should be read that way — including a clean verdict from a judgement engine it handed
the file to, which is that engine's opinion about a sample and not a property of your machine.

The distinction is not pedantry. `AV engine found nothing` and `this is harmless` differ in every
case where the sample is new, packed, or targeted, which is exactly the case this tool exists for.

### It may build a defanged variant, but never call it a cure

There is a real capability here and it is worth having: take a sample, cut out the hostile parts, fill
the gaps so the program still runs, and keep the result. On a PyInstaller build this is more tractable
than it sounds, because the payload lives at the **Python** level — replacing a malicious `.pyc` in the
PYZ with a stub that does nothing is a far smaller act than surgery on machine code.

So the tool offers it (`nanodesu neutralize`), under constraints that are not negotiable, because
without them the output is worse than useless:

1. **The original is never modified, moved, or deleted.** The sample is the only thing a real engine
   can still judge, and it stays exactly where it was. The variant is a new file.
2. **Every change is recorded**, byte range by byte range, with what was there before — and the record
   is enough to reverse the transformation. That is the difference between a transformation and an
   act of faith.
3. **The output is never described as clean, safe, or fixed** — not in the code, not in the report,
   not in the file's name. It is a *variant*, and the name says so.
4. **The report states what could not be verified.** A stub proves a module no longer runs; it does
   not prove nothing else in the file is hostile.

**Why the naming discipline is the whole point.** Editing a signed binary invalidates its signature,
and changing the bytes changes the hash — so a modified sample stops matching threat intelligence,
blocklists and AV caches. It will therefore *always scan clean*. Not because it is clean, but because
**nobody has seen it** — and the tool would be manufacturing files that no engine flags while calling
that a result. The difference between `I removed the malicious code` and `this is now safe` is the
difference between a real capability and one that gets somebody hurt.

### It will not replace your antivirus

Windows Security Center is backed by real-time monitoring, behavioural interception, kernel-level
components and a sample feed that no Python unpacker has. Claiming that role would mean promising
coverage that does not exist, and a user who believes it will be less protected than one who never
heard the claim.

What this tool does instead is the part it can do honestly: **hand the evidence to the engine that is
actually running on your machine and report that engine's verdict, attributed.** `--handoff` exists
for that and for nothing more.

## What this tool explicitly does not defend against

* **Running the sample.** It will not, and it cannot be asked to. If you need behaviour, that
  belongs in a disposable VM with no network — and a sandbox is not this tool's claim.
* **Being a sandbox.** A user-mode process cannot contain a kernel-level adversary. Nothing
  here isolates a running sample, because nothing here runs one.
* **Memory-only payloads.** A payload that never touches disk leaves no file to open.
* **Whatever you run afterwards.** If you unpack a sample and then execute what you found,
  the tool's safety property no longer applies to you. The report says what is inside; the
  decision is made outside this tool.

## Supply chain

* **No third-party dependencies.** Standard library only, so there is no tree to compromise,
  and `pip install .` pulls nothing.
* **No network access.** No reputation lookups, no telemetry. The tool works air-gapped by
  design, which is also why it is safe to run on an isolated analysis host.
* **ClamAV is optional and detected, never bundled or downloaded.** If it is absent, the tool
  says so and continues.
* **CI actions are pinned to commit SHAs** and the CI token is read-only.
