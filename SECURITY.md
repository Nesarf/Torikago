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
