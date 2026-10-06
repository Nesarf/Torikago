# Torikago 1.20.0

The invariant everything else rests on, now defended instead of merely true.

## It held by accident

`"Never runs the target."` was stated in two documents and one argparse help string, and **nothing
checked it.** It held because nobody had written the path — a property of the code as it happens to be,
not a property anyone was defending. The whole tool is auditable only while that stays true, and both
personas rest on it as well: she has the eye and the binding and no digestion, and **that constraint is
where the character's tension comes from.**

## Three attempts, and the first two are the lesson

**The first version** inspected only literal argv and skipped computed ones. Injecting
`subprocess.run([str(path)])` — **which is exactly what running the target looks like** — left the file
green. It audited the easy half.

**The second version** collected assignments file-wide, which merged same-named variables from different
functions: `exe` is a passed-in tool in one function and a path join in another.

**This version resolves per function**, because that is where a name means something. It inspects every
spawning call in eight modules, requires argv[0] to resolve to a known tool, and **trusts the
runtime-found programs (`find_defender`, `find_clamav`) only because a companion test asserts neither
can see a target parameter.** A reassuring name is not evidence.

**Verified against the regression:** the injected call now fails the test with
`argv[0] is str()`.

## What the audit found, for the record

Six spawning calls exist, and every one of them either **asks the machine a question** (PowerShell for
Defender settings, Security Center registration) or **hands a file to a scanner that reads it**
(`MpCmdRun.exe -Scan -File`, `clamscan`). **No call takes a program to run.**

## Two things the tests had to be taught, both from evidence

**The report field is `executed_target`, not `executed`.** The first assertion used the guessed name,
found nothing, and **would have passed a report that ran the file in a differently-named field.**

**A bare "execut" substring was too wide.** It caught `sections[0].executable` — a PE characteristic
bit, a format field rather than a claim about this tool — and `unpack_plan[0].needs_execution`, which
is **the opposite of a violation**: it says a step *would* require running the sample and that **this
tool will not do it**, pointing at a disposable VM. Removing that pairing would be the actual
regression, so there is now a test that it stays.

## Testing

**375 tests** (was 368), green on Python 3.9, 3.12, 3.13 and 3.14. Seven new, and the central one is
**verified to fail against the regression it exists to catch** — which the two previous attempts were
not.
