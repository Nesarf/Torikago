#!/usr/bin/env python3
"""Read-only report on what is actually protecting this machine, and where it conflicts with itself.

## Why this exists rather than "hack the security centre"

A tool that suppresses local protection makes **judgement** fail. Everything else in this project
makes judgement **more trustworthy** or the evidence more complete, and that is the line: a capability
whose obvious use is running something on a machine with the protection down is not built here.

But that is not the same as the argument in this file, which is real and defensible:

> **Replacing what a security centre *decides and does* is not the same as disabling it.**

Detection, verdict, quarantine, record — a tool can do all of that, and in one respect it can do it
better, because it is **auditable**. What it cannot do is the other half: real-time behavioural
interception, kernel-level components, a per-file-open hook. Claiming that would be promising coverage
that does not exist, and a user who believes it ends up less protected than one who never heard the
claim.

So this reports. It changes nothing.

## What it reports, and why each item is worth printing

* **Whether Defender's engine is actually watching.** A third-party product can hold the Security
  Center registration while Defender's engine still answers scans — observed on this machine, where
  Tencent PC Manager is registered alongside Defender. "Defender found nothing" then means much less
  than it sounds like, and the difference matters before it matters.
* **Whether real-time protection is on.** Three separate fields disagree with each other in practice.
* **What is excluded from scanning**, because an exclusion is invisible protection loss: somebody
  added it for a reason, forgot, and the machine has been less protected ever since. Printed whether
  or not this tool added it, and it is not added by this tool.
* **What has recently been detected**, so a machine can be described by its own history rather than by
  its current quiet.
Nothing here writes, sets, disables, adds or removes anything.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


# --------------------------------------------------------------------------- #
# The boundary
#
# Modelled on the same idea as the Tor/Firefox auditor: the notice travels verbatim with EVERY
# result, error paths included, because the failure mode it guards against is a reader taking a
# clean report as a statement about safety.
#
# A static audit can say what is configured. It cannot say what will happen.
# --------------------------------------------------------------------------- #

BOUNDARY_NOTICE = [
    "This tool performs a static audit only: it reads configuration and state, never launches a "
    "scanner, never changes a setting, and never touches the network.",
    "It does NOT address: whether protection actually detects anything. Real-time interception, "
    "behavioural blocking and kernel-level defence are not observable from here, and a product "
    "reporting itself active is not evidence that it is effective.",
    "It reports [registration, state flags, exclusions, and detection history]. It is NOT an "
    "antivirus, a firewall, or a replacement for either.",
    "A clean audit is NOT proof of safety. Treating it as one is a misuse. In particular, an "
    "empty exclusion list does not mean nothing is excluded, and a product listed as enabled "
    "does not mean it is watching.",
]


def _powershell(script: str, timeout: int = 120) -> tuple:
    """(ok, output). Console encoding forced to UTF-8 first: product names arrive in the system code
    page otherwise, and a garbled name is a wrong answer about which engine is watching."""
    if os.name != "nt":
        return False, "not Windows"
    cmd = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
           "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    out = (proc.stdout or b"").decode("utf-8", "replace")
    if proc.returncode != 0 and not out.strip():
        return False, (proc.stderr or b"").decode("utf-8", "replace")[-400:]
    return True, out


def defender_status() -> dict:
    """Whether Defender's engine is live, and whether it is the one doing the watching."""
    ok, out = _powershell(
        "$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; "
        "if ($s) { "
        "  Write-Output ('antivirus_enabled=' + $s.AntivirusEnabled); "
        "  Write-Output ('realtime=' + $s.RealTimeProtectionEnabled); "
        "  Write-Output ('behavior_monitor=' + $s.BehaviorMonitorEnabled); "
        "  Write-Output ('service_enabled=' + $s.AMServiceEnabled); "
        "  Write-Output ('signature_age_days=' + $s.AntivirusSignatureAge) "
        "} else { Write-Output 'defender=unavailable' }")
    result = {"ok": ok}
    if not ok:
        result["reason"] = out
        return _with_boundary(result)
    for line in out.splitlines():
        line = line.strip()
        if "=" in line:
            k, v = line.split("=", 1)
            result[k.strip()] = v.strip()
    return _with_boundary(result)


def registered_products() -> dict:
    """Everything registered with Security Center, and which of them is not Defender.

    The point is not the list. It is that a clean verdict from Defender means less when somebody else
    owns the registration, and that is only visible from here.
    """
    ok, out = _powershell(
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
        "ForEach-Object { Write-Output ('product=' + $_.displayName + '|' + $_.productState) }")
    result = {"ok": ok, "products": [], "third_party": []}
    if not ok:
        result["reason"] = out
        return _with_boundary(result)
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("product="):
            continue
        body = line[len("product="):]
        name, _, state = body.partition("|")
        result["products"].append({"name": name, "state": state})
        if "defender" not in name.lower():
            result["third_party"].append(name)
    return _with_boundary(result)


def exclusions() -> dict:
    """Paths and extensions excluded from scanning.

    Reported because an exclusion is silent, permanent protection loss: somebody added it for a good
    reason, forgot about it, and the machine has been less protected since. This tool never adds one —
    an encrypted container solves the same problem without lowering the protection on anything else.
    """
    ok, out = _powershell(
        "$p = Get-MpPreference -ErrorAction SilentlyContinue; "
        "if ($p) { "
        "  foreach ($x in $p.ExclusionPath) { Write-Output ('path=' + $x) }; "
        "  foreach ($x in $p.ExclusionExtension) { Write-Output ('ext=' + $x) }; "
        "  foreach ($x in $p.ExclusionProcess) { Write-Output ('proc=' + $x) } "
        "}")
    result = {"ok": ok, "paths": [], "extensions": [], "processes": []}
    if not ok:
        result["reason"] = out
        return _with_boundary(result)
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("path="):
            result["paths"].append(line[5:])
        elif line.startswith("ext="):
            result["extensions"].append(line[4:])
        elif line.startswith("proc="):
            result["processes"].append(line[5:])
    return _with_boundary(result)


def recent_detections(limit: int = 10) -> dict:
    """What this machine has actually caught, newest first.

    A machine described by its own history is more informative than one described by its current
    quiet, and this is also where an unexplained gap in the record would show up.
    """
    ok, out = _powershell(
        "Get-MpThreatDetection -ErrorAction SilentlyContinue | "
        "Sort-Object InitialDetectionTime -Descending | Select-Object -First %d | "
        "ForEach-Object { Write-Output ($_.InitialDetectionTime.ToString('s') + '|' + "
        "($_.Resources -join ';')) }" % limit)
    result = {"ok": ok, "detections": []}
    if not ok:
        result["reason"] = out
        return _with_boundary(result)
    for line in out.splitlines():
        line = line.strip()
        if "|" in line:
            when, _, what = line.partition("|")
            result["detections"].append({"at": when, "resources": what})
    return _with_boundary(result)


def _with_boundary(result: dict) -> dict:
    """Attach the notice to a result. Applied to every path, including failures.

    Wrapped rather than remembered: the first version attached it in one place, and a reader who
    takes an error result as a clean one gets exactly the false assurance the notice exists to
    prevent.
    """
    if isinstance(result, dict):
        result = dict(result)
        result["boundary_notice"] = BOUNDARY_NOTICE
    return result


def registration_audit() -> dict:
    """Contradictions between what registered products declare and what can be observed.

    Kept in its own module because it is the one part of this report that looks for something
    actively wrong rather than merely describing a state. It carries its own limits, and its own
    asymmetry: a contradiction means something, its absence means nothing.
    """
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import product_registration as pr
    except ImportError as exc:
        return {"ok": False, "reason": "product_registration is unavailable: %s" % exc}
    return _with_boundary(pr.audit_registrations())


def posture() -> dict:
    """Everything above, in one object. Read-only: no setting is written by any of it.

    The sample vault is deliberately *not* reported here. This module ships in a package and knows
    nothing about where anybody keeps samples; a tool that knows the path to a malware collection is
    a tool that leaks it. The vault check lives beside the vault.
    """
    return _with_boundary({
        "defender": defender_status(),
        "registered": registered_products(),
        "exclusions": exclusions(),
        "detections": recent_detections(),
        "registration_audit": registration_audit(),
        "read_only": True,
        "note": ("Nothing here changes a setting. This reports what is protecting the machine and "
                 "where it conflicts with itself; it does not alter any of it."),
    })


def findings(state: dict) -> list:
    """The parts of the report a person should act on, in plain language.

    Separated from the collection so the same facts can be read by a human or consumed by a script,
    and so the judgements are visible as judgements rather than buried in a status dump.
    """
    out = []
    defender = state.get("defender") or {}
    registered = state.get("registered") or {}
    exclusions_ = state.get("exclusions") or {}

    if defender.get("service_enabled") == "False" or defender.get("antivirus_enabled") == "False":
        out.append({"level": "critical",
                    "what": "Defender's engine reports itself disabled or not the antivirus provider"})
    if defender.get("realtime") == "False":
        out.append({"level": "critical",
                    "what": "real-time protection is OFF -- nothing is watching files as they open"})

    third = registered.get("third_party") or []
    if third and defender.get("antivirus_enabled") == "True":
        out.append({"level": "info",
                    "what": ("%s holds the Security Center registration alongside Defender, so a "
                             "'Defender found nothing' verdict is weaker than it sounds"
                             % ", ".join(third))})

    if exclusions_.get("paths"):
        out.append({"level": "warning",
                    "what": ("%d scanning exclusion path(s) are configured: %s. An exclusion is "
                             "silent protection loss that outlives the reason for it"
                             % (len(exclusions_["paths"]), ", ".join(exclusions_["paths"][:4])))})
    if exclusions_.get("processes") or exclusions_.get("extensions"):
        out.append({"level": "warning",
                    "what": "process or extension exclusions are configured"})

    detected = (state.get("detections") or {}).get("detections") or []
    if detected:
        out.append({"level": "info",
                    "what": ("%d recent detection(s) on record; newest: %s"
                             % (len(detected), detected[0].get("resources", "")[:90]))})
    return out


def main(argv=None) -> int:
    import argparse
    import sys

    ap = argparse.ArgumentParser(
        prog="security-posture",
        description="Read-only report on what is protecting this machine, where it conflicts with "
                    "itself. Changes nothing: no setting is written by any of it.")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    state = posture()
    if args.json:
        print(json.dumps(state, ensure_ascii=False, indent=1))
        return 0

    d = state["defender"]
    print("defender")
    print("  engine enabled     : %s" % d.get("antivirus_enabled"))
    print("  service enabled    : %s" % d.get("service_enabled"))
    print("  real-time          : %s" % d.get("realtime"))
    print("  behaviour monitor  : %s" % d.get("behavior_monitor"))
    print("  signature age      : %s day(s)" % d.get("signature_age_days"))
    print()
    print("registered with Security Center")
    for prod in state["registered"].get("products", []):
        print("  %-28s state=%s" % (prod["name"], prod["state"]))
    if not state["registered"].get("products"):
        print("  (none reported)")
    print()
    print("scanning exclusions  <- silent protection loss that outlives its reason")
    ex = state["exclusions"]
    print("  paths      : %s" % (", ".join(ex.get("paths", [])) or "(none)"))
    print("  extensions : %s" % (", ".join(ex.get("extensions", [])) or "(none)"))
    print("  processes  : %s" % (", ".join(ex.get("processes", [])) or "(none)"))
    print()
    print("findings")
    found = findings(state)
    if not found:
        print("  nothing to flag")
    for f in found:
        print("  [%-8s] %s" % (f["level"], f["what"]))
    print()
    print(state["note"])
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
