"""Contradictions between what a protection product declares and what can be observed.

## What this can and cannot do, stated before the code

**It cannot tell you a product is fake.** That needs a signature database and a sample corpus, and a
tool without either would be guessing. What it *can* do is find cases where **a product's own
declaration is contradicted by an observable fact** — which is a narrower claim and a true one.

The mechanism it audits is self-declared by design. A product registers with Security Center, states
that it is enabled and providing real-time protection, and **Windows turns Defender off in response**.
That is documented behaviour, not a flaw: it is how any third-party antivirus takes over. The flaw is
that **nothing verifies the declaration**.

Two public tools abuse exactly that:

* **`no-defender`** (2024) registered a fake antivirus that protected nothing. Defender stood down.
  The machine was left with no protection at all. It was removed after a DMCA claim from the vendor
  whose code it reused.
* **`Defendnot`** (2025) rebuilt it without third-party code, and **injected its fake DLL into
  `Taskmgr.exe`** — a Microsoft-signed process the system already trusts — to get past the
  registration checks. Defender switched off. (Kaspersky's write-up, `es3n1n/defendnot` on GitHub.)

Both leave a shape this can look for: **a product whose declared executable is a well-known
non-security system binary**, which is what injecting into a trusted process looks like from here.

## The asymmetry, and why it is written into the output

**Finding a contradiction means something. Finding none means nothing.** A convincing fake would
declare a plausible signed path that exists and runs, and would pass every check below. So the report
says which of the two it did, every time, in words — the same rule the rest of this project follows.

## Provenance

The shape — a self-declared state audited against independently observable facts, with the
non-conclusion stated explicitly — is modelled on Aragami's layer assessment, which requires each
layer to name what it does not cover. Adapted, not copied.
"""
from __future__ import annotations

import os
from pathlib import Path

# Binaries that are Microsoft-signed, trusted, and are *not* security products. A protection product
# declaring one of these as its executable is the signature of an injected fake: this is the list the
# DLL-injection approach would produce, because it has to point somewhere the system already trusts.
TRUSTED_BUT_NOT_SECURITY = (
    "taskmgr.exe", "notepad.exe", "explorer.exe", "cmd.exe", "powershell.exe",
    "calc.exe", "mspaint.exe", "regedit.exe", "control.exe", "rundll32.exe",
    "svchost.exe", "dllhost.exe", "conhost.exe", "msiexec.exe", "wscript.exe",
    "cscript.exe", "hh.exe", "write.exe", "charmap.exe", "cleanmgr.exe",
)

# productState is a packed integer whose full layout is not officially documented. Only one bit is
# decoded, and it was derived by measurement rather than looked up:
#
#   Defender   0x61100  = bits 8, 12, 16, 18   -- and Defender's own API reports
#                                                RealTimeProtectionEnabled = True
#   Tencent    0x40000  = bit 18 only           -- does not set bit 12
#
# Bit 12 is therefore the real-time flag, and its ABSENCE is deliberately not treated as a
# contradiction: a product may simply not report that bit, and this cannot tell the difference
# between "off" and "not stated". Unknown is reported as unknown.
STATE_REALTIME_ON = 1 << 12      # 0x1000, derived above

# The absent-flag message is a module constant so it can be asserted as a *value*. Reading it out of
# the source file instead measures the quoting and line breaks of the literals, not the sentence --
# a search for "cannot tell" against the raw file fails because the adjacent pieces are
# `"this cannot "` / `"tell the two apart"` and the quotes become tokens.
REALTIME_FLAG_ABSENT = (
    "productState has no bit-12 real-time flag. That may mean the product is not claiming real-time "
    "protection, or that it does not report that bit; this cannot tell the two apart.")



def _powershell(script: str, timeout: int = 120):
    import subprocess
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


def registered_products_detailed() -> dict:
    """Every registered product with the fields needed to check its declaration.

    `pathToSignedProductExe` is the interesting one: it is a claim about which file represents the
    product, and a file either exists or does not. Note that Defender's own entry is a URI
    (`windowsdefender://`) rather than a path, so a naive existence check would produce a false
    positive on the one product that is certainly real.
    """
    ok, out = _powershell(
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
        "ForEach-Object { Write-Output ("
        "$_.displayName + [char]1 + $_.productState + [char]1 + $_.instanceGuid + [char]1 + "
        "$_.pathToSignedProductExe + [char]1 + $_.pathToSignedReportingExe) }")
    result = {"ok": ok, "products": []}
    if not ok:
        result["reason"] = out
        return result
    for line in out.splitlines():
        line = line.strip()
        if not line or "\x01" not in line:
            continue
        parts = line.split("\x01")
        while len(parts) < 5:
            parts.append("")
        name, state, guid, exe, reporting = parts[:5]
        try:
            state_int = int(state)
        except ValueError:
            state_int = None
        product = {
            "name": name,
            "product_state": state_int,
            "instance_guid": guid,
            "declared_executable": exe,
            "declared_reporting_executable": reporting,
            "declares_realtime": bool(state_int & STATE_REALTIME_ON) if state_int else None,
        }
        product.update(check_declaration(product))
        # Observed and labelled as an observation, not as a finding: bit 12 absent means either the
        # product is not claiming real-time protection or it does not report that bit, and this
        # cannot distinguish the two.
        if state_int is not None and not (state_int & STATE_REALTIME_ON):
            product["realtime_flag_absent"] = REALTIME_FLAG_ABSENT
        result["products"].append(product)
    return result


def check_declaration(product: dict) -> dict:
    """Compare one product's declaration against facts that can be checked from here.

    Returns what was found and, importantly, what the finding does and does not mean.
    """
    exe = (product.get("declared_executable") or "").strip()
    out = {"checks": [], "contradictions": []}

    if not exe:
        out["checks"].append("no executable declared")
        return out

    # A URI rather than a path is a legitimate declaration -- Defender itself uses one -- so it is
    # neither a contradiction nor a pass.
    if "://" in exe:
        out["checks"].append("declared executable is a URI, not a path: not checkable as a file")
        return out

    path = Path(exe)
    if not path.is_file():
        out["checks"].append("declared executable does not exist")
        # Only a contradiction if the product simultaneously claims to be protecting right now.
        if product.get("declares_realtime"):
            out["contradictions"].append(
                "declares real-time protection active while its declared executable is missing")
        return out

    out["checks"].append("declared executable exists")
    if path.name.lower() in TRUSTED_BUT_NOT_SECURITY:
        out["contradictions"].append(
            "declares itself the protection product while pointing at %s, a signed Microsoft "
            "component that is not security software -- which is what an injected fake would "
            "produce, because it must point at something the system already trusts"
            % path.name)
    return out


def observed_services() -> dict:
    """Running services whose path mentions any registered product's name or directory.

    Used only to answer "is there something running that could be this product". An absence is
    reported as an absence rather than as proof, because a product may legitimately run as a driver
    or under a name that shares nothing with its display name.
    """
    ok, out = _powershell(
        "Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' } | "
        "ForEach-Object { Write-Output ($_.Name + [char]1 + $_.PathName) }")
    result = {"ok": ok, "services": []}
    if not ok:
        result["reason"] = out
        return result
    for line in out.splitlines():
        line = line.strip()
        if "\x01" in line:
            name, _, path = line.partition("\x01")
            result["services"].append({"name": name, "path": path})
    return result


def matching_service(product: dict, services: list) -> dict:
    """Whether any running service plausibly belongs to this product.

    Matched on the product's directory name and on distinctive words from its display name, because
    a display name is localised while a path is not.
    """
    exe = (product.get("declared_executable") or "")
    tokens = set()
    if exe and "://" not in exe:
        parts = Path(exe).parts
        # The vendor directory, and only that. An earlier version also matched words from the
        # display name, which matched "Windows Defender" against a service called Appinfo because
        # both contain "windows" -- a false positive produced by the matcher, not by the machine.
        if len(parts) >= 2:
            tokens.add(parts[-2].lower())
    generic = {"windows", "system", "program", "files", "common", "microsoft",
               "programs", "x86", "defender", "security", "antivirus", "protection"}
    for word in (product.get("name") or "").replace("(", " ").replace(")", " ").split():
        if len(word) >= 6 and word.lower() not in generic:
            tokens.add(word.lower())
    if not tokens:
        return {"matched": None, "reason": "nothing distinctive to match on"}
    for svc in services:
        blob = ("%s %s" % (svc.get("name", ""), svc.get("path", ""))).lower()
        for token in tokens:
            if token and token in blob:
                return {"matched": svc["name"], "on": token}
    return {"matched": None}


def audit_registrations() -> dict:
    """The whole check, with its own limits stated in the result.

    Any of these checks passing means **nothing**. A convincing fake declares a plausible signed path
    that exists and runs, and passes every one of them. Only a contradiction carries information,
    and the result says so rather than leaving the reader to infer it.
    """
    detailed = registered_products_detailed()
    services = observed_services()
    out = {
        "ok": detailed.get("ok", False) and services.get("ok", False),
        "products": [],
        "contradictions": [],
        "limits": [
            "This checks a product's declaration against observable facts. It does not verify that "
            "any product works, and it has no signature database.",
            "Finding a contradiction means something. Finding none means nothing: a convincing fake "
            "declares a plausible signed executable that exists and runs, and passes every check here.",
            "An absence of a visible service is not proof of absence -- a product may run as a "
            "kernel driver, or under a name sharing nothing with its display name.",
        ],
    }
    if not out["ok"]:
        out["reason"] = detailed.get("reason") or services.get("reason")
        return out

    for product in detailed["products"]:
        entry = dict(product)
        entry["observed_service"] = matching_service(product, services["services"])
        if not entry["observed_service"].get("matched") and product.get("declares_realtime"):
            entry["notes"] = ["declares real-time protection but no running service matches it"]
        out["products"].append(entry)
        for c in product.get("contradictions", []):
            out["contradictions"].append({"product": product["name"], "what": c})
        # A missing declared executable is recorded as an observation even when the product is not
        # claiming real-time protection -- the fact is still worth having, it just does not prove a
        # false declaration. Keeping it under "observations" rather than dropping it is the
        # difference between a report that is cautious and one that is useless.
        for check in product.get("checks", []):
            if "does not exist" in check:
                out.setdefault("observations", []).append({
                    "product": product["name"],
                    "what": ("declares %s, which does not exist on this machine"
                             % product.get("declared_executable")),
                })
    return out
