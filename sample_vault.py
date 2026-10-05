#!/usr/bin/env python3
"""Keep samples as genuinely encrypted artifacts, so an active protection product cannot delete them.

## The problem, observed rather than imagined

An EICAR test string was written to the quarantine directory. `ls` showed it. **Reading it returned
`Errno 22 Invalid argument`**, and Windows Defender's threat history held two detections of that
exact path. The sample existed and was unreadable -- removed from usefulness by the protection that is
supposed to be on your side, at the moment it became interesting.

That is not a fault in the antivirus. Destroying detected malware is correct behaviour for an
antivirus and exactly wrong for research. **What is missing is a research mode**, and it is the one
piece of a security product's job a tool like this can honestly take on:

    security centre:  detect -> destroy -> done
    research mode:    detect -> preserve -> judge -> a person decides

A scanner cannot look inside an encrypted archive, so the bytes survive as a *candidate* until somebody
deliberately opens one.

## The trap this module exists to avoid

The Python standard library **cannot write encrypted zip members.** It will happily set the encrypted
bit, report success, and write the data in **plaintext**:

    >>> info.flag_bits |= 0x1; zf.writestr(info, b"hello")
    flag_bits encrypted = False      # the flag did not survive
    read back without a password: b"hello"

A container that looks encrypted and is not is **worse than no container**, because the operator
believes the sample is protected and leaves it lying around. So every archive this module writes is
**verified by attempting to read it back without the password**, and a write that does not actually
encrypt is reported as a failure rather than a success.

`pyzipper` is required and there is no fallback. A silent fallback to unencrypted storage is the exact
failure this file was written to prevent.

## Two hashes, both labelled

The archive has its own hash and the content has its own. Conflating them files a sample under a name
that describes the container, which is worse than no record.

The password is `infected` -- the convention the collection sites use. It is not a secret; it is a
protocol. The protection is that scanners do not open encrypted archives, not that the password is
hard to guess.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

SAMPLE_PASSWORD = b"infected"
SAMPLE_SUFFIX = ".zip"

try:
    import pyzipper
except ImportError:                                            # noqa: N816 - reported, not hidden
    pyzipper = None

NEEDS_PYZIPPER = (
    "pyzipper is required and there is no fallback: the standard library cannot write encrypted zip\n"
    "members and will silently produce a plaintext archive with the encrypted bit set, which looks\n"
    "protected and is not.\n"
    "  install it:  python -m pip install pyzipper"
)


def sha256_file(path: Path, *, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def is_encrypted_zip(path: Path):
    """Whether a zip actually encrypts, proven by failing to read it without the password.

    **Returns `None` when the question cannot be answered**, which is not the same as `False`. Found
    by listing a vault on an interpreter without `pyzipper`: every artifact was reported
    `encrypted=False` -- a confident statement that a genuinely sealed file was plaintext, produced
    by an inability to read it. Unknown is reported as unknown.

    The flag bit alone is not evidence, either way: the standard library sets it on plaintext.
    """
    if pyzipper is None:
        return None
    path = Path(path)
    try:
        if not path.is_file() or path.read_bytes()[:2] != b"PK":
            return False
    except OSError:
        return False
    try:
        with pyzipper.AESZipFile(path) as zf:
            names = [zi.filename for zi in zf.infolist()]
            if not names:
                return False
            try:
                zf.read(names[0])
            except Exception:                                  # noqa: BLE001 - any failure is proof
                return True
            return False           # it opened without a password, so it is not encrypted
    except Exception:                                          # noqa: BLE001
        return False


def store(sample: Path, dest_dir: Path, *, password: bytes = SAMPLE_PASSWORD) -> dict:
    """Seal a sample into an AES-encrypted zip under `dest_dir`, named by its content hash.

    The name is the sample's sha256, so the artifact identifies itself: opening the directory says what
    is there without consulting a database, and two copies of one sample cannot collide under
    different names.
    """
    if pyzipper is None:
        return {"ok": False, "reason": NEEDS_PYZIPPER}

    sample = Path(sample)
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    content = sha256_file(sample)
    out = dest_dir / (content + SAMPLE_SUFFIX)
    if out.exists():
        return {"ok": True, "path": str(out), "sha256": content, "stored": False,
                "encrypted": is_encrypted_zip(out), "why": "already present"}

    try:
        with pyzipper.AESZipFile(out, "w", compression=pyzipper.ZIP_DEFLATED,
                                 encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(password)
            zf.writestr(sample.name, sample.read_bytes())
    except OSError as exc:
        return {"ok": False, "reason": "could not write the archive: %s" % exc}

    # The verification is the point of the module. A write that did not encrypt is a failure, not a
    # success with a warning, because the operator would otherwise keep a plaintext sample believing
    # it is sealed.
    sealed = is_encrypted_zip(out)
    if sealed is None:
        # Could not verify. Refusing to keep an unverified container is right, but the reason must
        # not say it was unencrypted -- that would be a claim we cannot make either way.
        out.unlink(missing_ok=True)
        return {"ok": False,
                "reason": ("the archive could not be verified as encrypted, so it was deleted "
                           "rather than left in a state nobody can confirm"),
                "hint": NEEDS_PYZIPPER}
    if not sealed:
        out.unlink(missing_ok=True)
        return {"ok": False,
                "reason": ("the archive did not come out encrypted, so it was deleted rather than "
                           "left looking protected"),
                "hint": NEEDS_PYZIPPER}

    return {"ok": True, "path": str(out), "sha256": content,
            "archive_sha256": sha256_file(out), "archive_bytes": out.stat().st_size,
            "stored": True, "encrypted": True}


def extract(archive: Path, work_dir: Path, *, password: bytes = SAMPLE_PASSWORD) -> dict:
    """Unseal into a work directory the caller names. Never in place.

    In place would make the sample readable exactly where the protection is watching, which is the
    situation the encryption exists to avoid.
    """
    if pyzipper is None:
        return {"ok": False, "reason": NEEDS_PYZIPPER}
    archive = Path(archive)
    work_dir = Path(work_dir)
    if not is_encrypted_zip(archive):
        return {"ok": False, "reason": "%s is not an encrypted zip" % archive.name}
    work_dir.mkdir(parents=True, exist_ok=True)
    try:
        with pyzipper.AESZipFile(archive) as zf:
            zf.setpassword(password)
            names = zf.namelist()
            zf.extractall(work_dir)
    except Exception as exc:                                   # noqa: BLE001
        # A wrong password raises here, and it is worth naming: that is a configuration mistake, not
        # a corrupt sample, and the two need different responses.
        return {"ok": False, "reason": "could not unseal: %s" % exc}
    return {
        "ok": True, "work_dir": str(work_dir), "members": names,
        "note": ("this directory now holds readable hostile bytes and the protection can see them. "
                 "Analyse it, then delete the directory. Do not leave it in place."),
    }


def record(entry: dict, log: Path) -> None:
    """Append-only. An audit log that can be rewritten is not a record of what happened."""
    log = Path(log)
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")


def main(argv=None) -> int:
    import argparse
    import sys

    ap = argparse.ArgumentParser(
        prog="sample-vault",
        description="Seal and unseal research samples as AES-encrypted zips, so an active "
                    "protection product cannot delete the evidence.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("store", help="seal a sample into the vault")
    p.add_argument("sample")
    p.add_argument("--dest", default=r"E:\Quarantine\samples")

    p = sub.add_parser("list", help="what the vault holds")
    p.add_argument("--dest", default=r"E:\Quarantine\samples")

    p = sub.add_parser("extract", help="unseal one sample into a work directory (never in place)")
    p.add_argument("archive")
    p.add_argument("--work", required=True,
                   help="a directory you will delete afterwards; the bytes are readable there")
    args = ap.parse_args(argv)

    if args.cmd == "store":
        result = store(Path(args.sample), Path(args.dest))
        if not result.get("ok"):
            print("failed: %s" % result["reason"])
            return 1
        print("sealed   : %s" % result["path"])
        print("  content sha256 : %s" % result["sha256"])
        print("  archive sha256 : %s" % result.get("archive_sha256"))
        print("  encrypted      : %s" % result["encrypted"])
        if not result.get("stored"):
            print("  (%s)" % result["why"])
        return 0

    if args.cmd == "list":
        dest = Path(args.dest)
        if not dest.is_dir():
            print("no vault at %s" % dest)
            return 1
        rows = sorted(dest.glob("*" + SAMPLE_SUFFIX))
        if not rows:
            print("the vault is empty")
            return 0
        for r in rows:
            sealed = is_encrypted_zip(r)
            state = {True: "yes", False: "NO", None: "unknown (pyzipper not installed)"}[sealed]
            print("  %-70s %9d B  encrypted=%s" % (r.name, r.stat().st_size, state))
        print("\n%d artifact(s) in %s" % (len(rows), dest))
        return 0

    result = extract(Path(args.archive), Path(args.work))
    if not result.get("ok"):
        print("failed: %s" % result["reason"])
        return 1
    print("unsealed : %s" % result["work_dir"])
    for m in result["members"]:
        print("   %s" % m)
    print()
    print(result["note"])
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
