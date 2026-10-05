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
import re
import json
from pathlib import Path

SAMPLE_PASSWORD = b"infected"

# Caps on unsealing. A sealed container is the one input nobody can inspect before opening, so the
# limits are enforced from the headers first and again while writing -- a header can lie.
MAX_MEMBERS = 64
MAX_TOTAL_BYTES = 1 << 30          # 1 GiB decompressed, across all members
MAX_MEMBER_BYTES = 512 << 20       # 512 MiB for any single member

# Names that address devices rather than files on Windows. Writing to one either fails or does not
# create a file at all, and a corpus entry recorded as extracted when nothing was written is worse
# than a refusal.
_DEVICE_NAMES = frozenset(
    ["CON", "PRN", "AUX", "NUL"]
    + ["COM%d" % i for i in range(1, 10)]
    + ["LPT%d" % i for i in range(1, 10)])
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


def _is_absolute_or_escaping(name: str) -> str | None:
    """Why a member name is unsafe, or None. Returned as a reason so the caller can report it.

    **The name is untrusted even though the container is ours.** It was written by whoever uploaded
    the sample, and `extractall()` does exactly what the names say -- so `../../x` writes wherever the
    user has permission. The first version of `extract()` called `extractall()` after checking only
    that the archive was encrypted, which is a check of the container and not of its contents.
    """
    if not name or name in (".", ".."):
        return "empty or relative to nothing"
    # Both separators, because a Windows host treats either as one and zip stores forward slashes.
    normalised = name.replace("\\", "/")
    if normalised.startswith("/") or re.match(r"^[A-Za-z]:", normalised):
        return "absolute path"
    if any(part == ".." for part in normalised.split("/")):
        return "contains a parent-directory segment"
    return None


def _safe_member_name(name: str) -> str:
    """A name safe to create on Windows and inside the work directory.

    Device names are handled because they are not filenames at all: `NUL`, `CON`, `PRN`, `AUX`,
    `COM1`-`COM9` and `LPT1`-`LPT9` address devices, so writing to them either fails or goes somewhere
    that is not a file -- **and a corpus entry that silently wrote to a device would be recorded as
    extracted**. The suffix trick is used rather than replacement, so two members cannot collide into
    one after sanitising.
    """
    parts = []
    for piece in name.replace("\\", "/").split("/"):
        piece = re.sub(r'[<>:"|?*\x00-\x1f]', "_", piece).strip(" .")
        if not piece:
            continue
        stem = piece.split(".", 1)[0].upper()
        if stem in _DEVICE_NAMES:
            piece = "_" + piece
        parts.append(piece)
    return "/".join(parts) or "_unnamed"


def is_encrypted_zip_cheaply(path: Path) -> bool:
    """Whether the zip's own directory says its members are encrypted. No password needed.

    **This exists because `is_encrypted_zip` answers `None` when `pyzipper` is missing, and `not None`
    is `True`** -- so a caller that treated the three-state result as a boolean concluded "not
    encrypted" from "could not check", and a genuinely AES-sealed sample was handled as plaintext.
    That is the same substitution the three-state return was introduced to prevent, made one layer
    down by a caller that ignored the third state.

    The central directory carries the answer and this reads it directly: the general-purpose
    encryption bit, and compression method 99 (WinZip AES). **Weaker evidence than failing to read
    the file** -- it is what the archive claims -- but it needs no dependency, and it is enough to
    decide whether to demand one.
    """
    import zipfile
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if not infos:
                return False
            return any((i.flag_bits & 0x1) or i.compress_type == 99 for i in infos)
    except (zipfile.BadZipFile, OSError):
        return False


def extract(archive: Path, work_dir: Path, *, password: bytes = SAMPLE_PASSWORD,
            max_members: int = MAX_MEMBERS, max_total_bytes: int = MAX_TOTAL_BYTES,
            max_member_bytes: int = MAX_MEMBER_BYTES) -> dict:
    """Unseal into a work directory the caller names. Never in place.

    In place would make the sample readable exactly where the protection is watching, which is the
    situation the encryption exists to avoid.

    **Members are written one at a time, after checking the name.** `extractall()` is not used: it
    trusts the archive's own names, which is the definition of a zip slip. Every member is also
    counted and sized against caps, because "it is only one sample" is an assumption about a file
    that arrives sealed precisely so nobody can check it in advance.
    """
    if pyzipper is None:
        return {"ok": False, "reason": NEEDS_PYZIPPER}
    archive = Path(archive)
    work_dir = Path(work_dir)
    if not is_encrypted_zip(archive):
        return {"ok": False, "reason": "%s is not an encrypted zip" % archive.name}
    work_dir.mkdir(parents=True, exist_ok=True)
    root = work_dir.resolve()

    written, refused = [], []
    total = 0
    try:
        with pyzipper.AESZipFile(archive) as zf:
            zf.setpassword(password)
            infos = zf.infolist()
            if len(infos) > max_members:
                return {"ok": False, "reason": "the archive holds %d members, over the cap of %d"
                                               % (len(infos), max_members),
                        "members_found": len(infos), "members_limit": max_members}
            declared = sum(i.file_size for i in infos)
            if declared > max_total_bytes:
                # Checked from the headers first, so a declared-bomb is refused before any byte is
                # decompressed rather than after the disk is full.
                return {"ok": False,
                        "reason": "the archive declares %d bytes, over the cap of %d"
                                  % (declared, max_total_bytes),
                        "declared_bytes": declared, "total_limit": max_total_bytes}

            for info in infos:
                name = info.filename
                why = _is_absolute_or_escaping(name)
                if why:
                    refused.append({"member": name, "why": why})
                    continue
                safe = _safe_member_name(name)
                target = root / safe
                # Belt to the sanitizer's braces: resolve and confirm, because a sanitiser that is
                # subtly wrong is exactly the sort of thing that looks fine until it is not.
                try:
                    resolved = target.resolve()
                    if resolved != root and root not in resolved.parents:
                        refused.append({"member": name, "why": "resolves outside the work directory"})
                        continue
                except OSError:
                    refused.append({"member": name, "why": "path could not be resolved"})
                    continue

                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if info.file_size > max_member_bytes:
                    refused.append({"member": name, "why": "declares %d bytes, over the per-member "
                                                          "cap of %d" % (info.file_size,
                                                                         max_member_bytes)})
                    continue

                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as dst:
                    while True:
                        block = src.read(1 << 20)
                        if not block:
                            break
                        total += len(block)
                        if total > max_total_bytes:
                            # Enforced while writing, not only from the header: a header can lie, and
                            # the header is the part an attacker controls.
                            dst.close()
                            target.unlink(missing_ok=True)
                            return {"ok": False,
                                    "reason": "decompressed past the total cap of %d bytes"
                                              % max_total_bytes,
                                    "written": written, "refused": refused}
                        dst.write(block)
                written.append(safe)
    except Exception as exc:                                   # noqa: BLE001
        # A wrong password raises here, and it is worth naming: that is a configuration mistake, not
        # a corrupt sample, and the two need different responses.
        return {"ok": False, "reason": "could not unseal: %s" % exc,
                "written": written, "refused": refused}
    result = {
        "ok": True, "work_dir": str(work_dir), "members": written,
        "note": ("this directory now holds readable hostile bytes and the protection can see them. "
                 "Analyse it, then delete the directory. Do not leave it in place."),
    }
    if refused:
        # Reported, never silent. A member dropped without a word is indistinguishable from an
        # archive that never held it.
        result["refused"] = refused
        result["note"] += (" %d member(s) were refused as unsafe; see `refused`." % len(refused))
    return result


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
