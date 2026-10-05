#!/usr/bin/env python3
"""Fetch research samples with the failure modes designed out.

This is a sharp tool, so the defaults are the ones that cannot hurt:

  * **metadata is the default; bytes are opt-in.** `--fetch` is required to download a file. Most of
    what a corpus needs is metadata -- hashes, family, size, file type -- and metadata cannot execute.
  * **the destination must be a quarantine directory.** Refuses the workspace, refuses `DaShaoHuo`,
    refuses anything inside a git repository, refuses `C:`. A sample that lands in a repository gets
    committed by somebody eventually.
  * **it never executes anything.** No `subprocess` call on a sample, at any point. `--handoff` exists
    in Torikago for asking an engine about a file, and that is the only sanctioned way to learn a
    verdict.
  * **protection state is recorded at fetch time.** If a live antivirus intercepts a download or eats
    a sample, that is an experimental fact about the run and it cannot be reconstructed afterwards.

**One thing this tool will not do, by design and not by omission: it does not fetch samples on its
own initiative.** Running it is a deliberate act with a deliberate `--fetch`, and the reason is
simple -- moving live malware onto a machine is a decision a person makes, not a tool.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from sample_vault import is_encrypted_zip          # noqa: E402
except ImportError:                                    # pragma: no cover - reported, not hidden
    def is_encrypted_zip(path):                        # type: ignore[misc]
        """Fallback: refuse to claim an encryption state that cannot be checked."""
        return None

# Refused outright, with the reason, so a mistake is caught before a byte is written.
FORBIDDEN_ROOTS = (
    r"E:\~Sayori~Sleeping~",     # the workspace: everything here ends up in a repository
    r"E:\DaShaoHuo",             # downloads and caches, not samples
    "C:\\",                      # system drive: never, whatever the reason
)

HASH_LEN = {"md5": 32, "sha1": 40, "sha256": 64}


def protection_state() -> dict:
    """What is watching this machine right now.

    Recorded per fetch because it changes what the fetch means: a product that intercepted the
    download, or that silently eats a sample, invalidates conclusions drawn from the run. This is
    experimental metadata, not decoration.
    """
    state = {"recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if os.name != "nt":
        state["platform"] = "not Windows"
        return state
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
             "$s = Get-MpComputerStatus; "
             "$p = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
             "Select-Object -ExpandProperty displayName; "
             "Write-Output ('realtime=' + $s.RealTimeProtectionEnabled); "
             "Write-Output ('av=' + $s.AntivirusEnabled); "
             "foreach ($n in $p) { Write-Output ('product=' + $n) }"],
            capture_output=True, timeout=90)
    except (OSError, subprocess.SubprocessError) as exc:
        state["error"] = str(exc)
        return state
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line.startswith("realtime="):
            state["realtime_protection"] = line.split("=", 1)[1]
        elif line.startswith("av="):
            state["antivirus_enabled"] = line.split("=", 1)[1]
        elif line.startswith("product="):
            state.setdefault("products", []).append(line.split("=", 1)[1])
    return state


def check_destination(dest: Path) -> None:
    """Refuse destinations where a sample would become somebody's problem later.

    Every check exists because of a specific way this goes wrong: a sample inside a git repository is
    committed eventually; a sample on the system drive survives a machine being handed on; a sample in
    a downloads folder gets opened by a person who forgot what it was.
    """
    resolved = str(Path(dest).resolve())
    for root in FORBIDDEN_ROOTS:
        if resolved.lower().startswith(root.lower()):
            raise SystemExit(
                "refusing to write samples under %s\n"
                "  (%s)\n"
                "  pick a quarantine directory outside the workspace, the cache area and C:" % (
                    root, resolved))
    # A repository anywhere above the destination means the sample can be committed by accident.
    probe = Path(resolved)
    for parent in [probe] + list(probe.parents):
        if (parent / ".git").exists():
            raise SystemExit(
                "refusing to write samples inside a git repository\n"
                "  (%s is a repository)\n"
                "  a sample in a repository gets committed eventually" % parent)


def classify_hash(value: str) -> str:
    """md5 / sha1 / sha256 from the length, so a mistyped hash fails here and not at the server."""
    for name, length in HASH_LEN.items():
        if len(value) == length and all(c in "0123456789abcdefABCDEF" for c in value):
            return name
    raise SystemExit("not a recognised hash: %r (expected md5, sha1 or sha256)" % value[:80])


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def log_record(log: Path, record: dict) -> None:
    """Append-only. A fetch log that can be rewritten is not a record of what happened."""
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def auth_headers(auth_key: str | None) -> dict:
    """Headers for abuse.ch, which now requires an Auth-Key on the query endpoint.

    Read from `--auth-key` or `MALWAREBAZAAR_AUTH_KEY`, never from a file in this directory: an API
    key that lives next to samples is one more thing a later cleanup has to remember to delete.
    """
    headers = {"User-Agent": "torikago-research/1.0 (malware corpus collection)"}
    if auth_key:
        headers["Auth-Key"] = auth_key
    return headers


def fetch_malwarebazaar(sha: str, *, fetch_bytes: bool, dest: Path, auth_key: str | None = None,
                       timeout: int = 300) -> dict:
    """Ask MalwareBazaar about one hash, and only download if explicitly told to.

    The API takes a hash and returns metadata; the sample itself comes from a separate URL in the
    response. Asking is one act and downloading is another, which is why they are separated here
    rather than bundled into one convenient call.
    """
    body = ("query=get_info&hash=%s" % sha).encode()
    req = urllib.request.Request("https://mb-api.abuse.ch/api/v1/", data=body,
                                 headers=auth_headers(auth_key))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as fh:
            payload = json.load(fh)
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return {"ok": False, "reason": "the endpoint returned HTTP 401",
                    "note": ("no key was accepted. Register at https://auth.abuse.ch/ and set "
                             "MALWAREBAZAAR_AUTH_KEY. Do not put the key in this directory.")}
        if exc.code == 403:
            # Distinguished from 401 on purpose. 401 is "no key given"; 403 is "a key was given and
            # this is not it". Reporting the first when the second happened sends the reader to
            # generate a key they already have -- observed, because a stale placeholder produced
            # exactly this and the message blamed a missing key.
            return {"ok": False, "reason": "the endpoint returned HTTP 403: the key was rejected",
                    "note": ("a key was sent and abuse.ch refused it. Check that the file has no "
                             "trailing whitespace or newline, that it is the current key (Generate "
                             "Key replaces the old one), and that the account is not rate-limited "
                             "-- abuse.ch limit accounts for up to 72 hours after unusually high "
                             "query volume.")}
        return {"ok": False, "reason": "query failed: HTTP %d" % exc.code}
    except (urllib.error.URLError, ValueError) as exc:
        return {"ok": False, "reason": "query failed: %s" % exc}

    status = payload.get("query_status")
    if status == "hash_not_found":
        # Authenticated and answered. Distinguished from an auth failure because the two send the
        # reader in opposite directions: this one means the corpus does not have that hash, and the
        # earlier message suggested generating a key that had just been proven to work.
        return {"ok": False, "reason": "MalwareBazaar does not have that hash",
                "note": ("the key worked -- the service answered. The sample is not in their corpus. "
                         "Check the hash is the full 64 hex characters of a SHA256, taken from a "
                         "report that labels it as SHA256."),
                "authenticated": True}
    if status != "ok":
        return {"ok": False, "reason": "MalwareBazaar said %r" % status,
                "note": "unexpected status; the key was accepted and the query was processed"}

    data = (payload.get("data") or [{}])[0]
    meta = {
        "sha256_hash": data.get("sha256_hash"),
        "file_name": data.get("file_name"),
        "file_type": data.get("file_type"),
        "file_size": data.get("file_size"),
        "signature": data.get("signature"),
        "first_seen": data.get("first_seen"),
        "tags": data.get("tags"),
    }
    result = {"ok": True, "metadata": meta, "downloaded": False}

    if not fetch_bytes:
        result["note"] = ("metadata only; pass --fetch to download the sample. Metadata cannot "
                          "execute and is enough to decide whether the sample is worth having.")
        return result
    if not meta.get("sha256_hash"):
        result["ok"] = False
        result["reason"] = "the response carried no hash to download by"
        return result

    # Request the sample and verify it against the hash we asked for. An unverified sample is worse
    # than no sample: it would be filed under a name that describes something else.
    dl = ("query=get_file&sha256_hash=%s" % meta["sha256_hash"]).encode()
    req = urllib.request.Request("https://mb-api.abuse.ch/api/v1/", data=dl,
                                 headers=auth_headers(auth_key))
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / (meta["sha256_hash"] + ".zip")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as fh, open(out, "wb") as target:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                target.write(chunk)
    except (urllib.error.URLError, OSError) as exc:
        return {"ok": False, "reason": "download failed: %s" % exc}

    got = sha256_file(out)
    result["downloaded"] = True
    result["path"] = str(out)
    result["sha256_of_download"] = got
    result["encrypted_at_rest"] = is_encrypted_zip(out)

    # The archive as downloaded is already password-protected by the collection site, and that is
    # what lets it survive on this machine at all: the protection cannot read inside it. Verified
    # rather than assumed, because an archive that only *looks* encrypted is worse than none -- the
    # operator would leave a readable sample lying about believing it sealed.
    if not result["encrypted_at_rest"]:
        result["warning"] = ("the downloaded archive is NOT encrypted, so the protection on this "
                             "machine can read and remove it. Move it into the vault immediately or "
                             "delete it.")
    result["note"] = ("the payload arrives as a password-protected zip (`infected`), which is why the "
                      "archive hash will not match the sample hash. Leave it sealed: to analyse it, "
                      "unseal into a work directory you will delete afterwards.")
    return result


def _list_by_tag(tag: str, auth_key, *, limit: int = 20) -> int:
    """What MalwareBazaar holds under a tag, as a table. Never downloads.

    Exists so browsing a collection does not require committing to a sample. The first corpus built
    for this tool was chosen one hash at a time from search results, and several of those turned out
    to be archives the unpacker cannot read -- which is the kind of thing a listing makes visible
    before anything is taken.
    """
    import urllib.parse

    body = urllib.parse.urlencode({"query": "get_taginfo", "tag": tag, "limit": limit}).encode()
    req = urllib.request.Request("https://mb-api.abuse.ch/api/v1/", data=body, headers=(
        {"Auth-Key": auth_key} if auth_key else {}))
    try:
        with urllib.request.urlopen(req, timeout=180) as fh:
            payload = json.load(fh)
    except (urllib.error.URLError, ValueError) as exc:
        print("failed: %s" % exc)
        return 1
    if payload.get("query_status") != "ok":
        print("failed: MalwareBazaar said %r" % payload.get("query_status"))
        return 1
    rows = payload.get("data") or []
    print("tag %r: %d sample(s)" % (tag, len(rows)))
    print()
    print("  %-18s %-6s %11s  %-19s %s" % ("sha256", "type", "size", "first_seen", "name"))
    for r in rows:
        print("  %-18s %-6s %11s  %-19s %s" % (
            (r.get("sha256_hash") or "")[:16], r.get("file_type") or "?",
            r.get("file_size"), (r.get("first_seen") or "")[:19],
            (r.get("file_name") or "")[:30]))
    types = {}
    for r in rows:
        types[r.get("file_type")] = types.get(r.get("file_type"), 0) + 1
    print()
    print("  types: %s" % ", ".join("%s=%d" % kv for kv in sorted(types.items())))
    print()
    print("To look one up:  sample_fetch.py <full sha256>")
    print("To take one:     sample_fetch.py <full sha256> --fetch")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="fetch-sample",
        description="Fetch research samples into a quarantine directory. Metadata by default; "
                    "bytes only with --fetch. Never executes anything.")
    ap.add_argument("hash", nargs="?",
                    help="md5, sha1 or sha256 of the sample to look up. Not needed with --tag or "
                         "--quota, which are browsing commands")
    ap.add_argument("--dest", default=r"E:\Quarantine\samples",
                    help="where samples land. The default is a suggestion, not an assumption -- "
                         "this tool has no idea where you keep them, and refuses any destination "
                         "inside the workspace, the cache area, a git repository, or on C:")
    ap.add_argument("--fetch", action="store_true",
                    help="actually download the bytes. Without this only metadata is retrieved, "
                         "which cannot execute and usually answers the question")
    ap.add_argument("--source", default="malwarebazaar",
                    choices=("malwarebazaar", "malshare"),
                    help="which collection to ask. Both are free; MalwareBazaar needs an abuse.ch "
                         "Auth-Key, MalShare needs MALSHARE_TOKEN")
    ap.add_argument("--tag", metavar="TAG",
                    help="instead of a hash: list what MalwareBazaar holds under this tag "
                         "(metadata only, never downloads)")
    ap.add_argument("--quota", action="store_true",
                    help="with --source malshare: report the key's remaining daily requests")
    ap.add_argument("--recent", action="store_true",
                    help="with --source malshare: list hashes added in the last 24 hours "
                         "(metadata only)")
    # The default follows the provider. Reading MALWAREBAZAAR_AUTH_KEY while talking to MalShare sent
    # the wrong credential to the wrong service -- surfaced as a bare HTTP 400 from MalShare rather
    # than as anything pointing at the cause.
    default_key = (os.environ.get("MALSHARE_TOKEN") if os.environ.get("_SAMPLE_SOURCE") == "malshare"
                   else os.environ.get("MALWAREBAZAAR_AUTH_KEY"))
    ap.add_argument("--auth-key", default=None,
                    help="API key for the chosen provider. Defaults to MALWAREBAZAAR_AUTH_KEY for "
                         "abuse.ch and MALSHARE_TOKEN for MalShare; never stored next to samples")
    ap.add_argument("--log", default=r"E:\Quarantine\fetch\fetches.jsonl")
    ap.add_argument("--limit", type=int, default=20,
                    help="rows to list with --tag (default 20)")
    args = ap.parse_args(argv)

    if not args.auth_key:
        args.auth_key = (os.environ.get("MALSHARE_TOKEN") if args.source == "malshare"
                         else os.environ.get("MALWAREBAZAAR_AUTH_KEY"))

    dest = Path(args.dest)
    # Everything checkable is checked before anything is fetched. The destination first, then the
    # hash, then whether a key even exists -- so a caller with two problems learns about both
    # instead of fixing one and being told about the next.
    check_destination(dest)                      # before any network call, so a mistake costs nothing
    # MalShare reports its own quota, so a caller can see the budget before spending an attempt.
    if args.quota or (args.source == "malshare" and args.quota):
        import provider_malshare as ms
        key = ms.find_auth_key(args.auth_key)
        if not key:
            print("[!] --quota needs MALSHARE_TOKEN (or --auth-key). "
                  "Register at https://malshare.com/register.php")
            return 1
        q = ms.quota(key)
        if not q.get("ok"):
            print("failed: %s" % q.get("reason"))
            return 1
        print("malshare quota: %s" % q.get("raw"))
        if "remaining" in q:
            print("  allocated %s, remaining %s" % (q.get("allocated"), q.get("remaining")))
        return 0

    if args.recent:
        import provider_malshare as ms
        key = ms.find_auth_key(args.auth_key)
        if not key:
            print("failed: --recent needs MALSHARE_TOKEN (or --auth-key)")
            return 1
        d = ms.recent(key, limit=args.limit)
        if not d.get("ok"):
            print("failed: %s" % d.get("reason"))
            return 1
        print("MalShare, last 24 hours: %s hash(es)" % d.get("count"))
        for row in (d.get("samples") or [])[:args.limit]:
            print("  %s" % (row.get("sha256") if isinstance(row, dict) else row))
        print()
        print("This feed is dominated by ELF and Mach-O. Measured on 2026-10-05: 24 samples, zero")
        print("PE -- so for Windows work it is a bulk source, not a targeted one.")
        return 0

    if args.tag:
        # Listing is metadata only, always. There is no flag that turns this into a download,
        # because browsing a collection and taking from it are different acts.
        return _list_by_tag(args.tag, args.auth_key, limit=args.limit)

    if not args.hash:
        # `--tag` and `--quota` are browsing commands and provide their own subject; anything else
        # needs a hash, and saying so once here is clearer than an argparse error that lists the
        # whole usage block.
        print("no hash given, and no browsing command asked for. Provide a hash, --tag TAG, or "
              "--quota", file=sys.stderr)
        return 1

    if not args.auth_key and args.source == "malwarebazaar":
        # Reported before the hash is validated, so a caller with two problems learns about both in
        # one run instead of fixing one and discovering the next.
        print("[!] no auth-key. abuse.ch now requires one:")
        print("      register at https://auth.abuse.ch/ (OAuth: X / Google / LinkedIn / GitHub)")
        print("      then:  set MALWAREBAZAAR_AUTH_KEY=<key>")
        print()
    if args.source == "malshare" and not args.auth_key:
        print("[!] no MalShare token. Register at https://malshare.com/register.php and:")
        print("      export MALSHARE_TOKEN=<token>")
        print()
    kind = classify_hash(args.hash)
    state = protection_state()

    print("hash        : %s (%s)" % (args.hash, kind))
    print("destination : %s" % dest)
    print("protection  : realtime=%s av=%s" % (state.get("realtime_protection"),
                                               state.get("antivirus_enabled")))
    for p in state.get("products", []):
        print("              product: %s" % p)
    print("mode        : %s" % ("FETCH BYTES" if args.fetch else "metadata only"))
    print()

    if not args.auth_key:
        print("auth-key    : none given -- the query endpoint now requires one (auth.abuse.ch)")
    if args.source == "malshare":
        import provider_malshare as ms
        key = ms.find_auth_key(args.auth_key)
        if not key:
            print("failed: no MalShare token (set MALSHARE_TOKEN or pass --auth-key)")
            return 1
        if args.fetch:
            result = ms.fetch_bytes(key, args.hash, dest)
            if result.get("ok"):
                result.setdefault("note", "")
        else:
            result = ms.details(key, args.hash)
            result["downloaded"] = False
            if result.get("ok"):
                result["note"] = ("metadata only; pass --fetch to download the bytes. Metadata "
                                  "cannot execute.")
    else:
        result = fetch_malwarebazaar(args.hash, fetch_bytes=args.fetch, dest=dest,
                                     auth_key=args.auth_key)

    record = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "query_hash": args.hash, "hash_kind": kind, "source": args.source,
              "fetch_bytes": bool(args.fetch), "destination": str(dest),
              "protection": state, "result": result}
    log_record(Path(args.log), record)

    if not result.get("ok"):
        print("failed: %s" % result.get("reason"))
        if result.get("note"):
            print("       %s" % result["note"])
        return 1

    for k, v in (result.get("metadata") or {}).items():
        print("  %-14s %s" % (k, v))
    if result.get("note"):
        print()
        print(result["note"])
    if result.get("path"):
        print()
        print("sample      : %s" % result["path"])
        print()
        print("At rest      : encrypted=%s" % result.get("encrypted_at_rest"))
        if result.get("warning"):
            print("WARNING      : %s" % result["warning"])
        print()
        print("Next steps, in order:")
        print("  1. leave it sealed where it is -- the protection cannot read inside it")
        print("  2. to analyse:  python sample_vault.py extract \"%s\" --work %s"
              % (result["path"], Path(r"E:\Quarantine\work")))
        print("  3. then:        torikago \"<unsealed file>\" --handoff defender")
        print("  4. delete the work directory when done -- it holds readable hostile bytes")
        print()
        print("Do not run the sample. The verdict is the engine's, not Torikago's.")
    print()
    print("logged      : %s" % args.log)
    return 0


if __name__ == "__main__":
    sys.exit(main())
