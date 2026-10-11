#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Can a second, independent implementation of the PYZ rebuild reproduce Nanodesu's bytes exactly?

**Why this is the first thing built rather than the last.** `ACTION_CONTRACT.md` §四 says the
cross-repository test compares `output_sha256`, and §五 says in the same breath that byte-level
reproducibility is *not promised* because repacking recompresses. Those two statements can both be true
only if the rebuild is deterministic in every choice it makes -- and if it is not, a whole
`neutralize` implementation on the Torikago side would be written before anyone found out that its
output could never match. So this measures the narrow question first.

The rebuild is fully specified by Nanodesu's `rewrite_pyz`, and the specification is short enough to
restate: every payload block is zlib-compressed at level 9 (including the ones that did not change),
offsets are recomputed from zero, the header is `PYZ\\x01 + pyc_magic + int32be(total_len) + 5 zero
bytes`, and the table of contents is re-marshalled.

**The two implementations below share no code on purpose.** `reference` calls Nanodesu's own
`rewrite_pyz`. `rival` is a from-scratch implementation of the restated specification, written the way
Torikago's side would have to be written -- it does not import anything from Nanodesu. If they agree
byte for byte on a synthetic archive, the contract's `output_sha256` requirement is achievable; if
they disagree, the first differing byte says which choice was underspecified, and that is what the
contract needs to pin down before either side writes more code.

    python tools/probe_pyz_rebuild.py
"""
from __future__ import annotations

import hashlib
import marshal
import struct
import sys
import zlib

# The reference lives in the neighbouring repository. Imported for its *specification*, not linked
# into anything: this probe never ships, and the point is to find out whether the spec is complete.
sys.path.insert(0, "E:/~Sayori~Sleeping~/nanodesu-release")
sys.path.insert(0, ".")

PYZ_MAGIC = b"PYZ" + bytes(1)
PYZ_HEADER_LEN = 17


def make_pyz(entries, *, pyc_magic=b"\xcb\x0d\x0d\x0a", level=6):
    """A PYZ archive in the documented layout, as PyInstaller writes one.

    `level=6` on purpose: PyInstaller does not use 9, so the reference implementation is recompressing
    every block rather than copying them. If both sides now produce the same bytes, that is a
    statement about the *transform*, not about the input having already been at level 9.
    """
    blocks = []
    layout = []
    for name, payload in entries:
        block = zlib.compress(payload, level)
        blocks.append(block)
        layout.append((name, block))
    body = b"".join(blocks)
    toc = []
    cursor = 0
    for name, block in layout:
        toc.append((name, (0, PYZ_HEADER_LEN + cursor, len(block))))
        cursor += len(block)
    header = PYZ_MAGIC + pyc_magic + (PYZ_HEADER_LEN + len(body)).to_bytes(4, "big") + bytes(5)
    assert len(header) == PYZ_HEADER_LEN
    return header + body + marshal.dumps(toc)


def rival_rewrite(blob, replacements, *, pyc_magic=None):
    """A from-scratch rebuild, restating the contract's specification in Torikago's own terms.

    Deliberately written without looking at `neutralize.py`'s control flow: read the TOC out of the
    tail, walk it in order, substitute, recompress everything at 9, lay the payloads out from zero,
    rebuild the header, re-marshal the TOC.
    """
    if not blob.startswith(PYZ_MAGIC):
        raise ValueError("not a PYZ")
    magic = blob[4:8]
    toc_off = struct.unpack_from("!i", blob, 8)[0]
    toc = marshal.loads(blob[toc_off:])

    out_blocks = []
    out_toc = []
    cursor = 0
    for name, meta in toc:
        typ, off, ln = meta
        if not ln or typ == 3:
            out_toc.append((name, (typ, 0, 0)))
            continue
        raw = replacements.get(name)
        if raw is None:
            raw = zlib.decompress(blob[off:off + ln])
        block = zlib.compress(raw, 9)
        out_toc.append((name, (typ, PYZ_HEADER_LEN + cursor, len(block))))
        cursor += len(block)
        out_blocks.append(block)

    body = b"".join(out_blocks)
    header = PYZ_MAGIC + magic + (PYZ_HEADER_LEN + len(body)).to_bytes(4, "big") + bytes(5)
    return header + body + marshal.dumps(out_toc)


def first_difference(a: bytes, b: bytes):
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i, a[i], b[i]
    if len(a) != len(b):
        return n, None if len(a) <= n else a[n], None if len(b) <= n else b[n]
    return None


def main():
    stub = marshal.dumps(compile("pass\n", "<stub>", "exec"))
    stub_hash = hashlib.sha256(stub).hexdigest()
    print("the contract's stub, compiled here: %d bytes  sha256=%s" % (len(stub), stub_hash))
    print("  (Nanodesu's own make_stub(None) gives 1892a9f681b713ef3c306f0f33d2469d3fefcf8976c88190e")
    print("   -- if this line differs, the two sides are compiling different stubs and nothing below")
    print("   can match; that check comes first for a reason.)")
    print("  MATCHES the recorded value: %s" % (stub_hash.startswith("1892a9f681b713ef")))
    print()

    # A small archive with a mixture: a module to replace, plain modules, an unstored namespace entry,
    # and payloads that compress differently so the recompress choice is visible in the bytes.
    entries = [
        ("alpha", b"x = 1\n" * 40),
        ("alpha.beta", b"def f():\n    return 'the original, which must not survive'\n" * 30),
        ("gamma", bytes(range(256)) * 12),
        ("delta", b"z" * 5000),
        ("epsilon", b"\x00" * 2000),
    ]
    blob = make_pyz(entries)
    print("synthetic PYZ: %d bytes, %d entries" % (len(blob), len(entries)))

    import neutralize as N
    # The reference mutates a file on disk, so it gets one.
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "test.pyz"
        p.write_bytes(blob)
        ref = N.rewrite_pyz(p, {"alpha.beta": stub}, dry_run=False)
        if not ref.get("ok"):
            print("the reference refused: %s" % ref.get("reason"))
            return 1
        ref_bytes = p.read_bytes()
    print("reference output: %d bytes  sha256=%s" % (len(ref_bytes), hashlib.sha256(ref_bytes).hexdigest()))

    rival_bytes = rival_rewrite(blob, {"alpha.beta": stub})
    print("rival output    : %d bytes  sha256=%s" % (len(rival_bytes), hashlib.sha256(rival_bytes).hexdigest()))
    print()

    # --- the semantic comparison, which is what the contract now requires ---------------------------
    #
    # Byte equality is the wrong test and the probe says why rather than leaving it as a curiosity.
    # `marshal.dumps` encodes the same string as TYPE_INTERNED (0xfa) or SHORT_ASCII (0x7a) depending
    # on the interpreter's interning state and the object graph's history -- not on anything either
    # implementation chose. So two correct rebuilds can differ in bytes while agreeing on every
    # decision, and `output_sha256` is therefore not a reachable target. See ACTION_CONTRACT §四之二.
    def entries_of(b):
        off = struct.unpack_from("!i", b, 8)[0]
        out = []
        for name, (typ, o, ln) in marshal.loads(b[off:]):
            raw = b""
            if ln and typ != 3:
                import zlib as _z
                raw = _z.decompress(b[o:o + ln])
            out.append((name, typ, o - PYZ_HEADER_LEN, ln, hashlib.sha256(raw).hexdigest()[:16]))
        return out

    re_, ve_ = entries_of(ref_bytes), entries_of(rival_bytes)
    print("=== the semantic comparison (name, type, offset-from-payload, length, sha of decompressed) ===")
    agree = True
    for a, b in zip(re_, ve_):
        same = a == b
        agree = agree and same
        print("  %s %-14s %s" % ("  " if same else "**", a[0], "identical" if same else "%r vs %r" % (a, b)))
    if len(re_) != len(ve_):
        agree = False
        print("  ** entry count differs: %d vs %d" % (len(re_), len(ve_)))
    print()
    print("headers equal : %s" % (ref_bytes[:17] == rival_bytes[:17]))
    print("payloads equal: %s" % (ref_bytes[17:struct.unpack_from('!i', ref_bytes, 8)[0]]
                                  == rival_bytes[17:struct.unpack_from('!i', rival_bytes, 8)[0]]))
    print("semantically identical: %s" % agree)
    print()

    if ref_bytes == rival_bytes:
        print("The two implementations agree BYTE FOR BYTE, which is better than the contract needs.")
        return 0
    if agree:
        print("The two implementations agree on every decisive value and differ only in how marshal")
        print("encoded the table of contents. That is the finding this probe exists for: byte equality")
        print("is not achievable across implementations, so the contract compares `output_entries`")
        print("(name, type, offset, length, and the hash of each decompressed payload) instead of")
        print("`output_sha256`. The assertion stays strong -- order, types, offsets and lengths must all")
        print("match -- and gives up only an encoding neither side chooses.")
        return 0

    where = first_difference(ref_bytes, rival_bytes)
    print("DIFFERENT, and not only in encoding: %r." % (where,))
    i = where[0]
    print("  reference around it: %r" % ref_bytes[max(0, i - 12):i + 12])
    print("  rival around it    : %r" % rival_bytes[max(0, i - 12):i + 12])
    print()
    print("So the specification is missing a real choice. Whatever fixes it belongs in")
    print("ACTION_CONTRACT.md before either side writes more code -- two implementations that disagree")
    print("here would pass their own tests and fail the only test the contract cares about.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
