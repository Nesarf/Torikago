"""Benchmark the full-file scans on a large real file.

Written to a file rather than piped through a heredoc, because the heredoc form produced no output at
all here -- not even the first print -- and the cost of guessing which layer swallowed it was higher
than the cost of writing a script that can be read.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import torikago as tk

ISO = Path(r"E:\DaShaoHuo\downloads\Win10_Enterprise_LTSC_2021_EVAL_x64_en-us.iso")

print("file            : %s" % ISO.name, flush=True)
print("size            : %.2f GB" % (ISO.stat().st_size / 1073741824), flush=True)

t0 = time.time()
size = 0
with ISO.open("rb") as fh:
    while True:
        block = fh.read(1 << 22)
        if not block:
            break
        size += len(block)
stream = time.time() - t0
print("streamed read   : %7.2f s  (%.0f MB/s)" % (stream, size / 1048576 / stream), flush=True)

t0 = time.time()
data = ISO.read_bytes()
print("read into memory: %7.2f s  (%.0f MB resident)" % (time.time() - t0, len(data) / 1048576), flush=True)

t0 = time.time()
n = data.count(tk.BOOT_SIG_PAIR)
print("count signature : %7.2f s  (%d occurrences)" % (time.time() - t0, n), flush=True)

t0 = time.time()
hits = tk.find_boot_sector_pattern(data)
boot = time.time() - t0
print("boot sector scan: %7.2f s  -> %d hit(s)" % (boot, len(hits)), flush=True)

t0 = time.time()
lang = tk.detect_language(data)
print("language markers: %7.2f s  -> %s" % (time.time() - t0, (lang or {}).get("language")), flush=True)

t0 = time.time()
pe = tk.parse_pe(data)
print("parse_pe        : %7.2f s  -> %s" % (time.time() - t0, "None (not a PE)" if pe is None else "dict"), flush=True)

print("DONE", flush=True)
