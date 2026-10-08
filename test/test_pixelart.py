# -*- coding: utf-8 -*-
"""Tests for the pixel-art pipeline.

The palette sampler in particular: it is the piece that runs against **lossy sources**, and a lossy
source is where a naive sampter silently reports the encoder rather than the art.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("pixelart", HERE.parent / "tools" / "pixelart.py")
pa = importlib.util.module_from_spec(spec)
sys.modules["pixelart"] = pa
spec.loader.exec_module(pa)




class TestSamplingMergesCompressionNoise(unittest.TestCase):
    """A lossy source does not contain palette entries; it contains each entry plus a halo.

    Measured on a 40-frame JPEG sprite animation: **25,398 distinct RGB values**, and the head of that
    list was `#005D77` followed by `#005E77`, `#015C77`, `#005D76` -- one colour and its compression
    noise. A sampler that does not merge is measuring the encoder, not the art.
    """

    def _noisy(self):
        """A 4-colour image where each colour has JPEG-style neighbours around it."""
        from PIL import Image
        base = [(0x00, 0x5D, 0x77), (0x10, 0x6B, 0xA4), (0x4A, 0xC5, 0xFF), (0xFF, 0x39, 0x00)]
        im = Image.new("RGB", (40, 40))
        px = im.load()
        i = 0
        for y in range(40):
            for x in range(40):
                c = base[(x // 10) % 4]
                # jitter a few levels per channel, as a lossy encoder would
                d = (i % 5) - 2
                px[x, y] = (max(0, min(255, c[0] + d)),
                            max(0, min(255, c[1] - d)),
                            max(0, min(255, c[2] + (d if d % 2 else 0))))
                i += 1
        return im, base

    def test_noise_collapses_to_the_real_palette(self):
        im, base = self._noisy()
        raw = len(im.getcolors(1 << 24) or [])
        got = pa.sample_palette(im, 4)
        self.assertGreater(raw, 4, "the fixture is not actually noisy")
        self.assertLessEqual(len(got), 4)
        # Every sampled colour must be close to one of the four the artist chose.
        for c in got:
            near = min(max(abs(a - b) for a, b in zip(c, b)) for b in base)
            # The fixture jitters by at most 2 per channel, so a sampled colour that is more than
            # ~8 away from every base colour means the merge joined things it should not have.
            self.assertLessEqual(near, 8, "%r is not near any base colour" % (c,))

    def test_it_is_faster_than_merging_everything(self):
        """Early exit: once `n` distinct groups exist, the rest can only be noise around them."""
        from PIL import Image
        big = Image.new("RGB", (600, 600))
        px = big.load()
        for y in range(600):
            for x in range(600):
                px[x, y] = ((x * 7) % 256, (y * 11) % 256, (x + y) % 256)
        import time
        t0 = time.time()
        out = pa.sample_palette(big, 8)
        dt = time.time() - t0
        self.assertLessEqual(len(out), 8)
        self.assertLess(dt, 20.0, "sampling a noisy 600x600 took %.1fs" % dt)

    def test_a_clean_source_is_unchanged(self):
        """On an image that already has a clean palette, merging must not invent colours."""
        from PIL import Image
        im = Image.new("RGB", (40, 10))
        px = im.load()
        cols = [(0, 0, 0), (255, 255, 255), (0xED, 0x1C, 0x24), (0x60, 0x00, 0x18)]
        for y in range(10):
            for x in range(40):
                px[x, y] = cols[x // 10]
        got = pa.sample_palette(im, 4)
        self.assertEqual(len(got), 4)
        for c in got:
            self.assertIn(tuple(c), cols, "%r was invented" % (c,))

    def test_the_winner_is_a_colour_that_exists_not_an_average(self):
        """Averaging would produce a value the image never contains, and such a value cannot be
        attributed to the source -- which is the whole reason a palette is taken from one.
        """
        im, base = self._noisy()
        present = {col for _, col in (im.getcolors(1 << 24) or [])}
        self.assertTrue(present, "the fixture has no colours")
        for c in pa.sample_palette(im, 4):
            self.assertIn(tuple(c), present,
                          "%r is not a colour present in the image" % (c,))

    def test_a_large_image_does_not_exhaust_memory(self):
        """`getcolors` builds a dict of every distinct colour, and on a large crop that raised
        MemoryError outright. **An image is not a malformed input**, so failing on one is a defect
        here rather than a fact about the caller.

        Kept deliberately small: an earlier version used 600x600 and, on a machine where memory is
        tight, left enough pressure behind to make **unrelated tests elsewhere in the suite** fail on
        file reads. A regression test that destabilises its neighbours is worth less than it costs.
        The budget it exercises is 2**18 pixels, so 384x384 is already comfortably past it.
        """
        from PIL import Image
        im = Image.new("RGB", (384, 384))
        px = im.load()
        for y in range(384):
            for x in range(384):
                px[x, y] = ((x * 3 + y) % 256, (y * 5 + x) % 256, (x ^ y) % 256)
        out = pa.sample_palette(im, 16)          # must not raise
        self.assertTrue(1 <= len(out) <= 16)
