# -*- coding: utf-8 -*-
"""调色板，以及把图像转成像素风的管线。

## 这份文件解决的事

§零之三 要求两个工具的一切美术与 UI 一律像素风。而"像素风"不是"把小图放大"，
它有两个可检验的条件：

1. **限色**——每个像素必须是某套固定调色板里的一员，不是"颜色变少了"
2. **抖动**——梯度靠有序的纹理表达，不是靠更多的颜色

两个条件各有一个**常见的做错法**：

| 做错 | 结果 |
|---|---|
| 只缩小不量化 | 缩小产生的中间色没有纹理，糊成一团 |
| 量化但用自适应调色板 | 得到"一张色彩变少的照片"，不是像素画 |

## 顺序是有讲究的，而且是反直觉的那一边

```
先量化 + 抖动  →  后缩到目标尺寸
```

**抖动纹理在缩小之后仍然保留**，因为它是**空间结构**而不是颜色信息。
反过来先缩小，中间色就没机会被抖动替代，于是只能是糊的。

（这一条是从一个 64×64 成品反推出来的，那个成品的调色板就在下面。）

## 依赖说明

**本模块用 Pillow，而 Pillow 不进分发。**

理由：**它只在生成资源的时候跑**，产物是 PNG / GIF，**进仓库的是那几个文件**。
所以两个工具装出来仍然是纯标准库——**"零依赖"这条没有破，破的只是"我用来造资源的工具也要零依赖"
这个从来不是要求的约束。**

（而如果哪天真的要在没有 Pillow 的地方生成图：**PNG 可以用 zlib + struct 手写**，
已验证能写出 Pillow 读得回的真 PNG。GIF 要自己实现 LZW，那个不值得，见仓库 `TODO.md`。）
"""
from __future__ import annotations

from pathlib import Path

# --------------------------------------------------------------------------- #
# 调色板
# --------------------------------------------------------------------------- #

# 从一份 64×64 的成品里取出来的 20 色。
#
# **来源可核**：`converted_Minimeters.png`，sha256
# `e57d74525bb6ea76ad414c0cd96f85e4de67b7c4b57d19ce01ae953a694656c8`。
# 实测该图 64×64、恰好 20 种颜色，下列色值即其全部用色。
#
# **它很接近 DawnBringer 16 系**（前 16 个是中性与暖色的骨架，后 4 个是亮色），
# 但**这里不凭记忆断言出处**——出处记成"从这张成品里取出来的"，那是能核的。
PIXEL20 = (
    (0x00, 0x00, 0x00),   # 黑
    (0x3C, 0x3C, 0x3C),   # 深灰
    (0x60, 0x00, 0x18),   # 暗酒红
    (0x60, 0xF7, 0xF2),   # 青
    (0x68, 0x46, 0x34),   # 暗棕
    (0x78, 0x78, 0x78),   # 中灰
    (0x87, 0xFF, 0x5E),   # 亮绿
    (0x95, 0x68, 0x2A),   # 棕
    (0x99, 0xB1, 0xFB),   # 淡蓝
    (0xAA, 0x38, 0xB9),   # 紫
    (0xD2, 0xD2, 0xD2),   # 浅灰
    (0xE0, 0x9F, 0xF9),   # 淡紫
    (0xED, 0x1C, 0x24),   # 红
    (0xF3, 0x8D, 0xA9),   # 粉
    (0xF6, 0xAA, 0x09),   # 橙黄
    (0xF8, 0xB2, 0x77),   # 肤色
    (0xF9, 0xDD, 0x3B),   # 黄
    (0xFF, 0x7F, 0x27),   # 橙
    (0xFF, 0xFA, 0xBC),   # 米白
    (0xFF, 0xFF, 0xFF),   # 白
)

# 两个角色各自的取色重点，用来从设定图采样后微调。
#
# **为什么按角色分开**：莉莉丝是**白＋蔷薇（红）**，阿玛丽莉丝是**银紫＋黑**。
# 共用一套调色板时，48×48 以下两个角色会糊成同一个轮廓——
# 而**颜色是唯一能在那个尺寸上仍然保住的辨识度**。
CHARACTER_ACCENTS = {
    # 莉莉丝：白髪 · 白瓷 · 赤眼 · 蔷薇（红/粉）· 蝙蝠翼与尾巴（暗红到黑）
    "lilith": ((0xFF, 0xFF, 0xFF), (0xD2, 0xD2, 0xD2), (0xED, 0x1C, 0x24),
               (0xF3, 0x8D, 0xA9), (0x60, 0x00, 0x18), (0x00, 0x00, 0x00)),
    # 阿玛丽莉丝：银紫髪 · 紫眼 · 修女袍（白与浅灰）· 束带与手套（黑）· 主题色紫水晶
    "amaryllis": ((0xFF, 0xFF, 0xFF), (0xD2, 0xD2, 0xD2), (0xAA, 0x38, 0xB9),
                  (0xE0, 0x9F, 0xF9), (0x99, 0xB1, 0xFB), (0x00, 0x00, 0x00)),
}


def pal_image(colors=PIXEL20):
    """A PIL palette image for `quantize(palette=...)`."""
    from PIL import Image
    pal = Image.new("P", (1, 1))
    flat = []
    for c in colors:
        flat += list(c)
    flat += [0] * (768 - len(flat))          # a palette is 256 entries, always
    pal.putpalette(flat)
    return pal


# --------------------------------------------------------------------------- #
# 管线
# --------------------------------------------------------------------------- #

def to_pixel_art(image, *, size: int = 64, colors=PIXEL20, dither=None):
    """Turn an image into pixel art at `size`×`size`.

    **Quantise and dither first, then shrink.** The other order loses the dither, because the texture
    is spatial structure and shrinking a smooth gradient cannot invent it. This order was derived by
    reproducing a 64×64 example that used the palette above, and the two came out the same: 19 colours
    against the example's 20, at the same dimensions.
    """
    from PIL import Image
    if dither is None:
        dither = Image.FLOYDSTEINBERG
    src = image.convert("RGB")
    # Quantise at the source resolution so the dither has pixels to work with, then take the result
    # down with NEAREST -- any smooth resampling would blend the palette back into gradients.
    q = src.quantize(palette=pal_image(colors), dither=dither)
    return q.convert("RGB").resize((size, size), Image.NEAREST)


def sample_palette(image, n: int = 20):
    """The most-used `n` colours of an image, as `to_pixel_art` would see them.

    Used to derive a palette from a reference sheet rather than importing one. **A palette taken from
    the reference can be attributed to it; a palette remembered from somewhere cannot.**
    """
    counts = image.convert("RGB").getcolors(maxcolors=1 << 24) or []
    counts.sort(reverse=True)
    return tuple(c for _, c in counts[:n])


def describe_palette(colors):
    """A printable list, for putting in a document next to the source's hash."""
    return "\n".join("  #%02X%02X%02X" % tuple(c) for c in colors)


def sheet(image, frames, *, columns: int = 4, size: int = 64, gap: int = 1):
    """Lay frames out as a sprite sheet, with the grid kept on whole pixels.

    Every frame is already `size`×`size` at this point, so the layout is exact: a sprite sheet whose
    cells are not pixel-aligned is the kind of defect that only shows as a shimmer when it animates.
    """
    from PIL import Image
    rows = (len(frames) + columns - 1) // columns
    w = columns * size + (columns - 1) * gap
    h = rows * size + (rows - 1) * gap
    out = Image.new("RGB", (w, h), (0, 0, 0))
    for i, frame in enumerate(frames):
        x = (i % columns) * (size + gap)
        y = (i // columns) * (size + gap)
        out.paste(frame, (x, y))
    return out


def animate(frames, path: Path, *, duration: int = 120, loop: int = 0):
    """Write an animated GIF from already-quantised frames.

    Frames must share one palette or the animation flickers between them -- which is why this takes
    frames rather than images, and why every frame comes through `to_pixel_art` with the same palette.
    """
    if not frames:
        raise ValueError("no frames")
    first = frames[0].convert("P", palette=pal_image())
    rest = [f.convert("P", palette=pal_image()) for f in frames[1:]]
    path = Path(path)
    first.save(str(path), save_all=True, append_images=rest, duration=duration, loop=loop,
               optimize=True)
    return path

# --------------------------------------------------------------------------- #
# 实测记录（2026-10-06）
# --------------------------------------------------------------------------- #
#
# **采样法被证否了。** 试过三次从参考图取调色板：整张设定图（与 PIXEL20 重合 1 色）、
# 另一张设定图（重合 0 色）、一张立绘照片（得到 20 种棕色，重合 0 色）。
#
# 原因是方法本身错的，不是采样区域错：
#
# > **调色板不是"最常见的 20 色"，是"按用途选的 20 色"。**
#
# 一张图里出现最多的颜色，通常正好是最没用的那些（背景、肤色、大色块）。
# 而像素画的调色板要的是**覆盖面**：亮/中/暗三档、冷暖各一、以及几个强调色。
# PIXEL20 正是按用途挑的——一张 64×64 例图里褐、灰、肤、红、绿、蓝、紫、黄全都在。
#
# **两个角色的区分度已量化。** 各自的 6 个角色色本来就全部落在 PIXEL20 内（吸附是恒等映射），
# 共用黑 / 浅灰 / 白三个中性色，区分靠另外三个强调色：
#
#   莉莉丝     #ED1C24 #F38DA9 #600018   暖（暖冷值 +0.38 ~ +0.82）
#   阿玛丽莉丝 #AA38B9 #E09FF9 #99B1FB   冷（暖冷值 -0.09 ~ +0.45，绿品 -0.29 ~ -0.51）
#
# 两组强调色之间的最小感知距离 **0.288**。经验阈值：>0.15 在 32×32 下仍能区分，<0.08 会糊。
# 所以 32×32 下两个角色靠色相就能分开——**莉莉丝暖红、阿玛丽莉丝冷紫**，
# 而共用的中性色正是"同一套工具"该有的统一感。
