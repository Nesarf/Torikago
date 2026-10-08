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
    # **三个中性色会把平均值拖下去，所以这一组里中性只留一个。**
    # 原先是 白 + 浅灰 + 黑 三个 S=0 的色，于是平均饱和只有 0.242 ——
    # 而莉莉丝那组恰好含 `#ED1C24`（S=0.88），平均 0.384。
    # **同级的两个角色，辨识强度差了一倍**，而那是我的选色失误，不是设定如此。
    #
# **补记：这条修过三次，前两次各自修坏了一个属性。**
#
#   版本                      最小感知距离   平均饱和
#   原始（含 白/浅灰/黑 三中性）  0.288        0.242   ← 饱和不够，32×32 下读不出
#   第一次修（直接换饱和色）        **0.066**    0.469   ← 分离度被毁（近白 vs 白、粉 vs 粉）
#   第二次修（在候选池上搜索）      **0.372**    **0.574**  ← 两个属性同时改善
#
# **教训不是"要小心"，是"这类选择该搜索而不是手选"。**
# 第一次修时我以为"更饱和 = 更好"，而实际上 32×32 下起决定作用的是**最接近的那一对**
# ——最接近的一对就是会被认错的一对。手选看不到那一对，搜索能看到。
#
# 第二次修的做法：候选池 = 设定图采样 → 提饱和 ×2.2，再并入一组紫系扩样；
# 在池上枚举 6 色组合，**以"到莉莉丝集的最小距离"为排序目标**，饱和只作下限筛。
    "amaryllis": ((0xA5, 0x7B, 0xDB), (0x8E, 0x6F, 0xD4), (0x7B, 0x4F, 0xCB),
                  (0x86, 0x45, 0xD6), (0x63, 0x4A, 0xA8), (0x53, 0x2E, 0x8F)),
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
    from PIL import Image
    src = image.convert("RGB")
    # Quantise at the source resolution so the dither has pixels to work with, then take the result
    # down with NEAREST -- any smooth resampling would blend the palette back into gradients.
    q = src.quantize(palette=pal_image(colors), dither=dither)
    return q.convert("RGB").resize((size, size), Image.NEAREST)


def sample_palette(image, n: int = 20, *, merge_distance: int = 24):
    """The `n` colours a reference image actually uses, with near-duplicates merged first.

    **The merge is the whole point.** A lossy source -- a JPEG, a screenshot, a photo of a screen --
    does not contain clean palette entries. It contains each entry plus a halo of neighbours that
    differ by a few levels per channel, and counting those separately is how a palette of ten colours
    reads as twenty-five thousand.

    Measured: a 40-frame JPEG sprite animation reported 25,398 distinct RGB values, and the head of
    that list was `#005D77` followed by `#005E77`, `#015C77`, `#005D76` -- one colour and its
    compression noise. **A sampler that does not merge is measuring the encoder, not the art.**

    `merge_distance` is a per-channel Chebyshev threshold: two colours within it are the same colour,
    and the more frequent one wins the group. **The winner's own value is kept rather than the group's
    average**, so every result is a colour that exists in the image -- which is what lets it be
    attributed to the source rather than invented.
    """
    from PIL import Image
    src = image.convert("RGB")
    # **A big image must not be able to fail this.** `getcolors` builds a dict of every distinct colour,
    # and on a large crop that raised MemoryError outright -- an image is not a malformed input, so
    # failing on one is a defect here rather than a fact about the caller.
    #
    # Above the threshold the image is strided down first. That is sound for palette extraction
    # because a colour's *share* is what the result reports, and taking every nth pixel of a large
    # image estimates every share closely -- far more closely than the merge threshold cares about.
    PIXEL_BUDGET = 1 << 18
    if src.width * src.height > PIXEL_BUDGET:
        step = int((src.width * src.height / PIXEL_BUDGET) ** 0.5) + 1
        src = src.resize((max(1, src.width // step), max(1, src.height // step)), Image.NEAREST)
    counts = src.getcolors(maxcolors=1 << 24) or []
    counts.sort(reverse=True)                  # most frequent first, so each group's winner is modal

    groups = []                                # [(winner, total_count)]
    for count, colour in counts:
        for i, (winner, total) in enumerate(groups):
            if max(abs(a - b) for a, b in zip(colour, winner)) <= merge_distance:
                groups[i] = (winner, total + count)
                break
        else:
            groups.append((colour, count))
            if len(groups) >= n:
                # Enough distinct colours; whatever is left can only be noise around them, and
                # merging thousands of near-duplicates to prove that costs more than it tells.
                break

    groups.sort(key=lambda g: -g[1])
    return tuple(winner for winner, _ in groups[:n])


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

# --------------------------------------------------------------------------- #
# 字符网格 → PNG
# --------------------------------------------------------------------------- #
#
# **格式来源可核**：`SbName/yoyopixel`（MIT）的 `pixelart-skill.md`，它的主张是
# "any text-only LLM can draw"——**LLM 只写结构化文本，渲染交给别的东西**。
#
# 而这解决的是我们真正卡住的那件事：**我这一侧没有图像生成能力。**
# 有了这个格式，"画"这个动作退化成"写一个字符串数组"，而那是文本工作。
#
# 格式（照抄来源）：
#
#     palette: { '.': 'transparent', 'S': '#F8B277', ... }   字母 → 颜色，'.' 固定是透明
#     pixels:  [ "..SS..", ".SHHS.", ... ]                   每个字符串一行，每个字符一个像素
#
# **字母是语义的**（S=skin, H=hair, E=eyes, B=body），不是索引——
# 所以改一行注释就能读懂一张图，而换色只需要动 palette 一处。
#
# 与 `to_pixel_art` 的关系：那条路是"把已有的图变成像素风"，这条是"从零画一张"。
# **两条都要**：前者处理参考图与截图，后者处理我们要放进工具里的原始资源。

def from_grid(grid: dict, *, letters: dict | None = None):
    """Build an RGBA image from a character grid.

    `grid` is the `<name>.json` form of the format above: `width`, `height`, `palette`, `pixels`.
    Raises rather than guessing when the grid does not match its declared size -- **a sprite that is
    silently the wrong shape shows up as a rendering bug much later**, in a place with no connection
    to the data that caused it.
    """
    from PIL import Image
    width = int(grid["width"])
    height = int(grid["height"])
    palette = dict(grid["palette"])
    if letters:
        palette.update(letters)
    rows = list(grid["pixels"])
    if len(rows) != height:
        raise ValueError("grid says %d rows, got %d" % (height, len(rows)))
    for i, row in enumerate(rows):
        if len(row) != width:
            raise ValueError("row %d is %d wide, grid says %d" % (i, len(row), width))

    im = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    px = im.load()
    for y, row in enumerate(rows):
        for x, ch in enumerate(row):
            if ch == ".":
                continue                     # transparent, and it is a palette member here
            try:
                spec = palette[ch]
            except KeyError:
                # **Unmapped characters are an error, not a blank pixel.** A typo in a grid would
                # otherwise read as a hole in the art, which looks deliberate.
                raise ValueError("row %d col %d uses %r, which the palette does not define"
                                 % (y, x, ch))
            if spec in (None, "transparent"):
                continue
            px[x, y] = _to_rgba(spec)
    return im


def _to_rgba(spec):
    if isinstance(spec, (tuple, list)):
        if len(spec) == 4:
            return tuple(spec)
        if len(spec) == 3:
            return tuple(spec) + (255,)
        raise ValueError("colour must be 3 or 4 components, got %r" % (spec,))
    text = str(spec).lstrip("#")
    if len(text) == 3:                        # #abc
        text = "".join(c * 2 for c in text)
    if len(text) == 6:
        text += "ff"
    if len(text) != 8:
        raise ValueError("cannot read colour %r" % (spec,))
    return tuple(int(text[i:i + 2], 16) for i in (0, 2, 4, 6))


def load_grid(path):
    """Read a grid from JSON. `.js` files that declare `const ART = {...}` are handled too, because
    that is how the source repository ships them and re-typing one by hand is a transcription error
    waiting to happen."""
    import json
    text = Path(path).read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except ValueError:
        start = text.index("{")
        end = text.rindex("}") + 1
        body = text[start:end]
        # The source format is JS object literal: unquoted keys and single-quoted strings.
        import re
        body = re.sub(r"([{,;\s])([A-Za-z_][A-Za-z0-9_]*)\s*:", r'"":', body)
        body = body.replace("'", '"')
        body = re.sub(r",(\s*[}\]])", r"", body)
        return json.loads(body)


def export_grid(grid: dict, path, *, size: int | None = None, colors=None):
    """Grid → PNG (or GIF if it is a list of grids), through the same palette rules."""
    im = from_grid(grid)
    if colors:
        # A grid that uses its own letters is already palette-limited by construction; this only
        # applies when the caller wants it forced into the shared palette as well.
        im = im.convert("RGBA").quantize(palette=pal_image(colors)).convert("RGBA")
    if size:
        im = im.resize((size, size), 3)       # 3 = NEAREST
    p = Path(path)
    im.save(str(p))
    return p

# --------------------------------------------------------------------------- #
# 实测记录：网格路线（2026-10-06）
# --------------------------------------------------------------------------- #
#
# 8×8 网格 → RGBA → 放大 128×128 = 484 字节。两条错误路径都验证过：
# 行数不符报错（不猜）、字符未定义报错（不静默留空洞）。
#
# **这条路线填的是先前那个空缺**：`to_pixel_art` 处理"把已有的图变成像素风"，
# 而"从零画"需要图像生成能力——**我这一侧没有。**
# 网格格式把"画"退化成"写字符串数组"，那是我能做的。
#
# 容量上的实话：**32×32 = 1024 个字符 ≈ 手写的上限。**
# 64×64 是 4096 个字符，那个量级不该手写——真要那尺寸，走 `to_pixel_art` 或跑图。
#
# 另一条待试的路（本仓库 `TODO.md` 里记着）：从设定图裁出表情差分后走 `to_pixel_art`，
# 而不是从零画。两条不冲突——**前者给"像"，后者给"可控"。**

# --------------------------------------------------------------------------- #
# 实测记录：JPEG 输入下的调色板采样（2026-10-08）
# --------------------------------------------------------------------------- #
#
# 一件 40 帧的 JPEG 像素动画（pixiv うごイラ，135x245 / 帧）报出 **25,398 个不同 RGB 值**。
# 而清单的开头是：
#
#     #005D77   <- 背景
#     #005E77   <- 同一个色的抖动
#     #015C77   #005D76   #082042   #005F78   #072142 ...
#
# 旧版 sample_palette() 直接取最常见色，于是 **前 20 里 14 个是压缩噪声**。
# 归并之后前 20 全是**互不相同**的色，而史莱姆的结构一眼可读：
#
#     #005D77 背景 · #106BA4 中蓝 · #092042 描边 · #2194D5 亮蓝
#     #4AC5FF 高光 · #FFFEFF 白 · #FFFF63 黄 · #FF3900 橙红(嘴) · #000200 黑
#
# 0.21 秒。**所以"不归并的采样器量的是编码器，不是画"** —— 而这正是先前
# "从参考图采样失败"的一部分原因（另两个是：采样区域大半是背景，以及调色板按用途选而非按频次）。
#
# `merge_distance` 是逐通道的切比雪夫阈值，而**保留的是组内最高频的色本身，不是组平均** ——
# 这样每个结果都是图里真实存在的色，**能被归给来源，而不是被发明的**。

# --------------------------------------------------------------------------- #
# 实测记录：从两张设定图采样（2026-10-08）
# --------------------------------------------------------------------------- #
#
# 用归并后的 sample_palette() 各取 16 色，两张设定图的结果：
#
#   莉莉丝     #FDFDFD #EDE4E8 #C1B5C1 #DACBD3 #A0A6C2 #838AAB #676A87 #33292D
#              #3D3F4E #918A8C #6A5E60 #AC9AA9 #C0C3DA #000000 #62384D #DBB5B7
#   阿玛丽莉丝 #F0ECEF #211C28 #9284A8 #7F748D #5B4653 #D6B0C2 #D8D3D9 #423340
#              #B9B2BF #665B7F #745A65 #AC99B6 #BD7C9B #BC9776 #0A080F #423A5A
#
# 归并修复**是必要的**：修之前这两次采样被噪声主导（与 PIXEL20 重合 1 色 / 0 色）。
# **而修之后仍然不够** —— 读数：
#
#   共用色        0 个        （好）
#   中位感知距离  0.303       （好，远高于 0.15 的可分辨阈值）
#   **最小感知距离 0.026**    （**坏**，远低于 0.08；两套里各有一对色几乎相同）
#   平均亮度      0.554 / 0.487
#   平均暖冷      +0.035 / +0.071
#
# **所以这两套在整体上分不开。** 那对 0.026 的色是"白髪区"与"近黑描边"——
# **两个角色都有的东西。**
#
# ## 结论（这条比上面任何数字都重要）
#
# **从设定图采样得到的是「这张图的色彩分布」，不是「这个角色的辨识色」。**
#
# 分布里大部分是**共用区**（白 · 灰 · 黑），而辨识色是那些**少数但有代表性**的色。
# 所以 `CHARACTER_ACCENTS` 那种「按用途列色再吸附到共用板」的做法是对的 ——
# **"按频次采样"给不了辨识度，无论采样器多干净。**
#
# 两者用途不同，都要留：
#   `PALETTE_*`（本节的采样结果）—— **材料板**：画的时候用哪些色
#   `CHARACTER_ACCENTS`        —— **辨识板**：靠哪几个色认出是谁
PALETTE_LILITH = (
    (0xFD,0xFD,0xFD), (0xED,0xE4,0xE8), (0xC1,0xB5,0xC1), (0xDA,0xCB,0xD3),
    (0xA0,0xA6,0xC2), (0x83,0x8A,0xAB), (0x67,0x6A,0x87), (0x33,0x29,0x2D),
    (0x3D,0x3F,0x4E), (0x91,0x8A,0x8C), (0x6A,0x5E,0x60), (0xAC,0x9A,0xA9),
    (0xC0,0xC3,0xDA), (0x00,0x00,0x00), (0x62,0x38,0x4D), (0xDB,0xB5,0xB7),
)
PALETTE_AMARYLLIS = (
    (0xF0,0xEC,0xEF), (0x21,0x1C,0x28), (0x92,0x84,0xA8), (0x7F,0x74,0x8D),
    (0x5B,0x46,0x53), (0xD6,0xB0,0xC2), (0xD8,0xD3,0xD9), (0x42,0x33,0x40),
    (0xB9,0xB2,0xBF), (0x66,0x5B,0x7F), (0x74,0x5A,0x65), (0xAC,0x99,0xB6),
    (0xBD,0x7C,0x9B), (0xBC,0x97,0x76), (0x0A,0x08,0x0F), (0x42,0x3A,0x5A),
)

# --------------------------------------------------------------------------- #
# 设定图 → 像素色：色相可用，饱和不够
# --------------------------------------------------------------------------- #
#
# **实测（2026-10-08，两张设定图各取 16 色）：**
#
#   角色        采样板平均 S    辨识板平均 S    PIXEL20 平均 S
#   lilith      0.190          0.384          0.478
#   amaryllis   0.220          0.242          0.478
#
# **设定图是粉彩调**（S 0.19–0.22），而 32×32 的像素图要 S ≈ 0.4–0.5 才读得出 ——
# 因为在那么小的画布上，颜色是唯一的辨识手段，而低饱和的色会糊成一团灰。
#
# **所以从设定图只能取「色相」，像素色要另提饱和。** `saturate()` 做那一步。

def saturate(colour, factor: float = 2.2, *, floor_value: float = 0.55):
    """Raise a colour's saturation, keeping its hue.

    **Why not just use the reference's colour.** A painted reference is pastel; a 32x32 sprite is not
    affordance for pastel, because at that size colour is the only thing carrying identity and low
    saturation collapses to grey. Measured on two character sheets: mean saturation 0.19 and 0.22,
    against 0.48 for the shared palette the sprites are drawn from.

    Hue is preserved exactly -- that is the part the reference is authoritative about. Saturation is
    scaled, and very light colours are also pulled down a little so they do not blow out to white when
    their saturation rises, which is what makes a highlight stay a highlight.
    """
    import colorsys
    r, g, b = [c / 255 for c in colour[:3]]
    h, s, v = colorsys.rgb_to_hsv(r, g, b)
    s = min(1.0, s * factor)
    if v > 0.5:
        v = min(1.0, floor_value + v * (1.0 - floor_value))
    r, g, b = colorsys.hsv_to_rgb(h, s, v)
    return (round(r * 255), round(g * 255), round(b * 255))
