"""Render a demo scene to an animated GIF — browser-free (PIL + ffmpeg).

VHS/terminalizer both rely on a headless browser, which hangs on this machine,
so this renderer draws terminal frames directly with Pillow and stitches them
with ffmpeg's high-quality palettegen/paletteuse path. It animates the same
``Block`` scenes defined in ``run_demo.py`` — typed lines are revealed
character by character, output is revealed line by line.

Usage:
    python demo/render_gif.py {summarize|filter|expert|live|chat} [out.gif]
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_demo import ROOT, SCENES, Block  # same-dir import after path insert

# ── Look & feel (GitHub-dark, matches the existing screenshot) ───────────────
FONT_PATH = r"C:\Windows\Fonts\CascadiaCode.ttf"
FONT_SIZE = 20
COLS = 92
PAD = 24
FPS = 20
BG = (13, 17, 23)
WINDOW_BAR = (22, 27, 34)

COLORS = {
    "prompt": (225, 228, 232),
    "cmd": (139, 148, 158),
    "header": (88, 196, 220),
    "tool": (63, 185, 80),
    "out": (173, 186, 199),
    "answer": (225, 228, 232),
    "note": (110, 118, 129),
}
PREFIX = {"cmd": "$ ", "prompt": "> ", "tool": "● "}


def _clip(line: str) -> str:
    # PIL has no concept of tab stops — expand to a fixed grid so TSV tool
    # output (decode_protocol etc.) lines up instead of rendering tofu boxes.
    line = line.expandtabs(8)
    return line if len(line) <= COLS else line[: COLS - 1] + "…"


def _wrap(block: Block) -> list[tuple[str, str]]:
    """Expand a block into (kind, text) physical lines, prefix on the first line."""
    pre = PREFIX.get(block.kind, "")
    rows: list[tuple[str, str]] = []
    for i, raw in enumerate(block.text.splitlines() or [""]):
        rows.append((block.kind, _clip((pre if i == 0 else " " * len(pre)) + raw)))
    return rows


def build_frames(blocks: list[Block]) -> list[list[tuple[str, str]]]:
    """Produce a list of frames; each frame is the visible (kind, line) rows so far."""
    frames: list[list[tuple[str, str]]] = []
    canvas: list[tuple[str, str]] = []

    def hold(n: int) -> None:
        for _ in range(n):
            frames.append(list(canvas))

    for block in blocks:
        rows = _wrap(block)
        if block.kind in ("cmd", "prompt"):
            # Type the (possibly multi-line) command out, char by char.
            full = rows
            canvas.extend(("", "") for _ in full)  # reserve lines
            base = len(canvas) - len(full)
            target = "\n".join(line for _, line in full)
            for ch_i in range(1, len(target) + 1):
                shown = target[:ch_i].split("\n")
                for j in range(len(full)):
                    canvas[base + j] = (full[j][0], shown[j] if j < len(shown) else "")
                if ch_i % 2 == 0 or ch_i == len(target):
                    frames.append(list(canvas))
            hold(int(FPS * 0.5))
        else:
            # Reveal output / answer one line at a time.
            for kind, line in rows:
                canvas.append((kind, line))
                frames.append(list(canvas))
            hold(int(FPS * (1.3 if block.kind in ("out", "answer") else 0.6)))
        canvas.append(("out", ""))  # blank spacer between blocks
    hold(int(FPS * 2.2))  # final pause
    return frames


def render(blocks: list[Block], out: Path) -> None:
    font = ImageFont.truetype(FONT_PATH, FONT_SIZE)
    asc, desc = font.getmetrics()
    ch_w = font.getbbox("M")[2]
    line_h = asc + desc + 4
    bar_h = 36

    frames = build_frames(blocks)
    n_lines = max(len(f) for f in frames)
    width = PAD * 2 + ch_w * COLS
    height = bar_h + PAD * 2 + line_h * n_lines

    tmp = Path(tempfile.mkdtemp(prefix="mcpws_gif_"))
    try:
        for idx, frame in enumerate(frames):
            img = Image.new("RGB", (width, height), BG)
            d = ImageDraw.Draw(img)
            d.rectangle([0, 0, width, bar_h], fill=WINDOW_BAR)
            for k, cx in enumerate((PAD, PAD + 22, PAD + 44)):
                col = [(255, 95, 86), (255, 189, 46), (39, 201, 63)][k]
                d.ellipse([cx, 12, cx + 12, 24], fill=col)
            d.text((PAD + 76, 9), "mcp-wireshark", font=font, fill=(110, 118, 129))
            y = bar_h + PAD
            for kind, line in frame:
                color = COLORS.get(kind, COLORS["out"])
                d.text((PAD, y), line, font=font, fill=color)
                y += line_h
            img.save(tmp / f"f{idx:05d}.png")

        out.parent.mkdir(parents=True, exist_ok=True)
        palette = tmp / "palette.png"
        common = ["-y", "-framerate", str(FPS), "-i", str(tmp / "f%05d.png")]
        subprocess.run(
            [
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                *common,
                "-vf",
                "palettegen=stats_mode=full",
                str(palette),
            ],
            check=True,
        )
        subprocess.run(
            [
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                *common,
                "-i",
                str(palette),
                "-lavfi",
                "paletteuse=dither=bayer:bayer_scale=3",
                str(out),
            ],
            check=True,
        )
        size_kb = out.stat().st_size / 1024
        print(f"wrote {out}  ({len(frames)} frames, {width}x{height}, {size_kb:.0f} KB)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


async def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in SCENES:
        print(f"usage: python demo/render_gif.py {{{'|'.join(SCENES)}}} [out.gif]", file=sys.stderr)
        return 2
    name = sys.argv[1]
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "demo" / f"{name}.gif"
    render(await SCENES[name](), out)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
