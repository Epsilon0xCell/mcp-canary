#!/usr/bin/env python3
"""Generate social-preview.png (1280x640) for the repository.

Name, one-line value proposition, address. Nothing else: the card is
read at thumbnail size. Re-run after any rebrand:

    python3 tools/make_preview.py
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 640
BG = (13, 17, 23)          # GitHub dark
YELLOW = (242, 201, 76)    # canary
WHITE = (240, 246, 252)
GRAY = (139, 148, 158)

FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")


def font(name, size):
    path = FONT_DIR / name
    if path.exists():
        return ImageFont.truetype(str(path), size)
    return ImageFont.load_default(size=size)


def main():
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)

    draw.rectangle([0, 0, W, 10], fill=YELLOW)

    kicker = font("DejaVuSans-Bold.ttf", 30)
    title = font("DejaVuSans-Bold.ttf", 128)
    tagline = font("DejaVuSans.ttf", 47)
    footer = font("DejaVuSans.ttf", 30)

    draw.text((84, 96), "R U N T I M E   S E C U R I T Y   T E S T E R",
              font=kicker, fill=YELLOW)
    draw.text((80, 168), "mcp-canary", font=title, fill=WHITE)
    draw.text((84, 348), "Test MCP servers while they run,",
              font=tagline, fill=WHITE)
    draw.text((84, 408), "not just their config.",
              font=tagline, fill=WHITE)

    draw.rectangle([84, 512, 220, 522], fill=YELLOW)
    draw.text((84, 540), "github.com/Epsilon0xCell/mcp-canary",
              font=footer, fill=GRAY)

    out = Path(__file__).resolve().parents[1] / "social-preview.png"
    img.save(out)
    print("wrote %s (%dx%d)" % (out, W, H))


if __name__ == "__main__":
    main()
