# Generates the Windows credential-provider tile: the sideways power symbol
# (bar to the left) in Signal on Ink. Brand tokens per project/CLAUDE.md.
# Placeholder until the final symbol lands; regenerate with: python3 brand/tile.py
import math
from PIL import Image, ImageDraw

INK = (0x14, 0x16, 0x1a)
SIGNAL = (0xe0, 0x7a, 0x24)

def power(size=192, rot=90, fg=SIGNAL, bg=INK, scale=4):
    S = size * scale
    im = Image.new("RGB", (S, S), bg)
    d = ImageDraw.Draw(im)
    cx = cy = S / 2
    r = S * 0.30
    w = S * 0.085
    d.arc([cx - r, cy - r, cx + r, cy + r], start=-90 + 35, end=270 - 35, fill=fg, width=int(w))
    for a in (-90 + 35, 270 - 35):
        x = cx + r * math.cos(math.radians(a))
        y = cy + r * math.sin(math.radians(a))
        d.ellipse([x - w / 2, y - w / 2, x + w / 2, y + w / 2], fill=fg)
    d.rounded_rectangle([cx - w / 2, cy - r * 1.15, cx + w / 2, cy - r * 0.05], radius=int(w / 2), fill=fg)
    im = im.rotate(rot, resample=Image.BICUBIC, fillcolor=bg)
    return im.resize((size, size), Image.LANCZOS)

if __name__ == "__main__":
    power(rot=90).save("windows/install/tile.bmp", "BMP")
    power(rot=90, size=512).save("brand/symbol-512.png", "PNG")
    print("wrote windows/install/tile.bmp and brand/symbol-512.png")
