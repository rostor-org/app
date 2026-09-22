# Renders the Rostor app icon (project/brand/rostor-icon.svg) to raster for
# places that cannot take SVG: the Windows credential-provider tile and PNG
# favicons. Construction follows project/brand/brand.md exactly; regenerate
# with: python3 brand/tile.py
import math
from PIL import Image, ImageDraw

INK = (0x14, 0x16, 0x1a)
SIGNAL = (0xe0, 0x7a, 0x24)
PHI = (1 + 5 ** 0.5) / 2

def icon(size, ss=8):
    S = size * ss
    im = Image.new("RGB", (S, S), INK)
    d = ImageDraw.Draw(im)
    d.rounded_rectangle([0, 0, S - 1, S - 1], radius=int(0.19 * S), fill=INK)
    # rostor-icon.svg: a 160 box, mark (84.89 x 100 units) placed at (37.56, 30).
    k = S / 160.0
    ox, oy = 37.56 * k, 30 * k
    u = (100 / 22.0) * k              # one 24-grid unit in pixels (mark is 22 units tall)
    cx, cy = ox + (12 - 5.825) * u, oy + 11 * u
    r, w = 9.5 * u, 3 * u
    half_gap = math.degrees(math.asin((w / 2 + PHI / 2 * w) / r))
    # ring with a break on the right, butt ends
    d.arc([cx - r, cy - r, cx + r, cy + r], start=half_gap, end=360 - half_gap, fill=SIGNAL, width=int(round(w)))
    # bar from centre to r + stroke
    d.rectangle([cx, cy - w / 2, cx + r + w, cy + w / 2], fill=SIGNAL)
    # straight clip: remove everything left of centre - 0.65 r
    d.rectangle([0, 0, cx - 0.65 * r, S], fill=INK)
    d.rounded_rectangle([0, 0, S - 1, S - 1], radius=int(0.19 * S), outline=None)
    return im.resize((size, size), Image.LANCZOS)

if __name__ == "__main__":
    icon(192).save("windows/install/tile.bmp", "BMP")
    for n in (16, 32, 180, 512):
        icon(n).save(f"brand/icon-{n}.png", "PNG")
    print("wrote windows/install/tile.bmp and brand/icon-{16,32,180,512}.png")
