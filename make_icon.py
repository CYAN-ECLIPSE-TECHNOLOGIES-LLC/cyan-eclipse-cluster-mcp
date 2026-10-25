#!/usr/bin/env python3
"""Generate icon-512.png — brand system §6: eclipse motif on the
navy field (#0d1b2a), one per-product glyph. Cluster's glyph is a
stack of containers — two below, one above — the governed workload
substrate, under the eclipse ring. PIL only; deterministic."""
from PIL import Image, ImageDraw

S = 512
NAVY = (13, 27, 42, 255)
STOPS = [(15, 246, 247), (0, 212, 255), (123, 44, 191)]  # cyan->blue->purple


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3)) + (255,)


def grad(t):
    return lerp(STOPS[0], STOPS[1], t * 2) if t < 0.5 else \
        lerp(STOPS[1], STOPS[2], (t - 0.5) * 2)


def container(d, box, t):
    d.rounded_rectangle(box, radius=14, outline=grad(t), width=12)
    # Corner rivet: the seal point on each box.
    d.ellipse([box[0] + 18, box[1] + 18, box[0] + 40, box[1] + 40],
              fill=grad(t))
    # Door seam: a vertical line right of center.
    mid = box[0] + (box[2] - box[0]) * 0.62
    d.line([(mid, box[1] + 14), (mid, box[3] - 14)], fill=grad(t), width=6)


def main():
    img = Image.new("RGBA", (S, S), NAVY)
    d = ImageDraw.Draw(img)
    # Eclipse ring: gradient arc segments, upper-right (house motif).
    box = [330, 30, 482, 182]
    for i in range(72):
        t = i / 72
        d.arc(box, start=i * 5, end=i * 5 + 6, fill=grad(t), width=13)
    d.ellipse([372, 72, 440, 140], fill=NAVY)  # occluding body
    # The stack: one container above, two below.
    container(d, [140, 190, 316, 296], 0.1)
    container(d, [48, 312, 224, 418], 0.5)
    container(d, [240, 312, 416, 418], 0.85)
    img.save("icon-512.png")
    print("wrote icon-512.png", img.size, img.mode)


if __name__ == "__main__":
    main()
