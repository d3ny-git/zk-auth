#!/usr/bin/env python3
"""Stitches demo-login.mjs screenshots into docs/img/demo.gif.
    build/venv/bin/python bench/make_gif.py FRAMES_DIR [OUT]"""
import glob
import sys

from PIL import Image  # installed with matplotlib

frames = [Image.open(p).convert("RGB") for p in sorted(glob.glob(f"{sys.argv[1]}/*.png"))]
out = sys.argv[2] if len(sys.argv) > 2 else "docs/img/demo.gif"
small = [f.resize((f.width * 2 // 3, f.height * 2 // 3)) for f in frames]
pal = [f.quantize(colors=128, method=Image.Quantize.MEDIANCUT) for f in small]
pal[0].save(out, save_all=True, append_images=pal[1:], duration=[1400] * (len(pal) - 1) + [3000], loop=0, optimize=True)
print(f"{out}: {len(pal)} frames")
