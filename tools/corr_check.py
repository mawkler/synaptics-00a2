#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Correlation-matcher feasibility check (M5 follow-up).

usage: corr_check.py FINGER_A_DIR FINGER_B_DIR
Enrolls finger A placements 01/04/07/10/13; scores the other A placements
(genuine) and all B placements (impostor). Prints scores only.
"""
# Prints scores only.
import sys, re, glob
import numpy as np

def load(path):
    raw = open(path, 'rb').read()
    return np.frombuffer(raw[raw.index(b'255\n') + 4:], np.uint8).reshape(112, 112).astype(float)

def rotate(img, deg):
    t = np.deg2rad(deg); c, s = np.cos(t), np.sin(t)
    y, x = np.indices(img.shape) - 55.5
    sx, sy = c * x + s * y + 55.5, -s * x + c * y + 55.5
    inside = (sx >= 0) & (sx <= 111) & (sy >= 0) & (sy <= 111)
    x0, y0 = np.clip(np.floor(sx).astype(int), 0, 110), np.clip(np.floor(sy).astype(int), 0, 110)
    fx, fy = np.clip(sx - x0, 0, 1), np.clip(sy - y0, 0, 1)
    out = (img[y0, x0] * (1 - fx) * (1 - fy) + img[y0, x0 + 1] * fx * (1 - fy)
           + img[y0 + 1, x0] * (1 - fx) * fy + img[y0 + 1, x0 + 1] * fx * fy)
    return out, inside.astype(float)

def masked_ncc(a, ma, b, mb):
    """Normalised cross-correlation over all shifts, counting only overlapping valid pixels"""
    n = 224
    F = lambda v: np.fft.rfft2(v, (n, n))
    I = lambda v: np.fft.irfft2(v, (n, n))
    Fa, Fa2, Fma = F(a * ma), F(a * a * ma), F(ma)
    Fb, Fb2, Fmb = F(b * mb), F(b * b * mb), F(mb)
    cnt = I(Fma * np.conj(Fmb))
    sa, sb = I(Fa * np.conj(Fmb)), I(Fma * np.conj(Fb))
    saa, sbb = I(Fa2 * np.conj(Fmb)), I(Fma * np.conj(Fb2))
    sab = I(Fa * np.conj(Fb))
    ok = cnt > 0.35 * 112 * 112          # require 35 % overlap
    cnt = np.where(ok, cnt, 1)
    cov = sab - sa * sb / cnt
    var = (saa - sa ** 2 / cnt) * (sbb - sb ** 2 / cnt)
    ncc = np.where(ok & (var > 0), cov / np.sqrt(np.maximum(var, 1e-9)), -1)
    return ncc.max()

def score(probe, gallery):
    best = -1
    for deg in range(-30, 31, 5):
        r, m = rotate(probe, deg)
        for g in gallery:
            best = max(best, masked_ncc(r, m, g, np.ones_like(g)))
    return best

a = sorted(glob.glob(sys.argv[1] + '/finger-a-*.pgm')); b = sorted(glob.glob(sys.argv[2] + '/finger-b-*.pgm'))
enroll = [load(p) for p in a if re.search(r'-(01|04|07|10|13)\.pgm$', p)]
genuine = [load(p) for p in a if not re.search(r'-(01|04|07|10|13)\.pgm$', p)]
impostor = [load(p) for p in b]
gs = sorted(round(score(p, enroll), 3) for p in genuine)
im = sorted(round(score(p, enroll), 3) for p in impostor)
print('genuine  (10):', gs)
print('impostor (15):', im)
print(f'separation: min genuine {gs[0]} vs max impostor {im[-1]}')
