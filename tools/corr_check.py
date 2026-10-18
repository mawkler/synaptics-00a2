#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Correlation-matcher feasibility check (M5 follow-up).

usage: corr_check.py --enroll PGM... --genuine PGM... --impostor PGM...
Scores each genuine and impostor probe against the enrolled placements.
Prints scores only.
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

import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--enroll', nargs='+', required=True)
parser.add_argument('--genuine', nargs='+', required=True)
parser.add_argument('--impostor', nargs='+', required=True)
args = parser.parse_args()
enroll = [load(p) for p in args.enroll]
gs = sorted(round(float(score(load(p), enroll)), 3) for p in args.genuine)
im = sorted(round(float(score(load(p), enroll)), 3) for p in args.impostor)
print(f'genuine  ({len(gs)}):', gs)
print(f'impostor ({len(im)}):', im)
print(f'separation: min genuine {gs[0]} vs max impostor {im[-1]}')
