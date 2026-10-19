#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Writes tests/vectors/moh.json: python-validity's MoH template pipeline on
synthetic frames (integer ridge pattern plus LCG noise, no biometric data).

  nix-shell --run 'python3 tools/moh_vectors.py PYTHON_VALIDITY_DIR > tests/vectors/moh.json'

`synthetic` here and in src/moh.rs's tests must stay in step.
"""

import hashlib
import json
import struct
import subprocess
import sys

import numpy as np

SIDE = 112
FRAMES = [
    # seed, centre x, centre y, quadratic form a, b, c
    (1, 40, 70, 9, 5, 3),
    (2, 75, 30, 4, 8, -2),
    (3, 56, 56, 6, 6, 1),
]
SUBTYPE = 0x00f5


def synthetic(seed, cx, cy, a, b, c):
    """Curved ridges from a triangle wave over a quadratic form, plus noise"""
    state = seed
    pixels = bytearray()
    for y in range(SIDE):
        for x in range(SIDE):
            state = (state * 6364136223846793005 + 1442695040888963407) % 2**64
            dx, dy = x - cx, y - cy
            t = ((a * dx * dx + b * dy * dy + c * dx * dy) >> 5) % 64
            ridge = t if t < 32 else 63 - t
            pixels.append(40 + ridge * 5 + (state >> 59))
    return bytes(pixels)


def main():
    sys.path.insert(0, sys.argv[1])
    from validitysensor import moh_native

    revision = subprocess.run(['git', '-C', sys.argv[1], 'rev-parse', '--short', 'HEAD'],
                              capture_output=True, text=True).stdout.strip()
    out = {'source': f'python-validity {revision} moh_native, synthetic frames', 'subtype': SUBTYPE, 'frames': []}
    per_frame = []
    for spec in FRAMES:
        image = np.frombuffer(synthetic(*spec), np.uint8).reshape(SIDE, SIDE)
        stats = {}
        kps = moh_native.extract_frame_native(image.astype(np.int32) << 16, stats=stats)
        per_frame.append(kps)
        out['frames'].append({
            'spec': spec,
            'image_sha256': hashlib.sha256(image.tobytes()).hexdigest(),
            'pool': stats['n_pool'],
            # x, y, orientation (f64 bits, little-endian), descriptor
            'keypoints': [f'{x:02x}{y:02x}{struct.pack("<d", o).hex()}{bytes(d).hex()}' for x, y, o, d in kps],
        })
    scaffold = moh_native._load_ws_scaffold()
    out['scaffold_sha256'] = hashlib.sha256(scaffold).hexdigest()
    out['scaffold_template_id'] = moh_native.compute_tid(scaffold).hex()
    envelope = moh_native.assemble_template(per_frame, SUBTYPE)
    out['envelope_sha256'] = hashlib.sha256(envelope).hexdigest()
    out['envelope_head'] = envelope[:16].hex()
    out['envelope_tail'] = envelope[-80:].hex()
    json.dump(out, sys.stdout, indent=1)
    print()


if __name__ == '__main__':
    main()
