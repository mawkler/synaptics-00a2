#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""M5 matching gate: can stock libfprint match this sensor's images?

Feeds PGM captures to libfprint's virtual_image driver in-process, the way
the planned feeder would: enrolls one finger from a few placements, then
verifies held-out placements of the same finger (genuine) and of another
finger (impostor). Prints decisions, minutiae counts and Bozorth3 scores as
JSON, never image data.

Run inside the dev shell with stock libfprint's typelib first:
  GI_TYPELIB_PATH=$LIBFPRINT_TYPELIB:$GI_TYPELIB_PATH python3 tools/m5_gate.py ...
"""

import argparse
import json
import os
import re
import shutil
import socket
import struct
import sys
import tempfile
import time

import numpy as np


def load_pgm(path):
    raw = open(path, 'rb').read()
    offset, fields = 0, []
    while len(fields) < 4:
        match = re.compile(rb'\s*(\S+)').match(raw, offset)
        fields.append(match.group(1))
        offset = match.end()
    magic, width, height, maxval = fields[0], int(fields[1]), int(fields[2]), int(fields[3])
    if magic != b'P5' or maxval != 255:
        raise ValueError(f'{path}: not an 8-bit binary PGM')
    pixels = raw[offset + 1:offset + 1 + width * height]
    return np.frombuffer(pixels, np.uint8).reshape(height, width)


def bilinear(img, scale):
    """Resamples by `scale` (e.g. 500/363 dpi) with bilinear interpolation"""
    if scale == 1:
        return img
    h, w = img.shape
    nh, nw = round(h * scale), round(w * scale)
    ys = np.clip((np.arange(nh) + 0.5) / scale - 0.5, 0, h - 1)
    xs = np.clip((np.arange(nw) + 0.5) / scale - 0.5, 0, w - 1)
    y0, x0 = np.floor(ys).astype(int), np.floor(xs).astype(int)
    y1, x1 = np.minimum(y0 + 1, h - 1), np.minimum(x0 + 1, w - 1)
    fy, fx = (ys - y0)[:, None], (xs - x0)[None, :]
    f = img.astype(float)
    top = f[y0][:, x0] * (1 - fx) + f[y0][:, x1] * fx
    bottom = f[y1][:, x0] * (1 - fx) + f[y1][:, x1] * fx
    return np.clip(np.round(top * (1 - fy) + bottom * fy), 0, 255).astype(np.uint8)


def box(img, k):
    """Mean over a k×k window (k odd), edges reflected"""
    padded = np.pad(img, k // 2, mode='reflect')
    sums = np.pad(padded.cumsum(0).cumsum(1), ((1, 0), (1, 0)))
    return (sums[k:, k:] - sums[:-k, k:] - sums[k:, :-k] + sums[:-k, :-k]) / (k * k)


def local_normalise(img, k=15):
    """Zero local mean, unit local variance, mapped back to 0..255"""
    f = img.astype(float)
    mean = box(f, k)
    sd = np.sqrt(np.maximum(box(f * f, k) - mean * mean, 1e-6))
    return np.clip(128 + 48 * (f - mean) / sd, 0, 255).astype(np.uint8)


def prepare(path, scale, invert, preprocess):
    img = load_pgm(path)
    if preprocess == 'smooth-localnorm':
        img = np.clip(np.round(box(img.astype(float), 3)), 0, 255).astype(np.uint8)
    if preprocess in ('localnorm', 'smooth-localnorm'):
        img = local_normalise(img)
    img = bilinear(img, scale)
    return 255 - img if invert else img


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--enroll', nargs='+', required=True, help='placements to enroll from, in order')
    parser.add_argument('--genuine', nargs='+', required=True, help='held-out placements of the enrolled finger')
    parser.add_argument('--impostor', nargs='+', required=True, help='placements of other fingers')
    parser.add_argument('--scale', type=float, default=1.0, help='resample factor before feeding')
    parser.add_argument('--invert', action='store_true', help='invert grey levels before feeding')
    parser.add_argument('--preprocess', choices=['none', 'localnorm', 'smooth-localnorm'], default='none')
    parser.add_argument('--debug-log', help='keep libfprint\'s log here (it holds no image data)')
    args = parser.parse_args()

    tmpdir = tempfile.mkdtemp(prefix='m5-gate-')
    sockaddr = os.path.join(tmpdir, 'virtual-image.socket')
    os.environ['FP_VIRTUAL_IMAGE'] = sockaddr
    # Stock libfprint 1.94.100 reports the virtual device as overheated on its
    # first operation unless its thermal model is off, as libfprint's tests do
    os.environ.setdefault('FP_VIRTUAL_IMAGE_HOT_SECONDS', '-1')
    os.environ.setdefault('G_MESSAGES_DEBUG', 'libfprint-print libfprint-image')
    # GLib prints libfprint's debug lines, including Bozorth3 scores, to stdout
    # and warnings to stderr. Send both to a private file, with a marker before
    # each attempt so scores can be attributed; the report goes to the real stdout.
    log_path = args.debug_log or os.path.join(tmpdir, 'libfprint.log')
    log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    saved_stdout, saved_stderr = os.dup(1), os.dup(2)
    os.dup2(log_fd, 1)
    os.dup2(log_fd, 2)

    def restore():
        sys.stdout.flush()
        os.dup2(saved_stdout, 1)
        os.dup2(saved_stderr, 2)

    import gi
    gi.require_version('FPrint', '2.0')
    from gi.repository import FPrint, Gio, GLib

    ctx = GLib.main_context_default()
    context = FPrint.Context()
    dev = next((d for d in context.get_devices() if d.get_driver() == 'virtual_image'), None)
    if dev is None:
        restore()
        sys.exit('stock libfprint has no virtual_image driver')
    dev.open_sync()
    con = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    con.connect(sockaddr)

    def feed(path):
        img = prepare(path, args.scale, args.invert, args.preprocess)
        h, w = img.shape
        con.sendall(struct.pack('ii', w, h) + img.tobytes())

    def iterate_until(done, what, seconds=20):
        deadline = time.monotonic() + seconds
        while not done():
            if time.monotonic() > deadline:
                restore()
                sys.exit(f'timed out waiting for {what}; see --debug-log')
            ctx.iteration(False) or time.sleep(0.005)

    def wait_needed():
        iterate_until(lambda: dev.get_finger_status() & FPrint.FingerStatusFlags.NEEDED, 'finger-needed')

    # Enrollment: one placement per stage; a retry consumes the next placement
    state = {'done': None, 'progress': []}

    def progress_cb(dev, stage, print_, *rest):
        error = next((r for r in rest if isinstance(r, GLib.Error)), None)
        state['progress'].append({'stage': stage, 'retry': error.message if error else None})

    def enroll_cb(dev, res):
        try:
            state['done'] = dev.enroll_finish(res)
        except GLib.Error as e:
            state['done'] = e

    template = FPrint.Print.new(dev)
    cancellable = Gio.Cancellable()
    dev.enroll(template, cancellable, progress_cb, tuple(), enroll_cb)
    used = []
    for path in args.enroll:
        if state['done'] is not None:
            break
        wait_needed()
        os.write(2, f'=== enroll {os.path.basename(path)}\n'.encode())
        feed(path)
        used.append(os.path.basename(path))
        before = len(state['progress'])
        iterate_until(lambda: len(state['progress']) > before or state['done'] is not None, 'enroll progress')
    stages = dev.get_nr_enroll_stages()
    if state['done'] is None and any(p['stage'] == stages for p in state['progress']):
        iterate_until(lambda: state['done'] is not None, 'enroll completion')
    if state['done'] is None:
        # Retries used up the placements before the last stage
        cancellable.cancel()
        iterate_until(lambda: state['done'] is not None, 'enroll cancellation')
    enrolled = state['done'] if isinstance(state['done'], FPrint.Print) else None
    result = {
        'scale': args.scale,
        'invert': args.invert,
        'preprocess': args.preprocess,
        'enroll': {
            'stages_needed': stages,
            'placements_fed': used,
            'progress': state['progress'],
            'completed': enrolled is not None,
            'error': state['done'].message if isinstance(state['done'], GLib.Error) else None,
        },
        'attempts': [],
    }

    if enrolled is not None:
        for kind, paths in (('genuine', args.genuine), ('impostor', args.impostor)):
            for path in paths:
                outcome = {}

                def verify_cb(dev, res):
                    try:
                        match, print_ = dev.verify_finish(res)
                        image = print_.props.image if print_ else None
                        outcome.update(match=match, minutiae=len(image.get_minutiae()) if image else None)
                    except GLib.Error as e:
                        outcome.update(error=e.message)

                dev.verify(enrolled, callback=verify_cb)
                wait_needed()
                os.write(2, f'=== {kind} {os.path.basename(path)}\n'.encode())
                feed(path)
                iterate_until(lambda: outcome, 'verify result')
                result['attempts'].append(dict(kind=kind, file=os.path.basename(path), **outcome))

    con.close()
    dev.close_sync()
    restore()
    os.close(log_fd)

    # Attribute logged scores and minutiae counts to the marker before them
    current, scores = None, {}
    for line in open(log_path, errors='replace'):
        if line.startswith('=== '):
            current = line[4:].strip()
            scores[current] = []
        elif current and (m := re.search(r'score (\d+)/(\d+)', line)):
            scores[current].append(int(m.group(1)))
            result['threshold'] = int(m.group(2))
    for attempt in result['attempts']:
        attempt['scores'] = scores.get(f"{attempt['kind']} {attempt['file']}", [])
    shutil.rmtree(tmpdir)  # the log too, unless --debug-log put it elsewhere

    genuine = [a for a in result['attempts'] if a['kind'] == 'genuine']
    impostor = [a for a in result['attempts'] if a['kind'] == 'impostor']
    result['summary'] = {
        'genuine_accepted': f"{sum(bool(a.get('match')) for a in genuine)}/{len(genuine)}",
        'impostor_accepted': f"{sum(bool(a.get('match')) for a in impostor)}/{len(impostor)}",
        'genuine_best_scores': [max(a['scores'], default=None) for a in genuine],
        'impostor_best_scores': [max(a['scores'], default=None) for a in impostor],
        'minutiae': [a.get('minutiae') for a in result['attempts']],
    }
    print(json.dumps(result))


if __name__ == '__main__':
    main()
