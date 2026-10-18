#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Drives the TOD module through libfprint-tod the way fprintd would.

  tod_test.py --typelib DIR --drivers DIR --serial-file F enroll --out PRINT
  tod_test.py ... verify --print PRINT --attempts N
  tod_test.py ... identify --print PRINT [PRINT...] --attempts N

Each command opens the reader (calibration takes about a second; keep the
sensor clear), then waits for touch-and-lift placements. A rejected
placement is retried. Prints finger-status changes, progress and decisions,
never image data; the serialized print is written mode 0600.
"""

import argparse
import json
import os
import signal
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--typelib', required=True, help="libfprint-tod's girepository-1.0 directory")
    parser.add_argument('--drivers', required=True, help='directory holding libsyna_00a2_tod.so')
    parser.add_argument('--serial-file', required=True, help='private copy of the DMI serial (sysfs needs root)')
    parser.add_argument('--output', help='also write the JSON report here (0600)')
    sub = parser.add_subparsers(dest='command', required=True)
    enroll = sub.add_parser('enroll')
    enroll.add_argument('--out', required=True)
    for name in ('verify', 'identify'):
        p = sub.add_parser(name)
        p.add_argument('--print', nargs='+', required=True, dest='prints')
        p.add_argument('--attempts', type=int, default=5)
    args = parser.parse_args()

    os.environ['GI_TYPELIB_PATH'] = args.typelib + os.pathsep + os.environ.get('GI_TYPELIB_PATH', '')
    os.environ['FP_TOD_DRIVERS_DIR'] = os.path.abspath(args.drivers)
    os.environ['SYNA_00A2_SERIAL_FILE'] = os.path.abspath(args.serial_file)

    import gi
    gi.require_version('FPrint', '2.0')
    from gi.repository import FPrint, Gio, GLib

    loop = GLib.main_context_default()
    started = time.monotonic()
    report = {'command': args.command, 'events': []}

    def event(kind, **fields):
        entry = dict(t=round(time.monotonic() - started, 2), event=kind, **fields)
        report['events'].append(entry)
        print(json.dumps(entry), flush=True)

    # A stop request cancels the running action, so the driver stops the scan
    # (0x04) and libfprint completes it before the device is closed
    cancellable = Gio.Cancellable()

    def stop(*_):
        event('stop_requested')
        cancellable.cancel()
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    def wait(done, what, seconds=120):
        deadline = time.monotonic() + seconds
        while not done():
            if time.monotonic() > deadline:
                if cancellable.is_cancelled():
                    raise TimeoutError(f'no {what} even after cancelling')
                cancellable.cancel()
                deadline = time.monotonic() + 10
            # Non-blocking, so Python gets to run the signal handler promptly
            if not loop.iteration(False):
                time.sleep(0.01)

    context = FPrint.Context()
    dev = next((d for d in context.get_devices() if d.get_driver() == 'syna_00a2'), None)
    if dev is None:
        sys.exit('the syna_00a2 TOD driver did not load or found no reader')

    def on_status(*_):
        status = dev.get_finger_status()
        if status & FPrint.FingerStatusFlags.PRESENT:
            event('finger_present')
        elif status & FPrint.FingerStatusFlags.NEEDED:
            event('place_finger')
            print('PLACE YOUR FINGER on the sensor now', flush=True)
    dev.connect('notify::finger-status', on_status)

    try:
        event('opening')
        dev.open_sync()
        event('opened')
        if args.command == 'enroll':
            state = {'done': None}

            def progress_cb(dev, stage, print_, *rest):
                error = next((r for r in rest if isinstance(r, GLib.Error)), None)
                event('enroll_progress', stage=stage, of=dev.get_nr_enroll_stages(), retry=error.message if error else None)

            def done_cb(dev, res):
                try:
                    state['done'] = dev.enroll_finish(res)
                except GLib.Error as e:
                    state['done'] = e

            template = FPrint.Print.new(dev)
            template.set_finger(FPrint.Finger.UNKNOWN)
            dev.enroll(template, cancellable, progress_cb, tuple(), done_cb)
            wait(lambda: state['done'] is not None, 'enrollment', seconds=600)
            if isinstance(state['done'], GLib.Error):
                raise RuntimeError(f"enroll failed: {state['done'].message}")
            data = bytes(state['done'].serialize())
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.write(fd, data)
            os.close(fd)
            event('enrolled', print_bytes=len(data), file=args.out)
        else:
            prints = [FPrint.Print.deserialize(open(p, 'rb').read()) for p in args.prints]
            results = []
            while len(results) < args.attempts:
                outcome = {}

                def done_cb(dev, res):
                    try:
                        if args.command == 'verify':
                            match, _ = dev.verify_finish(res)
                            outcome['match'] = bool(match)
                        else:
                            match, _ = dev.identify_finish(res)
                            outcome['match'] = None if match is None else prints.index(next(p for p in prints if p.equal(match)))
                    except GLib.Error as e:
                        outcome['error'] = e.message
                        # libfprint's retry errors use the fp-device-retry-quark domain
                        outcome['retry'] = 'retry' in e.domain

                if cancellable.is_cancelled():
                    raise RuntimeError('stopped')
                if args.command == 'verify':
                    dev.verify(prints[0], cancellable=cancellable, callback=done_cb)
                else:
                    dev.identify(prints, cancellable=cancellable, callback=done_cb)
                wait(lambda: outcome, 'result', seconds=300)
                event('attempt', **outcome)
                if 'error' in outcome and not outcome.get('retry'):
                    raise RuntimeError(f"{args.command} failed: {outcome['error']}")
                if 'error' not in outcome:
                    results.append(outcome['match'])
            report['results'] = results
            event('summary', attempts=len(results),
                  matched=sum(1 for r in results if r not in (False, None)))
    except Exception as e:
        report['error'] = str(e)
        event('error', message=str(e))
    finally:
        try:
            dev.close_sync()
            event('closed')
        except GLib.Error as e:
            event('close_error', message=e.message)
        if args.output:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.write(fd, json.dumps(report, indent=1).encode())
            os.close(fd)
        del dev, context
    sys.exit(1 if 'error' in report else 0)


if __name__ == '__main__':
    main()
