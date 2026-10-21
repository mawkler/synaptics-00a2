#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Drives the TOD module through libfprint-tod the way fprintd would.

  tod_test.py --typelib DIR --drivers DIR --serial-file F COMMAND ...
    enroll --out PRINT [--finger F]        10 touch-and-lift placements; the
                                           template goes onto the sensor (a
                                           database write) under your user
    list                                   the prints stored on the sensor
    delete --print PRINT                   delete one stored print (a write)
    verify --print PRINT --attempts N      N attempts against one print
    identify --print PRINT... --attempts N N attempts against several
    reopen --cycles N                      open/close back to back, no touch
    cancel --when waiting|finger --print PRINT
                                           cancel a verify while waiting for a
                                           finger (or 0.8 s after one is down),
                                           reopen at once, then verify once
    resume --print PRINT                   wait for the reader to disappear and
                                           come back (suspend/resume), then
                                           open the new device and verify once

Opening calibrates for about a second: keep the sensor clear. A rejected
placement is retried. Prints finger-status changes, progress and decisions,
never image data; serialized prints (which only name a stored finger) are
written mode 0600.
"""

import argparse
import gc
import getpass
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
    parser.add_argument('--trace', help="have the driver append each scan's raw events here (SYNA_00A2_TRACE)")
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('enroll')
    p.add_argument('--out', required=True)
    p.add_argument('--finger', default='right-middle', help='e.g. right-middle, left-index')
    sub.add_parser('list')
    sub.add_parser('delete').add_argument('--print', required=True, dest='prints', type=lambda v: [v])
    for name in ('verify', 'identify'):
        p = sub.add_parser(name)
        p.add_argument('--print', nargs='+', required=True, dest='prints')
        p.add_argument('--attempts', type=int, default=5)
    sub.add_parser('reopen').add_argument('--cycles', type=int, default=5)
    p = sub.add_parser('cancel')
    p.add_argument('--when', choices=['waiting', 'finger'], required=True)
    p.add_argument('--print', required=True, dest='prints', type=lambda v: [v])
    sub.add_parser('resume').add_argument('--print', required=True, dest='prints', type=lambda v: [v])
    args = parser.parse_args()

    os.environ['GI_TYPELIB_PATH'] = args.typelib + os.pathsep + os.environ.get('GI_TYPELIB_PATH', '')
    os.environ['FP_TOD_DRIVERS_DIR'] = os.path.abspath(args.drivers)
    os.environ['SYNA_00A2_SERIAL_FILE'] = os.path.abspath(args.serial_file)
    if args.trace:
        os.environ['SYNA_00A2_TRACE'] = os.path.abspath(args.trace)

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

    def driver_log(domain, level, message, *_):
        if level & (GLib.LogLevelFlags.LEVEL_WARNING | GLib.LogLevelFlags.LEVEL_CRITICAL):
            event('driver_warning', message=message)
    GLib.log_set_handler('libfprint-syna_00a2', GLib.LogLevelFlags.LEVEL_MASK, driver_log, None)

    # A stop request cancels the running action, so the driver stops the scan
    # (0x04) and libfprint completes it before the device is closed
    cancellable = Gio.Cancellable()

    def stop(*_):
        event('stop_requested')
        cancellable.cancel()
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    def iterate():
        # Non-blocking, so Python gets to run the signal handler promptly
        if not loop.iteration(False):
            time.sleep(0.01)

    def wait(done, what, seconds=120, action=None):
        deadline = time.monotonic() + seconds
        while not done():
            # Waits with a running action end when the action is cancelled;
            # other waits end here once a stop was requested
            if action is None and cancellable.is_cancelled():
                raise RuntimeError(f'stopped while waiting for {what}')
            if time.monotonic() > deadline:
                if action is None or action.is_cancelled():
                    raise TimeoutError(f'no {what} within the time limit')
                action.cancel()
                deadline = time.monotonic() + 10
            iterate()

    context = FPrint.Context()
    state = {'dev': None}

    def find_device():
        return next((d for d in context.get_devices() if d.get_driver() == 'syna_00a2'), None)

    def watch(dev):
        def on_status(*_):
            status = dev.get_finger_status()
            if status & FPrint.FingerStatusFlags.PRESENT:
                event('finger_present')
            elif status & FPrint.FingerStatusFlags.NEEDED:
                event('place_finger')
                print('PLACE YOUR FINGER on the sensor now', flush=True)
        dev.connect('notify::finger-status', on_status)

    def open_device(dev):
        t0 = time.monotonic()
        dev.open_sync()
        event('opened', seconds=round(time.monotonic() - t0, 2))

    def close_device(dev):
        try:
            dev.close_sync()
            event('closed')
        except GLib.Error as e:
            event('close_error', message=e.message)

    def attempt(dev, prints, mode, action, on_finger=None):
        """One verify/identify; returns the outcome dict (retries are outcomes too)"""
        outcome = {}

        def done_cb(dev, res):
            try:
                if mode == 'verify':
                    match, _ = dev.verify_finish(res)
                    outcome['match'] = bool(match)
                else:
                    match, _ = dev.identify_finish(res)
                    outcome['match'] = None if match is None else next(i for i, p in enumerate(prints) if p.equal(match))
            except GLib.Error as e:
                outcome['error'] = e.message
                # libfprint's retry errors use the fp-device-retry-quark domain
                outcome['retry'] = 'retry' in e.domain
                outcome['cancelled'] = e.matches(Gio.io_error_quark(), Gio.IOErrorEnum.CANCELLED)

        handler = dev.connect('notify::finger-status', on_finger) if on_finger else None
        if mode == 'verify':
            dev.verify(prints[0], cancellable=action, callback=done_cb)
        else:
            dev.identify(prints, cancellable=action, callback=done_cb)
        wait(lambda: outcome, 'result', seconds=300, action=action)
        if handler:
            dev.disconnect(handler)
        return outcome

    def attempts(dev, prints, mode, count):
        results = []
        while len(results) < count:
            if cancellable.is_cancelled():
                raise RuntimeError('stopped')
            outcome = attempt(dev, prints, mode, cancellable)
            event('attempt', **outcome)
            if 'error' in outcome and not outcome['retry']:
                raise RuntimeError(f"{mode} failed: {outcome['error']}")
            if 'error' not in outcome:
                results.append(outcome['match'])
        return results

    def load_prints():
        return [FPrint.Print.deserialize(open(p, 'rb').read()) for p in args.prints]

    try:
        dev = state['dev'] = find_device()
        if dev is None:
            raise RuntimeError('the syna_00a2 TOD driver did not load or found no reader')
        watch(dev)
        if args.command == 'reopen':
            for _ in range(args.cycles):
                open_device(dev)
                close_device(dev)
            report['results'] = 'ok'
        else:
            open_device(dev)

        if args.command == 'enroll':
            done = {}

            def progress_cb(dev, stage, print_, *rest):
                error = next((r for r in rest if isinstance(r, GLib.Error)), None)
                event('enroll_progress', stage=stage, of=dev.get_nr_enroll_stages(), retry=error.message if error else None)

            def enroll_done(dev, res):
                try:
                    done['print'] = dev.enroll_finish(res)
                except GLib.Error as e:
                    done['error'] = e.message

            template = FPrint.Print.new(dev)
            template.set_finger(getattr(FPrint.Finger, args.finger.upper().replace('-', '_')))
            template.set_username(getpass.getuser())
            dev.enroll(template, cancellable, progress_cb, tuple(), enroll_done)
            wait(lambda: done, 'enrollment', seconds=600, action=cancellable)
            if 'error' in done:
                raise RuntimeError(f"enroll failed: {done['error']}")
            data = bytes(done['print'].serialize())
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.write(fd, data)
            os.close(fd)
            event('enrolled', print_bytes=len(data), file=args.out)

        elif args.command == 'list':
            prints = dev.list_prints_sync()
            report['results'] = [{'finger': p.get_finger().value_nick, 'username': p.get_username()} for p in prints]
            event('listed', prints=report['results'])

        elif args.command == 'delete':
            dev.delete_print_sync(load_prints()[0])
            event('deleted', file=args.prints[0])

        elif args.command in ('verify', 'identify'):
            report['results'] = attempts(dev, load_prints(), args.command, args.attempts)
            event('summary', attempts=len(report['results']),
                  matched=sum(1 for r in report['results'] if r is not False and r is not None), results=report['results'])

        elif args.command == 'cancel':
            prints = load_prints()
            action = Gio.Cancellable()

            def cancel_later(ms):
                def fire():
                    event('cancelling')
                    action.cancel()
                    return False
                GLib.timeout_add(ms, fire)

            on_finger = None
            if args.when == 'waiting':
                cancel_later(3000)
            else:
                def on_finger(dev, _):
                    if dev.get_finger_status() & FPrint.FingerStatusFlags.PRESENT and not action.is_cancelled():
                        cancel_later(800)
            cancelled_at = []
            action.connect(lambda *_: cancelled_at.append(time.monotonic()))
            outcome = attempt(dev, prints, 'verify', action, on_finger)
            if cancelled_at:
                outcome['completed_after_cancel_s'] = round(time.monotonic() - cancelled_at[0], 2)
            event('cancelled_attempt', **outcome)
            close_device(dev)
            event('reopening')
            open_device(dev)
            report['results'] = attempts(dev, prints, 'verify', 1)
            event('summary', after_cancel=outcome.get('cancelled'), verify_after_reopen=report['results'])

        elif args.command == 'resume':
            prints = load_prints()
            seen = {}

            def added(ctx, d):
                if d.get_driver() == 'syna_00a2':
                    seen.setdefault('added', d)
            # The reader re-enumerates on resume. An open device emits its own
            # "removed"; the context only reports it once the device is closed,
            # which is what fprintd does next
            dev.connect('removed', lambda d: seen.setdefault('removed', True))
            context.connect('device-added', added)
            event('waiting_for_suspend', hint='suspend the laptop now, then resume it')
            wait(lambda: 'removed' in seen, 'device removal (suspend/resume)', seconds=600)
            event('device_removed')
            close_device(dev)
            wait(lambda: 'added' in seen, 'the new device', seconds=120)
            event('device_added')
            # Drop the removed device now (fprintd unrefs it too): kept alive
            # past the GUsb context, it crashed the process at exit
            del dev
            gc.collect()
            dev = state['dev'] = seen.pop('added')
            watch(dev)
            open_device(dev)
            report['results'] = attempts(dev, prints, 'verify', 1)
            event('summary', verify_after_resume=report['results'])
    except Exception as e:
        report['error'] = f'{type(e).__name__}: {e}'
        event('error', message=report['error'])
    finally:
        if state.get('dev') is not None and state['dev'].is_open():
            close_device(state['dev'])
        if args.output:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.write(fd, json.dumps(report, indent=1).encode())
            os.close(fd)
        state.clear()
        gc.collect()
        del context
    sys.exit(1 if 'error' in report else 0)


if __name__ == '__main__':
    main()
