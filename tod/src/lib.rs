// SPDX-License-Identifier: LGPL-2.1-or-later
//! libfprint-TOD driver module for the Synaptics 06cb:00a2 reader. The C half
//! (`syna_00a2_tod.c`) is the FpDevice subclass; this half is the C ABI over
//! the `syna-00a2` crate that it calls from worker threads. Every entry point
//! catches panics, as unwinding into C is undefined behaviour.

use std::{
    ffi::{c_char, c_int, c_void, CString},
    fs,
    io::Write,
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::{ensure, Context, Result};
use syna_00a2::{
    calibrate,
    capture::Scan,
    chip::{self, DataFull, NotFound, Print},
    device::{self, ScanOutcome, Scanner},
    matcher, moh,
    pairing::HostKeys,
    usb,
};

pub const SYNA_IMAGE: c_int = 0;
pub const SYNA_RETRY: c_int = 1;
pub const SYNA_CANCELLED: c_int = 2;
pub const SYNA_MATCH: c_int = 3;
pub const SYNA_NO_MATCH: c_int = 4;
pub const SYNA_DATA_FULL: c_int = 5;
pub const SYNA_NOT_FOUND: c_int = 6;
pub const SYNA_OK: c_int = 0;
pub const SYNA_ERROR: c_int = -1;

/// A finger stored on the sensor, as the C side keeps it in the print:
/// the Linux uid and the WinBio finger position
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SynaPrint {
    pub uid: u32,
    pub subtype: u16,
}

impl From<Print> for SynaPrint {
    fn from(p: Print) -> Self {
        Self {
            uid: p.uid,
            subtype: p.subtype,
        }
    }
}

impl From<SynaPrint> for Print {
    fn from(p: SynaPrint) -> Self {
        Self {
            uid: p.uid,
            subtype: p.subtype,
        }
    }
}

pub const SYNA_STATUS_NEEDED: c_int = 1;
pub const SYNA_STATUS_PRESENT: c_int = 2;

/// fprintd decides how long to wait for a finger; cancellation ends the wait
const FINGER_TIMEOUT: Duration = Duration::from_secs(24 * 3600);

pub type CancelledFn = extern "C" fn(*mut c_void) -> c_int;
pub type StatusFn = extern "C" fn(*mut c_void, c_int);

/// A match this soon after a miss refreshes the matched finger's templates
/// (see `chip::refresh`): a miss then a match is the finger reading
/// differently from what is stored, and the matching touch shows how it reads
/// now
const REFRESH_AFTER_MISS: Duration = Duration::from_secs(120);

/// The last miss, kept by the process rather than the open reader: fprintd
/// opens the reader anew for each login attempt, often for a single touch
static LAST_MISS: Mutex<Option<Instant>> = Mutex::new(None);

/// At most one refresh per process (a panel run, or fprintd's lifetime at a
/// lock screen), so the recent slots keep templates from several sittings.
/// On 2026-10-27 all three came from one evening and nothing matched
static REFRESHED: AtomicBool = AtomicBool::new(false);

pub struct SynaHandle {
    scanner: Scanner,
}

extern "C" {
    fn fpi_device_syna_00a2_get_type() -> usize;
}

/// The libfprint-TOD entry point: the driver's GType
#[no_mangle]
pub extern "C" fn fpi_tod_shared_driver_get_type() -> usize {
    // SAFETY: a plain G_DEFINE_TYPE getter from the C half
    unsafe { fpi_device_syna_00a2_get_type() }
}

/// Stores a message for the C side, which frees it with `syna_string_free`
fn set_error(out: *mut *mut c_char, message: String) {
    if !out.is_null() {
        let message = CString::new(message.replace('\0', " ")).expect("NULs were replaced");
        // SAFETY: the C side passes a valid pointer to a char *
        unsafe { *out = message.into_raw() };
    }
}

fn guard<T>(error: *mut *mut c_char, failed: T, f: impl FnOnce() -> Result<T>) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(value)) => value,
        Ok(Err(e)) => {
            set_error(error, format!("{e:#}"));
            failed
        }
        Err(_) => {
            set_error(error, "panic in the syna-00a2 driver core".into());
            failed
        }
    }
}

/// # Safety
/// `message` must be NULL or a string this library returned through an error out-parameter.
#[no_mangle]
pub unsafe extern "C" fn syna_string_free(message: *mut c_char) {
    if !message.is_null() {
        // SAFETY: allocated by set_error
        drop(unsafe { CString::from_raw(message) });
    }
}

/// fprintd runs as root, so the serial can be read from sysfs directly.
/// For tests as a normal user, SYNA_00A2_SERIAL_FILE names a private copy.
fn host_keys() -> Result<HostKeys> {
    let path = std::env::var_os("SYNA_00A2_SERIAL_FILE")
        .unwrap_or("/sys/class/dmi/id/product_serial".into());
    let serial = fs::read_to_string(&path).with_context(|| {
        format!(
            "reading the DMI serial from {} (sysfs needs root)",
            path.to_string_lossy()
        )
    })?;
    Ok(HostKeys::derive(
        &device::dmi_product_name()?,
        serial.trim(),
    ))
}

/// Opens the reader at `bus`/`address`, handshakes and calibrates. Blocks.
/// # Safety
/// `error` must be NULL or point to a writable `char *`.
#[no_mangle]
pub unsafe extern "C" fn syna_open(
    bus: u8,
    address: u8,
    error: *mut *mut c_char,
) -> *mut SynaHandle {
    guard(error, ptr::null_mut(), || {
        let keys = host_keys()?;
        let sensor = usb::Sensor::open_at(bus, address)?;
        // One journal line per calibration, to explain failures in real use
        let scanner = Scanner::open(sensor, &keys, &mut |name, value| {
            if name.starts_with("calibration") {
                let diff = &value["blank_vs_partition6_mean_abs_diff"];
                eprintln!("syna_00a2: {name}: blank vs clean slate {diff}");
            }
        })?;
        Ok(Box::into_raw(Box::new(SynaHandle { scanner })))
    })
}

/// Releases the reader (no reset, as in the CLI)
/// # Safety
/// `handle` must be NULL or a handle from `syna_open` that is not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn syna_close(handle: *mut SynaHandle) {
    if !handle.is_null() {
        // SAFETY: allocated by syna_open; the C side drops its copy
        let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { Box::from_raw(handle) })));
    }
}

#[no_mangle]
pub extern "C" fn syna_image_size() -> usize {
    matcher::SIDE * matcher::SIDE
}

/// One placement. Writes `syna_image_size()` pixels to `image` and returns
/// SYNA_IMAGE, or returns SYNA_RETRY (the sensor rejected the placement),
/// SYNA_CANCELLED or SYNA_ERROR. `on_status` reports when the sensor waits
/// for a finger and when one is down. Blocks until then.
/// # Safety
/// `handle` must come from `syna_open` and not be used concurrently, `image` must hold
/// `syna_image_size()` bytes, and `error` must be NULL or point to a writable `char *`.
#[no_mangle]
pub unsafe extern "C" fn syna_capture(
    handle: *mut SynaHandle,
    is_cancelled: CancelledFn,
    on_status: StatusFn,
    user: *mut c_void,
    image: *mut u8,
    error: *mut *mut c_char,
) -> c_int {
    guard(error, SYNA_ERROR, || {
        // SAFETY: the C side passes the handle from syna_open, used by one thread at a time
        let handle = unsafe { handle.as_mut() }.context("the device is not open")?;
        let cancelled = || is_cancelled(user) != 0;
        let outcome = handle.scanner.capture(
            FINGER_TIMEOUT,
            &cancelled,
            || on_status(user, SYNA_STATUS_NEEDED),
            || on_status(user, SYNA_STATUS_PRESENT),
        );
        trace(&outcome);
        match outcome.result {
            Ok(Scan::Image(scan)) => {
                ensure!(
                    scan.pixels.len() == syna_image_size(),
                    "unexpected image size {}x{}",
                    scan.width,
                    scan.height
                );
                // SAFETY: the C side passes a buffer of syna_image_size() bytes
                unsafe { slice::from_raw_parts_mut(image, scan.pixels.len()) }
                    .copy_from_slice(&scan.pixels);
                Ok(SYNA_IMAGE)
            }
            Ok(Scan::Rejected(_)) => Ok(SYNA_RETRY),
            Err(_) if cancelled() => Ok(SYNA_CANCELLED),
            Err(e) => Err(e),
        }
    })
}

/// Appends one JSON line per scan to the file named by SYNA_00A2_TRACE, for
/// diagnosing scans that stall. Off unless the variable is set (tests only).
fn trace(scan: &ScanOutcome) {
    if std::env::var_os("SYNA_00A2_TRACE").is_none() {
        return;
    }
    let outcome = match &scan.result {
        Ok(Scan::Image(_)) => "image".to_owned(),
        Ok(Scan::Rejected(code)) => format!("rejected {code:#x}"),
        Err(e) => format!("error: {e:#}"),
    };
    note(serde_json::json!({
        "outcome": outcome,
        "events": scan.events,
        "stale": scan.stale,
        "stalled": scan.stalled,
    }));
}

/// Appends one JSON line to the file named by SYNA_00A2_TRACE (test runs
/// only; off unless the variable is set)
fn note(mut line: serde_json::Value) {
    let Some(path) = std::env::var_os("SYNA_00A2_TRACE") else {
        return;
    };
    // Wall-clock stamp: event times are relative to each scan's start
    line["at_ms"] = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
        .into();
    let file = fs::OpenOptions::new().create(true).append(true).open(path);
    if let Ok(mut file) = file {
        let _ = writeln!(file, "{line}");
    }
}

/// Builds a template from `count` enroll-mode images of `syna_image_size()`
/// pixels and stores it as finger `subtype` (WinBio position) of uid's user
/// record on the sensor, creating the record if needed. Fills `out` and
/// returns SYNA_OK, or SYNA_DATA_FULL or SYNA_ERROR. Blocks.
/// # Safety
/// `handle` must come from `syna_open` and not be used concurrently, `images` must hold
/// `count * syna_image_size()` bytes, `out` must be writable, and `error` must be NULL or
/// point to a writable `char *`.
#[no_mangle]
pub unsafe extern "C" fn syna_chip_enroll(
    handle: *mut SynaHandle,
    uid: u32,
    subtype: u16,
    images: *const u8,
    count: usize,
    out: *mut SynaPrint,
    error: *mut *mut c_char,
) -> c_int {
    guard(error, SYNA_ERROR, || {
        // SAFETY: the C side passes the handle from syna_open, used by one thread at a time
        let handle = unsafe { handle.as_mut() }.context("the device is not open")?;
        let size = syna_image_size();
        // SAFETY: the C side passes count images back to back
        let images = unsafe { slice::from_raw_parts(images, count * size) };
        let frames = images
            .chunks_exact(size)
            .map(moh::extract)
            .collect::<Result<Vec<_>>>()?;
        let scanner = &mut handle.scanner;
        match chip::enroll(&mut scanner.session, &scanner.sensor, uid, subtype, &frames) {
            Ok(stored) => {
                // SAFETY: the C side passes a writable SynaPrint
                unsafe { *out = stored.into() };
                Ok(SYNA_OK)
            }
            Err(e) if e.is::<DataFull>() => Ok(SYNA_DATA_FULL),
            Err(e) => Err(e),
        }
    })
}

/// One identify-mode touch, matched by the chip against uid `restrict_uid`'s
/// fingers (any Linux user's when negative). Returns SYNA_MATCH with the
/// matched print in `out`, SYNA_NO_MATCH, SYNA_RETRY (the sensor rejected the
/// placement), SYNA_CANCELLED or SYNA_ERROR. `on_status` reports when the
/// sensor waits for a finger and when one is down. Blocks.
/// # Safety
/// As for `syna_capture`; `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn syna_chip_identify(
    handle: *mut SynaHandle,
    restrict_uid: i64,
    is_cancelled: CancelledFn,
    on_status: StatusFn,
    status_user: *mut c_void,
    out: *mut SynaPrint,
    error: *mut *mut c_char,
) -> c_int {
    guard(error, SYNA_ERROR, || {
        // SAFETY: the C side passes the handle from syna_open, used by one thread at a time
        let handle = unsafe { handle.as_mut() }.context("the device is not open")?;
        let cancelled = || is_cancelled(status_user) != 0;
        // Look the user record up before the scan: the first database lookup
        // after opening, sent between the scan and the match, lost the match
        // (the first touch of every driver run missed until 2026-10-23)
        let user = match u32::try_from(restrict_uid) {
            Ok(uid) => chip::find_user(&mut handle.scanner.session, &handle.scanner.sensor, uid)?,
            Err(_) => Some(0),
        };
        let outcome = handle.scanner.scan(
            calibrate::Mode::Identify,
            FINGER_TIMEOUT,
            &cancelled,
            || on_status(status_user, SYNA_STATUS_NEEDED),
            || on_status(status_user, SYNA_STATUS_PRESENT),
        );
        trace(&outcome);
        let (held, stalled) = (outcome.held, outcome.stalled);
        let image = match outcome.result {
            Ok(Scan::Image(image)) => image,
            Ok(Scan::Rejected(code)) => {
                eprintln!("syna_00a2: touch rejected ({code:#x})");
                return Ok(SYNA_RETRY);
            }
            Err(_) if cancelled() => return Ok(SYNA_CANCELLED),
            Err(e) => {
                eprintln!("syna_00a2: scan failed: {e:#}");
                return Err(e);
            }
        };
        let scanner = &mut handle.scanner;
        let found = match user {
            Some(user) => chip::identify(&mut scanner.session, &scanner.sensor, user)?,
            None => None,
        };
        eprintln!(
            "syna_00a2: touch: {} (held {held}, stalled {stalled})",
            found.map_or("no match".to_owned(), |(_, m)| format!("match {m:#x}"))
        );
        let Some((print, matched)) = found else {
            *LAST_MISS.lock().unwrap() = Some(Instant::now());
            note(serde_json::json!({ "match": null }));
            return Ok(SYNA_NO_MATCH);
        };
        note(serde_json::json!({ "match": format!("{matched:#x}") }));
        let after_miss = LAST_MISS
            .lock()
            .unwrap()
            .take()
            .is_some_and(|miss| miss.elapsed() < REFRESH_AFTER_MISS);
        if after_miss && REFRESHED.load(Ordering::Relaxed) {
            eprintln!("syna_00a2: refresh skipped: already refreshed in this process");
            note(serde_json::json!({ "refresh_skipped": "already refreshed in this process" }));
        } else if after_miss {
            // Never fails the match: the refresh is a side effect
            match chip::refresh(&mut scanner.session, &scanner.sensor, &print, &image.pixels) {
                Ok(subtype) => {
                    REFRESHED.store(true, Ordering::Relaxed);
                    eprintln!(
                        "syna_00a2: refreshed uid {} as subtype {subtype:#x}",
                        print.uid
                    );
                    note(serde_json::json!({ "refreshed": format!("{subtype:#x}") }));
                }
                Err(e) => {
                    eprintln!("syna_00a2: refresh skipped: {e:#}");
                    note(serde_json::json!({ "refresh_skipped": format!("{e:#}") }));
                }
            }
        }
        // SAFETY: the C side passes a writable SynaPrint
        unsafe { *out = print.into() };
        Ok(SYNA_MATCH)
    })
}

/// The fingers stored under Linux-owned user records. On SYNA_OK, `*out`
/// holds `*len` prints, which the C side frees with `syna_prints_free`.
/// # Safety
/// `handle` must come from `syna_open` and not be used concurrently, `out` and `len`
/// must be writable, and `error` must be NULL or point to a writable `char *`.
#[no_mangle]
pub unsafe extern "C" fn syna_chip_list(
    handle: *mut SynaHandle,
    out: *mut *mut SynaPrint,
    len: *mut usize,
    error: *mut *mut c_char,
) -> c_int {
    guard(error, SYNA_ERROR, || {
        // SAFETY: the C side passes the handle from syna_open, used by one thread at a time
        let handle = unsafe { handle.as_mut() }.context("the device is not open")?;
        let scanner = &mut handle.scanner;
        let prints: Box<[SynaPrint]> = chip::list(&mut scanner.session, &scanner.sensor)?
            .into_iter()
            .map(SynaPrint::from)
            .collect();
        // SAFETY: the C side passes writable out-parameters
        unsafe {
            *len = prints.len();
            *out = Box::into_raw(prints).cast();
        }
        Ok(SYNA_OK)
    })
}

/// # Safety
/// `prints`/`len` must come from `syna_chip_list`, freed once.
#[no_mangle]
pub unsafe extern "C" fn syna_prints_free(prints: *mut SynaPrint, len: usize) {
    if !prints.is_null() {
        // SAFETY: allocated by syna_chip_list with this length
        drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(prints, len)) });
    }
}

/// Deletes a stored finger (and its user record once empty). Returns
/// SYNA_OK, SYNA_NOT_FOUND or SYNA_ERROR. Blocks.
/// # Safety
/// `handle` must come from `syna_open` and not be used concurrently, `print` must be
/// readable, and `error` must be NULL or point to a writable `char *`.
#[no_mangle]
pub unsafe extern "C" fn syna_chip_delete(
    handle: *mut SynaHandle,
    print: *const SynaPrint,
    error: *mut *mut c_char,
) -> c_int {
    guard(error, SYNA_ERROR, || {
        // SAFETY: the C side passes the handle from syna_open, used by one thread at a time
        let handle = unsafe { handle.as_mut() }.context("the device is not open")?;
        // SAFETY: the C side passes a readable SynaPrint
        let print = Print::from(unsafe { *print });
        let scanner = &mut handle.scanner;
        match chip::delete(&mut scanner.session, &scanner.sensor, &print) {
            Ok(()) => Ok(SYNA_OK),
            Err(e) if e.is::<NotFound>() => Ok(SYNA_NOT_FOUND),
            Err(e) => Err(e),
        }
    })
}
