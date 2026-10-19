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
    time::Duration,
};

use anyhow::{ensure, Context, Result};
use syna_00a2::{
    capture::Scan,
    device::{self, Scanner},
    matcher::{self, Matcher, Template},
    pairing::HostKeys,
    usb,
};

pub const SYNA_IMAGE: c_int = 0;
pub const SYNA_RETRY: c_int = 1;
pub const SYNA_CANCELLED: c_int = 2;
pub const SYNA_ERROR: c_int = -1;

pub const SYNA_STATUS_NEEDED: c_int = 1;
pub const SYNA_STATUS_PRESENT: c_int = 2;

/// fprintd decides how long to wait for a finger; cancellation ends the wait
const FINGER_TIMEOUT: Duration = Duration::from_secs(24 * 3600);

pub type CancelledFn = extern "C" fn(*mut c_void) -> c_int;
pub type StatusFn = extern "C" fn(*mut c_void, c_int);

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
        let scanner = Scanner::open(sensor, &keys, &mut |_, _| {})?;
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

#[no_mangle]
pub extern "C" fn syna_threshold() -> f64 {
    matcher::THRESHOLD
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
        let (result, events, stale) = handle.scanner.capture(
            FINGER_TIMEOUT,
            &cancelled,
            || on_status(user, SYNA_STATUS_NEEDED),
            || on_status(user, SYNA_STATUS_PRESENT),
        );
        trace(&result, &events, &stale);
        match result {
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
fn trace(result: &Result<Scan>, events: &[syna_00a2::capture::Event], stale: &[String]) {
    let Some(path) = std::env::var_os("SYNA_00A2_TRACE") else {
        return;
    };
    let outcome = match result {
        Ok(Scan::Image(_)) => "image".to_owned(),
        Ok(Scan::Rejected(code)) => format!("rejected {code:#x}"),
        Err(e) => format!("error: {e:#}"),
    };
    let line = serde_json::json!({ "outcome": outcome, "events": events, "stale": stale });
    let file = fs::OpenOptions::new().create(true).append(true).open(path);
    if let Ok(mut file) = file {
        let _ = writeln!(file, "{line}");
    }
}

/// Encodes `count` images of `syna_image_size()` pixels as a template. The
/// C side frees the result with `syna_bytes_free`.
/// # Safety
/// `images` must hold `count * syna_image_size()` bytes and `len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn syna_template_encode(
    images: *const u8,
    count: usize,
    len: *mut usize,
) -> *mut u8 {
    guard(ptr::null_mut(), ptr::null_mut(), || {
        let size = syna_image_size();
        // SAFETY: the C side passes count images back to back
        let images = unsafe { slice::from_raw_parts(images, count * size) };
        let template = Template {
            images: images.chunks_exact(size).map(<[u8]>::to_vec).collect(),
        };
        let bytes = template.to_bytes().into_boxed_slice();
        // SAFETY: the C side passes a valid pointer
        unsafe { *len = bytes.len() };
        Ok(Box::into_raw(bytes).cast())
    })
}

/// # Safety
/// `bytes`/`len` must come from `syna_template_encode`, freed once.
#[no_mangle]
pub unsafe extern "C" fn syna_bytes_free(bytes: *mut u8, len: usize) {
    if !bytes.is_null() {
        // SAFETY: allocated by syna_template_encode with this length
        drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(bytes, len)) });
    }
}

/// Matcher score of `image` against a template; NAN if the template is bad.
/// Compare with `syna_threshold()`. Takes a few hundred milliseconds.
/// # Safety
/// `template` must hold `len` bytes, `image` `syna_image_size()` bytes, and `error`
/// must be NULL or point to a writable `char *`.
#[no_mangle]
pub unsafe extern "C" fn syna_match(
    template: *const u8,
    len: usize,
    image: *const u8,
    error: *mut *mut c_char,
) -> f64 {
    guard(error, f64::NAN, || {
        // SAFETY: the C side passes the stored template bytes and one image
        let template = Template::from_bytes(unsafe { slice::from_raw_parts(template, len) })?;
        let image = unsafe { slice::from_raw_parts(image, syna_image_size()) };
        Ok(Matcher::new(&template).score(image))
    })
}
