// SPDX-License-Identifier: LGPL-2.1-or-later
//! Getting the sensor ready for scans, shared by the CLI and the TOD driver:
//! the plain open sequence, the TLS session with the stored pairing, the
//! factory calibration values, and an in-memory calibration checked against
//! the clean slate in flash partition 6. Everything here blocks.

use std::{fs, thread::sleep, time::Duration};

use anyhow::{anyhow, ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    blobs, calibrate,
    capture::{Capture, Event, Scan, Stalled},
    pairing::{self, HostKeys},
    proto, tables, tls, usb,
};

/// Receives named steps for reports
pub type Log<'a> = &'a mut dyn FnMut(&str, Value);

/// Status of the first plain command when an open follows the previous
/// release within a second or two (M4c, M4d). A few seconds later it works.
const BUSY: u16 = 0x0315;
const BUSY_RETRIES: usize = 8;
const BUSY_WAIT: Duration = Duration::from_millis(500);

/// Largest mean absolute difference between the blank scan and the stored
/// clean slate that still counts as an empty sensor. M4a measured 2.29; a
/// finger during calibration gave 7.05 (M4d).
pub const MAX_BLANK_DIFF: f64 = 6.0;
const CALIBRATION_ATTEMPTS: usize = 3;
const CALIBRATION_RETRY_WAIT: Duration = Duration::from_secs(1);

/// Identify scans of a finger still down from the previous touch, discarded
/// before giving up. Each takes about 0.4 s with the wait.
const MAX_HELD: usize = 100;
const HELD_RESCAN_WAIT: Duration = Duration::from_millis(100);
/// Pause between the capture stop that ends a stalled scan and the restart
const STALL_RESTART_WAIT: Duration = Duration::from_millis(500);

/// This host's DMI product name, which is world-readable in sysfs
pub fn dmi_product_name() -> Result<String> {
    Ok(fs::read_to_string("/sys/class/dmi/id/product_name")?
        .trim()
        .to_owned())
}

/// The plain open sequence, then a TLS session with the stored pairing.
/// Returns the session and the plain ROM info response.
pub fn open_session(
    sensor: &usb::Sensor,
    keys: &HostKeys,
    log: Log,
) -> Result<(tls::Session, Vec<u8>)> {
    let mut rom_info = sensor.cmd(&[0x01])?;
    for _ in 0..BUSY_RETRIES {
        if proto::split_status(&rom_info)?.0 != BUSY {
            break;
        }
        sleep(BUSY_WAIT);
        rom_info = sensor.cmd(&[0x01])?;
    }
    // The plain open sequence python-validity, MR 626 and synafp all send
    let mut plain = |name: &str, response: Vec<u8>| -> Result<Vec<u8>> {
        let (status, _) = proto::split_status(&response)?;
        log(name, json!({ "status": format!("{status:04x}") }));
        ensure!(
            status == proto::STATUS_OK,
            "{name} failed with status {status:04x}"
        );
        Ok(response)
    };
    let rom_info = plain("rom_info", rom_info)?;
    plain("get_status", sensor.cmd(&[0x19])?)?;
    // A missing fwext would need the clean-slate blob, which isn't implemented
    plain("fwext_info", sensor.cmd(&[0x43, 0x02])?)?;
    plain("init_blob", sensor.cmd(&blobs::INIT)?)?;
    let response = plain(
        "read_partition1",
        sensor.cmd(&proto::read_flash_request(1, 0, 0x1000))?,
    )?;
    let flash = proto::read_flash_data(&response[2..])?;

    let (pairing, check) = pairing::Pairing::load(flash, keys, &pairing::firmware_key())?;
    log("pairing_check", json!(check));
    ensure!(
        check.sensor_key_signed,
        "the sensor's ECDH key is not signed by the firmware key"
    );

    let session = tls::connect(sensor, &pairing)?;
    log("handshake", "ok".into());
    Ok((session, rom_info))
}

pub fn read_flash_tls(
    session: &mut tls::Session,
    sensor: &usb::Sensor,
    partition: u8,
    address: u32,
    size: u32,
) -> Result<Vec<u8>> {
    let payload = session.cmd_ok(sensor, &proto::read_flash_request(partition, address, size))?;
    Ok(proto::read_flash_data(&payload)?.to_vec())
}

/// Checks the sensor is the type the capture tables are for, then reads its
/// factory calibration values (factory bits 0x0e00, subtag 3, minus 4 bytes)
pub fn factory_values(
    session: &mut tls::Session,
    sensor: &usb::Sensor,
    log: Log,
) -> Result<Vec<u8>> {
    let id = proto::SensorId::parse(&session.cmd_ok(sensor, &[0x75])?)?;
    ensure!(
        (id.major, id.minor) == (0x0190, 0x0061),
        "the tables are for sensor 0x0190/0x0061 (57K0 FM-3380-003), not {:#06x}/{:#06x}",
        id.major,
        id.minor
    );
    let bits =
        proto::parse_factory_bits(&session.cmd_ok(sensor, &proto::factory_bits_request(0x0e00))?)?;
    let factory = bits
        .get(&3)
        .and_then(|value| value.get(4..))
        .context("no factory calibration values (factory bits subtag 3)")?
        .to_vec();
    log(
        "factory_bits",
        json!({ "subtags": bits.keys().collect::<Vec<_>>(), "calibration_values": factory.len() }),
    );
    Ok(factory)
}

/// A frame's pixels: each line without its 8-byte header
pub fn pixels(frame: &[u8]) -> Vec<u8> {
    frame
        .chunks(tables::BYTES_PER_LINE)
        .flat_map(|line| line.get(8..).unwrap_or_default().to_vec())
        .collect()
}

fn mean_abs_diff(a: &[u8], b: &[u8]) -> f64 {
    let total: u64 = a.iter().zip(b).map(|(&x, &y)| x.abs_diff(y) as u64).sum();
    total as f64 / a.len().min(b.len()).max(1) as f64
}

pub fn pixel_stats(pixels: &[u8]) -> Value {
    let n = pixels.len().max(1) as f64;
    let mean = pixels.iter().map(|&p| p as f64).sum::<f64>() / n;
    let variance = pixels
        .iter()
        .map(|&p| (p as f64 - mean).powi(2))
        .sum::<f64>()
        / n;
    json!({
        "min": pixels.iter().min(),
        "max": pixels.iter().max(),
        "mean": (mean * 100.0).round() / 100.0,
        "stddev": (variance.sqrt() * 100.0).round() / 100.0,
    })
}

/// The clean slate record in partition 6, if there is a valid one
pub fn read_clean_slate(
    session: &mut tls::Session,
    sensor: &usb::Sensor,
    log: Log,
) -> Result<Option<Vec<u8>>> {
    let header = read_flash_tls(session, sensor, 6, 0, calibrate::CLEAN_SLATE_HEADER as u32)?;
    let Some((len, hash)) = calibrate::clean_slate_header(&header) else {
        log(
            "partition6",
            json!({ "clean_slate": false, "header": hex(&header[..8.min(header.len())]) }),
        );
        return Ok(None);
    };
    let mut record = Vec::new();
    while record.len() < len {
        let address = (calibrate::CLEAN_SLATE_HEADER + record.len()) as u32;
        let chunk = read_flash_tls(
            session,
            sensor,
            6,
            address,
            (len - record.len()).min(0x1000) as u32,
        )?;
        ensure!(!chunk.is_empty(), "partition 6 read returned nothing");
        record.extend(chunk);
    }
    record.truncate(len);
    let hash_ok = Sha256::digest(&record).as_slice() == hash;
    log(
        "partition6",
        json!({ "clean_slate": true, "bytes": len, "hash_ok": hash_ok }),
    );
    Ok(hash_ok.then_some(record))
}

pub struct Calibrated {
    pub calibration: calibrate::Calibration,
    pub blank: Vec<u8>,
    pub raw_scans: Vec<Vec<u8>>,
    /// Mean absolute pixel difference between our blank scan and the clean
    /// slate's frame, if partition 6 has one
    pub blank_vs_flash: Option<f64>,
}

/// Runs python-validity's calibration scans plus one blank scan, keeping the
/// result in memory. Every capture session calibrates first: scans need it
/// after a power cycle, and it only takes about a second.
pub fn calibrate_in_memory(
    session: &mut tls::Session,
    sensor: &usb::Sensor,
    factory: Vec<u8>,
    clean_slate: Option<&[u8]>,
    log: Log,
) -> Result<Calibrated> {
    let mut calibration = calibrate::Calibration::new(factory)?;
    let mut raw_scans = Vec::new();
    let mut blank = Vec::new();
    // python-validity's calibration iterations, then one more scan for the blank frame
    for i in 0..=calibrate::ITERATIONS {
        session.cmd_ok(sensor, &calibration.command(calibrate::Mode::Calibrate)?)?;
        let raw = sensor.read_data()?;
        let averaged = calibration.average(&raw)?;
        raw_scans.push(raw);
        if i < calibrate::ITERATIONS {
            calibration.accumulate(&averaged);
        } else {
            blank = averaged;
        }
    }
    // The record is (u16 length, averaged blank frame, u16 0)
    let blank_vs_flash = clean_slate.and_then(|record| {
        let len = u16::from_le_bytes([record[0], record[1]]) as usize;
        let frame = record.get(2..2 + len)?;
        Some(mean_abs_diff(&pixels(&blank), &pixels(frame)))
    });
    log(
        "calibration",
        json!({
            "scan_bytes": raw_scans.iter().map(Vec::len).collect::<Vec<_>>(),
            "expected_scan_bytes": calibration.frame_size() * 3 + tables::BYTES_PER_LINE,
            "blank_pixels": pixel_stats(&pixels(&blank)),
            "blank_vs_partition6_mean_abs_diff": blank_vs_flash,
        }),
    );
    Ok(Calibrated {
        calibration,
        blank,
        raw_scans,
        blank_vs_flash,
    })
}

/// A sensor ready for finger scans
pub struct Scanner {
    pub sensor: usb::Sensor,
    pub session: tls::Session,
    enroll: Vec<u8>,
    identify: Vec<u8>,
    /// An identify scan finishes without waiting for the lift, so its finger
    /// may still be down when the next scan starts
    finger_may_be_down: bool,
}

/// What [`Scanner::scan`] did
pub struct ScanOutcome {
    pub result: Result<Scan>,
    /// The events of every scan run, in order; each scan's start with its `00`
    pub events: Vec<Event>,
    /// Events left over from before the first scan
    pub stale: Vec<String>,
    /// Identify scans discarded because the finger was still down from the
    /// previous touch
    pub held: usize,
    /// Scans restarted because they stalled after the touch
    pub stalled: usize,
}

impl Scanner {
    /// Opens the session and calibrates. If the blank scan shows a finger
    /// (or anything else on the sensor), waits and recalibrates, up to
    /// `CALIBRATION_ATTEMPTS` times.
    pub fn open(sensor: usb::Sensor, keys: &HostKeys, log: Log) -> Result<Self> {
        let (mut session, _) = open_session(&sensor, keys, log)?;
        let factory = factory_values(&mut session, &sensor, log)?;
        let clean_slate = read_clean_slate(&mut session, &sensor, log)?
            .context("partition 6 has no valid clean slate to check calibration against")?;
        let mut diff = f64::NAN;
        for attempt in 1..=CALIBRATION_ATTEMPTS {
            let calibrated = calibrate_in_memory(
                &mut session,
                &sensor,
                factory.clone(),
                Some(&clean_slate),
                log,
            )?;
            diff = calibrated.blank_vs_flash.unwrap_or(f64::INFINITY);
            if diff <= MAX_BLANK_DIFF {
                let enroll = calibrated.calibration.command(calibrate::Mode::Enroll)?;
                let identify = calibrated.calibration.command(calibrate::Mode::Identify)?;
                return Ok(Self {
                    sensor,
                    session,
                    enroll,
                    identify,
                    finger_may_be_down: false,
                });
            }
            log(
                "calibration_retry",
                json!({ "attempt": attempt, "blank_vs_partition6_mean_abs_diff": diff }),
            );
            sleep(CALIBRATION_RETRY_WAIT);
        }
        anyhow::bail!(
            "the blank scan differs from the stored clean slate by {diff:.1} grey levels (limit {MAX_BLANK_DIFF}): \
             was a finger on the sensor during calibration? Lift it and try again"
        )
    }

    /// One enroll-mode scan; see [`Scanner::scan`]
    pub fn capture(
        &mut self,
        finger_timeout: Duration,
        cancelled: &dyn Fn() -> bool,
        on_ready: impl FnMut(),
        on_finger: impl FnMut(),
    ) -> ScanOutcome {
        self.scan(
            calibrate::Mode::Enroll,
            finger_timeout,
            cancelled,
            on_ready,
            on_finger,
        )
    }

    /// One touch in the given mode (enroll, or identify for on-chip
    /// matching); see [`Capture::scan`]. `on_ready` runs whenever the sensor
    /// waits for a new touch, `on_finger` when one is down.
    ///
    /// Identify scans of a finger still down from the previous touch are
    /// discarded and rescanned until a new touch comes. A scan that stalls
    /// after the touch is stopped and restarted once.
    pub fn scan(
        &mut self,
        mode: calibrate::Mode,
        finger_timeout: Duration,
        cancelled: &dyn Fn() -> bool,
        mut on_ready: impl FnMut(),
        mut on_finger: impl FnMut(),
    ) -> ScanOutcome {
        let mut out = ScanOutcome {
            result: Err(anyhow!("no scan ran")),
            events: Vec::new(),
            stale: Vec::new(),
            held: 0,
            stalled: 0,
        };
        let mut capture = Capture::new(&mut self.session, &self.sensor, cancelled);
        match capture.drain() {
            Ok(stale) => out.stale = stale,
            Err(e) => {
                out.result = Err(e);
                return out;
            }
        }
        let command = if mode == calibrate::Mode::Identify {
            &self.identify
        } else {
            &self.enroll
        };
        let mut waiting = false;
        loop {
            let check_held = mode == calibrate::Mode::Identify && self.finger_may_be_down;
            // A held rescan continues the same wait for a touch
            let mut ready = || {
                if !waiting {
                    waiting = true;
                    on_ready();
                }
            };
            let result = capture.scan(
                command,
                finger_timeout,
                check_held,
                &mut ready,
                &mut on_finger,
            );
            out.events.append(&mut capture.events);
            match result {
                Err(e) if e.is::<Stalled>() && out.stalled == 0 => {
                    // The touch was lost: the restarted scan takes any finger
                    out.stalled += 1;
                    self.finger_may_be_down = false;
                    waiting = false;
                    sleep(STALL_RESTART_WAIT);
                }
                Ok(_) if capture.held => {
                    out.held += 1;
                    if out.held > MAX_HELD {
                        out.result = Err(anyhow!("the finger stayed on the sensor for too long"));
                        return out;
                    }
                    sleep(HELD_RESCAN_WAIT);
                }
                result => {
                    if result.is_ok() {
                        // Enroll scans end on the lift
                        self.finger_may_be_down = mode == calibrate::Mode::Identify;
                    }
                    out.result = result;
                    return out;
                }
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
