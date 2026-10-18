// SPDX-License-Identifier: LGPL-2.1-or-later
//! One finger scan, following python-validity's `Sensor.capture`: start the
//! `0x02` program, follow its events on EP 0x83 until the scan is done, then
//! fetch the reconstructed image with `0x51`.

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Result};
use serde::Serialize;

use crate::{proto, tls::Session, usb::Sensor};

const EVENT_START: u8 = 0;
const EVENT_FINGER: u8 = 2;
const EVENT_PROGRESS: u8 = 3;
/// Bit in a progress event's third byte that marks the scan as done
const PROGRESS_DONE: u8 = 0x04;
const CAPTURE_STOP: [u8; 1] = [0x04];

const POLL: Duration = Duration::from_millis(100);
const START_TIMEOUT: Duration = Duration::from_secs(5);
const SCAN_TIMEOUT: Duration = Duration::from_secs(10);
/// python-validity caps the follow-up `0x51` reads the same way
const MAX_RESULT_READS: usize = 8;

/// A scan event, timed from when the program was started
#[derive(Debug, Serialize)]
pub struct Event {
    pub ms: u128,
    pub bytes: String,
}

#[derive(Debug, Serialize)]
pub struct Image {
    pub width: usize,
    pub height: usize,
    /// Unexplained header fields python-validity logs as `w1`, `w2`
    pub w1: u16,
    pub w2: u16,
    #[serde(skip)]
    pub pixels: Vec<u8>,
}

pub struct Capture<'a> {
    pub session: &'a mut Session,
    pub sensor: &'a Sensor,
    pub cancelled: &'a AtomicBool,
    pub events: Vec<Event>,
    started: Instant,
}

impl<'a> Capture<'a> {
    pub fn new(session: &'a mut Session, sensor: &'a Sensor, cancelled: &'a AtomicBool) -> Self {
        Self {
            session,
            sensor,
            cancelled,
            events: Vec::new(),
            started: Instant::now(),
        }
    }

    /// Events left over from earlier scans, read before starting a new one
    pub fn drain(&mut self) -> Result<Vec<String>> {
        let mut stale = Vec::new();
        while let Some(event) = self.sensor.read_interrupt(Duration::from_millis(20))? {
            stale.push(hex(&event));
            ensure!(stale.len() < 64, "the event endpoint keeps producing data");
        }
        Ok(stale)
    }

    /// The next scan event, or an error once `timeout` passes or the run is cancelled
    fn event(&mut self, timeout: Duration, waiting_for: &str) -> Result<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.cancelled.load(Ordering::Relaxed) {
                bail!("cancelled while waiting for {waiting_for}");
            }
            if let Some(event) = self.sensor.read_interrupt(POLL)? {
                ensure!(!event.is_empty(), "empty scan event");
                self.events.push(Event {
                    ms: self.started.elapsed().as_millis(),
                    bytes: hex(&event),
                });
                return Ok(event);
            }
            if Instant::now() > deadline {
                bail!("no {waiting_for} within {} s", timeout.as_secs());
            }
        }
    }

    /// Runs one scan with `command`, waiting up to `finger_timeout` for a
    /// finger. An interrupted scan gets `0x04` (capture stop); a completed one
    /// does not, as python-validity says the 00a2 rejects it then.
    pub fn scan(
        &mut self,
        command: &[u8],
        finger_timeout: Duration,
        on_ready: impl FnOnce(),
    ) -> Result<Image> {
        self.started = Instant::now();
        self.session.cmd_ok(self.sensor, command)?;
        let result = self.follow(finger_timeout, on_ready);
        if result.is_err() {
            // Best effort: the error that got us here matters more
            let _ = self.session.cmd(self.sensor, &CAPTURE_STOP);
        }
        result
    }

    fn follow(&mut self, finger_timeout: Duration, on_ready: impl FnOnce()) -> Result<Image> {
        let start = self.event(START_TIMEOUT, "scan start event")?;
        ensure!(
            start[0] == EVENT_START,
            "unexpected first scan event {}",
            hex(&start)
        );
        on_ready();
        while self.event(finger_timeout, "finger")?[0] != EVENT_FINGER {}
        loop {
            let event = self.event(SCAN_TIMEOUT, "end of scan")?;
            ensure!(
                event[0] == EVENT_PROGRESS,
                "unexpected scan event {}",
                hex(&event)
            );
            if event.get(2).is_some_and(|b| b & PROGRESS_DONE != 0) {
                break;
            }
        }
        self.image()
    }

    /// The scan result: x, y, w1, w2 and an error code (`<HHHHL`), then x·y
    /// pixels, delivered over one or more `0x51` reads
    fn image(&mut self) -> Result<Image> {
        let first = self
            .session
            .cmd_ok(self.sensor, &proto::SCAN_RESULT_REQUEST)?;
        let data = proto::scan_result_data(&first)?;
        ensure!(
            data.len() >= 12,
            "scan result header too short: {} bytes",
            data.len()
        );
        let field = |at: usize| u16::from_le_bytes([data[at], data[at + 1]]);
        let (height, width, w1, w2) = (field(0) as usize, field(2) as usize, field(4), field(6));
        let error = u32::from_le_bytes(data[8..12].try_into()?);
        ensure!(error == 0, "the sensor reported scan error {error:#x}");
        let mut pixels = data[12..].to_vec();
        for _ in 0..MAX_RESULT_READS {
            if pixels.len() >= width * height {
                break;
            }
            let more = self
                .session
                .cmd_ok(self.sensor, &proto::SCAN_RESULT_REQUEST)?;
            pixels.extend(proto::scan_result_data(&more)?);
        }
        ensure!(
            pixels.len() >= width * height,
            "image underrun: {} of {} bytes",
            pixels.len(),
            width * height
        );
        pixels.truncate(width * height);
        Ok(Image {
            width,
            height,
            w1,
            w2,
            pixels,
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
