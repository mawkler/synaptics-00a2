// SPDX-License-Identifier: LGPL-2.1-or-later
//! Command transport: requests go out on bulk EP 0x01, responses come back on
//! bulk EP 0x81. Scan data comes on bulk EP 0x82; EP 0x83/0x84 (interrupts) are unused so far.

use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use rusb::{DeviceHandle, GlobalContext};

pub const VID: u16 = 0x06cb;
pub const PID: u16 = 0x00a2;
const INTERFACE: u8 = 0;
const EP_CMD_OUT: u8 = 0x01;
const EP_CMD_IN: u8 = 0x81;
const EP_DATA_IN: u8 = 0x82;
const TIMEOUT: Duration = Duration::from_secs(5);
/// python-validity reads responses into a buffer this size
const MAX_RESPONSE: usize = 100 * 1024;
/// python-validity's `read_82` limits
const MAX_DATA: usize = 1024 * 1024;
const DATA_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Sensor {
    handle: DeviceHandle<GlobalContext>,
    pub path: String,
}

impl Sensor {
    /// Opens and claims the reader. Never resets it or re-sends SET_CONFIGURATION,
    /// since either changes device state (python-validity does both).
    pub fn open() -> Result<Self> {
        let device = rusb::devices()?
            .iter()
            .find(|d| {
                d.device_descriptor()
                    .is_ok_and(|desc| desc.vendor_id() == VID && desc.product_id() == PID)
            })
            .context("no 06cb:00a2 device found")?;
        let path = format!(
            "/dev/bus/usb/{:03}/{:03}",
            device.bus_number(),
            device.address()
        );
        // rusb's open_device_with_vid_pid would hide a permission error behind None
        let handle = device
            .open()
            .with_context(|| format!("opening {path} (does `getfacl {path}` list your user?)"))?;
        let config = handle.active_configuration()?;
        if config != 1 {
            bail!("{path} is in configuration {config}, expected 1; refusing to reconfigure it");
        }
        handle
            .claim_interface(INTERFACE)
            .with_context(|| format!("claiming interface {INTERFACE} of {path}"))?;
        Ok(Self { handle, path })
    }

    pub fn cmd(&self, request: &[u8]) -> Result<Vec<u8>> {
        let written = self
            .handle
            .write_bulk(EP_CMD_OUT, request, TIMEOUT)
            .context("sending command")?;
        ensure!(
            written == request.len(),
            "short write: {written} of {} bytes",
            request.len()
        );
        let mut response = vec![0; MAX_RESPONSE];
        let read = self
            .handle
            .read_bulk(EP_CMD_IN, &mut response, TIMEOUT)
            .context("reading response")?;
        response.truncate(read);
        Ok(response)
    }
}

impl Sensor {
    /// Reads raw scan data from EP 0x82 (plain, not TLS)
    pub fn read_data(&self) -> Result<Vec<u8>> {
        let mut data = vec![0; MAX_DATA];
        let read = self
            .handle
            .read_bulk(EP_DATA_IN, &mut data, DATA_TIMEOUT)
            .context("reading scan data")?;
        data.truncate(read);
        Ok(data)
    }
}

impl Drop for Sensor {
    fn drop(&mut self) {
        let _ = self.handle.release_interface(INTERFACE);
    }
}
