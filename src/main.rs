// SPDX-License-Identifier: LGPL-2.1-or-later
//! Userspace driver for the Synaptics 06cb:00a2 fingerprint reader

mod proto;
mod usb;

use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Map, Value};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read-only identity probe: ROM info, sensor ID, flash layout, firmware extension
    Info {
        /// Also write the JSON report here (mode 0600)
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

type Decoder = fn(&[u8]) -> Result<Value>;

/// Plain reads that python-validity sends before TLS. The list is closed on
/// purpose: nothing here writes flash or changes sensor state.
const PROBES: &[(&str, &[u8], Decoder)] = &[
    ("rom_info", &[0x01], |p| Ok(serde_json::to_value(proto::RomInfo::parse(p)?)?)),
    ("sensor_id", &[0x75], |p| Ok(serde_json::to_value(proto::SensorId::parse(p)?)?)),
    ("flash_info", &[0x3e], |p| Ok(serde_json::to_value(proto::FlashInfo::parse(p)?)?)),
    ("fwext_info", &[0x43, 0x02], |p| Ok(serde_json::to_value(proto::FwInfo::parse(p)?)?)),
];

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Info { output } => info(output),
    }
}

fn info(output: Option<PathBuf>) -> Result<()> {
    let sensor = usb::Sensor::open()?;
    let mut probes = Map::new();
    let mut failed = None;
    for &(name, request, decode) in PROBES {
        match sensor.cmd(request) {
            Ok(response) => probes.insert(name.into(), describe(name, &response, decode)),
            Err(e) => {
                // A transport error may mean a wedged sensor, so stop poking it
                probes.insert(name.into(), json!({ "request": hex(request), "transport_error": format!("{e:#}") }));
                failed = Some(name);
                break;
            }
        };
    }
    let device = sensor.path.clone();
    drop(sensor);

    let report = serde_json::to_string_pretty(&json!({ "device": device, "probes": probes }))?;
    println!("{report}");
    if let Some(path) = output {
        OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?.write_all(report.as_bytes())?;
    }
    if let Some(name) = failed {
        bail!("transport error during {name}; stopped probing");
    }
    Ok(())
}

fn describe(name: &str, response: &[u8], decode: Decoder) -> Value {
    let mut entry = json!({ "response": hex(response) });
    match proto::split_status(response) {
        Err(e) => entry["error"] = format!("{e:#}").into(),
        Ok((status, payload)) => {
            entry["status"] = format!("{status:04x}").into();
            entry["parsed"] = match status {
                proto::STATUS_OK => decode(payload).unwrap_or_else(|e| json!({ "error": format!("{e:#}") })),
                proto::STATUS_NO_FW if name == "fwext_info" => "not loaded".into(),
                _ => Value::Null,
            };
        }
    }
    entry
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
