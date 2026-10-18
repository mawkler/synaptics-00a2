// SPDX-License-Identifier: LGPL-2.1-or-later
//! Userspace driver for the Synaptics 06cb:00a2 fingerprint reader

mod pairing;
mod proto;
mod usb;

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

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
    /// Read-only: read flash partition 1 and check whether its pairing record
    /// was sealed for this host. Prints structure and verdicts, never key material.
    Pairing {
        /// File holding the DMI product serial (root-only in sysfs)
        #[arg(long)]
        serial_file: PathBuf,
        /// Save the raw partition here (mode 0600); it holds sealed key material
        #[arg(long, conflicts_with = "from_dump")]
        dump: Option<PathBuf>,
        /// Check a saved partition dump instead of reading the sensor
        #[arg(long)]
        from_dump: Option<PathBuf>,
        /// Also write the JSON report here (mode 0600)
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

type Decoder = fn(&[u8]) -> Result<Value>;

/// Plain reads that python-validity sends before TLS. The list is closed on
/// purpose: nothing here writes flash or changes sensor state.
const PROBES: &[(&str, &[u8], Decoder)] = &[
    ("rom_info", &[0x01], |p| {
        Ok(serde_json::to_value(proto::RomInfo::parse(p)?)?)
    }),
    ("sensor_id", &[0x75], |p| {
        Ok(serde_json::to_value(proto::SensorId::parse(p)?)?)
    }),
    ("flash_info", &[0x3e], |p| {
        Ok(serde_json::to_value(proto::FlashInfo::parse(p)?)?)
    }),
    ("fwext_info", &[0x43, 0x02], |p| {
        Ok(serde_json::to_value(proto::FwInfo::parse(p)?)?)
    }),
];

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Info { output } => info(output),
        Command::Pairing {
            serial_file,
            dump,
            from_dump,
            output,
        } => pairing(&serial_file, dump, from_dump, output),
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
                probes.insert(
                    name.into(),
                    json!({ "request": hex(request), "transport_error": format!("{e:#}") }),
                );
                failed = Some(name);
                break;
            }
        };
    }
    let device = sensor.path.clone();
    drop(sensor);

    report(&json!({ "device": device, "probes": probes }), output)?;
    if let Some(name) = failed {
        bail!("transport error during {name}; stopped probing");
    }
    Ok(())
}

fn pairing(
    serial_file: &Path,
    dump: Option<PathBuf>,
    from_dump: Option<PathBuf>,
    output: Option<PathBuf>,
) -> Result<()> {
    // Read the host identity first, so a missing file fails before the sensor is touched
    let product_name = fs::read_to_string("/sys/class/dmi/id/product_name")?
        .trim()
        .to_owned();
    let serial = fs::read_to_string(serial_file)
        .with_context(|| format!("reading {}", serial_file.display()))?;
    let identities = [
        (
            "dmi",
            pairing::HostKeys::derive(&product_name, serial.trim()),
        ),
        // python-validity silently uses this identity when it can't read the serial
        (
            "python_validity_fallback",
            pairing::HostKeys::derive("VirtualBox", "0"),
        ),
    ];

    let (source, flash) = match from_dump {
        Some(path) => (json!(path), fs::read(&path)?),
        None => {
            let sensor = usb::Sensor::open()?;
            let response = sensor.cmd(&proto::read_flash_request(1, 0, 0x1000))?;
            let source = json!(sensor.path);
            drop(sensor);
            let (status, payload) = proto::split_status(&response)?;
            if status != proto::STATUS_OK {
                report(
                    &json!({ "device": source, "flash_read": { "status": format!("{status:04x}"), "response": hex(&response) } }),
                    output,
                )?;
                bail!("flash read failed with status {status:04x}");
            }
            let data = proto::read_flash_data(payload)?.to_vec();
            if let Some(path) = dump {
                write_private(&path, &data)?;
            }
            (source, data)
        }
    };

    let blocks = pairing::blocks(&flash)?;
    let sealed_for: Result<Option<Vec<&str>>> = blocks
        .iter()
        .find(|b| b.id == pairing::BLOCK_PRIVATE_KEY)
        .map(|b| {
            identities
                .iter()
                .filter_map(|(name, keys)| {
                    keys.sealed(b.body)
                        .map(|ok| ok.then_some(*name))
                        .transpose()
                })
                .collect()
        })
        .transpose();
    report(
        &json!({
            "source": source,
            "partition": { "bytes": flash.len(), "sha256": hex(&Sha256::digest(&flash)) },
            "product_name": product_name,
            "blocks": blocks,
            // Names of the host identities whose keys sealed the private-key block
            "private_key_sealed_for": match sealed_for {
                Ok(Some(names)) => json!(names),
                Ok(None) => json!("no private key block"),
                Err(e) => json!({ "error": format!("{e:#}") }),
            },
        }),
        output,
    )
}

fn report(value: &Value, output: Option<PathBuf>) -> Result<()> {
    let text = serde_json::to_string_pretty(value)?;
    println!("{text}");
    if let Some(path) = output {
        write_private(&path, text.as_bytes())?;
    }
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?
        .write_all(bytes)?;
    Ok(())
}

fn describe(name: &str, response: &[u8], decode: Decoder) -> Value {
    let mut entry = json!({ "response": hex(response) });
    match proto::split_status(response) {
        Err(e) => entry["error"] = format!("{e:#}").into(),
        Ok((status, payload)) => {
            entry["status"] = format!("{status:04x}").into();
            entry["parsed"] = match status {
                proto::STATUS_OK => {
                    decode(payload).unwrap_or_else(|e| json!({ "error": format!("{e:#}") }))
                }
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
