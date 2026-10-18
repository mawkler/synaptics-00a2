// SPDX-License-Identifier: LGPL-2.1-or-later
//! Userspace driver for the Synaptics 06cb:00a2 fingerprint reader

mod blobs;
mod pairing;
mod proto;
mod tls;
mod usb;

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use anyhow::{bail, ensure, Context, Result};
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
    /// Opens a TLS session with the stored pairing: python-validity's plain open
    /// sequence (including the init blob), the handshake, then one encrypted
    /// ROM-info read. Writes no flash and prints no key material.
    Handshake {
        /// File holding the DMI product serial (root-only in sysfs)
        #[arg(long)]
        serial_file: PathBuf,
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
        Command::Handshake {
            serial_file,
            output,
        } => handshake(&serial_file, output),
    }
}

/// This host's DMI product name and its pairing keys. The serial is root-only
/// in sysfs, so it comes from a private copy.
fn dmi_keys(serial_file: &Path) -> Result<(String, pairing::HostKeys)> {
    let product_name = fs::read_to_string("/sys/class/dmi/id/product_name")?
        .trim()
        .to_owned();
    let serial = fs::read_to_string(serial_file)
        .with_context(|| format!("reading {}", serial_file.display()))?;
    let keys = pairing::HostKeys::derive(&product_name, serial.trim());
    Ok((product_name, keys))
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
    let (product_name, dmi) = dmi_keys(serial_file)?;
    let identities = [
        ("dmi", dmi),
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
    // Offline checks of what a handshake would use, for a pairing sealed for this host
    let check = match &sealed_for {
        Ok(Some(names)) if names.contains(&"dmi") => {
            match pairing::Pairing::load(&flash, &identities[0].1, &pairing::firmware_key()) {
                Ok((_, check)) => json!(check),
                Err(e) => json!({ "error": format!("{e:#}") }),
            }
        }
        _ => Value::Null,
    };
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
            "pairing_check": check,
        }),
        output,
    )
}

fn handshake(serial_file: &Path, output: Option<PathBuf>) -> Result<()> {
    let (_, keys) = dmi_keys(serial_file)?;
    let sensor = usb::Sensor::open()?;
    let mut steps = Map::new();
    let result = run_handshake(&sensor, &keys, &mut steps);
    let device = sensor.path.clone();
    // No reboot or reset: the sensor keeps its TLS session, as with MR 626
    drop(sensor);
    if let Err(e) = &result {
        steps.insert("error".into(), format!("{e:#}").into());
    }
    report(&json!({ "device": device, "steps": steps }), output)?;
    result
}

fn run_handshake(
    sensor: &usb::Sensor,
    keys: &pairing::HostKeys,
    steps: &mut Map<String, Value>,
) -> Result<()> {
    // The plain open sequence python-validity, MR 626 and synafp all send
    let mut plain = |name: &str, request: &[u8]| -> Result<Vec<u8>> {
        let response = sensor.cmd(request)?;
        let (status, _) = proto::split_status(&response)?;
        steps.insert(name.into(), json!({ "status": format!("{status:04x}") }));
        ensure!(
            status == proto::STATUS_OK,
            "{name} failed with status {status:04x}"
        );
        Ok(response)
    };
    let rom_info = plain("rom_info", &[0x01])?;
    plain("get_status", &[0x19])?;
    // A missing fwext would need the clean-slate blob, which isn't implemented
    plain("fwext_info", &[0x43, 0x02])?;
    plain("init_blob", &blobs::INIT)?;
    let response = plain("read_partition1", &proto::read_flash_request(1, 0, 0x1000))?;
    let flash = proto::read_flash_data(&response[2..])?;

    let (pairing, check) = pairing::Pairing::load(flash, keys, &pairing::firmware_key())?;
    steps.insert("pairing_check".into(), json!(check));
    ensure!(
        check.sensor_key_signed,
        "the sensor's ECDH key is not signed by the firmware key"
    );

    let mut session = tls::connect(sensor, &pairing)?;
    steps.insert("handshake".into(), "ok".into());
    let tls_rom_info = session.cmd(sensor, &[0x01])?;
    steps.insert(
        "tls_rom_info".into(),
        json!({ "response": hex(&tls_rom_info), "matches_plain": tls_rom_info == rom_info }),
    );
    Ok(())
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
