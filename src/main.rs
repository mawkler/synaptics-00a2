// SPDX-License-Identifier: LGPL-2.1-or-later
//! Userspace driver for the Synaptics 06cb:00a2 fingerprint reader

mod blobs;
mod calibrate;
mod capture;
mod pairing;
mod prog;
mod proto;
mod tables;
mod tls;
mod usb;

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
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
    /// Calibrates with no finger on the sensor: reads the factory calibration
    /// bits and any clean slate in flash partition 6, runs python-validity's
    /// calibration scans plus a blank scan, and saves them (mode 0600). Unlike
    /// python-validity, writes nothing to flash.
    Calibrate {
        /// File holding the DMI product serial (root-only in sysfs)
        #[arg(long)]
        serial_file: PathBuf,
        /// Directory for the raw scans, calibration data and blank frame
        #[arg(long)]
        out_dir: PathBuf,
        /// Also write the JSON report here (mode 0600)
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Captures one fingerprint image (enroll-mode scan) using a calibration
    /// saved by `calibrate`, and saves it as a PGM (mode 0600). Writes nothing
    /// to flash. SIGINT/SIGTERM stop the scan cleanly.
    Capture {
        /// File holding the DMI product serial (root-only in sysfs)
        #[arg(long)]
        serial_file: PathBuf,
        /// calibration.bin from an empty-sensor `calibrate` run
        #[arg(long)]
        calibration: PathBuf,
        /// Directory for the image
        #[arg(long)]
        out_dir: PathBuf,
        /// Image file name, without extension: lowercase letters, digits, dashes
        #[arg(long, default_value = "capture")]
        label: String,
        /// Seconds to wait for a finger
        #[arg(long, default_value_t = 30)]
        finger_timeout: u64,
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
        } => with_sensor(&serial_file, output, run_handshake),
        Command::Calibrate {
            serial_file,
            out_dir,
            output,
        } => with_sensor(&serial_file, output, |sensor, keys, steps| {
            run_calibrate(sensor, keys, steps, &out_dir)
        }),
        Command::Capture {
            serial_file,
            calibration,
            out_dir,
            label,
            finger_timeout,
            output,
        } => {
            ensure!(
                !label.is_empty()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "--label may only hold lowercase letters, digits and dashes"
            );
            // Registered before the sensor is opened, so a stop request always reaches the scan loop
            let cancelled = Arc::new(AtomicBool::new(false));
            for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
                signal_hook::flag::register(signal, Arc::clone(&cancelled))?;
            }
            let image = out_dir.join(format!("{label}.pgm"));
            let timeout = Duration::from_secs(finger_timeout);
            with_sensor(&serial_file, output, |sensor, keys, steps| {
                run_capture(
                    sensor,
                    keys,
                    steps,
                    &calibration,
                    &image,
                    timeout,
                    &cancelled,
                )
            })
        }
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

/// Opens the sensor, runs `run` with a map of named steps for the report, and
/// releases the sensor whatever happens
fn with_sensor(
    serial_file: &Path,
    output: Option<PathBuf>,
    run: impl FnOnce(&usb::Sensor, &pairing::HostKeys, &mut Map<String, Value>) -> Result<()>,
) -> Result<()> {
    let (_, keys) = dmi_keys(serial_file)?;
    let sensor = usb::Sensor::open()?;
    let mut steps = Map::new();
    let result = run(&sensor, &keys, &mut steps);
    let device = sensor.path.clone();
    // No reboot or reset: the sensor keeps its TLS session, as with MR 626
    drop(sensor);
    if let Err(e) = &result {
        steps.insert("error".into(), format!("{e:#}").into());
    }
    report(&json!({ "device": device, "steps": steps }), output)?;
    result
}

/// The plain open sequence, then a TLS session with the stored pairing.
/// Returns the session and the plain ROM info response.
fn open_session(
    sensor: &usb::Sensor,
    keys: &pairing::HostKeys,
    steps: &mut Map<String, Value>,
) -> Result<(tls::Session, Vec<u8>)> {
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

    let session = tls::connect(sensor, &pairing)?;
    steps.insert("handshake".into(), "ok".into());
    Ok((session, rom_info))
}

fn run_handshake(
    sensor: &usb::Sensor,
    keys: &pairing::HostKeys,
    steps: &mut Map<String, Value>,
) -> Result<()> {
    let (mut session, rom_info) = open_session(sensor, keys, steps)?;
    let tls_rom_info = session.cmd(sensor, &[0x01])?;
    steps.insert(
        "tls_rom_info".into(),
        json!({ "response": hex(&tls_rom_info), "matches_plain": tls_rom_info == rom_info }),
    );
    Ok(())
}

fn run_calibrate(
    sensor: &usb::Sensor,
    keys: &pairing::HostKeys,
    steps: &mut Map<String, Value>,
    out_dir: &Path,
) -> Result<()> {
    let (mut session, _) = open_session(sensor, keys, steps)?;
    let factory = factory_values(&mut session, sensor, steps)?;

    // Read-only look at any clean slate already in partition 6
    let header = read_flash_tls(
        &mut session,
        sensor,
        6,
        0,
        calibrate::CLEAN_SLATE_HEADER as u32,
    )?;
    let flash_frame = match calibrate::clean_slate_header(&header) {
        None => {
            steps.insert(
                "partition6".into(),
                json!({ "clean_slate": false, "header": hex(&header[..8.min(header.len())]) }),
            );
            None
        }
        Some((len, hash)) => {
            let mut record = Vec::new();
            while record.len() < len {
                let address = (calibrate::CLEAN_SLATE_HEADER + record.len()) as u32;
                let chunk = read_flash_tls(
                    &mut session,
                    sensor,
                    6,
                    address,
                    (len - record.len()).min(0x1000) as u32,
                )?;
                ensure!(!chunk.is_empty(), "partition 6 read returned nothing");
                record.extend(chunk);
            }
            record.truncate(len);
            write_private(&out_dir.join("partition6-clean-slate.bin"), &record)?;
            let hash_ok = Sha256::digest(&record).as_slice() == hash;
            steps.insert(
                "partition6".into(),
                json!({ "clean_slate": true, "bytes": len, "hash_ok": hash_ok }),
            );
            // (u16 length, averaged blank frame, u16 0)
            let frame_len = u16::from_le_bytes([record[0], record[1]]) as usize;
            record.get(2..2 + frame_len).map(<[u8]>::to_vec)
        }
    };

    let mut calibration = calibrate::Calibration::new(factory)?;
    let mut scans = Vec::new();
    let mut blank = Vec::new();
    // python-validity's calibration iterations, then one more scan for the blank frame
    for i in 0..=calibrate::ITERATIONS {
        tls_ok(
            &mut session,
            sensor,
            &calibration.command(calibrate::Mode::Calibrate)?,
        )?;
        let raw = sensor.read_data()?;
        write_private(&out_dir.join(format!("scan-{i}.raw")), &raw)?;
        scans.push(raw.len());
        let averaged = calibration.average(&raw)?;
        if i < calibrate::ITERATIONS {
            calibration.accumulate(&averaged);
        } else {
            blank = averaged;
        }
    }
    write_private(&out_dir.join("calibration.bin"), &calibration.data)?;
    write_private(&out_dir.join("blank.bin"), &blank)?;
    let rows = blank.len() / tables::BYTES_PER_LINE;
    write_private(
        &out_dir.join("blank.pgm"),
        &pgm(tables::LINE_WIDTH, rows, &pixels(&blank)),
    )?;
    steps.insert(
        "calibration".into(),
        json!({
            "scan_bytes": scans,
            "expected_scan_bytes": calibration.frame_size() * 3 + tables::BYTES_PER_LINE,
            "blank_pixels": pixel_stats(&pixels(&blank)),
            "blank_vs_partition6_mean_abs_diff": flash_frame.map(|frame| {
                let (ours, theirs) = (pixels(&blank), pixels(&frame));
                let total: u64 = ours.iter().zip(&theirs).map(|(&a, &b)| a.abs_diff(b) as u64).sum();
                total as f64 / ours.len().min(theirs.len()).max(1) as f64
            }),
        }),
    );
    Ok(())
}

/// Checks the sensor is the type the capture tables are for, then reads its
/// factory calibration values (factory bits 0x0e00, subtag 3, minus 4 bytes)
fn factory_values(
    session: &mut tls::Session,
    sensor: &usb::Sensor,
    steps: &mut Map<String, Value>,
) -> Result<Vec<u8>> {
    let id = proto::SensorId::parse(&tls_ok(session, sensor, &[0x75])?)?;
    ensure!(
        (id.major, id.minor) == (0x0190, 0x0061),
        "the tables are for sensor 0x0190/0x0061 (57K0 FM-3380-003), not {:#06x}/{:#06x}",
        id.major,
        id.minor
    );
    let bits = proto::parse_factory_bits(&tls_ok(
        session,
        sensor,
        &proto::factory_bits_request(0x0e00),
    )?)?;
    let factory = bits
        .get(&3)
        .and_then(|value| value.get(4..))
        .context("no factory calibration values (factory bits subtag 3)")?
        .to_vec();
    steps.insert(
        "factory_bits".into(),
        json!({ "subtags": bits.keys().collect::<Vec<_>>(), "calibration_values": factory.len() }),
    );
    Ok(factory)
}

fn run_capture(
    sensor: &usb::Sensor,
    keys: &pairing::HostKeys,
    steps: &mut Map<String, Value>,
    calibration: &Path,
    image_path: &Path,
    finger_timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<()> {
    let saved =
        fs::read(calibration).with_context(|| format!("reading {}", calibration.display()))?;
    let (mut session, _) = open_session(sensor, keys, steps)?;
    let factory = factory_values(&mut session, sensor, steps)?;
    let command =
        calibrate::Calibration::with_data(factory, saved)?.command(calibrate::Mode::Enroll)?;
    ensure!(
        !cancelled.load(Ordering::Relaxed),
        "cancelled before the scan started"
    );

    let mut capture = capture::Capture::new(&mut session, sensor, cancelled);
    let stale = capture.drain()?;
    let result = capture.scan(&command, finger_timeout, || {
        println!("PLACE YOUR FINGER on the sensor now");
        let _ = std::io::stdout().flush();
    });
    steps.insert(
        "scan_events".into(),
        json!({ "stale": stale, "events": capture.events }),
    );
    let image = result?;
    write_private(image_path, &pgm(image.width, image.height, &image.pixels))?;
    steps.insert(
        "image".into(),
        json!({ "file": image_path, "header": image, "pixels": pixel_stats(&image.pixels) }),
    );
    Ok(())
}

fn tls_ok(session: &mut tls::Session, sensor: &usb::Sensor, request: &[u8]) -> Result<Vec<u8>> {
    session.cmd_ok(sensor, request)
}

fn read_flash_tls(
    session: &mut tls::Session,
    sensor: &usb::Sensor,
    partition: u8,
    address: u32,
    size: u32,
) -> Result<Vec<u8>> {
    let payload = tls_ok(
        session,
        sensor,
        &proto::read_flash_request(partition, address, size),
    )?;
    Ok(proto::read_flash_data(&payload)?.to_vec())
}

/// A frame's pixels: each line without its 8-byte header
fn pixels(frame: &[u8]) -> Vec<u8> {
    frame
        .chunks(tables::BYTES_PER_LINE)
        .flat_map(|line| line.get(8..).unwrap_or_default().to_vec())
        .collect()
}

fn pgm(width: usize, height: usize, pixels: &[u8]) -> Vec<u8> {
    let mut out = format!("P5\n{width} {height}\n255\n").into_bytes();
    out.extend(pixels);
    out
}

fn pixel_stats(pixels: &[u8]) -> Value {
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
