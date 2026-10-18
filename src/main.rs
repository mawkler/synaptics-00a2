// SPDX-License-Identifier: LGPL-2.1-or-later
//! Userspace driver for the Synaptics 06cb:00a2 fingerprint reader

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
use syna_00a2::{blobs, calibrate, capture, matcher, pairing, proto, tables, tls, usb};

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
    /// Calibrates in memory with no finger on the sensor, then captures
    /// fingerprint images (enroll-mode scans) and saves them as PGMs (mode
    /// 0600). Writes nothing to flash. SIGINT/SIGTERM stop the scan cleanly.
    Capture {
        /// File holding the DMI product serial (root-only in sysfs)
        #[arg(long)]
        serial_file: PathBuf,
        /// Directory for the images
        #[arg(long)]
        out_dir: PathBuf,
        /// Image file name, without extension: lowercase letters, digits, dashes.
        /// With --count above 1, each image gets a -01, -02, ... suffix.
        #[arg(long, default_value = "capture")]
        label: String,
        /// Placements to capture after one calibration; lift the finger between them
        #[arg(long, default_value_t = 1)]
        count: usize,
        /// Seconds to wait for each touch
        #[arg(long, default_value_t = 30)]
        finger_timeout: u64,
        /// Also write the JSON report here (mode 0600)
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Offline: scores probe images against a template built from enrolled
    /// images, as the driver's matcher does. Prints scores only.
    Score {
        /// 112×112 PGMs to build the template from
        #[arg(long, num_args = 1.., required = true)]
        enroll: Vec<PathBuf>,
        /// 112×112 PGMs to score
        #[arg(long, num_args = 1.., required = true)]
        probe: Vec<PathBuf>,
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
        Command::Score { enroll, probe } => score(&enroll, &probe),
        Command::Capture {
            serial_file,
            out_dir,
            label,
            count,
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
            ensure!(
                (1..=50).contains(&count),
                "--count must be between 1 and 50"
            );
            // Registered before the sensor is opened, so a stop request always reaches the scan loop
            let cancelled = Arc::new(AtomicBool::new(false));
            for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
                signal_hook::flag::register(signal, Arc::clone(&cancelled))?;
            }
            let names: Vec<String> = match count {
                1 => vec![format!("{label}.pgm")],
                _ => (1..=count).map(|i| format!("{label}-{i:02}.pgm")).collect(),
            };
            let timeout = Duration::from_secs(finger_timeout);
            with_sensor(&serial_file, output, |sensor, keys, steps| {
                run_capture(sensor, keys, steps, &out_dir, &names, timeout, &cancelled)
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
    let calibrated = calibrate_in_memory(&mut session, sensor, factory, steps)?;
    if let Some(record) = &calibrated.flash_record {
        write_private(&out_dir.join("partition6-clean-slate.bin"), record)?;
    }
    for (i, raw) in calibrated.raw_scans.iter().enumerate() {
        write_private(&out_dir.join(format!("scan-{i}.raw")), raw)?;
    }
    write_private(
        &out_dir.join("calibration.bin"),
        &calibrated.calibration.data,
    )?;
    write_private(&out_dir.join("blank.bin"), &calibrated.blank)?;
    let rows = calibrated.blank.len() / tables::BYTES_PER_LINE;
    write_private(
        &out_dir.join("blank.pgm"),
        &pgm(tables::LINE_WIDTH, rows, &pixels(&calibrated.blank)),
    )?;
    Ok(())
}

struct Calibrated {
    calibration: calibrate::Calibration,
    blank: Vec<u8>,
    raw_scans: Vec<Vec<u8>>,
    /// The clean slate record in partition 6, if there is a valid one
    flash_record: Option<Vec<u8>>,
    /// Mean absolute pixel difference between our blank scan and that record's frame
    blank_vs_flash: Option<f64>,
}

/// Reads any clean slate in partition 6 (read-only), then runs
/// python-validity's calibration scans plus one blank scan, keeping the
/// result in memory. Scans only completed after calibration scans in the same
/// power cycle (M4b), so every capture calibrates first.
fn calibrate_in_memory(
    session: &mut tls::Session,
    sensor: &usb::Sensor,
    factory: Vec<u8>,
    steps: &mut Map<String, Value>,
) -> Result<Calibrated> {
    let header = read_flash_tls(session, sensor, 6, 0, calibrate::CLEAN_SLATE_HEADER as u32)?;
    let flash_record = match calibrate::clean_slate_header(&header) {
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
            steps.insert(
                "partition6".into(),
                json!({ "clean_slate": true, "bytes": len, "hash_ok": hash_ok }),
            );
            hash_ok.then_some(record)
        }
    };

    let mut calibration = calibrate::Calibration::new(factory)?;
    let mut raw_scans = Vec::new();
    let mut blank = Vec::new();
    // python-validity's calibration iterations, then one more scan for the blank frame
    for i in 0..=calibrate::ITERATIONS {
        tls_ok(
            session,
            sensor,
            &calibration.command(calibrate::Mode::Calibrate)?,
        )?;
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
    let blank_vs_flash = flash_record.as_ref().and_then(|record| {
        let len = u16::from_le_bytes([record[0], record[1]]) as usize;
        let frame = record.get(2..2 + len)?;
        Some(mean_abs_diff(&pixels(&blank), &pixels(frame)))
    });
    steps.insert(
        "calibration".into(),
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
        flash_record,
        blank_vs_flash,
    })
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

/// Largest mean absolute difference between the blank scan and the stored
/// clean slate that still counts as an empty sensor. M4a measured 2.29; a
/// finger's ridges would differ far more.
const MAX_BLANK_DIFF: f64 = 6.0;

/// Rejected placements (sensor scan errors) tolerated per capture run
const MAX_REJECTED: usize = 10;

fn run_capture(
    sensor: &usb::Sensor,
    keys: &pairing::HostKeys,
    steps: &mut Map<String, Value>,
    out_dir: &Path,
    names: &[String],
    finger_timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<()> {
    let (mut session, _) = open_session(sensor, keys, steps)?;
    let factory = factory_values(&mut session, sensor, steps)?;
    let calibrated = calibrate_in_memory(&mut session, sensor, factory, steps)?;
    let diff = calibrated
        .blank_vs_flash
        .context("partition 6 has no valid clean slate to check the blank scan against")?;
    ensure!(
        diff <= MAX_BLANK_DIFF,
        "the blank scan differs from the stored clean slate by {diff:.1} grey levels (limit {MAX_BLANK_DIFF}): \
         was a finger on the sensor during calibration? Lift it and run again"
    );
    let command = calibrated.calibration.command(calibrate::Mode::Enroll)?;
    ensure!(
        !cancelled.load(Ordering::Relaxed),
        "cancelled before the scan started"
    );

    let mut capture = capture::Capture::new(&mut session, sensor, cancelled);
    let mut captures = Vec::new();
    let mut failure = None;
    let (mut saved, mut rejected) = (0, 0);
    while saved < names.len() {
        let name = &names[saved];
        let stale = capture.drain()?;
        let result = capture.scan(&command, finger_timeout, || {
            println!(
                "PLACE YOUR FINGER on the sensor now ({}/{})",
                saved + 1,
                names.len()
            );
            let _ = std::io::stdout().flush();
        });
        let events = std::mem::take(&mut capture.events);
        match result {
            Ok(capture::Scan::Rejected(code)) => {
                captures.push(json!({ "stale_events": stale, "events": events, "rejected": format!("{code:#x}") }));
                rejected += 1;
                if rejected > MAX_REJECTED {
                    failure = Some(anyhow::anyhow!(
                        "{rejected} placements rejected after {saved} of {} captures",
                        names.len()
                    ));
                    break;
                }
            }
            Ok(capture::Scan::Image(image)) => {
                saved += 1;
                write_private(
                    &out_dir.join(name),
                    &pgm(image.width, image.height, &image.pixels),
                )?;
                captures.push(json!({
                    "file": name,
                    "header": image,
                    "pixels": pixel_stats(&image.pixels),
                    "stale_events": stale,
                    "events": events,
                }));
            }
            Err(e) => {
                captures.push(
                    json!({ "stale_events": stale, "events": events, "error": format!("{e:#}") }),
                );
                failure = Some(e.context(format!("after {saved} of {} captures", names.len())));
                break;
            }
        }
    }
    steps.insert("captures".into(), json!(captures));
    failure.map_or(Ok(()), Err)
}

fn score(enroll: &[PathBuf], probes: &[PathBuf]) -> Result<()> {
    let template = matcher::Template { images: enroll.iter().map(|p| read_pgm(p)).collect::<Result<_>>()? };
    let started = std::time::Instant::now();
    let matcher = matcher::Matcher::new(&template);
    for path in probes {
        let score = matcher.score(&read_pgm(path)?);
        println!("{:.3} {}", score, path.file_name().unwrap_or_default().to_string_lossy());
    }
    eprintln!(
        "{} probes against {} images in {:.2} s; threshold {}",
        probes.len(),
        template.images.len(),
        started.elapsed().as_secs_f64(),
        matcher::THRESHOLD
    );
    Ok(())
}

/// Pixels of a 112×112 8-bit binary PGM as written by `pgm`
fn read_pgm(path: &Path) -> Result<Vec<u8>> {
    let data = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let header = format!("P5\n{0} {0}\n255\n", matcher::SIDE);
    ensure!(data.starts_with(header.as_bytes()), "{} is not a 112×112 PGM from this tool", path.display());
    let pixels = data[header.len()..].to_vec();
    ensure!(pixels.len() == matcher::SIDE * matcher::SIDE, "{} is truncated", path.display());
    Ok(pixels)
}

fn mean_abs_diff(a: &[u8], b: &[u8]) -> f64 {
    let total: u64 = a.iter().zip(b).map(|(&x, &y)| x.abs_diff(y) as u64).sum();
    total as f64 / a.len().min(b.len()).max(1) as f64
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
