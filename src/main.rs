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
use syna_00a2::{capture, db, device, matcher, pairing, proto, tables, usb};

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
    /// Read-only look at the sensor's template database (flash partition 4):
    /// the record tree with types and sizes, storage names, and optionally a
    /// full backup of the partition (mode 0600). Reads no user identities or
    /// template contents into the report, and writes nothing to the sensor.
    Db {
        /// File holding the DMI product serial (root-only in sysfs)
        #[arg(long)]
        serial_file: PathBuf,
        /// Save a full copy of partition 4 here (mode 0600; it may hold templates)
        #[arg(long)]
        backup: Option<PathBuf>,
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
        /// Image preparation: "default", "raw", or "SMOOTHxWINDOW" (e.g. 3x15)
        #[arg(long, default_value = "default")]
        prepare: String,
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
        Command::Score {
            enroll,
            probe,
            prepare,
        } => score(&enroll, &probe, &prepare),
        Command::Db {
            serial_file,
            backup,
            output,
        } => with_sensor(&serial_file, output, |sensor, keys, steps| {
            run_db(sensor, keys, steps, backup.as_deref())
        }),
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
/// releases the sensor when `run` drops it, whatever happens
fn with_sensor(
    serial_file: &Path,
    output: Option<PathBuf>,
    run: impl FnOnce(usb::Sensor, &pairing::HostKeys, &mut Map<String, Value>) -> Result<()>,
) -> Result<()> {
    let (_, keys) = dmi_keys(serial_file)?;
    let sensor = usb::Sensor::open()?;
    let device = sensor.path.clone();
    let mut steps = Map::new();
    // No reboot or reset when it is released: the sensor keeps its TLS session, as with MR 626
    let result = run(sensor, &keys, &mut steps);
    if let Err(e) = &result {
        steps.insert("error".into(), format!("{e:#}").into());
    }
    report(&json!({ "device": device, "steps": steps }), output)?;
    result
}

/// Adapts a report's step map to the library's log callback
fn log(steps: &mut Map<String, Value>) -> impl FnMut(&str, Value) + '_ {
    move |name, value| {
        steps.insert(name.into(), value);
    }
}

fn run_handshake(
    sensor: usb::Sensor,
    keys: &pairing::HostKeys,
    steps: &mut Map<String, Value>,
) -> Result<()> {
    let (mut session, rom_info) = device::open_session(&sensor, keys, &mut log(steps))?;
    let tls_rom_info = session.cmd(&sensor, &[0x01])?;
    steps.insert(
        "tls_rom_info".into(),
        json!({ "response": hex(&tls_rom_info), "matches_plain": tls_rom_info == rom_info }),
    );
    Ok(())
}

fn run_calibrate(
    sensor: usb::Sensor,
    keys: &pairing::HostKeys,
    steps: &mut Map<String, Value>,
    out_dir: &Path,
) -> Result<()> {
    let mut log = log(steps);
    let (mut session, _) = device::open_session(&sensor, keys, &mut log)?;
    let factory = device::factory_values(&mut session, &sensor, &mut log)?;
    let clean_slate = device::read_clean_slate(&mut session, &sensor, &mut log)?;
    if let Some(record) = &clean_slate {
        write_private(&out_dir.join("partition6-clean-slate.bin"), record)?;
    }
    let calibrated = device::calibrate_in_memory(
        &mut session,
        &sensor,
        factory,
        clean_slate.as_deref(),
        &mut log,
    )?;
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
        &pgm(tables::LINE_WIDTH, rows, &device::pixels(&calibrated.blank)),
    )?;
    Ok(())
}

/// Records to walk at most, in case the tree is not what python-validity describes
const MAX_RECORDS: usize = 500;

fn run_db(
    sensor: usb::Sensor,
    keys: &pairing::HostKeys,
    steps: &mut Map<String, Value>,
    backup: Option<&Path>,
) -> Result<()> {
    let (mut session, _) = device::open_session(&sensor, keys, &mut log(steps))?;
    let info = db::parse_info(&session.cmd_ok(&sensor, &db::info_request())?)?;
    steps.insert("db_info".into(), json!(info));

    // Walk the tree through 0x46 only: types and sizes, not values. Storage
    // records carry just a name, so those values are read too.
    let (mut records, mut kinds) = (
        Vec::new(),
        std::collections::BTreeMap::<String, usize>::new(),
    );
    let mut queue: std::collections::VecDeque<u16> = info.roots.iter().copied().collect();
    let mut seen = std::collections::HashSet::new();
    while let Some(dbid) = queue.pop_front() {
        if !seen.insert(dbid) || records.len() >= MAX_RECORDS {
            continue;
        }
        let record = db::parse_children(&session.cmd_ok(&sensor, &db::children_request(dbid))?)?;
        let mut entry = json!({
            "dbid": record.dbid,
            "kind": record.kind,
            "kind_name": db::kind_name(record.kind),
            "storage": record.storage,
            "value_size": record.value_size,
            "children": record.children.iter().map(|c| c.dbid).collect::<Vec<_>>(),
        });
        if record.kind == 4 {
            let (_, value) = db::parse_value(&session.cmd_ok(&sensor, &db::value_request(dbid))?)?;
            entry["name"] = String::from_utf8_lossy(&value)
                .trim_end_matches('\0')
                .into();
        }
        *kinds
            .entry(db::kind_name(record.kind).to_owned())
            .or_default() += 1;
        records.push(entry);
        queue.extend(record.children.iter().map(|c| c.dbid));
    }
    steps.insert("records".into(), json!(records));
    steps.insert("record_kinds".into(), json!(kinds));

    let response = session.cmd(&sensor, &db::user_storage_request("StgWindsor"))?;
    let (status, payload) = proto::split_status(&response)?;
    let storage = match status {
        proto::STATUS_OK => json!(db::parse_user_storage(payload)?),
        db::STATUS_NOT_FOUND => "not found".into(),
        other => json!({ "status": format!("{other:04x}") }),
    };
    steps.insert("stg_windsor".into(), storage);

    if let Some(path) = backup {
        let flash = proto::FlashInfo::parse(&session.cmd_ok(&sensor, &[0x3e])?)?;
        let partition = flash
            .partitions
            .iter()
            .find(|p| p.id == 4)
            .context("no partition 4")?;
        let size = partition.size as usize;
        let mut data = Vec::with_capacity(size);
        while data.len() < size {
            let chunk = device::read_flash_tls(
                &mut session,
                &sensor,
                4,
                data.len() as u32,
                (size - data.len()).min(0x1000) as u32,
            )?;
            ensure!(!chunk.is_empty(), "partition 4 read returned nothing");
            data.extend(chunk);
        }
        data.truncate(size);
        write_private(path, &data)?;
        let erased = data.iter().filter(|&&b| b == 0xff).count() as f64 / size as f64;
        steps.insert(
            "partition4_backup".into(),
            json!({ "bytes": size, "sha256": hex(&Sha256::digest(&data)), "erased_fraction": (erased * 1000.0).round() / 1000.0 }),
        );
    }
    Ok(())
}

/// Rejected placements (sensor scan errors) tolerated per capture run
const MAX_REJECTED: usize = 10;

fn run_capture(
    sensor: usb::Sensor,
    keys: &pairing::HostKeys,
    steps: &mut Map<String, Value>,
    out_dir: &Path,
    names: &[String],
    finger_timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<()> {
    let mut scanner = device::Scanner::open(sensor, keys, &mut log(steps))?;
    ensure!(
        !cancelled.load(Ordering::Relaxed),
        "cancelled before the scan started"
    );

    let is_cancelled = || cancelled.load(Ordering::Relaxed);
    let mut captures = Vec::new();
    let mut failure = None;
    let (mut saved, mut rejected) = (0, 0);
    while saved < names.len() {
        let name = &names[saved];
        let (result, events, stale) = scanner.capture(
            finger_timeout,
            &is_cancelled,
            || {
                println!(
                    "PLACE YOUR FINGER on the sensor now ({}/{})",
                    saved + 1,
                    names.len()
                );
                let _ = std::io::stdout().flush();
            },
            || {},
        );
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
                    "pixels": device::pixel_stats(&image.pixels),
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

fn score(enroll: &[PathBuf], probes: &[PathBuf], prepare: &str) -> Result<()> {
    let how = match prepare {
        "default" => matcher::PREPARE,
        "raw" => matcher::Prepare::Raw,
        spec => {
            let (smooth, window) = spec
                .split_once('x')
                .context("--prepare SMOOTHxWINDOW, e.g. 3x15")?;
            matcher::Prepare::Normalise {
                smooth: smooth.parse()?,
                window: window.parse()?,
            }
        }
    };
    let template = matcher::Template {
        images: enroll.iter().map(|p| read_pgm(p)).collect::<Result<_>>()?,
    };
    let started = std::time::Instant::now();
    let matcher = matcher::Matcher::with(&template, how);
    for path in probes {
        let score = matcher.score(&read_pgm(path)?);
        println!(
            "{:.3} {}",
            score,
            path.file_name().unwrap_or_default().to_string_lossy()
        );
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
    ensure!(
        data.starts_with(header.as_bytes()),
        "{} is not a 112×112 PGM from this tool",
        path.display()
    );
    let pixels = data[header.len()..].to_vec();
    ensure!(
        pixels.len() == matcher::SIDE * matcher::SIDE,
        "{} is truncated",
        path.display()
    );
    Ok(pixels)
}

fn pgm(width: usize, height: usize, pixels: &[u8]) -> Vec<u8> {
    let mut out = format!("P5\n{width} {height}\n255\n").into_bytes();
    out.extend(pixels);
    out
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
