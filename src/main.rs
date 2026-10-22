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
use syna_00a2::pose;
use syna_00a2::{
    blobs, calibrate, capture, chip, db, device, matcher, moh, pairing, proto, tables, usb,
};

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
    /// On-chip matching against the templates already in the sensor's
    /// database: identify-mode scans, each matched by the chip itself (0x5e,
    /// 0x60, then 0x62). Lists the stored fingers by subtype only. Sends no
    /// database writes.
    ChipIdentify {
        /// File holding the DMI product serial (root-only in sysfs)
        #[arg(long)]
        serial_file: PathBuf,
        /// Touches to match. A touch the sensor rejects counts too, so a run
        /// always ends after this many touches.
        #[arg(long, default_value_t = 6)]
        attempts: usize,
        /// Seconds to wait for each touch
        #[arg(long, default_value_t = 30)]
        finger_timeout: u64,
        /// Restrict the chip's match to this user record id (0 = every user,
        /// as python-validity). Experimental: whether the chip honours it is
        /// being tested.
        #[arg(long, value_delimiter = ',', default_value = "0")]
        match_user: Vec<u16>,
        /// Or the Linux uids whose user records (found by their SIDs) to match
        /// against, instead of --match-user
        #[arg(long, value_delimiter = ',')]
        match_uid: Vec<u32>,
        /// With several --match-user ids: match each touch against only one
        /// of them, in rotation (touch 1 the first id, touch 2 the second,
        /// ...). The chip allows one match per scan, so this is how to compare
        /// users under the same conditions.
        #[arg(long)]
        alternate: bool,
        /// Also save each scanned image here as LABEL-NN.pgm (mode 0600)
        #[arg(long)]
        save_dir: Option<PathBuf>,
        /// File name prefix for saved images: lowercase letters, digits, dashes
        #[arg(long, default_value = "identify")]
        label: String,
        /// Also write the JSON report here (mode 0600)
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// DATABASE WRITE. Stores one template envelope (built offline) as a new
    /// finger record in the sensor's template database, under an existing
    /// user record: the db_write_enable blob, then 0x47, then 0x1a. Refuses to
    /// run unless --confirm is the envelope's SHA-256. Writes nothing else.
    ChipEnroll {
        /// File holding the DMI product serial (root-only in sysfs)
        #[arg(long)]
        serial_file: PathBuf,
        /// The 23136-byte template envelope
        #[arg(long)]
        envelope: PathBuf,
        /// Existing user record to file the finger under. python-validity: the
        /// chip's matcher never finds a finger under a user that doesn't exist.
        #[arg(
            long,
            required_unless_present = "parent_uid",
            conflicts_with = "parent_uid"
        )]
        parent: Option<u16>,
        /// Or the Linux uid whose user record (found by its SID) to use
        #[arg(long)]
        parent_uid: Option<u32>,
        /// The envelope's SHA-256, as shown when the write was approved
        #[arg(long)]
        confirm: String,
        /// Also write the JSON report here (mode 0600)
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Offline: registers each probe image's keypoints against every section
    /// of each template envelope and prints inlier counts only (no images,
    /// no keypoints).
    ProbeScore {
        /// Template envelopes (23136 bytes)
        #[arg(long, num_args = 1.., required = true)]
        envelopes: Vec<PathBuf>,
        /// 112×112 PGMs to score
        #[arg(long, num_args = 1.., required = true)]
        images: Vec<PathBuf>,
        /// Where to write the JSON report (mode 0600)
        #[arg(long)]
        output: PathBuf,
        /// Keep only the first N records of each section, N from the
        /// envelope's per-section header values (a test of whether the chip
        /// reads them as counts)
        #[arg(long)]
        counts: bool,
    },
    /// Offline: descriptor-consistent agreement (see `pose::register`) between
    /// every pair of frame groups in a manifest, same group included. Prints
    /// summary statistics only.
    RepeatReport {
        /// JSON {"groups": {name: [pgm paths]}}
        #[arg(long)]
        manifest: PathBuf,
        /// Where to write the JSON report (mode 0600)
        #[arg(long)]
        output: PathBuf,
    },
    /// Offline: for every frame, how well it agrees with the frames of the
    /// OTHER groups that share its finger (the group name's part before the
    /// first underscore), plus simple image statistics. Numbers only.
    FrameGeneralisation {
        /// JSON {"groups": {FINGER_session: [pgm paths]}}
        #[arg(long)]
        manifest: PathBuf,
        /// Where to write the JSON report (mode 0600)
        #[arg(long)]
        output: PathBuf,
    },
    /// Offline: the agreement (descriptor-consistent candidates) of every
    /// frame in a manifest against every frame of the groups whose name starts
    /// with a prefix. Writes the matrix of counts and the frame names.
    PairMatrix {
        /// JSON {"groups": {name: [pgm paths]}}
        #[arg(long)]
        manifest: PathBuf,
        /// Group-name prefix of the reference frames (the columns)
        #[arg(long)]
        refs_prefix: String,
        /// Where to write the JSON report (mode 0600)
        #[arg(long)]
        output: PathBuf,
    },
    /// DATABASE WRITE. Deletes one finger the way the driver does
    /// (`chip::delete`): uid's user record's finger with that subtype; the
    /// user record goes too once it is empty. `--dry-run` prints what would be
    /// sent without opening the sensor. A real run needs `--confirm` to repeat
    /// `--subtype`.
    ChipDelete {
        /// File holding the DMI product serial (root-only in sysfs)
        #[arg(long)]
        serial_file: Option<PathBuf>,
        /// Linux uid in the user record's SID
        #[arg(long)]
        uid: u32,
        /// The finger position (1..=10, e.g. 3 = right middle); every template
        /// of that finger (its recent slots too) goes
        #[arg(long, value_parser = parse_u16)]
        subtype: u16,
        /// Print the requests, send nothing
        #[arg(long)]
        dry_run: bool,
        /// The position again, as approved
        #[arg(long, value_parser = parse_u16)]
        confirm: Option<u16>,
        /// Also write the JSON report here (mode 0600)
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// DATABASE WRITE (erase). Reclaims the template database's space, which
    /// deletes never free (`chip::compact`): saves the Linux-owned templates in
    /// memory, erases flash partition 4, recreates the user storage and the
    /// Linux users, and stores the templates again. Every other record (the
    /// Windows user's, test users without a Linux SID) is gone afterwards.
    /// `--check` only reads and verifies the templates; `--dry-run` prints the
    /// requests without opening the sensor.
    ChipCompact {
        /// File holding the DMI product serial (root-only in sysfs)
        #[arg(long)]
        serial_file: Option<PathBuf>,
        /// Print the requests, send nothing
        #[arg(long)]
        dry_run: bool,
        /// Read and verify the templates only; writes nothing
        #[arg(long)]
        check: bool,
        /// "erase-and-restore", as approved
        #[arg(long)]
        confirm: Option<String>,
        /// Also write the JSON report here (mode 0600)
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// DATABASE WRITE. Creates one user record for a Linux uid under the
    /// StgWindsor user storage (python-validity's `new_user`): the
    /// db_write_enable blob, then 0x47, then 0x1a. Refuses if a user with that
    /// SID exists. `--dry-run` prints the exact request and its SHA-256 without
    /// opening the sensor. A real run needs `--confirm` to equal that SHA-256.
    ChipNewUser {
        /// File holding the DMI product serial (root-only in sysfs)
        #[arg(long)]
        serial_file: Option<PathBuf>,
        /// Linux uid: the last sub-authority of the user's SID
        #[arg(long)]
        uid: u32,
        /// Print the request and its SHA-256, send nothing
        #[arg(long)]
        dry_run: bool,
        /// The request's SHA-256, as shown by --dry-run and approved
        #[arg(long)]
        confirm: Option<String>,
        /// Also write the JSON report here (mode 0600)
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Offline: builds a template envelope for chip-enroll from enroll-mode
    /// images. Uses the four largest keypoint pools, in capture order. Prints
    /// the pools, the frames used and the envelope's SHA-256.
    ChipTemplate {
        /// 112×112 PGMs, in capture order
        #[arg(long, num_args = 1.., required = true)]
        images: Vec<PathBuf>,
        /// Finger subtype for the record header, e.g. 0xf5
        #[arg(long, value_parser = parse_u16)]
        subtype: u16,
        /// Where to write the envelope (mode 0600)
        #[arg(long)]
        out: PathBuf,
        /// Estimate the sections' mutual poses instead of python-validity's
        /// near-identity. Fails if the four placements don't register.
        #[arg(long)]
        poses: bool,
        /// With --poses: pick the same registered placements but keep the
        /// near-identity header (the control for --poses)
        #[arg(long, requires = "poses")]
        identity_header: bool,
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
        Command::ChipTemplate {
            images,
            subtype,
            out,
            poses,
            identity_header,
        } => chip_template(&images, subtype, &out, poses, identity_header),
        Command::ChipIdentify {
            serial_file,
            attempts,
            finger_timeout,
            match_user,
            match_uid,
            alternate,
            save_dir,
            label,
            output,
        } => {
            ensure!(
                label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "--label may only hold lowercase letters, digits and dashes"
            );
            let save = save_dir.map(|dir| (dir, label));
            let cancelled = Arc::new(AtomicBool::new(false));
            for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
                signal_hook::flag::register(signal, Arc::clone(&cancelled))?;
            }
            let timeout = Duration::from_secs(finger_timeout);
            with_sensor(&serial_file, output, |sensor, keys, steps| {
                run_chip_identify(
                    sensor,
                    keys,
                    steps,
                    &IdentifyPlan {
                        attempts,
                        finger_timeout: timeout,
                        match_users: match_user,
                        match_uids: match_uid,
                        alternate,
                    },
                    &cancelled,
                    save.as_ref(),
                )
            })
        }
        Command::RepeatReport { manifest, output } => repeat_report(&manifest, &output),
        Command::PairMatrix {
            manifest,
            refs_prefix,
            output,
        } => pair_matrix(&manifest, &refs_prefix, &output),
        Command::FrameGeneralisation { manifest, output } => {
            frame_generalisation(&manifest, &output)
        }
        Command::ProbeScore {
            envelopes,
            images,
            output,
            counts,
        } => probe_score(&envelopes, &images, &output, counts),
        Command::ChipDelete {
            serial_file,
            uid,
            subtype,
            dry_run,
            confirm,
            output,
        } => {
            ensure!(
                (1..=10).contains(&subtype),
                "--subtype is the finger position, 1..=10 (a slot template's {subtype:#x} is position {}); nothing was sent",
                subtype & 0x0f
            );
            let print = chip::Print { uid, subtype };
            if dry_run {
                return report(
                    &json!({
                        "finds": "uid's user record by its SID, then its finger with this subtype",
                        "sends": "48 <finger record>, 1a; then 48 <user record>, 1a if the user record is left empty",
                    }),
                    output,
                );
            }
            ensure!(
                confirm == Some(subtype),
                "--confirm must repeat --subtype; nothing was sent"
            );
            let serial_file = serial_file.context("--serial-file is required for a real run")?;
            with_sensor(&serial_file, output, |sensor, keys, steps| {
                let (mut session, _) = device::open_session(&sensor, keys, &mut log(steps))?;
                steps.insert("before".into(), db_state(&mut session, &sensor)?);
                let deleted = chip::delete(&mut session, &sensor, &print);
                steps.insert("after".into(), db_state(&mut session, &sensor)?);
                deleted
            })
        }
        Command::ChipCompact {
            serial_file,
            dry_run,
            check,
            confirm,
            output,
        } => {
            if dry_run {
                return report(
                    &json!({
                        "reads": "every Linux-owned finger record's value (0x49), rebuilt and checked against its TemplateId, in memory only",
                        "erase": format!("{} (db_write_enable first, 1a after)", hex(&[0x3f, 4])),
                        "recreate_user_storage": hex(&db::new_record_request(1, 4, 3, b"StgWindsor\0", &[])),
                        "then": "each Linux user record (47 03 00 05 00 03 00 4c 00 + identity) and each saved template (47 <user> 06 00 03 00 60 5a + envelope + 00)",
                    }),
                    output,
                );
            }
            let serial_file = serial_file.context("--serial-file is required")?;
            ensure!(
                check || confirm.as_deref() == Some("erase-and-restore"),
                "a real run needs --confirm erase-and-restore (or use --check, which writes nothing)"
            );
            with_sensor(&serial_file, output, |sensor, keys, steps| {
                let (mut session, _) = device::open_session(&sensor, keys, &mut log(steps))?;
                steps.insert("before".into(), db_state(&mut session, &sensor)?);
                if check {
                    let saved = chip::saved_templates(&mut session, &sensor)?;
                    steps.insert(
                        "saved".into(),
                        json!(saved.iter().map(|(p, e)| json!({ "uid": p.uid, "subtype": p.subtype, "bytes": e.len(), "sha256": hex(&Sha256::digest(e)) })).collect::<Vec<_>>()),
                    );
                    return Ok(());
                }
                let done = chip::compact(&mut session, &sensor);
                if let Ok(c) = &done {
                    steps.insert(
                        "compacted".into(),
                        json!({ "kept": c.kept.iter().map(|p| json!([p.uid, p.subtype])).collect::<Vec<_>>(), "free_before": c.free_before, "free_after": c.free_after }),
                    );
                }
                steps.insert("after".into(), db_state(&mut session, &sensor)?);
                done.map(drop)
            })
        }
        Command::ChipNewUser {
            serial_file,
            uid,
            dry_run,
            confirm,
            output,
        } => {
            // The storage's dbid is read from the sensor; the request shown by
            // --dry-run uses the one this database has (3), which the real run
            // checks again
            let identity = db::linux_identity(uid);
            let request = db::new_user_request(NEW_USER_STORAGE_DBID, &identity);
            let hash = hex(&Sha256::digest(&request));
            if dry_run {
                return report(
                    &json!({
                        "uid": uid,
                        "sid": format!("S-1-5-{}-{uid}", db::LINUX_SID_PREFIX.map(|s| s.to_string()).join("-")),
                        "storage_dbid": NEW_USER_STORAGE_DBID,
                        "request_bytes": request.len(),
                        "request": hex(&request),
                        "request_sha256": hash,
                    }),
                    output,
                );
            }
            ensure!(
                confirm.as_deref().map(str::to_lowercase) == Some(hash.clone()),
                "--confirm does not match the request's SHA-256 {hash}; nothing was sent"
            );
            let serial_file = serial_file.context("--serial-file is required for a real run")?;
            with_sensor(&serial_file, output, |sensor, keys, steps| {
                run_chip_new_user(sensor, keys, steps, &identity)
            })
        }
        Command::ChipEnroll {
            serial_file,
            envelope,
            parent,
            parent_uid,
            confirm,
            output,
        } => {
            let envelope =
                fs::read(&envelope).with_context(|| format!("reading {}", envelope.display()))?;
            let hash = hex(&Sha256::digest(&envelope));
            ensure!(
                hash == confirm.to_lowercase(),
                "--confirm does not match the envelope's SHA-256 {hash}; nothing was sent"
            );
            ensure!(
                envelope.len() == moh::ENVELOPE_SIZE,
                "a MoH envelope is {} bytes, not {}",
                moh::ENVELOPE_SIZE,
                envelope.len()
            );
            with_sensor(&serial_file, output, |sensor, keys, steps| {
                run_chip_enroll(sensor, keys, steps, &envelope, parent, parent_uid)
            })
        }
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

/// The user storage's dbid in this sensor's database (checked at run time)
const NEW_USER_STORAGE_DBID: u16 = 3;

fn run_chip_new_user(
    sensor: usb::Sensor,
    keys: &pairing::HostKeys,
    steps: &mut Map<String, Value>,
    identity: &[u8],
) -> Result<()> {
    let (mut session, _) = device::open_session(&sensor, keys, &mut log(steps))?;
    // Checks first, all reads
    let before = db::parse_info(&session.cmd_ok(&sensor, &db::info_request())?)?;
    ensure!(
        before.free > 8192,
        "not enough free space in the template database"
    );
    let response = session.cmd(&sensor, &db::user_storage_request("StgWindsor"))?;
    let (status, payload) = proto::split_status(&response)?;
    ensure!(
        status == proto::STATUS_OK,
        "no StgWindsor storage (status {status:04x}); nothing was written"
    );
    let storage = db::parse_user_storage(payload)?;
    ensure!(
        storage.dbid == NEW_USER_STORAGE_DBID,
        "StgWindsor is record {}, not {NEW_USER_STORAGE_DBID}: the approved request does not apply; nothing was written",
        storage.dbid
    );
    let lookup = |session: &mut syna_00a2::tls::Session| -> Result<Option<u16>> {
        let response = session.cmd(
            &sensor,
            &db::user_by_identity_request(storage.dbid, identity),
        )?;
        let (status, payload) = proto::split_status(&response)?;
        match status {
            db::STATUS_NOT_FOUND => Ok(None),
            proto::STATUS_OK => Ok(Some(db::parse_user_fingers(payload)?.0)),
            other => bail!("looking up the user failed with status {other:04x}"),
        }
    };
    ensure!(
        lookup(&mut session)?.is_none(),
        "a user with this SID already exists; nothing was written"
    );
    steps.insert(
        "before".into(),
        json!({ "db_info": before, "users": storage.users }),
    );

    // The write: unlock, create, commit (always, as python-validity does)
    session
        .cmd_ok(&sensor, &blobs::DB_WRITE_ENABLE)
        .context("db_write_enable; nothing was written")?;
    let request = db::new_user_request(storage.dbid, identity);
    let created = session.cmd(&sensor, &request);
    let commit = session.cmd(&sensor, &db::COMMIT_REQUEST);
    let created = created?;
    let (status, payload) = proto::split_status(&created)?;
    let commit_status = proto::split_status(&commit?)?.0;
    steps.insert(
        "write".into(),
        json!({
            "header": hex(&request[..9]),
            "store_status": format!("{status:04x}"),
            "commit_status": format!("{commit_status:04x}"),
        }),
    );
    ensure!(
        status == proto::STATUS_OK,
        "the sensor refused the user record (status {status:04x})"
    );
    ensure!(
        [proto::STATUS_OK, db::STATUS_NOTHING_TO_COMMIT].contains(&commit_status),
        "commit failed with status {commit_status:04x}"
    );
    ensure!(payload.len() >= 2, "no record id in the response");
    let dbid = u16::from_le_bytes([payload[0], payload[1]]);

    let after = db::parse_info(&session.cmd_ok(&sensor, &db::info_request())?)?;
    let found = lookup(&mut session)?;
    let users = db::parse_user_storage(
        proto::split_status(&session.cmd(&sensor, &db::user_storage_request("StgWindsor"))?)?.1,
    )?
    .users;
    steps.insert(
        "after".into(),
        json!({ "db_info": after, "new_user": dbid, "lookup_by_identity": found, "users": users }),
    );
    ensure!(
        found == Some(dbid),
        "the new user {dbid} is not found by its identity"
    );
    Ok(())
}

fn run_chip_enroll(
    sensor: usb::Sensor,
    keys: &pairing::HostKeys,
    steps: &mut Map<String, Value>,
    envelope: &[u8],
    parent: Option<u16>,
    parent_uid: Option<u32>,
) -> Result<()> {
    let (mut session, _) = device::open_session(&sensor, keys, &mut log(steps))?;
    let parent = match (parent, parent_uid) {
        (Some(parent), _) => parent,
        (None, Some(uid)) => chip::find_user(&mut session, &sensor, uid)?
            .with_context(|| format!("uid {uid} has no user record; nothing was written"))?,
        (None, None) => bail!("give --parent or --parent-uid; nothing was written"),
    };
    // Checks first, all reads
    let before = db::parse_info(&session.cmd_ok(&sensor, &db::info_request())?)?;
    ensure!(
        before.free as usize > envelope.len() + 4096,
        "not enough free space in the template database"
    );
    let response = session.cmd(&sensor, &db::user_storage_request("StgWindsor"))?;
    let (status, payload) = proto::split_status(&response)?;
    ensure!(
        status == proto::STATUS_OK,
        "no StgWindsor storage (status {status:04x}); nothing was written"
    );
    let storage = db::parse_user_storage(payload)?;
    ensure!(
        storage.users.iter().any(|&(user, _)| user == parent),
        "user record {parent} is not in StgWindsor; nothing was written"
    );
    let children = |session: &mut syna_00a2::tls::Session| -> Result<Vec<u16>> {
        Ok(
            db::parse_children(&session.cmd_ok(&sensor, &db::children_request(parent))?)?
                .children
                .iter()
                .map(|c| c.dbid)
                .collect(),
        )
    };
    steps.insert(
        "before".into(),
        json!({ "db_info": before, "parent_children": children(&mut session)? }),
    );

    // The write: unlock, store, commit (always, as python-validity does)
    session
        .cmd_ok(&sensor, &blobs::DB_WRITE_ENABLE)
        .context("db_write_enable; nothing was written")?;
    let request = db::new_record_request(parent, moh::FINGER_KIND, storage.dbid, envelope, &[0]);
    let stored = session.cmd(&sensor, &request);
    let commit = session.cmd(&sensor, &db::COMMIT_REQUEST);
    let stored = stored?;
    let (status, payload) = proto::split_status(&stored)?;
    let commit_status = proto::split_status(&commit?)?.0;
    steps.insert(
        "write".into(),
        json!({
            "header": hex(&request[..9]),
            "store_status": format!("{status:04x}"),
            "commit_status": format!("{commit_status:04x}"),
        }),
    );
    ensure!(
        status == proto::STATUS_OK,
        "the sensor refused the record (status {status:04x})"
    );
    ensure!(
        [proto::STATUS_OK, db::STATUS_NOTHING_TO_COMMIT].contains(&commit_status),
        "commit failed with status {commit_status:04x}"
    );
    ensure!(payload.len() >= 2, "no record id in the response");
    let dbid = u16::from_le_bytes([payload[0], payload[1]]);

    let after = db::parse_info(&session.cmd_ok(&sensor, &db::info_request())?)?;
    steps.insert(
        "after".into(),
        json!({ "new_record": dbid, "db_info": after, "parent_children": children(&mut session)? }),
    );
    Ok(())
}

/// What a chip-identify run asks for
struct IdentifyPlan {
    attempts: usize,
    finger_timeout: Duration,
    /// Each scan is matched against these users in turn (0 = every user)
    match_users: Vec<u16>,
    /// Linux uids to look up and use instead of `match_users`, if any
    match_uids: Vec<u32>,
    /// Match each scan against one user only, in rotation
    alternate: bool,
}

fn run_chip_identify(
    sensor: usb::Sensor,
    keys: &pairing::HostKeys,
    steps: &mut Map<String, Value>,
    plan: &IdentifyPlan,
    cancelled: &AtomicBool,
    save: Option<&(PathBuf, String)>,
) -> Result<()> {
    let IdentifyPlan {
        attempts,
        finger_timeout,
        ref match_users,
        ref match_uids,
        alternate,
    } = *plan;
    let mut scanner = device::Scanner::open(sensor, keys, &mut log(steps))?;
    let mut match_users = match_users.clone();
    if !match_uids.is_empty() {
        match_users = match_uids
            .iter()
            .map(|&uid| {
                chip::find_user(&mut scanner.session, &scanner.sensor, uid)?
                    .with_context(|| format!("uid {uid} has no user record"))
            })
            .collect::<Result<_>>()?;
    }
    let match_users = &match_users;
    steps.insert("match_users".into(), json!(match_users));

    // The stored fingers, by subtype only: user records hold Windows SIDs
    let response = scanner
        .session
        .cmd(&scanner.sensor, &db::user_storage_request("StgWindsor"))?;
    let (status, payload) = proto::split_status(&response)?;
    ensure!(
        status == proto::STATUS_OK,
        "no StgWindsor storage (status {status:04x})"
    );
    let mut stored = Vec::new();
    for (user, _) in db::parse_user_storage(payload)?.users {
        let (_, fingers) = db::parse_user_fingers(
            &scanner
                .session
                .cmd_ok(&scanner.sensor, &db::user_request(user))?,
        )?;
        let fingers: Vec<_> = fingers
            .iter()
            .map(|f| json!({ "dbid": f.dbid, "subtype": f.subtype, "finger": db::subtype_name(f.subtype), "value_size": f.value_size }))
            .collect();
        stored.push(json!({ "user": user, "fingers": fingers }));
    }
    steps.insert("stored_fingers".into(), json!(stored));
    ensure!(
        !cancelled.load(Ordering::Relaxed),
        "cancelled before the first scan"
    );

    let is_cancelled = || cancelled.load(Ordering::Relaxed);
    let (mut results, mut rejected) = (Vec::new(), 0);
    let mut failure = None;
    while results.len() + rejected < attempts {
        let attempt = results.len() + rejected + 1;
        let device::ScanOutcome {
            result,
            events,
            stale,
            held,
            stalled,
        } = scanner.scan(
            calibrate::Mode::Identify,
            finger_timeout,
            &is_cancelled,
            || {
                println!("PLACE YOUR FINGER on the sensor now ({attempt}/{attempts})");
                let _ = std::io::stdout().flush();
            },
            || {},
        );
        match result {
            Ok(capture::Scan::Rejected(code)) => {
                rejected += 1;
                steps.insert(
                    format!("rejected_{rejected}"),
                    json!({ "attempt": attempt, "code": format!("{code:#x}"), "events": events, "held": held, "stalled": stalled }),
                );
                if rejected > MAX_REJECTED {
                    failure = Some(anyhow::anyhow!("{rejected} placements rejected"));
                    break;
                }
            }
            Ok(capture::Scan::Image(image)) => {
                if let (Some((dir, label)), false) = (save, image.pixels.is_empty()) {
                    write_private(
                        &dir.join(format!("{label}-{attempt:02}.pgm")),
                        &pgm(image.width, image.height, &image.pixels),
                    )?;
                }
                let mut entry = json!({ "attempt": attempt, "result_pixels": image.pixels.len(), "stale_events": stale, "events": events, "held": held, "stalled": stalled });
                // The same scan against each user in turn. "match" is the first
                // user's decision; a later user that errors is recorded, not fatal.
                let mut matches = Vec::new();
                let rotation = [match_users[results.len() % match_users.len()]];
                let users = if alternate {
                    &rotation[..]
                } else {
                    &match_users[..]
                };
                for (i, &user) in users.iter().enumerate() {
                    match chip_match(&mut scanner, user) {
                        Ok(decision) => {
                            if i == 0 {
                                entry["match"] = decision.clone();
                            }
                            matches.push(json!({ "match_user": user, "decision": decision }));
                        }
                        Err(e) if i == 0 => {
                            entry["error"] = format!("{e:#}").into();
                            failure = Some(e);
                            break;
                        }
                        Err(e) => {
                            matches.push(json!({ "match_user": user, "error": format!("{e:#}") }));
                        }
                    }
                }
                entry["matches"] = matches.into();
                results.push(entry);
                // No pause before the next scan: identify scans don't wait for
                // the lift, so the scanner rescans the held finger until it
                // comes off. A touch that lands while no scan runs looks held
                // and is lost (x1 lost one in three during a 1.5 s pause).
                if failure.is_some() {
                    break;
                }
            }
            Err(e) => {
                results.push(
                    json!({ "attempt": attempt, "error": format!("{e:#}"), "events": events, "held": held, "stalled": stalled }),
                );
                failure = Some(e);
                break;
            }
        }
    }
    steps.insert("attempts".into(), json!(results));
    failure.map_or(Ok(()), Err)
}

/// The chip's own match of the last identify-mode scan (see
/// [`chip::chip_match`]), as a report
fn chip_match(scanner: &mut device::Scanner, user: u16) -> Result<Value> {
    let decision = chip::chip_match(&mut scanner.session, &scanner.sensor, user)?;
    let mut report = match &decision.result {
        None => json!({ "recognised": false, "event": hex(&decision.event) }),
        Some(result) => json!({
            "recognised": true,
            "event": hex(&decision.event),
            "user": result.user,
            "subtype": result.subtype,
            "finger": db::subtype_name(result.subtype),
            "hash_prefix": &result.hash[..result.hash.len().min(16)],
        }),
    };
    report["cleanup"] = match decision.cleanup {
        Ok(response) => hex(&response).into(),
        Err(e) => format!("error: {e:#}").into(),
    };
    Ok(report)
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
        let device::ScanOutcome {
            result,
            events,
            stale,
            stalled,
            ..
        } = scanner.capture(
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
                captures.push(json!({ "stale_events": stale, "events": events, "stalled": stalled, "rejected": format!("{code:#x}") }));
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
                    "stalled": stalled,
                }));
            }
            Err(e) => {
                captures.push(
                    json!({ "stale_events": stale, "events": events, "stalled": stalled, "error": format!("{e:#}") }),
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

fn chip_template(
    images: &[PathBuf],
    subtype: u16,
    out: &Path,
    poses: bool,
    identity_header: bool,
) -> Result<()> {
    let frames = images
        .iter()
        .map(|p| moh::extract(&read_pgm(p)?))
        .collect::<Result<Vec<_>>>()?;
    let (envelope, chosen) = if poses {
        moh::template_with_poses(&frames, subtype, !identity_header)
            .context("no four placements register against each other")?
    } else {
        (moh::template(&frames, subtype), moh::choose(&frames))
    };
    write_private(out, &envelope)?;
    let name = |p: &PathBuf| {
        p.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    };
    let used: Vec<_> = chosen.into_iter().map(|k| name(&images[k])).collect();
    let pools: Vec<_> = frames.iter().map(|f| f.pool).collect();
    let weak = pools.iter().filter(|&&n| n < moh::FRAME_KP_CAP).count();
    report(
        &json!({
            "pools": pools,
            "weak_frames": weak,
            "used": used,
            "subtype": format!("{subtype:#06x}"),
            "poses": poses && !identity_header,
            "bytes": envelope.len(),
            "sha256": hex(&Sha256::digest(&envelope)),
        }),
        None,
    )
}

fn probe_score(
    envelopes: &[PathBuf],
    images: &[PathBuf],
    output: &Path,
    counts: bool,
) -> Result<()> {
    let name = |p: &PathBuf| {
        p.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    };
    let templates = envelopes
        .iter()
        .map(|p| {
            let data = fs::read(p).with_context(|| format!("reading {}", p.display()))?;
            let mut sections = moh::sections(&data)?;
            if counts {
                for (s, n) in sections.iter_mut().zip(moh::section_counts(&data)?) {
                    s.truncate(n as usize);
                }
            }
            Ok((name(p), sections))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut rows = Vec::new();
    for path in images {
        let frame = moh::extract(&read_pgm(path)?)?;
        let mut scores = Map::new();
        for (template, sections) in &templates {
            let per_section: Vec<_> = sections
                .iter()
                .map(|s| {
                    pose::register(&frame.keypoints, s).map_or(json!([0, 0, 0]), |p| {
                        json!([p.inliers, p.quality, p.candidates])
                    })
                })
                .collect();
            scores.insert(template.clone(), json!(per_section));
        }
        rows.push(json!({ "image": name(path), "pool": frame.pool, "scores": scores }));
    }
    write_private(
        output,
        serde_json::to_string_pretty(&json!({ "probes": rows }))?.as_bytes(),
    )
}

fn repeat_report(manifest: &Path, output: &Path) -> Result<()> {
    let manifest: Value = serde_json::from_slice(&fs::read(manifest)?)?;
    let groups = manifest["groups"].as_object().context("no groups")?;
    let mut frames: Vec<(String, Vec<moh::Frame>)> = Vec::new();
    for (name, paths) in groups {
        let list = paths
            .as_array()
            .context("a group is a list of paths")?
            .iter()
            .map(|p| moh::extract(&read_pgm(Path::new(p.as_str().context("path")?))?))
            .collect::<Result<Vec<_>>>()?;
        frames.push((name.clone(), list));
    }
    let stats = |mut v: Vec<u8>| {
        v.sort_unstable();
        let at = |q: f64| v[((v.len() - 1) as f64 * q).round() as usize];
        json!({ "n": v.len(), "min": v[0], "median": at(0.5), "p90": at(0.9), "max": v[v.len() - 1] })
    };
    let mut report = Map::new();
    for (i, (ni, fi)) in frames.iter().enumerate() {
        for (nj, fj) in &frames[i..] {
            let jobs: Vec<(usize, usize)> = (0..fi.len())
                .flat_map(|a| (0..fj.len()).map(move |b| (a, b)))
                .filter(|&(a, b)| ni != nj || a < b)
                .collect();
            let counts: Vec<u8> = std::thread::scope(|s| {
                let chunk = jobs.len().div_ceil(8).max(1);
                jobs.chunks(chunk)
                    .map(|part| {
                        s.spawn(move || {
                            part.iter()
                                .map(|&(a, b)| {
                                    pose::register(&fi[a].keypoints, &fj[b].keypoints)
                                        .map_or(0, |p| p.candidates)
                                })
                                .collect::<Vec<u8>>()
                        })
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .flat_map(|h| h.join().expect("worker"))
                    .collect()
            });
            if !counts.is_empty() {
                report.insert(format!("{ni} x {nj}"), stats(counts));
            }
        }
    }
    write_private(
        output,
        serde_json::to_string_pretty(&Value::Object(report))?.as_bytes(),
    )
}

fn frame_generalisation(manifest: &Path, output: &Path) -> Result<()> {
    let manifest: Value = serde_json::from_slice(&fs::read(manifest)?)?;
    let groups = manifest["groups"].as_object().context("no groups")?;
    struct Item {
        group: String,
        file: String,
        frame: moh::Frame,
        stats: [f64; 4],
    }
    let mut items = Vec::new();
    for (name, paths) in groups {
        for p in paths.as_array().context("a group is a list of paths")? {
            let path = Path::new(p.as_str().context("path")?);
            let pixels = read_pgm(path)?;
            let n = pixels.len() as f64;
            let mean = pixels.iter().map(|&v| v as f64).sum::<f64>() / n;
            let sd = (pixels
                .iter()
                .map(|&v| (v as f64 - mean).powi(2))
                .sum::<f64>()
                / n)
                .sqrt();
            let dark = pixels.iter().filter(|&&v| v <= 2).count() as f64 / n;
            let bright = pixels.iter().filter(|&&v| v >= 253).count() as f64 / n;
            items.push(Item {
                group: name.clone(),
                file: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                frame: moh::extract(&pixels)?,
                stats: [mean, sd, dark, bright],
            });
        }
    }
    let finger = |g: &str| g.split('_').next().unwrap_or(g).to_owned();
    let items = &items;
    let rows: Vec<Value> = std::thread::scope(|s| {
        let chunk = items.len().div_ceil(8).max(1);
        let handles: Vec<_> = (0..items.len())
            .step_by(chunk)
            .map(|start| {
                s.spawn(move || {
                    (start..(start + chunk).min(items.len()))
                        .map(|i| {
                            let it = &items[i];
                            let mut counts: Vec<u8> = items
                                .iter()
                                .filter(|o| {
                                    finger(&o.group) == finger(&it.group) && o.group != it.group
                                })
                                .map(|o| {
                                    pose::register(&it.frame.keypoints, &o.frame.keypoints)
                                        .map_or(0, |p| p.candidates)
                                })
                                .collect();
                            counts.sort_unstable();
                            let mean = counts.iter().map(|&c| c as f64).sum::<f64>()
                                / counts.len().max(1) as f64;
                            json!({
                                "group": it.group, "file": it.file, "pool": it.frame.pool,
                                "mean": it.stats[0], "sd": it.stats[1], "dark": it.stats[2], "bright": it.stats[3],
                                "others": counts.len(), "gen_mean": mean,
                                "gen_p90": counts.get(counts.len() * 9 / 10).copied().unwrap_or(0),
                            })
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("worker"))
            .collect()
    });
    write_private(
        output,
        serde_json::to_string_pretty(&json!({ "frames": rows }))?.as_bytes(),
    )
}

fn pair_matrix(manifest: &Path, refs_prefix: &str, output: &Path) -> Result<()> {
    let manifest: Value = serde_json::from_slice(&fs::read(manifest)?)?;
    let groups = manifest["groups"].as_object().context("no groups")?;
    let mut names = Vec::new();
    let mut frames = Vec::new();
    for (name, paths) in groups {
        for p in paths.as_array().context("a group is a list of paths")? {
            let path = Path::new(p.as_str().context("path")?);
            frames.push(moh::extract(&read_pgm(path)?)?);
            names.push((
                name.clone(),
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
            ));
        }
    }
    let cols: Vec<usize> = (0..frames.len())
        .filter(|&i| names[i].0.starts_with(refs_prefix))
        .collect();
    let (frames, cols) = (&frames, &cols);
    let matrix: Vec<Vec<u8>> = std::thread::scope(|s| {
        let chunk = frames.len().div_ceil(8).max(1);
        let handles: Vec<_> = (0..frames.len())
            .step_by(chunk)
            .map(|start| {
                s.spawn(move || {
                    (start..(start + chunk).min(frames.len()))
                        .map(|i| {
                            cols.iter()
                                .map(|&j| {
                                    if i == j {
                                        0
                                    } else {
                                        pose::register(&frames[i].keypoints, &frames[j].keypoints)
                                            .map_or(0, |p| p.candidates)
                                    }
                                })
                                .collect::<Vec<u8>>()
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("worker"))
            .collect()
    });
    let label = |i: usize| json!({ "group": names[i].0, "file": names[i].1 });
    write_private(
        output,
        serde_json::to_string(&json!({
            "rows": (0..frames.len()).map(label).collect::<Vec<_>>(),
            "cols": cols.iter().map(|&j| label(j)).collect::<Vec<_>>(),
            "m": matrix,
        }))?
        .as_bytes(),
    )
}

/// Free space and the Linux-owned prints, for before/after reports
fn db_state(session: &mut syna_00a2::tls::Session, sensor: &usb::Sensor) -> Result<Value> {
    let info = db::parse_info(&session.cmd_ok(sensor, &db::info_request())?)?;
    let prints = chip::list(session, sensor)?;
    Ok(json!({
        "db_info": info,
        "linux_prints": prints.iter().map(|p| json!([p.uid, p.subtype])).collect::<Vec<_>>(),
    }))
}

fn parse_u16(s: &str) -> Result<u16, String> {
    match s.strip_prefix("0x") {
        Some(digits) => u16::from_str_radix(digits, 16),
        None => s.parse(),
    }
    .map_err(|e| e.to_string())
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
