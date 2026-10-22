// SPDX-License-Identifier: LGPL-2.1-or-later
//! The sensor's template database as the driver uses it (see
//! `docs/on-chip-driver.md`): one user record per Linux uid, identified by
//! python-validity's SID scheme ([`db::linux_identity`]), with the user's
//! fingers under it, and the chip's own matching. Records Linux didn't create,
//! such as the Windows user, are never listed, matched as a success or
//! deleted.

use std::{fmt, time::Duration};

use anyhow::{bail, ensure, Context, Result};

use crate::{blobs, db, moh, proto, tls::Session, usb::Sensor};

/// A finger the driver stored: the Linux uid in its user record's SID and
/// the finger's subtype (WinBio position, 1..=10). The pair names one finger:
/// a uid has one user record, and the sensor refuses a second finger with the
/// same subtype under a user (`0x04c3`). Record ids are left out on purpose,
/// so a print stays valid when [`compact`] rebuilds the database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Print {
    pub uid: u32,
    pub subtype: u16,
}

/// The database has no room for another template
#[derive(Debug)]
pub struct DataFull;

/// The record isn't there, or isn't the Linux user's
#[derive(Debug)]
pub struct NotFound;

impl fmt::Display for DataFull {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("the sensor's template database is full")
    }
}

impl fmt::Display for NotFound {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("the print is not on the sensor")
    }
}

impl std::error::Error for DataFull {}
impl std::error::Error for NotFound {}

/// How long the chip may take to report a match decision
const MATCH_TIMEOUT: Duration = Duration::from_secs(10);

/// What the chip said about the last identify-mode scan
pub struct Decision {
    pub event: Vec<u8>,
    /// Set when the chip recognised the finger
    pub result: Option<db::MatchResult>,
    /// The cleanup command's response; reported, not checked
    pub cleanup: Result<Vec<u8>>,
}

/// The chip's own match of the last identify-mode scan, against one user
/// record (0 = every user), as python-validity's `Sensor.match_finger`. The
/// cleanup command is always sent.
pub fn chip_match(session: &mut Session, sensor: &Sensor, user: u16) -> Result<Decision> {
    let decision = (|| -> Result<(Vec<u8>, Option<db::MatchResult>)> {
        session.cmd_ok(sensor, &db::match_request(user))?;
        let deadline = std::time::Instant::now() + MATCH_TIMEOUT;
        let event = loop {
            if let Some(event) = sensor.read_interrupt(Duration::from_millis(100))? {
                break event;
            }
            ensure!(
                std::time::Instant::now() < deadline,
                "no match decision within {} s",
                MATCH_TIMEOUT.as_secs()
            );
        };
        if event.first() != Some(&db::EVENT_RECOGNISED) {
            return Ok((event, None));
        }
        let result = db::parse_match_result(&session.cmd_ok(sensor, &db::MATCH_RESULT_REQUEST)?)?;
        Ok((event, Some(result)))
    })();
    let cleanup = session.cmd(sensor, &db::MATCH_CLEANUP_REQUEST);
    let (event, result) = decision?;
    Ok(Decision {
        event,
        result,
        cleanup,
    })
}

fn storage(session: &mut Session, sensor: &Sensor) -> Result<db::UserStorage> {
    let response = session.cmd(sensor, &db::user_storage_request("StgWindsor"))?;
    let (status, payload) = proto::split_status(&response)?;
    ensure!(
        status == proto::STATUS_OK,
        "no StgWindsor storage (status {status:04x})"
    );
    db::parse_user_storage(payload)
}

/// The Linux uid (if the user record is Linux-owned) and fingers of a user
/// record; [`NotFound`] if there is no such record
fn user_record(
    session: &mut Session,
    sensor: &Sensor,
    user: u16,
) -> Result<(Option<u32>, Vec<db::Finger>)> {
    let response = session.cmd(sensor, &db::user_request(user))?;
    let (status, payload) = proto::split_status(&response)?;
    if status == db::STATUS_NOT_FOUND {
        return Err(NotFound.into());
    }
    ensure!(
        status == proto::STATUS_OK,
        "reading user record {user} failed with status {status:04x}"
    );
    let (dbid, fingers, identity) = db::parse_user(payload)?;
    ensure!(dbid == user, "asked for user record {user}, got {dbid}");
    Ok((db::linux_uid(&identity), fingers))
}

/// The user record for a Linux uid, if there is one
pub fn find_user(session: &mut Session, sensor: &Sensor, uid: u32) -> Result<Option<u16>> {
    let storage = storage(session, sensor)?;
    let request = db::user_by_identity_request(storage.dbid, &db::linux_identity(uid));
    let response = session.cmd(sensor, &request)?;
    let (status, payload) = proto::split_status(&response)?;
    match status {
        db::STATUS_NOT_FOUND => Ok(None),
        proto::STATUS_OK => Ok(Some(db::parse_user_fingers(payload)?.0)),
        other => bail!("looking up uid {uid}'s user record failed with status {other:04x}"),
    }
}

/// A database write as python-validity's `new_record`: unlock, the request,
/// then the commit (always). Returns the request's response payload.
fn write(session: &mut Session, sensor: &Sensor, request: &[u8]) -> Result<Vec<u8>> {
    session
        .cmd_ok(sensor, &blobs::DB_WRITE_ENABLE)
        .context("db_write_enable; nothing was written")?;
    let response = session.cmd(sensor, request);
    let commit = session.cmd(sensor, &db::COMMIT_REQUEST);
    let response = response?;
    let (status, payload) = proto::split_status(&response)?;
    let commit = proto::split_status(&commit?)?.0;
    ensure!(
        status == proto::STATUS_OK,
        "the sensor refused the write (status {status:04x})"
    );
    ensure!(
        [proto::STATUS_OK, db::STATUS_NOTHING_TO_COMMIT].contains(&commit),
        "commit failed with status {commit:04x}"
    );
    Ok(payload.to_vec())
}

fn new_dbid(payload: &[u8]) -> Result<u16> {
    ensure!(payload.len() >= 2, "no record id in the response");
    Ok(u16::from_le_bytes([payload[0], payload[1]]))
}

/// Deletes one record: python-validity's `del_record` (0x48 alone), then a
/// commit, which answers "nothing to commit" if 0x48 needs none. Verified
/// 2026-10-21 (run 83d7c562): the record is gone in a fresh session. The
/// space is not freed: `free` stays put until the flash is compacted.
/// The Windows driver has no compaction command either (its firmware-command
/// table, `synaWudfBioUsb.dll` 0x180113588, has none), so the firmware may
/// compact by itself when a write needs room. Unverified.
/// shortcut: deletes may never make room; watch `free` and stop testing before the database fills
fn delete_record(session: &mut Session, sensor: &Sensor, dbid: u16) -> Result<()> {
    let response = session.cmd(sensor, &db::delete_request(dbid))?;
    let commit = session.cmd(sensor, &db::COMMIT_REQUEST)?;
    let status = proto::split_status(&response)?.0;
    ensure!(
        status == proto::STATUS_OK,
        "deleting record {dbid} failed with status {status:04x}"
    );
    let commit = proto::split_status(&commit)?.0;
    ensure!(
        [proto::STATUS_OK, db::STATUS_NOTHING_TO_COMMIT].contains(&commit),
        "commit after deleting record {dbid} failed with status {commit:04x}"
    );
    Ok(())
}

/// uid's user record, created on first use
fn user_for(session: &mut Session, sensor: &Sensor, uid: u32) -> Result<u16> {
    if let Some(user) = find_user(session, sensor, uid)? {
        return Ok(user);
    }
    let storage = storage(session, sensor)?;
    let request = db::new_user_request(storage.dbid, &db::linux_identity(uid));
    let user = new_dbid(&write(session, sensor, &request)?)?;
    ensure!(
        find_user(session, sensor, uid)? == Some(user),
        "the new user record {user} is not found by its identity"
    );
    Ok(user)
}

/// Stores an envelope as a finger record under `user`
fn store(session: &mut Session, sensor: &Sensor, user: u16, envelope: &[u8]) -> Result<()> {
    let storage = storage(session, sensor)?;
    let request = db::new_record_request(user, moh::FINGER_KIND, storage.dbid, envelope, &[0]);
    new_dbid(&write(session, sensor, &request)?).map(drop)
}

fn free_space(session: &mut Session, sensor: &Sensor) -> Result<u32> {
    Ok(db::parse_info(&session.cmd_ok(sensor, &db::info_request())?)?.free)
}

/// Builds the template from enroll-mode frames and stores it as the finger
/// `subtype` of uid's user record, creating the record on first use. A
/// finger already stored there with the same subtype is the old copy of this
/// finger, so it is replaced.
pub fn enroll(
    session: &mut Session,
    sensor: &Sensor,
    uid: u32,
    subtype: u16,
    frames: &[moh::Frame],
) -> Result<Print> {
    ensure!(
        (1..=10).contains(&subtype),
        "finger position {subtype} is not a WinBio position"
    );
    let envelope = moh::template(frames, subtype);
    if (free_space(session, sensor)? as usize) < envelope.len() + 4096 {
        return Err(DataFull.into());
    }
    let user = user_for(session, sensor, uid)?;
    let (_, fingers) = user_record(session, sensor, user)?;
    for old in fingers.iter().filter(|f| f.subtype == subtype) {
        delete_record(session, sensor, old.dbid)?;
    }
    store(session, sensor, user, &envelope)?;
    Ok(Print { uid, subtype })
}

/// The chip's match of the last identify-mode scan, against uid's user
/// record only, or every user with None. Returns the matched print if the
/// finger is a Linux-owned one; a match of anything else is no match.
pub fn identify(session: &mut Session, sensor: &Sensor, uid: Option<u32>) -> Result<Option<Print>> {
    let user = match uid {
        Some(uid) => match find_user(session, sensor, uid)? {
            Some(user) => user,
            None => return Ok(None),
        },
        None => 0,
    };
    let Some(result) = chip_match(session, sensor, user)?.result else {
        return Ok(None);
    };
    let user = u16::try_from(result.user).context("matched user record id out of range")?;
    Ok(user_record(session, sensor, user)?.0.map(|uid| Print {
        uid,
        subtype: result.subtype,
    }))
}

/// Every finger under a Linux-owned user record
pub fn list(session: &mut Session, sensor: &Sensor) -> Result<Vec<Print>> {
    let mut prints = Vec::new();
    for (user, _) in storage(session, sensor)?.users {
        if let (Some(uid), fingers) = user_record(session, sensor, user)? {
            prints.extend(fingers.iter().map(|f| Print {
                uid,
                subtype: f.subtype,
            }));
        }
    }
    Ok(prints)
}

/// Deletes a stored finger; the user record goes too once it is empty.
/// [`NotFound`] if the uid has no user record or no finger with that subtype.
pub fn delete(session: &mut Session, sensor: &Sensor, print: &Print) -> Result<()> {
    let user = find_user(session, sensor, print.uid)?.ok_or(NotFound)?;
    let (_, fingers) = user_record(session, sensor, user)?;
    let finger = fingers
        .iter()
        .find(|f| f.subtype == print.subtype)
        .ok_or(NotFound)?;
    delete_record(session, sensor, finger.dbid)?;
    if fingers.len() == 1 {
        delete_record(session, sensor, user)?;
    }
    Ok(())
}

/// `0x3f`, python-validity's `erase_flash`: erases one flash partition.
/// Partition 4 holds the template database.
const ERASE_TEMPLATE_PARTITION: [u8; 2] = [0x3f, 4];

/// What [`compact`] did
pub struct Compacted {
    pub kept: Vec<Print>,
    pub free_before: u32,
    pub free_after: u32,
}

/// Reads every Linux-owned template back off the sensor (in memory only)
/// and rebuilds each envelope byte-exactly; fails before anything is written
/// if one can't be read or doesn't check out
pub fn saved_templates(session: &mut Session, sensor: &Sensor) -> Result<Vec<(Print, Vec<u8>)>> {
    let mut saved = Vec::new();
    for (user, _) in storage(session, sensor)?.users {
        if let (Some(uid), fingers) = user_record(session, sensor, user)? {
            for finger in fingers {
                let response = session.cmd_ok(sensor, &db::value_request(finger.dbid))?;
                let (_, value) = db::parse_value(&response)?;
                let envelope = moh::envelope_from_stored(finger.subtype, &value)
                    .with_context(|| format!("finger record {}", finger.dbid))?;
                let subtype = finger.subtype;
                saved.push((Print { uid, subtype }, envelope));
            }
        }
    }
    Ok(saved)
}

/// Reclaims the database's space, which deletes never free: saves the
/// Linux-owned templates in memory, erases the template partition (which
/// also drops every record Linux didn't create), recreates the user storage
/// and the Linux users, and stores the templates again. If it fails after the
/// erase, the templates are lost and the fingers need enrolling again.
pub fn compact(session: &mut Session, sensor: &Sensor) -> Result<Compacted> {
    let free_before = free_space(session, sensor)?;
    let saved = saved_templates(session, sensor)?;
    write(session, sensor, &ERASE_TEMPLATE_PARTITION).context("erasing the template partition")?;
    if storage(session, sensor).is_err() {
        // python-validity's new_user_storate
        let request = db::new_record_request(1, 4, 3, b"StgWindsor\0", &[]);
        write(session, sensor, &request).context("recreating the user storage")?;
    }
    for (print, envelope) in &saved {
        let user = user_for(session, sensor, print.uid)?;
        store(session, sensor, user, envelope)?;
    }
    let kept = list(session, sensor)?;
    ensure!(
        saved.iter().all(|(print, _)| kept.contains(print)),
        "not every template came back after the erase"
    );
    Ok(Compacted {
        kept,
        free_before,
        free_after: free_space(session, sensor)?,
    })
}
