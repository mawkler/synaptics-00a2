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

/// A finger the driver stored
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stored {
    /// The Linux uid in the user record's SID
    pub uid: u32,
    /// The user record's dbid
    pub user: u16,
    /// The finger record's dbid
    pub finger: u16,
    /// WinBio finger position (1..=10)
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
) -> Result<Stored> {
    ensure!(
        (1..=10).contains(&subtype),
        "finger position {subtype} is not a WinBio position"
    );
    let envelope = moh::template(frames, subtype);
    let info = db::parse_info(&session.cmd_ok(sensor, &db::info_request())?)?;
    if (info.free as usize) < envelope.len() + 4096 {
        return Err(DataFull.into());
    }
    let user = match find_user(session, sensor, uid)? {
        Some(user) => user,
        None => {
            let storage = storage(session, sensor)?;
            let identity = db::linux_identity(uid);
            let user = new_dbid(&write(
                session,
                sensor,
                &db::new_user_request(storage.dbid, &identity),
            )?)?;
            ensure!(
                find_user(session, sensor, uid)? == Some(user),
                "the new user record {user} is not found by its identity"
            );
            user
        }
    };
    let (_, fingers) = user_record(session, sensor, user)?;
    for old in fingers.iter().filter(|f| f.subtype == subtype) {
        delete_record(session, sensor, old.dbid)?;
    }
    let storage = storage(session, sensor)?;
    let request = db::new_record_request(user, moh::FINGER_KIND, storage.dbid, &envelope, &[0]);
    let finger = new_dbid(&write(session, sensor, &request)?)?;
    Ok(Stored {
        uid,
        user,
        finger,
        subtype,
    })
}

/// Every finger under a Linux-owned user record
pub fn list(session: &mut Session, sensor: &Sensor) -> Result<Vec<Stored>> {
    let mut prints = Vec::new();
    for (user, _) in storage(session, sensor)?.users {
        if let (Some(uid), fingers) = user_record(session, sensor, user)? {
            prints.extend(fingers.iter().map(|f| Stored {
                uid,
                user,
                finger: f.dbid,
                subtype: f.subtype,
            }));
        }
    }
    Ok(prints)
}

/// Deletes a stored finger after re-reading it: the user record must still
/// be the print's Linux uid and hold that finger. An emptied user record is
/// deleted too. [`NotFound`] if the print isn't there.
pub fn delete(session: &mut Session, sensor: &Sensor, print: &Stored) -> Result<()> {
    let (uid, fingers) = user_record(session, sensor, print.user)?;
    if uid != Some(print.uid)
        || !fingers
            .iter()
            .any(|f| f.dbid == print.finger && f.subtype == print.subtype)
    {
        return Err(NotFound.into());
    }
    delete_record(session, sensor, print.finger)?;
    if fingers.len() == 1 {
        delete_record(session, sensor, print.user)?;
    }
    Ok(())
}
