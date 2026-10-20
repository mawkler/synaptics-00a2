// SPDX-License-Identifier: LGPL-2.1-or-later
//! The sensor's template database (flash partition 4), following
//! python-validity's `validitysensor/db.py` and `sensor.py`. Only reads and
//! the on-chip identify so far: 0x45 info, 0x46 record children, 0x49 record
//! value, 0x4a user, 0x4b user storage; 0x5e/0x60/0x62 match. Responses are
//! TLS payloads with the status already stripped.

use anyhow::{ensure, Result};
use serde::Serialize;

/// `0x4b` status when no storage has the name asked for
pub const STATUS_NOT_FOUND: u16 = 0x04b3;

/// Record types python-validity uses
pub fn kind_name(kind: u16) -> &'static str {
    match kind {
        4 => "user storage",
        5 => "user",
        6 => "finger (MoH template)",
        8 => "data",
        0xb => "finger",
        _ => "unknown",
    }
}

fn u16_at(p: &[u8], at: usize) -> Result<u16> {
    ensure!(p.len() >= at + 2, "database response truncated");
    Ok(u16::from_le_bytes([p[at], p[at + 1]]))
}

fn u32_at(p: &[u8], at: usize) -> Result<u32> {
    ensure!(p.len() >= at + 4, "database response truncated");
    Ok(u32::from_le_bytes(p[at..at + 4].try_into()?))
}

#[derive(Debug, PartialEq, Serialize)]
pub struct Info {
    /// python-validity: "seems to always be" 1 and 0
    pub unknown: [u32; 2],
    pub total: u32,
    pub used: u32,
    pub free: u32,
    /// Including deleted ones
    pub records: u16,
    pub roots: Vec<u16>,
}

pub fn info_request() -> Vec<u8> {
    vec![0x45]
}

/// `<LLLLLHH`, then the root ids
pub fn parse_info(p: &[u8]) -> Result<Info> {
    let count = u16_at(p, 22)? as usize;
    let roots = (0..count)
        .map(|i| u16_at(p, 24 + 2 * i))
        .collect::<Result<_>>()?;
    Ok(Info {
        unknown: [u32_at(p, 0)?, u32_at(p, 4)?],
        total: u32_at(p, 8)?,
        used: u32_at(p, 12)?,
        free: u32_at(p, 16)?,
        records: u16_at(p, 20)?,
        roots,
    })
}

#[derive(Debug, PartialEq, Serialize)]
pub struct Child {
    pub dbid: u16,
    pub kind: u16,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct Children {
    pub dbid: u16,
    pub kind: u16,
    pub storage: u16,
    pub value_size: u16,
    pub children: Vec<Child>,
}

pub fn children_request(dbid: u16) -> Vec<u8> {
    let mut request = vec![0x46];
    request.extend(dbid.to_le_bytes());
    request
}

/// dbid, type, storage, value size, child count, 2 unknown bytes, then
/// (dbid, type) per child
pub fn parse_children(p: &[u8]) -> Result<Children> {
    let count = u16_at(p, 8)? as usize;
    let children = (0..count)
        .map(|i| {
            Ok(Child {
                dbid: u16_at(p, 12 + 4 * i)?,
                kind: u16_at(p, 14 + 4 * i)?,
            })
        })
        .collect::<Result<_>>()?;
    Ok(Children {
        dbid: u16_at(p, 0)?,
        kind: u16_at(p, 2)?,
        storage: u16_at(p, 4)?,
        value_size: u16_at(p, 6)?,
        children,
    })
}

pub fn value_request(dbid: u16) -> Vec<u8> {
    let mut request = vec![0x49];
    request.extend(dbid.to_le_bytes());
    request
}

/// dbid, type, storage, value size, 2 unknown bytes, then the value
pub fn parse_value(p: &[u8]) -> Result<(u16, Vec<u8>)> {
    let size = u16_at(p, 6)? as usize;
    ensure!(p.len() >= 10 + size, "record value truncated");
    Ok((u16_at(p, 2)?, p[10..10 + size].to_vec()))
}

#[derive(Debug, PartialEq, Serialize)]
pub struct UserStorage {
    pub dbid: u16,
    pub name: String,
    /// (user dbid, value size)
    pub users: Vec<(u16, u16)>,
}

pub fn user_storage_request(name: &str) -> Vec<u8> {
    let mut name = name.as_bytes().to_vec();
    if !name.is_empty() {
        name.push(0);
    }
    let mut request = vec![0x4b, 0, 0];
    request.extend((name.len() as u16).to_le_bytes());
    request.extend(name);
    request
}

/// dbid, user count, name size, 2 unknown bytes, (dbid, value size) per user,
/// then the name
pub fn parse_user_storage(p: &[u8]) -> Result<UserStorage> {
    let (count, name_size) = (u16_at(p, 2)? as usize, u16_at(p, 4)? as usize);
    let users = (0..count)
        .map(|i| Ok((u16_at(p, 8 + 4 * i)?, u16_at(p, 10 + 4 * i)?)))
        .collect::<Result<_>>()?;
    let at = 8 + 4 * count;
    ensure!(
        p.len() == at + name_size,
        "unexpected bytes after the storage name"
    );
    let name = String::from_utf8_lossy(&p[at..])
        .trim_end_matches('\0')
        .to_owned();
    Ok(UserStorage {
        dbid: u16_at(p, 0)?,
        name,
        users,
    })
}

#[derive(Debug, PartialEq, Serialize)]
pub struct Finger {
    pub dbid: u16,
    pub subtype: u16,
    pub storage: u16,
    pub value_size: u16,
}

/// `0x4a` by dbid: `<BHHH`, dbid, then two zeros (no identity search)
pub fn user_request(dbid: u16) -> Vec<u8> {
    let mut request = vec![0x4a];
    request.extend(dbid.to_le_bytes());
    request.extend([0; 4]);
    request
}

/// dbid, finger count, 2 unknown bytes, identity size, (dbid, subtype,
/// storage, value size) per finger, then the identity, which is skipped:
/// it is the Windows account's SID
pub fn parse_user_fingers(p: &[u8]) -> Result<(u16, Vec<Finger>)> {
    let count = u16_at(p, 2)? as usize;
    let identity_size = u16_at(p, 6)? as usize;
    ensure!(
        p.len() == 8 + 8 * count + identity_size,
        "unexpected user record length"
    );
    let fingers = (0..count)
        .map(|i| {
            let at = 8 + 8 * i;
            Ok(Finger {
                dbid: u16_at(p, at)?,
                subtype: u16_at(p, at + 2)?,
                storage: u16_at(p, at + 4)?,
                value_size: u16_at(p, at + 6)?,
            })
        })
        .collect::<Result<_>>()?;
    Ok((u16_at(p, 0)?, fingers))
}

/// Finger names for WinBio subtypes (python-validity's fingerprint_constants)
pub fn subtype_name(subtype: u16) -> String {
    const NAMES: [&str; 10] = [
        "right thumb",
        "right index",
        "right middle",
        "right ring",
        "right little",
        "left thumb",
        "left index",
        "left middle",
        "left ring",
        "left little",
    ];
    match subtype {
        1..=10 => NAMES[subtype as usize - 1].to_owned(),
        0xf5..=0xfe => format!("unspecified position {}", subtype - 0xf4),
        _ => format!("unknown ({subtype:#x})"),
    }
}

/// `0x47` new record, `<BHHHH`: parent, type, storage, value size, then the
/// value and an uncounted trailer (python-validity's MoH finger store sends
/// one 0x00 byte). Must follow the `db_write_enable` blob; the response
/// payload is the new record's dbid.
pub fn new_record_request(
    parent: u16,
    kind: u16,
    storage: u16,
    value: &[u8],
    trailer: &[u8],
) -> Vec<u8> {
    let mut request = vec![0x47];
    for field in [parent, kind, storage, value.len() as u16] {
        request.extend(field.to_le_bytes());
    }
    request.extend(value);
    request.extend(trailer);
    request
}

/// Record type of a user under a storage
pub const USER_KIND: u16 = 5;
/// Sub-authorities every Linux-owned user's SID starts with (see
/// `docs/on-chip-driver.md`); the Linux uid follows
pub const LINUX_SID_PREFIX: [u32; 4] = [21, 111_111_111, 1_111_111_111, 1_111_111_111];

/// The identity value of a user record, as python-validity's
/// `identity_to_bytes(SidIdentity(1, 5, LINUX_SID_PREFIX + [uid]))`: type 3,
/// the SID's length, the SID (revision 1, authority 5), zero-padded to 0x4c
/// bytes because the chip treats the same SID at different sizes as different
/// keys
pub fn linux_identity(uid: u32) -> Vec<u8> {
    let sub: Vec<u32> = LINUX_SID_PREFIX.iter().copied().chain([uid]).collect();
    let mut sid = vec![1, sub.len() as u8, 0, 0, 0, 0, 0, 5];
    for s in sub {
        sid.extend(s.to_le_bytes());
    }
    let mut value = Vec::from(3u32.to_le_bytes());
    value.extend((sid.len() as u32).to_le_bytes());
    value.extend(sid);
    value.resize(0x4c, 0);
    value
}

/// `0x4a` by identity: `<BHHH`, 0, the storage's dbid, the identity's size,
/// then the identity. Status 0x04b3 (not found) when no user has it.
pub fn user_by_identity_request(storage: u16, identity: &[u8]) -> Vec<u8> {
    let mut request = vec![0x4a, 0, 0];
    request.extend(storage.to_le_bytes());
    request.extend((identity.len() as u16).to_le_bytes());
    request.extend(identity);
    request
}

/// `0x47` for a new user record under the user storage: parent and storage
/// are both the storage's dbid, no trailer
pub fn new_user_request(storage: u16, identity: &[u8]) -> Vec<u8> {
    new_record_request(storage, USER_KIND, storage, identity, &[])
}

/// `0x1a` (python-validity's `call_cleanups`), sent after every write
pub const COMMIT_REQUEST: [u8; 1] = [0x1a];
/// `0x1a` status when there is nothing to commit, which is not an error
pub const STATUS_NOTHING_TO_COMMIT: u16 = 0x0491;

/// Starts an on-chip identify of the last scan against every storage and
/// user: `<BBBHHHHH` 0x5e, 2, 0xff, storage 0, user 0, 1, 0, 0
pub const MATCH_REQUEST: [u8; 13] = [0x5e, 0x02, 0xff, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0];
/// [`MATCH_REQUEST`] restricted to one user record id (0 = every user). The
/// Windows driver's builder (`FUN_180085df0`) lays the command out as: mode,
/// 0xff, storage u16, user u16, a u16 (1), then a u32 payload length and the
/// payload. Whether the chip honours the user field is an open question.
pub fn match_request(user: u16) -> [u8; 13] {
    let mut request = MATCH_REQUEST;
    request[5..7].copy_from_slice(&user.to_le_bytes());
    request
}

/// Fetches the match result after the "recognised" event
pub const MATCH_RESULT_REQUEST: [u8; 5] = [0x60, 0, 0, 0, 0];
/// Ends the identify; python-validity always sends it and ignores errors
pub const MATCH_CLEANUP_REQUEST: [u8; 5] = [0x62, 0, 0, 0, 0];
/// First byte of the event that reports a recognised finger
pub const EVENT_RECOGNISED: u8 = 3;

#[derive(Debug, PartialEq, Serialize)]
pub struct MatchResult {
    pub user: u32,
    pub subtype: u16,
    /// The template's identify hash, a stable per-enrollment id
    pub hash: String,
}

/// u16 length, then (u16 tag, u16 length, value) entries: 1 user, 3 subtype, 4 hash
pub fn parse_match_result(p: &[u8]) -> Result<MatchResult> {
    let len = u16_at(p, 0)? as usize;
    ensure!(p.len() == 2 + len, "match result length mismatch");
    let mut entries = std::collections::BTreeMap::new();
    let mut at = 2;
    while at < p.len() {
        let (tag, size) = (u16_at(p, at)?, u16_at(p, at + 2)? as usize);
        ensure!(p.len() >= at + 4 + size, "match result entry overruns");
        entries.insert(tag, &p[at + 4..at + 4 + size]);
        at += 4 + size;
    }
    let field = |tag: u16| {
        entries
            .get(&tag)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("match result has no field {tag}"))
    };
    let user = field(1)?;
    let subtype = field(3)?;
    ensure!(
        user.len() == 4 && subtype.len() == 2,
        "unexpected match result field sizes"
    );
    Ok(MatchResult {
        user: u32::from_le_bytes(user.try_into()?),
        subtype: u16::from_le_bytes(subtype.try_into()?),
        hash: field(4)?.iter().map(|b| format!("{b:02x}")).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn requests_match_python_validity() {
        assert_eq!(children_request(3), [0x46, 3, 0]);
        assert_eq!(value_request(0x102), [0x49, 2, 1]);
        // pack('<BHH', 0x4b, 0, len(b'StgWindsor\0')) + b'StgWindsor\0'
        assert_eq!(
            user_storage_request("StgWindsor"),
            [&unhex("4b00000b00")[..], b"StgWindsor\0"].concat()
        );
        assert_eq!(user_storage_request(""), unhex("4b00000000"));
    }

    #[test]
    fn new_record_matches_python_validity() {
        // pack('<BHHHH', 0x47, 5, 6, 3, 4) + data + b'\x00'
        assert_eq!(
            new_record_request(5, 6, 3, &[1, 2, 3, 4], &[0]),
            unhex("47 0500 0600 0300 0400 01020304 00")
        );
    }

    #[test]
    fn linux_identity_matches_python_validity() {
        // identity_to_bytes(sid_from_string("S-1-5-21-111111111-1111111111-1111111111-90001"))
        let want = unhex(
            "030000001c000000010500000000000515000000c76b9f06c7353a42c7353a42915f0100\
             00000000000000000000000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(want.len(), 0x4c);
        assert_eq!(linux_identity(90001), want);
        assert_ne!(linux_identity(90001), linux_identity(90002));
        let request = new_user_request(3, &want);
        assert_eq!(request[..9], unhex("47 0300 0500 0300 4c00")[..9]);
        assert_eq!(request.len(), 9 + 0x4c);
        assert_eq!(
            user_by_identity_request(3, &want)[..7],
            unhex("4a 00 00 0300 4c00")[..7]
        );
    }

    #[test]
    fn match_requests_match_python_validity() {
        // pack('<BBBHHHHH', 0x5e, 2, 0xff, 0, 0, 1, 0, 0)
        assert_eq!(
            MATCH_REQUEST.to_vec(),
            unhex("5e02ff 0000 0000 0100 0000 0000")
        );
        assert_eq!(match_request(0), MATCH_REQUEST);
        assert_eq!(
            match_request(5).to_vec(),
            unhex("5e02ff 0000 0500 0100 0000 0000")
        );
        assert_eq!(user_request(5), unhex("4a 0500 0000 0000"));
    }

    #[test]
    fn parses_users_and_match_results() {
        let p = [
            &unhex("0500 0100 0000 0400 0600 f500 0300 c85a")[..],
            &[0xaa; 4],
        ]
        .concat();
        let (dbid, fingers) = parse_user_fingers(&p).unwrap();
        assert_eq!(dbid, 5);
        assert_eq!(
            fingers,
            [Finger {
                dbid: 6,
                subtype: 0xf5,
                storage: 3,
                value_size: 0x5ac8
            }]
        );
        assert!(parse_user_fingers(&p[..p.len() - 1]).is_err());
        assert_eq!(subtype_name(0xf5), "unspecified position 1");
        assert_eq!(subtype_name(2), "right index");

        let result = parse_match_result(&unhex(
            "1400 0100 0400 05000000 0300 0200 f500 0400 0200 abcd",
        ))
        .unwrap();
        assert_eq!(
            result,
            MatchResult {
                user: 5,
                subtype: 0xf5,
                hash: "abcd".into()
            }
        );
        assert!(parse_match_result(&unhex("0400 0100 0400")).is_err());
    }

    #[test]
    fn parses_synthetic_responses() {
        let info = parse_info(&unhex(
            "01000000 00000000 00000800 00100000 00f00700 0500 0200 0100 0300",
        ))
        .unwrap();
        assert_eq!(
            (info.total, info.used, info.free, info.records),
            (0x80000, 0x1000, 0x7f000, 5)
        );
        assert_eq!(info.roots, [1, 3]);

        let children =
            parse_children(&unhex("0300 0400 0300 0b00 0200 0000 0400 0500 0700 0600")).unwrap();
        assert_eq!(
            (
                children.dbid,
                children.kind,
                children.storage,
                children.value_size
            ),
            (3, 4, 3, 11)
        );
        assert_eq!(
            children.children,
            [Child { dbid: 4, kind: 5 }, Child { dbid: 7, kind: 6 }]
        );

        let (kind, value) =
            parse_value(&[&unhex("0300 0400 0300 0b00 0000")[..], b"StgWindsor\0"].concat())
                .unwrap();
        assert_eq!((kind, value.as_slice()), (4, &b"StgWindsor\0"[..]));
        assert!(parse_value(&unhex("0300 0400 0300 0b00 0000 00")).is_err());

        let storage = parse_user_storage(
            &[&unhex("0300 0100 0b00 0000 0400 4c00")[..], b"StgWindsor\0"].concat(),
        )
        .unwrap();
        assert_eq!(
            storage,
            UserStorage {
                dbid: 3,
                name: "StgWindsor".into(),
                users: vec![(4, 0x4c)]
            }
        );
    }
}
