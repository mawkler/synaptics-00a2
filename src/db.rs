// SPDX-License-Identifier: LGPL-2.1-or-later
//! The sensor's template database (flash partition 4), following
//! python-validity's `validitysensor/db.py`. Only the read commands so far:
//! 0x45 info, 0x46 record children, 0x49 record value, 0x4b user storage.
//! Responses are TLS payloads with the status already stripped.

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
