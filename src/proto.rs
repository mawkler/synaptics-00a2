// SPDX-License-Identifier: LGPL-2.1-or-later
//! VCSFW command responses: a little-endian u16 status, then the payload.
//! Layouts follow python-validity (`validitysensor/{sensor,flash}.py`).

use anyhow::{ensure, Result};
use serde::Serialize;

pub const STATUS_OK: u16 = 0x0000;
/// `0x43` status when the partition holds no firmware
pub const STATUS_NO_FW: u16 = 0x04b0;

pub fn split_status(rsp: &[u8]) -> Result<(u16, &[u8])> {
    ensure!(
        rsp.len() >= 2,
        "response shorter than its status: {} bytes",
        rsp.len()
    );
    Ok((u16::from_le_bytes([rsp[0], rsp[1]]), &rsp[2..]))
}

/// `0x40` request, `<BBBHLL`: partition, a constant 1, a zero u16, address, size
pub fn read_flash_request(partition: u8, address: u32, size: u32) -> Vec<u8> {
    let mut request = vec![0x40, partition, 1, 0, 0];
    request.extend(address.to_le_bytes());
    request.extend(size.to_le_bytes());
    request
}

/// `0x40` response: a u32 length, two unknown bytes, then the data
pub fn read_flash_data(payload: &[u8]) -> Result<&[u8]> {
    let mut r = Le(payload);
    let size = r.u32()? as usize;
    r.take(2)?;
    r.take(size)
}

/// `0x6f` request, `<BHHL`: tag, then zeros
pub fn factory_bits_request(tag: u16) -> Vec<u8> {
    let mut request = vec![0x6f];
    request.extend(tag.to_le_bytes());
    request.extend([0; 6]);
    request
}

/// `0x6f` response: a u32 of unknown meaning, a u32 entry count, then entries
/// of `<LHHHH` (pointer, length, tag, subtag, flags) and a value. Keyed by subtag.
pub fn parse_factory_bits(payload: &[u8]) -> Result<std::collections::BTreeMap<u16, Vec<u8>>> {
    let mut r = Le(payload);
    r.u32()?;
    let count = r.u32()?;
    let mut entries = std::collections::BTreeMap::new();
    for _ in 0..count {
        let (_pointer, len, _tag, subtag, _flags) =
            (r.u32()?, r.u16()?, r.u16()?, r.u16()?, r.u16()?);
        entries.insert(subtag, r.take(len as usize)?.to_vec());
    }
    ensure!(
        r.0.is_empty(),
        "{} bytes of garbage after the factory bits",
        r.0.len()
    );
    Ok(entries)
}

/// `get_prg_status2`: fetches the next part of a finished scan's result
pub const SCAN_RESULT_REQUEST: [u8; 5] = [0x51, 0x00, 0x20, 0x00, 0x00];

/// A `0x51` response payload: a u32 length, then that many bytes
pub fn scan_result_data(payload: &[u8]) -> Result<&[u8]> {
    let mut r = Le(payload);
    let len = r.u32()? as usize;
    ensure!(
        r.0.len() == len,
        "scan result says {len} bytes but carries {}",
        r.0.len()
    );
    Ok(r.0)
}

/// Little-endian cursor over a payload
struct Le<'a>(&'a [u8]);

impl<'a> Le<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(
            self.0.len() >= n,
            "payload truncated: wanted {n} more bytes, have {}",
            self.0.len()
        );
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }
}

/// `0x01` response, `<LLBBxBxxxB`
#[derive(Debug, PartialEq, Serialize)]
pub struct RomInfo {
    pub timestamp: u32,
    pub build: u32,
    pub major: u8,
    pub minor: u8,
    pub product: u8,
    pub unknown1: u8,
}

impl RomInfo {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut r = Le(payload);
        let (timestamp, build, major, minor) = (r.u32()?, r.u32()?, r.u8()?, r.u8()?);
        r.take(1)?;
        let product = r.u8()?;
        r.take(3)?;
        Ok(Self {
            timestamp,
            build,
            major,
            minor,
            product,
            unknown1: r.u8()?,
        })
    }
}

/// `0x75` response, `<LHH`: a zero word, then the pair python-validity looks up
/// in `hw_tables.dev_info_table`
#[derive(Debug, PartialEq, Serialize)]
pub struct SensorId {
    pub major: u16,
    pub minor: u16,
}

impl SensorId {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut r = Le(payload);
        let zero = r.u32()?;
        ensure!(zero == 0, "expected a zero word, got {zero:#x}");
        let minor = r.u16()?;
        Ok(Self {
            major: r.u16()?,
            minor,
        })
    }
}

/// One `<BBHLL` entry of the `0x3e` partition table
#[derive(Debug, PartialEq, Serialize)]
pub struct Partition {
    pub id: u8,
    pub kind: u8,
    pub access_level: u16,
    pub offset: u32,
    pub size: u32,
}

/// `0x3e` response: seven u16s, then the partition table
#[derive(Debug, PartialEq, Serialize)]
pub struct FlashInfo {
    pub jedec_id: [u16; 2],
    pub blocks: u16,
    pub unknown0: u16,
    pub block_size: u16,
    pub unknown1: u16,
    pub partitions: Vec<Partition>,
}

impl FlashInfo {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut r = Le(payload);
        let jedec_id = [r.u16()?, r.u16()?];
        let (blocks, unknown0, block_size, unknown1) = (r.u16()?, r.u16()?, r.u16()?, r.u16()?);
        let count = r.u16()?;
        let partitions = (0..count)
            .map(|_| {
                Ok(Partition {
                    id: r.u8()?,
                    kind: r.u8()?,
                    access_level: r.u16()?,
                    offset: r.u32()?,
                    size: r.u32()?,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            jedec_id,
            blocks,
            unknown0,
            block_size,
            unknown1,
            partitions,
        })
    }
}

/// One `<HHHHL` module entry of a `0x43` firmware header
#[derive(Debug, PartialEq, Serialize)]
pub struct Module {
    pub kind: u16,
    pub subtype: u16,
    pub major: u16,
    pub minor: u16,
    pub size: u32,
}

/// `0x43 <partition>` response: `<HHHL`, then the module table
#[derive(Debug, PartialEq, Serialize)]
pub struct FwInfo {
    pub major: u16,
    pub minor: u16,
    pub build_time: u32,
    pub modules: Vec<Module>,
}

impl FwInfo {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut r = Le(payload);
        let (major, minor, count, build_time) = (r.u16()?, r.u16()?, r.u16()?, r.u32()?);
        let modules = (0..count)
            .map(|_| {
                Ok(Module {
                    kind: r.u16()?,
                    subtype: r.u16()?,
                    major: r.u16()?,
                    minor: r.u16()?,
                    size: r.u32()?,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            major,
            minor,
            build_time,
            modules,
        })
    }
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
    fn status_is_little_endian() {
        assert_eq!(
            split_status(&unhex("b004")).unwrap(),
            (STATUS_NO_FW, &[][..])
        );
        assert_eq!(
            split_status(&unhex("0000 aa")).unwrap(),
            (STATUS_OK, &[0xaa][..])
        );
        assert!(split_status(&[0]).is_err());
    }

    #[test]
    fn read_flash_matches_python_validity() {
        // pack('<BBBHLL', 0x40, 1, 1, 0, 0, 0x1000)
        assert_eq!(
            read_flash_request(1, 0, 0x1000),
            unhex("40010100000000000000100000")
        );
        assert_eq!(
            read_flash_data(&unhex("03000000 0000 aabbcc dd")).unwrap(),
            [0xaa, 0xbb, 0xcc]
        );
        assert!(read_flash_data(&unhex("04000000 0000 aabbcc")).is_err());
    }

    #[test]
    fn factory_bits_are_keyed_by_subtag() {
        assert_eq!(factory_bits_request(0x0e00), unhex("6f000e000000000000"));
        let p = unhex(
            "880d0000 02000000
             08000000 0600 000e 0300 0080 07000000 7e7f
             14000000 0200 000e 0700 0080 aabb",
        );
        let bits = parse_factory_bits(&p).unwrap();
        assert_eq!(bits[&3], unhex("070000007e7f"));
        assert_eq!(bits[&7], [0xaa, 0xbb]);
        assert!(parse_factory_bits(&[p.as_slice(), &[0]].concat()).is_err());
        assert!(parse_factory_bits(&p[..p.len() - 1]).is_err());
    }

    #[test]
    fn scan_result_length_must_match() {
        assert_eq!(
            scan_result_data(&unhex("02000000 aabb")).unwrap(),
            [0xaa, 0xbb]
        );
        assert!(scan_result_data(&unhex("03000000 aabb")).is_err());
    }

    #[test]
    fn rom_info_skips_padding() {
        let p = unhex("44332211 a4000000 06 07 ff 33 ffffff 01");
        let rom = RomInfo::parse(&p).unwrap();
        assert_eq!(
            rom,
            RomInfo {
                timestamp: 0x11223344,
                build: 164,
                major: 6,
                minor: 7,
                product: 0x33,
                unknown1: 1
            }
        );
        assert!(RomInfo::parse(&p[..15]).is_err());
    }

    #[test]
    fn sensor_id_requires_zero_word() {
        assert_eq!(
            SensorId::parse(&unhex("00000000 4a00 9001")).unwrap(),
            SensorId {
                major: 0x0190,
                minor: 0x004a
            }
        );
        assert!(SensorId::parse(&unhex("01000000 4a00 9001")).is_err());
    }

    #[test]
    fn flash_info_reads_partition_table() {
        // python-validity's flash_layout_hardcoded, first two entries
        let p = unhex(
            "c220 1340 0001 0000 0010 0000 0200
             01 04 0700 00100000 00100000
             02 01 0200 00200000 00e00300",
        );
        let info = FlashInfo::parse(&p).unwrap();
        assert_eq!(info.jedec_id, [0x20c2, 0x4013]);
        assert_eq!((info.blocks, info.block_size), (0x100, 0x1000));
        assert_eq!(
            info.partitions[1],
            Partition {
                id: 2,
                kind: 1,
                access_level: 2,
                offset: 0x2000,
                size: 0x3e000
            }
        );
        assert!(FlashInfo::parse(&p[..p.len() - 1]).is_err());
    }

    #[test]
    fn fw_info_matches_python_validity_sample() {
        // `4302` response quoted in validitysensor/flash.py, status stripped
        let p = unhex(
            "0100 0100 0800 c28c745a
             0100 3446 0200 0700 d03e0000
             0100 8408 0100 0700 00040000
             0200 8428 0300 1200 e0100000
             0200 7636 0100 0c00 100a0000
             0100 8647 0000 0100 505a0000
             0200 2377 0000 0100 802f0000
             0200 6637 0100 0c00 f0220200
             0100 2556 0000 0100 60040000",
        );
        let fw = FwInfo::parse(&p).unwrap();
        assert_eq!((fw.major, fw.minor, fw.build_time), (1, 1, 0x5a748cc2));
        assert_eq!(fw.modules.len(), 8);
        assert_eq!(
            fw.modules[0],
            Module {
                kind: 1,
                subtype: 0x4634,
                major: 2,
                minor: 7,
                size: 0x3ed0
            }
        );
        assert_eq!(fw.modules[6].size, 0x222f0);
    }
}
