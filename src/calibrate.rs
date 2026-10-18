// SPDX-License-Identifier: LGPL-2.1-or-later
//! Calibration without a finger, following python-validity's `Sensor`
//! (`sensor.py`) for sensor type 0x199, which uses "line update type 1".
//! Unlike python-validity, this never writes the result ("clean slate") to
//! flash partition 6. It stays in memory and in private files.

use anyhow::{ensure, Context, Result};

use crate::{
    prog,
    tables::{
        BYTES_PER_LINE, CALIBRATION_BLOB, CAPTURE_PROGRAM, LINES_PER_CALIBRATION_DATA, LINE_WIDTH,
        REPEAT_MULTIPLIER,
    },
};

/// python-validity hardcodes these three for type 0x199
const KEY_CALIBRATION_LINE: usize = 0x38;
const CALIBRATION_FRAMES: usize = 3;
pub const ITERATIONS: usize = 3;

const REGISTER_8000203C: u32 = 0x8000_203c;

/// Partition 6 record python-validity writes: magic, length, the SHA-256 of
/// the rest, 32 zero bytes, then (u16 length, averaged blank frame, u16 0)
pub const CLEAN_SLATE_MAGIC: u16 = 0x5002;
pub const CLEAN_SLATE_HEADER: usize = 0x44;

pub struct Calibration {
    /// Factory bits 0x0e00, subtag 3, without its first 4 bytes
    factory: Vec<u8>,
    /// Accumulated, scaled scans: one line per calibration line
    pub data: Vec<u8>,
    lines_per_frame: usize,
}

fn clip(x: i32) -> u8 {
    x.clamp(-128, 127) as i8 as u8
}

/// "TODO: scaling factor depends on a device" in python-validity
fn scale(x: u8) -> u8 {
    clip((x as i32 - 0x80) * 10 / 0x22)
}

/// Packs values as (bits, minimum, data): each value minus the minimum in
/// `bits` bits, least significant first
fn bitpack(values: &[u8]) -> (u8, u8, Vec<u8>) {
    let min = values.iter().copied().min().unwrap_or(0);
    let max = values.iter().copied().max().unwrap_or(0);
    let bits = (u8::BITS - (max - min).leading_zeros()) as usize;
    let mut packed = vec![0u8; (bits * values.len()).div_ceil(8)];
    for (k, &value) in values.iter().enumerate() {
        for bit in 0..bits {
            if (value - min) >> bit & 1 == 1 {
                let at = k * bits + bit;
                packed[at / 8] |= 1 << (at % 8);
            }
        }
    }
    (bits as u8, min, packed)
}

struct Line {
    mask: u32,
    /// Bits 20..24 hold a count; lines with a count above 1 go in the
    /// transform chunk with their 4-byte header
    flags: u32,
    transform: [u8; 4],
    data: Vec<u8>,
}

impl Calibration {
    pub fn new(factory: Vec<u8>) -> Result<Self> {
        let (_, lines_2d) = prog::split_chunks(&CAPTURE_PROGRAM)?
            .into_iter()
            .find(|(kind, _)| *kind == prog::LINES_2D)
            .context("the capture program has no 2D lines chunk")?;
        let lines = u32::from_le_bytes(lines_2d[..4].try_into()?) as usize;
        Ok(Self {
            factory,
            data: Vec::new(),
            lines_per_frame: lines * REPEAT_MULTIPLIER,
        })
    }

    pub fn frame_size(&self) -> usize {
        self.lines_per_frame * BYTES_PER_LINE
    }

    fn key_line(&self) -> Vec<u8> {
        if self.data.is_empty() {
            return vec![0; LINE_WIDTH];
        }
        let at = 8 + self.data.len() / LINES_PER_CALIBRATION_DATA * KEY_CALIBRATION_LINE;
        self.data[at..at + LINE_WIDTH]
            .iter()
            .map(|&b| if b == 5 { 4 } else { b })
            .collect()
    }

    /// The `0x02` command for one calibration scan, python-validity's
    /// `build_cmd_02(CaptureMode.CALIBRATE)`
    pub fn command(&self) -> Result<Vec<u8>> {
        let mut chunks = prog::split_chunks(&CAPTURE_PROGRAM)?;
        let mut timeslots = None;
        for (kind, value) in &mut chunks {
            if *kind == prog::TIMESLOT_TABLE {
                let table = prog::patch_timeslot_table(value, true, REPEAT_MULTIPLIER as u8)?;
                *value = [self.key_line().as_slice(), &table[LINE_WIDTH..]].concat();
                timeslots = Some(table);
            }
        }
        let table = timeslots.context("the capture program has no timeslot table")?;
        chunks.push((0x17, Vec::new())); // reply configuration
        chunks.push((0x44, 1u32.to_le_bytes().to_vec())); // interleave

        let (bits, min, packed) = bitpack(&self.factory);
        ensure!(bits > 0, "the factory calibration values are all equal");
        let mut lines = vec![
            Line {
                mask: 0xff,
                flags: (prog::find_nth_insn(&table, prog::ENABLE_RX, 2)? as u32 + 1)
                    | 2 << 20
                    | 0x700_0000,
                transform: [0xf, 0, 0, 0],
                data: CALIBRATION_BLOB.to_vec(),
            },
            Line {
                mask: 0xff,
                flags: (prog::find_nth_regwrite(&table, REGISTER_8000203C, 1)? as u32 + 1)
                    | 3 << 20
                    | 0x700_0000,
                transform: [(bits - 1) | 8, min, 0, 0],
                data: packed,
            },
        ];
        if !self.data.is_empty() {
            let per_line = self.data.len() / LINES_PER_CALIBRATION_DATA;
            for i in (0..112).step_by(4) {
                let data = (0..112)
                    .flat_map(|j| self.data[8 + j * per_line + i..][..4].to_vec())
                    .collect();
                lines.push(Line {
                    mask: 0xffff_ffff,
                    flags: i as u32 | 0x85 << 24,
                    transform: [0; 4],
                    data,
                });
            }
        }
        for line in &mut lines {
            line.data.resize(line.data.len().next_multiple_of(4), 0);
        }

        let transformed = |line: &&Line| (line.flags >> 20) & 0xf > 1;
        let mut update = (lines.len() as u32).to_le_bytes().to_vec();
        for line in &lines {
            update.extend(line.mask.to_le_bytes());
            update.extend(line.flags.to_le_bytes());
        }
        for line in lines.iter().filter(|l| !transformed(l)) {
            update.extend(&line.data);
        }
        chunks.push((0x30, update)); // line update
        let mut transform = Vec::new();
        for line in lines.iter().filter(transformed) {
            transform.extend(line.transform);
            transform.extend(&line.data);
        }
        chunks.push((0x43, transform)); // line update transform

        let requested_lines = (CALIBRATION_FRAMES * self.lines_per_frame + 1) as u16;
        let mut command = vec![2];
        command.extend((BYTES_PER_LINE as u16).to_le_bytes());
        command.extend(requested_lines.to_le_bytes());
        command.extend(prog::merge_chunks(&chunks));
        Ok(command)
    }

    /// Reduces a raw calibration scan to one line per calibration line: skips
    /// the first frame, then averages each group of interleaved lines
    pub fn average(&self, raw: &[u8]) -> Result<Vec<u8>> {
        let interleave = self.lines_per_frame / LINES_PER_CALIBRATION_DATA;
        ensure!(interleave > 1, "only interleaved scans are implemented");
        let frame_size = self.frame_size();
        ensure!(
            raw.len() >= 2 * frame_size,
            "calibration scan too short: {} bytes",
            raw.len()
        );
        let averaged = raw[frame_size..2 * frame_size]
            .chunks(interleave * BYTES_PER_LINE)
            .flat_map(|group| {
                (0..BYTES_PER_LINE).map(move |col| {
                    let sum: usize = (0..interleave)
                        .map(|line| group[line * BYTES_PER_LINE + col] as usize)
                        .sum();
                    (sum / interleave) as u8
                })
            })
            .collect();
        Ok(averaged)
    }

    /// Scales an averaged scan (keeping each line's 8-byte header) and adds it,
    /// as signed bytes with clipping, to the running calibration
    pub fn accumulate(&mut self, averaged: &[u8]) {
        let scaled: Vec<u8> = averaged
            .chunks(BYTES_PER_LINE)
            .flat_map(|line| {
                line[..8]
                    .iter()
                    .copied()
                    .chain(line[8..].iter().map(|&x| scale(x)))
            })
            .collect();
        if self.data.is_empty() {
            self.data = scaled;
            return;
        }
        self.data = self
            .data
            .chunks(BYTES_PER_LINE)
            .zip(scaled.chunks(BYTES_PER_LINE))
            .flat_map(|(old, new)| {
                let sums = old[8..]
                    .iter()
                    .zip(&new[8..])
                    .map(|(&l, &r)| clip(l as i8 as i32 + r as i8 as i32));
                old[..8].iter().copied().chain(sums)
            })
            .collect();
    }
}

/// The length and hash of a partition 6 clean slate, if the header holds one
pub fn clean_slate_header(header: &[u8]) -> Option<(usize, &[u8])> {
    let magic = u16::from_le_bytes([*header.first()?, *header.get(1)?]);
    let len = u16::from_le_bytes([*header.get(2)?, *header.get(3)?]) as usize;
    let (hash, zeros) = (header.get(4..36)?, header.get(36..68)?);
    (magic == CLEAN_SLATE_MAGIC && zeros.iter().all(|&b| b == 0)).then_some((len, hash))
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    use super::*;

    // Synthetic vectors from python-validity's own Sensor methods (tests/vectors/calibration.json)
    fn vectors() -> Value {
        serde_json::from_str(include_str!("../tests/vectors/calibration.json")).unwrap()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn sha256(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn str<'a>(v: &'a Value, key: &str) -> &'a str {
        v[key].as_str().unwrap()
    }

    #[test]
    fn inputs_are_python_validitys() {
        let v = vectors();
        assert_eq!(unhex(str(&v, "program")), CAPTURE_PROGRAM);
        assert_eq!(unhex(str(&v, "type_calibration_blob")), CALIBRATION_BLOB);
        let factory: Vec<u8> = (0..144).map(|k| 0x60 + (k * 7 % 0x3f) as u8).collect();
        assert_eq!(unhex(str(&v, "factory_calibration_values")), factory);
        let (bits, min, packed) = bitpack(&factory);
        assert_eq!(v["bitpack"][0], bits);
        assert_eq!(v["bitpack"][1], min);
        assert_eq!(unhex(v["bitpack"][2].as_str().unwrap()), packed);
    }

    #[test]
    fn calibration_matches_python_validity() {
        let v = vectors();
        let factory = (0..144).map(|k| 0x60 + (k * 7 % 0x3f) as u8).collect();
        let mut calibration = Calibration::new(factory).unwrap();
        assert_eq!(v["lines_per_frame"], calibration.lines_per_frame);
        assert_eq!(
            calibration.command().unwrap(),
            unhex(str(&v, "cmd_calibrate_first"))
        );

        let len = 3 * calibration.frame_size() + BYTES_PER_LINE;
        for (it, step) in v["calibration_steps"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            let raw: Vec<u8> = (0..len)
                .map(|k| ((k * 31 + it * 17 + (k >> 7)) & 0xff) as u8)
                .collect();
            assert_eq!(sha256(&raw), v["raw_frames_sha256"][it].as_str().unwrap());
            let averaged = calibration.average(&raw).unwrap();
            assert_eq!(sha256(&averaged), str(step, "average"), "iteration {it}");
            calibration.accumulate(&averaged);
            assert_eq!(
                sha256(&calibration.data),
                str(step, "calib_data"),
                "iteration {it}"
            );
        }
        assert_eq!(
            sha256(&calibration.command().unwrap()),
            str(&v, "cmd_calibrate_calibrated_sha256")
        );
        assert!(calibration.average(&[0; 100]).is_err());
    }

    #[test]
    fn clean_slate_header_needs_magic_and_zeros() {
        let mut header = vec![0x02, 0x50, 0x84, 0x34];
        header.extend([0xaa; 32]);
        header.extend([0; 32]);
        assert_eq!(clean_slate_header(&header), Some((0x3484, &[0xaa; 32][..])));
        header[40] = 1;
        assert_eq!(clean_slate_header(&header), None);
        assert_eq!(clean_slate_header(&[0xff; 0x44]), None);
    }
}
