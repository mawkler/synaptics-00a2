// SPDX-License-Identifier: LGPL-2.1-or-later
//! Capture programs: TLV chunks (`<HH` type and length), one of which (0x34)
//! holds a timeslot table of sensor microcode. Follows python-validity's
//! `timeslot.py`.

use anyhow::{bail, ensure, Context, Result};

pub const LINES_2D: u16 = 0x2f;
pub const TIMESLOT_TABLE: u16 = 0x34;

pub const ENABLE_RX: u8 = 6;
const REGISTER_WRITE: u8 = 13;

pub fn split_chunks(mut program: &[u8]) -> Result<Vec<(u16, Vec<u8>)>> {
    let mut chunks = Vec::new();
    while !program.is_empty() {
        ensure!(program.len() >= 4, "truncated chunk header");
        let kind = u16::from_le_bytes([program[0], program[1]]);
        let len = u16::from_le_bytes([program[2], program[3]]) as usize;
        ensure!(
            program.len() >= 4 + len,
            "chunk {kind:#x} overruns the program"
        );
        chunks.push((kind, program[4..4 + len].to_vec()));
        program = &program[4 + len..];
    }
    Ok(chunks)
}

pub fn merge_chunks(chunks: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut program = Vec::new();
    for (kind, value) in chunks {
        program.extend(kind.to_le_bytes());
        program.extend((value.len() as u16).to_le_bytes());
        program.extend(value);
    }
    program
}

/// Opcode and length of the timeslot instruction at the start of `code`
fn decode(code: &[u8]) -> Result<(u8, usize)> {
    let op = code[0];
    let decoded = match op {
        0..=4 => (op, 1),
        5..=7 => (op, 2),
        0x08..=0x09 => (8, 2),
        0x0a..=0x0b => (9, 2),
        0x0c..=0x0f => (10, 1),
        0x10..=0x17 => (11, 3),
        0x20..=0x3f => (12, 1),
        0x40..=0x7f => (REGISTER_WRITE, 3),
        0x80..=0xbf => (14, 1),
        0xc0..=0xff => (15, 2),
        _ => bail!("unhandled timeslot instruction {op:#04x}"),
    };
    ensure!(decoded.1 <= code.len(), "truncated timeslot instruction");
    Ok(decoded)
}

/// Offset of the `n`th (1-based) instruction matching `pred`, decoding the
/// whole table from offset 0 as python-validity does
fn find_nth(table: &[u8], n: usize, pred: impl Fn(u8, &[u8]) -> bool) -> Result<usize> {
    let (mut pc, mut seen) = (0, 0);
    while pc < table.len() {
        let (op, len) = decode(&table[pc..])?;
        if pred(op, &table[pc..pc + len]) {
            seen += 1;
            if seen == n {
                return Ok(pc);
            }
        }
        pc += len;
    }
    bail!("the timeslot table has no instruction #{n} of the kind wanted")
}

pub fn find_nth_insn(table: &[u8], opcode: u8, n: usize) -> Result<usize> {
    find_nth(table, n, |op, _| op == opcode)
}

pub fn find_nth_regwrite(table: &[u8], register: u32, n: usize) -> Result<usize> {
    find_nth(table, n, |op, insn| {
        op == REGISTER_WRITE && (insn[0] & 0x3f) as u32 * 4 + 0x8000_2000 == register
    })
}

/// The DLL's timeslot patch, which python-validity copies ("If it looks broken
/// that was probably intended"). It multiplies Call repeat counts, optionally
/// bumps their addresses, and stops at the first instruction that is not a
/// Call, NOOP or Idle Rx.
pub fn patch_timeslot_table(table: &[u8], inc_address: bool, mult: u8) -> Result<Vec<u8>> {
    let mut b = table.to_vec();
    let mut i = 0;
    while i + 3 < b.len() {
        if b[i] & 0xf8 == 0x10 {
            if b[i + 2] > 1 {
                b[i + 2] = b[i + 2]
                    .checked_mul(mult)
                    .context("Call repeat count overflows")?;
                if inc_address {
                    b[i + 1] = b[i + 1].checked_add(1).context("Call address overflows")?;
                }
            }
            i += 3;
        } else if b[i] == 0 {
            i += 1;
        } else if b[i] == 7 {
            i += 2;
        } else {
            break;
        }
    }
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_round_trip() {
        let chunks = split_chunks(&crate::tables::CAPTURE_PROGRAM).unwrap();
        assert_eq!(merge_chunks(&chunks), crate::tables::CAPTURE_PROGRAM);
        assert!(split_chunks(&[0x34, 0, 5, 0, 1]).is_err());
    }

    #[test]
    fn finds_instructions_and_register_writes() {
        // NOOP, Enable Rx 1, Register Write *0x8000203c, Enable Rx 2, Call
        let table = [
            0x00, 0x06, 0x01, 0x4f, 0x34, 0x12, 0x06, 0x02, 0x11, 0x05, 0x03,
        ];
        assert_eq!(find_nth_insn(&table, ENABLE_RX, 2).unwrap(), 6);
        assert_eq!(find_nth_regwrite(&table, 0x8000_203c, 1).unwrap(), 3);
        assert!(find_nth_insn(&table, ENABLE_RX, 3).is_err());
        assert!(find_nth_insn(&[0x18], ENABLE_RX, 1).is_err());
    }

    #[test]
    fn patch_multiplies_calls_until_another_instruction() {
        let table = [
            0x00, 0x11, 0x05, 0x03, 0x07, 0x10, 0x10, 0x09, 0x01, 0x06, 0x01, 0x11, 0x05, 0x03,
            0x00,
        ];
        let patched = patch_timeslot_table(&table, true, 2).unwrap();
        assert_eq!(
            patched,
            [
                0x00, 0x11, 0x06, 0x06, 0x07, 0x10, 0x10, 0x09, 0x01, 0x06, 0x01, 0x11, 0x05, 0x03,
                0x00
            ]
        );
        assert!(patch_timeslot_table(&[0x11, 0x05, 0x90, 0x00], false, 2).is_err());
    }
}
