// SPDX-License-Identifier: LGPL-2.1-or-later
//! Pairing record in flash partition 1, following python-validity's
//! `validitysensor/tls.py`. Nothing here exposes key material: callers get the
//! block structure and verdicts only.

use anyhow::{ensure, Result};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// `password_hardcoded`
const PASSWORD: [u8; 32] = [
    0x71, 0x7c, 0xd7, 0x2d, 0x09, 0x62, 0xbc, 0x4a, 0x28, 0x46, 0x13, 0x8d, 0xbb, 0x2c, 0x24, 0x19,
    0x25, 0x12, 0xa7, 0x64, 0x07, 0x06, 0x5f, 0x38, 0x38, 0x46, 0x13, 0x9d, 0x4b, 0xec, 0x20, 0x33,
];
/// `gwk_sign_hardcoded`
const GWK_SIGN: [u8; 32] = [
    0x3a, 0x4c, 0x76, 0xb7, 0x6a, 0x97, 0x98, 0x1d, 0x12, 0x74, 0x24, 0x7e, 0x16, 0x66, 0x10, 0xe7,
    0x7f, 0x4d, 0x9c, 0x9d, 0x07, 0xd3, 0xc7, 0x28, 0xe5, 0x32, 0x91, 0x6b, 0xdd, 0x28, 0xb4, 0x54,
];
/// Block holding the host's ECDH private key, sealed with [`HostKeys`]
pub const BLOCK_PRIVATE_KEY: u16 = 4;

fn hmac(key: &[u8], parts: &[&[u8]]) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes keys of any length");
    for part in parts {
        mac.update(part);
    }
    mac
}

/// TLS 1.2 P_SHA256
pub fn prf(secret: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut a = hmac(secret, &[seed]).finalize().into_bytes();
    while out.len() < len {
        out.extend(hmac(secret, &[&a, seed]).finalize().into_bytes());
        a = hmac(secret, &[&a]).finalize().into_bytes();
    }
    out.truncate(len);
    out
}

/// Pre-TLS keys derived from the host's DMI identity (`Tls.set_hwkey`)
pub struct HostKeys {
    #[allow(dead_code)] // decrypts the private key once M2 needs it
    pub encryption: Vec<u8>,
    pub validation: Vec<u8>,
}

impl HostKeys {
    pub fn derive(product_name: &str, serial: &str) -> Self {
        let mut seed = b"GWK".to_vec();
        for field in [product_name, serial] {
            seed.extend(field.as_bytes());
            seed.push(0);
        }
        let encryption = prf(&PASSWORD, &seed, 32);
        let validation = prf(
            &encryption,
            &[b"GWK_SIGN".as_slice(), &GWK_SIGN].concat(),
            32,
        );
        Self {
            encryption,
            validation,
        }
    }

    /// Whether a private-key block (prefix 2, sealed data, HMAC-SHA256) was
    /// sealed with these keys, i.e. paired by a host with this identity
    pub fn sealed(&self, block: &[u8]) -> Result<bool> {
        ensure!(
            block.first() == Some(&2),
            "unknown private key prefix {:02x?}",
            block.first()
        );
        ensure!(
            block.len() > 1 + 32,
            "private key block too short: {} bytes",
            block.len()
        );
        let (data, tag) = block[1..].split_at(block.len() - 1 - 32);
        Ok(hmac(&self.validation, &[data]).verify_slice(tag).is_ok())
    }
}

#[derive(Debug, Serialize)]
pub struct Block<'a> {
    pub id: u16,
    pub size: usize,
    pub hash_ok: bool,
    #[serde(skip)]
    pub body: &'a [u8],
}

/// Blocks are a `<HH` id and size, the body's SHA-256, then the body.
/// Id 0xffff (erased flash) ends the list.
pub fn blocks(mut flash: &[u8]) -> Result<Vec<Block<'_>>> {
    let mut out = Vec::new();
    while !flash.is_empty() {
        ensure!(
            flash.len() >= 4,
            "{} trailing bytes after the last block",
            flash.len()
        );
        let id = u16::from_le_bytes([flash[0], flash[1]]);
        if id == 0xffff {
            break;
        }
        let size = u16::from_le_bytes([flash[2], flash[3]]) as usize;
        ensure!(
            flash.len() >= 36 + size,
            "block {id:#x} overruns the partition"
        );
        let (hash, body) = (&flash[4..36], &flash[36..36 + size]);
        out.push(Block {
            id,
            size,
            hash_ok: Sha256::digest(body).as_slice() == hash,
            body,
        });
        flash = &flash[36 + size..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Expected values come from python-validity's prf()/set_hwkey() on the same inputs

    #[test]
    fn prf_matches_python_validity() {
        assert_eq!(
            prf(b"secret", b"seed", 80),
            unhex(
                "8e4d932530d765a0aae974c304735ecc1202a819f80adbd5ad09c1a34fc06918\
                 e3d07795214d94c6a1976caea5a0b644c5b04d1ad3e09c6111c37afc00df0b6d\
                 134279f973813359ad8be59625d3ba60"
            )
        );
    }

    #[test]
    fn host_keys_match_python_validity() {
        let keys = HostKeys::derive("TestProduct", "TestSerial");
        assert_eq!(
            keys.encryption,
            unhex("c61832d6161ca1a67f0b2102b54d91cae15d4ec584c2a780a21d14c24a76ecc5")
        );
        assert_eq!(
            keys.validation,
            unhex("6940adbcc871294144cc3eceb1ce70f28a8bc45b0a3bb05b7bb48fb404a8a017")
        );
    }

    #[test]
    fn sealed_checks_the_hmac() {
        let mut block = vec![2];
        block.extend(0..0x50u8);
        block.extend(unhex(
            "0fdc76fde2fe68ac5fe292adccdabeaab0e565da75fb22a78f85da643795f0a2",
        ));
        assert!(HostKeys::derive("TestProduct", "TestSerial")
            .sealed(&block)
            .unwrap());
        assert!(!HostKeys::derive("TestProduct", "OtherSerial")
            .sealed(&block)
            .unwrap());
        block[0] = 3;
        assert!(HostKeys::derive("TestProduct", "TestSerial")
            .sealed(&block)
            .is_err());
    }

    fn block(id: u16, body: &[u8]) -> Vec<u8> {
        let mut out = id.to_le_bytes().to_vec();
        out.extend((body.len() as u16).to_le_bytes());
        out.extend(Sha256::digest(body));
        out.extend(body);
        out
    }

    #[test]
    fn blocks_stop_at_erased_flash() {
        let mut flash = [block(0, &[0]), block(4, &[2; 0x71])].concat();
        flash.resize(0x1000, 0xff);
        let parsed = blocks(&flash).unwrap();
        assert_eq!(
            parsed
                .iter()
                .map(|b| (b.id, b.size, b.hash_ok))
                .collect::<Vec<_>>(),
            [(0, 1, true), (4, 0x71, true)]
        );

        flash[40] ^= 1; // first byte of block 4's hash
        assert!(!blocks(&flash).unwrap()[1].hash_ok);
        assert!(blocks(&flash[..50]).is_err());
    }
}
