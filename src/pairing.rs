// SPDX-License-Identifier: LGPL-2.1-or-later
//! Pairing record in flash partition 1, following python-validity's
//! `validitysensor/tls.py`. Nothing here exposes key material: callers get the
//! block structure and verdicts only.

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use anyhow::{anyhow, ensure, Context, Result};
use hmac::{Hmac, Mac};
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
    EncodedPoint, FieldBytes, PublicKey, SecretKey,
};
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
/// Block holding the host certificate sent in the TLS Certificate message
pub const BLOCK_CERT: u16 = 3;
/// Block holding the host's ECDH private key, sealed with [`HostKeys`]
pub const BLOCK_PRIVATE_KEY: u16 = 4;
/// Block holding the sensor's ECDH public key, signed by the firmware key
pub const BLOCK_SENSOR_KEY: u16 = 6;

/// The key the firmware signs block 6 with. python-validity says it is
/// hardcoded per firmware revision in synaWudfBioUsb.dll.
const FIRMWARE_KEY_X: [u8; 32] = [
    0xf7, 0x27, 0x65, 0x3b, 0x4e, 0x16, 0xce, 0x06, 0x65, 0xa6, 0x89, 0x4d, 0x7f, 0x3a, 0x30, 0xd7,
    0xd0, 0xa0, 0xbe, 0x31, 0x0d, 0x12, 0x92, 0xa7, 0x43, 0x67, 0x1f, 0xdf, 0x69, 0xf6, 0xa8, 0xd3,
];
const FIRMWARE_KEY_Y: [u8; 32] = [
    0xa8, 0x55, 0x38, 0xf8, 0xb6, 0xbe, 0xc5, 0x0d, 0x6e, 0xef, 0x8b, 0xd5, 0xf4, 0xd0, 0x7a, 0x88,
    0x62, 0x43, 0xc5, 0x8b, 0x23, 0x93, 0x94, 0x8d, 0xf7, 0x61, 0xa8, 0x47, 0x21, 0xa6, 0xca, 0x94,
];

pub fn firmware_key() -> VerifyingKey {
    let point = EncodedPoint::from_affine_coordinates(
        &FIRMWARE_KEY_X.into(),
        &FIRMWARE_KEY_Y.into(),
        false,
    );
    VerifyingKey::from_encoded_point(&point).expect("the firmware key is on P-256")
}

pub(crate) fn hmac(key: &[u8], parts: &[&[u8]]) -> HmacSha256 {
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

    /// Decrypts a sealed private-key block: an IV, then AES-256-CBC over x, y
    /// and d (32 bytes each, little-endian) with PKCS#7 padding. Also reports
    /// whether the sealed public half matches d, or None when it is zero, which
    /// python-validity says the latest Windows driver writes.
    pub fn unseal(&self, block: &[u8]) -> Result<(SecretKey, Option<bool>)> {
        ensure!(
            self.sealed(block)?,
            "the private key was sealed for another host"
        );
        let data = &block[1..block.len() - 32];
        ensure!(
            data.len() >= 32 && data.len().is_multiple_of(16),
            "sealed key has a bad length: {}",
            data.len()
        );
        let (iv, ciphertext) = data.split_at(16);
        let mut plain = cbc::Decryptor::<aes::Aes256>::new_from_slices(&self.encryption, iv)
            .expect("32-byte key, 16-byte IV")
            .decrypt_padded_vec_mut::<NoPadding>(ciphertext)
            .map_err(|e| anyhow!("decrypting the private key: {e:?}"))?;
        let pad = *plain.last().expect("at least one block") as usize;
        ensure!(
            plain.len() >= 96 + pad,
            "unsealed key is too short or badly padded"
        );
        plain.truncate(plain.len() - pad);
        let big_endian = |at: usize| -> FieldBytes {
            let mut field: [u8; 32] = plain[at..at + 32].try_into().expect("32 bytes");
            field.reverse();
            field.into()
        };
        let secret = SecretKey::from_bytes(&big_endian(64))
            .context("sealed d is not a valid P-256 scalar")?;
        let (x, y) = (big_endian(0), big_endian(32));
        let matches = if x.iter().chain(&y).all(|&b| b == 0) {
            None
        } else {
            let point = secret.public_key().to_encoded_point(false);
            Some(point.x() == Some(&x) && point.y() == Some(&y))
        };
        Ok((secret, matches))
    }
}

/// Block 6: a 0x90-byte key record (x at 0x08, y at 0x4c, both little-endian),
/// then a u32 length, the firmware's DER ECDSA-SHA256 signature over the
/// record, and zero padding. Returns the key and whether the signature verifies.
fn sensor_key(body: &[u8], firmware_key: &VerifyingKey) -> Result<(PublicKey, bool)> {
    ensure!(
        body.len() >= 0x94,
        "sensor key block too short: {} bytes",
        body.len()
    );
    let (record, rest) = body.split_at(0x90);
    let len = u32::from_le_bytes(rest[..4].try_into()?) as usize;
    ensure!(
        rest.len() >= 4 + len,
        "sensor key signature overruns its block"
    );
    let (signature, padding) = rest[4..].split_at(len);
    ensure!(
        padding.iter().all(|&b| b == 0),
        "expected zero padding after the sensor key signature"
    );
    let mut point = vec![4];
    for at in [0x08, 0x4c] {
        point.extend(record[at..at + 32].iter().rev());
    }
    let key = PublicKey::from_sec1_bytes(&point).context("the sensor key is not on P-256")?;
    let signed =
        Signature::from_der(signature).is_ok_and(|s| firmware_key.verify(record, &s).is_ok());
    Ok((key, signed))
}

/// What a TLS session needs from partition 1
pub struct Pairing {
    pub cert: Vec<u8>,
    pub private_key: SecretKey,
    pub sensor_key: PublicKey,
}

/// Verdicts about a loaded pairing, safe to report
#[derive(Debug, Serialize)]
pub struct PairingCheck {
    pub sensor_key_signed: bool,
    pub public_key_matches: Option<bool>,
}

impl Pairing {
    pub fn load(
        flash: &[u8],
        keys: &HostKeys,
        firmware_key: &VerifyingKey,
    ) -> Result<(Self, PairingCheck)> {
        let blocks = blocks(flash)?;
        let body = |id: u16| -> Result<&[u8]> {
            let block = blocks
                .iter()
                .find(|b| b.id == id)
                .with_context(|| format!("no block {id}"))?;
            ensure!(block.hash_ok, "block {id} fails its SHA-256 check");
            Ok(block.body)
        };
        let (private_key, public_key_matches) = keys.unseal(body(BLOCK_PRIVATE_KEY)?)?;
        let (sensor_key, sensor_key_signed) = sensor_key(body(BLOCK_SENSOR_KEY)?, firmware_key)?;
        let pairing = Self {
            cert: body(BLOCK_CERT)?.to_vec(),
            private_key,
            sensor_key,
        };
        Ok((
            pairing,
            PairingCheck {
                sensor_key_signed,
                public_key_matches,
            },
        ))
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

    fn vector(key: &str) -> Vec<u8> {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/tls.json")).unwrap();
        unhex(v[key].as_str().unwrap())
    }

    #[test]
    fn unseal_matches_python_validity() {
        let keys = HostKeys::derive("TestProduct", "TestSerial");
        let (secret, matches) = keys.unseal(&vector("priv_block")).unwrap();
        assert_eq!(secret.to_bytes().to_vec(), vector("host_private"));
        assert_eq!(matches, Some(true));
        assert!(HostKeys::derive("TestProduct", "Other")
            .unseal(&vector("priv_block"))
            .is_err());
    }

    fn sensor_block(firmware: &p256::ecdsa::SigningKey) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;
        let point = SecretKey::from_slice(&[0x22; 32])
            .unwrap()
            .public_key()
            .to_encoded_point(false);
        let mut record = vec![0; 0x90];
        for (at, coordinate) in [(0x08, point.x().unwrap()), (0x4c, point.y().unwrap())] {
            record[at..at + 32].copy_from_slice(coordinate);
            record[at..at + 32].reverse();
        }
        let signature: Signature = firmware.sign(&record);
        let der = signature.to_der();
        let mut body = record;
        body.extend((der.as_bytes().len() as u32).to_le_bytes());
        body.extend(der.as_bytes());
        body.resize(400, 0);
        body
    }

    #[test]
    fn sensor_key_checks_the_firmware_signature() {
        let firmware = p256::ecdsa::SigningKey::from_slice(&[0x44; 32]).unwrap();
        let mut body = sensor_block(&firmware);
        let (key, signed) = sensor_key(&body, firmware.verifying_key()).unwrap();
        assert!(signed);
        assert_eq!(
            key,
            SecretKey::from_slice(&[0x22; 32]).unwrap().public_key()
        );
        assert!(!sensor_key(&body, &firmware_key()).unwrap().1);
        body[0] ^= 1;
        assert!(!sensor_key(&body, firmware.verifying_key()).unwrap().1);
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
