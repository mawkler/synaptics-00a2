// SPDX-License-Identifier: LGPL-2.1-or-later
//! The sensor's TLS 1.2 dialect, following python-validity's `tls.py`. It
//! negotiates TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA (0xc005), but:
//! - records are MAC-then-encrypt with HMAC-SHA256 and no sequence number
//! - the handshake hash leaves out the client Finished
//! - Certificate and CertificateVerify have non-standard framing
//!
//! Handshake flights go out wrapped in a `44 00 00 00` command; application
//! records go out bare.

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::{anyhow, bail, ensure, Context, Result};
use hmac::Mac;
use p256::{
    ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
    NonZeroScalar, PublicKey, SecretKey,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::{
    pairing::{hmac, prf, Pairing},
    proto, usb,
};

const HANDSHAKE_COMMAND: [u8; 4] = [0x44, 0, 0, 0];

const CHANGE_CIPHER_SPEC: u8 = 0x14;
const ALERT: u8 = 0x15;
const HANDSHAKE: u8 = 0x16;
const APP_DATA: u8 = 0x17;

const MAC_LEN: usize = 32;

struct Keys {
    sign: Vec<u8>,
    validate: Vec<u8>,
    encrypt: Vec<u8>,
    decrypt: Vec<u8>,
}

pub struct Session {
    hash: Sha256,
    client_random: [u8; 32],
    server_random: [u8; 32],
    master: Vec<u8>,
    keys: Option<Keys>,
    secure_tx: bool,
    secure_rx: bool,
    finished: bool,
    next_iv: Box<dyn FnMut() -> [u8; 16]>,
}

/// The MAC'd header: content type, version 3.3, plaintext length
fn header(kind: u8, len: usize) -> [u8; 5] {
    let len = (len as u16).to_be_bytes();
    [kind, 3, 3, len[0], len[1]]
}

impl Session {
    pub fn new(client_random: [u8; 32], next_iv: impl FnMut() -> [u8; 16] + 'static) -> Self {
        Self {
            hash: Sha256::new(),
            client_random,
            server_random: [0; 32],
            master: Vec::new(),
            keys: None,
            secure_tx: false,
            secure_rx: false,
            finished: false,
            next_iv: Box::new(next_iv),
        }
    }

    /// A handshake message (type, u24 length, body), added to the handshake hash
    fn message(&mut self, kind: u8, body: &[u8]) -> Vec<u8> {
        let mut message = vec![kind];
        message.extend(&(body.len() as u32).to_be_bytes()[1..]);
        message.extend(body);
        self.hash.update(&message);
        message
    }

    fn record(&mut self, kind: u8, body: &[u8]) -> Vec<u8> {
        let payload = if self.secure_tx {
            self.seal(kind, body)
        } else {
            body.to_vec()
        };
        let mut record = header(kind, payload.len()).to_vec();
        record.extend(payload);
        record
    }

    fn seal(&mut self, kind: u8, body: &[u8]) -> Vec<u8> {
        let iv = (self.next_iv)();
        let keys = self
            .keys
            .as_ref()
            .expect("keys are derived before anything is encrypted");
        let mut plain = body.to_vec();
        plain.extend(
            hmac(&keys.sign, &[&header(kind, body.len()), body])
                .finalize()
                .into_bytes(),
        );
        let pad = 16 - plain.len() % 16;
        plain.resize(plain.len() + pad, (pad - 1) as u8);
        let mut sealed = iv.to_vec();
        sealed.extend(
            cbc::Encryptor::<aes::Aes256>::new_from_slices(&keys.encrypt, &iv)
                .expect("32-byte key, 16-byte IV")
                .encrypt_padded_vec_mut::<NoPadding>(&plain),
        );
        sealed
    }

    fn open(&self, kind: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let keys = self
            .keys
            .as_ref()
            .context("encrypted record before the key exchange")?;
        ensure!(
            payload.len() >= 32 && payload.len().is_multiple_of(16),
            "bad encrypted record length {}",
            payload.len()
        );
        let (iv, ciphertext) = payload.split_at(16);
        let mut plain = cbc::Decryptor::<aes::Aes256>::new_from_slices(&keys.decrypt, iv)
            .expect("32-byte key, 16-byte IV")
            .decrypt_padded_vec_mut::<NoPadding>(ciphertext)
            .map_err(|e| anyhow!("decrypting a record: {e:?}"))?;
        let pad = *plain.last().expect("at least one block") as usize + 1;
        ensure!(plain.len() >= pad + MAC_LEN, "bad record padding");
        plain.truncate(plain.len() - pad);
        let tag = plain.split_off(plain.len() - MAC_LEN);
        hmac(&keys.validate, &[&header(kind, plain.len()), &plain])
            .verify_slice(&tag)
            .map_err(|_| anyhow!("record MAC check failed"))?;
        Ok(plain)
    }

    pub fn client_hello(&mut self) -> Vec<u8> {
        let mut hello = vec![3, 3];
        hello.extend(self.client_random);
        hello.extend([7, 0, 0, 0, 0, 0, 0, 0]); // session ID
        hello.extend([0, 6, 0xc0, 0x05, 0x00, 0x3d, 0x00, 0x8d]); // cipher suites
        hello.push(0); // no compression
                       // truncated_hmac and ec_point_formats (uncompressed). python-validity
                       // gives the extensions length as 2 less than their size ("WHY?!").
        hello.extend([
            0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
        ]);
        let message = self.message(1, &hello);
        self.record(HANDSHAKE, &message)
    }

    /// Processes the sensor's records and returns any decrypted application data
    pub fn parse(&mut self, mut response: &[u8]) -> Result<Vec<u8>> {
        // A refusal on the command path is a bare u16 status, not a record
        if response.len() == 2 {
            bail!(
                "sensor refused with status {:04x}",
                u16::from_le_bytes([response[0], response[1]])
            );
        }
        let mut app_data = Vec::new();
        while !response.is_empty() {
            ensure!(
                response.len() >= 5,
                "truncated record header: {:02x?}",
                response
            );
            let (kind, version) = (response[0], [response[1], response[2]]);
            let len = u16::from_be_bytes([response[3], response[4]]) as usize;
            ensure!(
                version == [3, 3],
                "unexpected record version {version:02x?}"
            );
            ensure!(response.len() >= 5 + len, "truncated record");
            let payload = &response[5..5 + len];
            response = &response[5 + len..];
            match kind {
                HANDSHAKE => {
                    let body = if self.secure_rx {
                        self.open(HANDSHAKE, payload)?
                    } else {
                        payload.to_vec()
                    };
                    self.handshake_messages(&body)?;
                }
                CHANGE_CIPHER_SPEC => {
                    ensure!(payload == [1], "unexpected ChangeCipherSpec {payload:02x?}");
                    self.secure_rx = true;
                }
                APP_DATA => {
                    ensure!(self.secure_rx, "application data before ChangeCipherSpec");
                    app_data.extend(self.open(APP_DATA, payload)?);
                }
                ALERT => {
                    let alert = if self.secure_rx {
                        self.open(ALERT, payload).unwrap_or(payload.to_vec())
                    } else {
                        payload.to_vec()
                    };
                    bail!("sensor sent TLS alert {alert:02x?}");
                }
                _ => bail!("unexpected record type {kind:#04x}"),
            }
        }
        Ok(app_data)
    }

    fn handshake_messages(&mut self, mut body: &[u8]) -> Result<()> {
        while !body.is_empty() {
            ensure!(body.len() >= 4, "truncated handshake message header");
            let kind = body[0];
            let len = u32::from_be_bytes([0, body[1], body[2], body[3]]) as usize;
            ensure!(body.len() >= 4 + len, "truncated handshake message");
            let (message, payload) = (&body[..4 + len], &body[4..4 + len]);
            match kind {
                2 => self.server_hello(payload)?,
                // ECDSA with SHA-256, no CA list
                0x0d => ensure!(
                    payload == [0x01, 0x40, 0, 0],
                    "unexpected CertificateRequest {payload:02x?}"
                ),
                0x0e => ensure!(payload.is_empty(), "ServerHelloDone with a body"),
                0x14 => {
                    let seed =
                        [b"server finished".as_slice(), &self.hash.clone().finalize()].concat();
                    ensure!(
                        payload == prf(&self.master, &seed, 12),
                        "the server Finished does not verify"
                    );
                    self.finished = true;
                }
                _ => bail!("unexpected handshake message {kind:#04x}"),
            }
            self.hash.update(message);
            body = &body[4 + len..];
        }
        Ok(())
    }

    fn server_hello(&mut self, hello: &[u8]) -> Result<()> {
        ensure!(
            hello.len() >= 35 && hello[..2] == [3, 3],
            "unexpected ServerHello {hello:02x?}"
        );
        self.server_random.copy_from_slice(&hello[2..34]);
        let rest = hello
            .get(35 + hello[34] as usize..)
            .context("truncated ServerHello")?;
        ensure!(
            rest == [0xc0, 0x05, 0],
            "ServerHello picked {rest:02x?}, expected suite c005 without compression"
        );
        Ok(())
    }

    /// ECDH between our ephemeral key and the sensor's static key from the
    /// pairing, then the TLS 1.2 master secret and key block
    pub fn derive_keys(&mut self, ephemeral: &NonZeroScalar, sensor_key: &PublicKey) {
        let shared = p256::ecdh::diffie_hellman(ephemeral, sensor_key.as_affine());
        let seed = [self.client_random, self.server_random].concat();
        self.master = prf(
            shared.raw_secret_bytes(),
            &[b"master secret".as_slice(), &seed].concat(),
            0x30,
        );
        let block = prf(
            &self.master,
            &[b"key expansion".as_slice(), &seed].concat(),
            0x120,
        );
        self.keys = Some(Keys {
            sign: block[0x00..0x20].to_vec(),
            validate: block[0x20..0x40].to_vec(),
            encrypt: block[0x40..0x60].to_vec(),
            decrypt: block[0x60..0x80].to_vec(),
        });
    }

    /// Certificate, ClientKeyExchange, CertificateVerify, ChangeCipherSpec, Finished.
    /// `sign` gets the handshake hash and returns a DER ECDSA signature over it.
    pub fn client_flight(
        &mut self,
        cert: &[u8],
        ephemeral: &PublicKey,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> Vec<u8> {
        // Both list lengths are the bare cert's, and an unexplained `ac 16` precedes it
        let len = (cert.len() as u16).to_be_bytes();
        let mut certificate = [0, len[0], len[1], 0, len[0], len[1], 0xac, 0x16].to_vec();
        certificate.extend(cert);
        let mut flight = self.message(0x0b, &certificate);
        // Fixed-width coordinates: python-validity drops their leading zero bytes
        flight.extend(self.message(0x10, ephemeral.to_encoded_point(false).as_bytes()));
        let signature = sign(&self.hash.clone().finalize());
        flight.extend(self.message(0x0f, &signature));

        let mut out = self.record(HANDSHAKE, &flight);
        out.extend([CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1]);
        self.secure_tx = true;
        let seed = [b"client finished".as_slice(), &self.hash.clone().finalize()].concat();
        // Not added to the handshake hash
        let mut finished = vec![0x14, 0, 0, 12];
        finished.extend(prf(&self.master, &seed, 12));
        out.extend(self.record(HANDSHAKE, &finished));
        out
    }

    pub fn app_request(&mut self, plain: &[u8]) -> Vec<u8> {
        assert!(self.secure_tx, "application data before the handshake");
        self.record(APP_DATA, plain)
    }

    /// Sends a command over the session and returns the decrypted response
    pub fn cmd(&mut self, sensor: &usb::Sensor, request: &[u8]) -> Result<Vec<u8>> {
        let record = self.app_request(request);
        let response = sensor.cmd(&record)?;
        self.parse(&response)
    }

    /// Like [`Session::cmd`], but fails on a non-zero status and returns the payload
    pub fn cmd_ok(&mut self, sensor: &usb::Sensor, request: &[u8]) -> Result<Vec<u8>> {
        let response = self.cmd(sensor, request)?;
        let (status, payload) = proto::split_status(&response)?;
        ensure!(
            status == proto::STATUS_OK,
            "command {:02x} failed with status {status:04x}",
            request[0]
        );
        Ok(payload.to_vec())
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn sign_digest(key: &SecretKey, digest: &[u8]) -> Vec<u8> {
    let signature: Signature = SigningKey::from(key)
        .sign_prehash(digest)
        .expect("a SHA-256 digest is a valid prehash");
    signature.to_der().as_bytes().to_vec()
}

/// Runs the handshake with the stored pairing. The sensor must have had its
/// init blob, on the plain command path.
pub fn connect(sensor: &usb::Sensor, pairing: &Pairing) -> Result<Session> {
    let mut session = Session::new(random(), random);
    let response = sensor.cmd(&[&HANDSHAKE_COMMAND[..], &session.client_hello()].concat())?;
    session.parse(&response).context("ClientHello")?;
    let ephemeral = NonZeroScalar::random(&mut OsRng);
    session.derive_keys(&ephemeral, &pairing.sensor_key);
    let flight = session.client_flight(
        &pairing.cert,
        &PublicKey::from_secret_scalar(&ephemeral),
        |digest| sign_digest(&pairing.private_key, digest),
    );
    let response = sensor.cmd(&[&HANDSHAKE_COMMAND[..], &flight].concat())?;
    session.parse(&response).context("client Finished flight")?;
    ensure!(
        session.secure_rx && session.finished,
        "the sensor never sent ChangeCipherSpec and Finished"
    );
    Ok(session)
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};
    use serde_json::Value;

    use super::*;

    // Synthetic vectors from python-validity's Tls with deterministic randomness
    fn vectors() -> Value {
        serde_json::from_str(include_str!("../tests/vectors/tls.json")).unwrap()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn bytes(v: &Value, key: &str) -> Vec<u8> {
        unhex(v[key].as_str().unwrap())
    }

    /// Replays the vectors up to and including the client's Finished
    fn client_side(v: &Value) -> Session {
        let mut ivs = [[0xa1; 16], [0xa2; 16]].into_iter();
        let mut session = Session::new([0xa0; 32], move || {
            ivs.next().expect("only two IVs are recorded")
        });
        assert_eq!(session.client_hello(), bytes(v, "flight1"));
        assert_eq!(session.parse(&bytes(v, "server_flight1")).unwrap(), b"");

        let ephemeral = SecretKey::from_slice(&bytes(v, "ephemeral_private"))
            .unwrap()
            .to_nonzero_scalar();
        let sensor = [
            [4].as_slice(),
            &unhex(v["sensor_public"]["x"].as_str().unwrap()),
            &unhex(v["sensor_public"]["y"].as_str().unwrap()),
        ]
        .concat();
        session.derive_keys(&ephemeral, &PublicKey::from_sec1_bytes(&sensor).unwrap());
        assert_eq!(session.master, bytes(v, "master_secret"));
        let keys = session.keys.as_ref().unwrap();
        for (ours, theirs) in [
            (&keys.sign, "sign_key"),
            (&keys.validate, "validation_key"),
            (&keys.encrypt, "encryption_key"),
            (&keys.decrypt, "decryption_key"),
        ] {
            assert_eq!(
                *ours,
                unhex(v["keys"][theirs].as_str().unwrap()),
                "{theirs}"
            );
        }

        let flight = session.client_flight(
            &bytes(v, "cert"),
            &PublicKey::from_secret_scalar(&ephemeral),
            |digest| {
                assert_eq!(digest, bytes(v, "cert_verify_digest"));
                bytes(v, "cert_verify_signature")
            },
        );
        assert_eq!(flight, bytes(v, "flight2"));
        session
    }

    fn handshake(v: &Value) -> Session {
        let mut session = client_side(v);
        assert_eq!(session.parse(&bytes(v, "server_flight2")).unwrap(), b"");
        assert!(session.secure_rx && session.finished);
        session
    }

    #[test]
    fn handshake_and_app_data_match_python_validity() {
        let v = vectors();
        let mut session = handshake(&v);
        assert_eq!(session.app_request(&[0x01]), bytes(&v, "app_request"));
        assert_eq!(
            session.parse(&bytes(&v, "app_response")).unwrap(),
            bytes(&v, "app_plain")
        );
    }

    #[test]
    fn tampered_records_are_rejected() {
        let v = vectors();
        let mut session = handshake(&v);
        let mut response = bytes(&v, "app_response");
        let last = response.len() - 1;
        response[last] ^= 1;
        assert!(session.parse(&response).is_err());

        let mut finished = bytes(&v, "server_flight2");
        let last = finished.len() - 1;
        finished[last] ^= 1;
        assert!(client_side(&v).parse(&finished).is_err());
    }

    #[test]
    fn refusals_and_alerts_are_errors() {
        let mut session = Session::new([0; 32], || [0; 16]);
        assert!(session
            .parse(&[0x04, 0x04])
            .unwrap_err()
            .to_string()
            .contains("0404"));
        assert!(session
            .parse(&[ALERT, 3, 3, 0, 2, 2, 40])
            .unwrap_err()
            .to_string()
            .contains("alert"));
    }

    #[test]
    fn certificate_verify_signature_verifies() {
        let key = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let digest = Sha256::digest(b"handshake");
        let signature = Signature::from_der(&sign_digest(&key, &digest)).unwrap();
        assert!(VerifyingKey::from(key.public_key())
            .verify_prehash(&digest, &signature)
            .is_ok());
    }
}
