// SPDX-License-Identifier: LGPL-2.1-or-later
//! Userspace driver core for the Synaptics 06cb:00a2 fingerprint reader

pub mod blobs;
pub mod calibrate;
pub mod capture;
pub mod matcher;
pub mod pairing;
pub mod prog;
pub mod proto;
pub mod tables;
pub mod tls;
pub mod usb;
