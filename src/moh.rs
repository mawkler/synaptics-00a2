// SPDX-License-Identifier: LGPL-2.1-or-later
//! Match-on-Host finger templates. Placements go in; out comes the 23136-byte
//! envelope that the chip stores (`0x47`, record type 6) and matches against.
//! This is a port of python-validity's native pipeline
//! (`validitysensor/moh_native.py`, with the tables and scaffold from
//! `blobs_a2.py`, PR #261 at 840cfbe). That code is MIT-licensed, see
//! `LICENSES/python-validity-MIT.txt`. The arithmetic follows numpy's
//! operation order, so the envelopes are byte-identical to python-validity's
//! (`tests/vectors/moh.json`).
//!
//! Each frame is cut into a 3×3 grid of overlapping tiles. Each tile gets a
//! determinant-of-Hessian response, its 8-neighbour maxima, and subpixel
//! refinement. Across the frame, the 250 strongest keypoints then get an
//! orientation and a 16-byte oriented-BRIEF descriptor. Each of the template's
//! four sections holds one placement.

use std::f64::consts::TAU;

use anyhow::{ensure, Context, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::matcher::SIDE;
use crate::pose::{choose_registered, Pose};

/// Envelope size: 8-byte header, tag-1 WS body, tag-2 template id, 32 zeros
pub const ENVELOPE_SIZE: usize = 8 + 4 + WS_SIZE + 4 + 32 + 32;
/// Record type the envelope is stored as
pub const FINGER_KIND: u16 = 6;
/// Keypoints kept per frame. A frame whose uncapped pool is smaller than
/// this is a poor placement (healthy ones pool about 500).
pub const FRAME_KP_CAP: usize = 250;

const GRID: usize = 3;
/// Tile overlap on each side
const GRID_X: i64 = 10;
/// Mid-gray padding outside the frame
const FILL: f64 = 128.0;

/// Orientation weights by |dy|, |dx| (the DLL's dword_180120C00)
const GAUSS_Q: [[f64; 7]; 7] = [
    [1669.0, 1541.0, 1212.0, 812.0, 464.0, 226.0, 94.0],
    [1541.0, 1422.0, 1119.0, 750.0, 428.0, 208.0, 86.0],
    [1212.0, 1119.0, 880.0, 590.0, 337.0, 164.0, 68.0],
    [812.0, 750.0, 590.0, 395.0, 226.0, 110.0, 46.0],
    [464.0, 428.0, 337.0, 226.0, 129.0, 63.0, 26.0],
    [226.0, 208.0, 164.0, 110.0, 63.0, 31.0, 13.0],
    [94.0, 86.0, 68.0, 46.0, 26.0, 13.0, 0.0],
];

/// (offset, tap): out[i] = Σ in[i − offset]·tap
type Kernel = [(isize, f64)];
const DERIV: [(isize, f64); 3] = [(-1, 1.0), (0, 0.0), (1, -1.0)];
const SMOOTH: [(isize, f64); 3] = [(-1, 0.25), (0, 0.5), (1, 0.25)];

/// Scales the response so that the DLL-tuned NMS thresholds apply
const RESP_SCALE: f64 = 17.04;
const NMS_LOW: f64 = 671.0;
const NMS_HIGH: f64 = 168.0;
const NMS_DEDUP_Q: i64 = 72064;
const NMS_MARGIN: usize = 10;
/// Global keypoints stay this far inside the frame
const MERGE_MARGIN: i64 = 3;

/// The 128 sample pairs of the BRIEF test, bit j = samples[a] > samples[b]
#[rustfmt::skip]
const BRIEF_TABLE: [(u8, u8); 128] = [
    (0, 2), (1, 3), (0, 4), (1, 5), (0, 6), (1, 7),
    (2, 4), (3, 5), (2, 6), (3, 7), (4, 6), (5, 7),
    (8, 10), (9, 11), (12, 14), (13, 15), (8, 16), (9, 17),
    (18, 20), (19, 21), (22, 20), (23, 21), (24, 26), (25, 27),
    (28, 16), (29, 17), (18, 30), (19, 31), (10, 32), (11, 33),
    (34, 10), (35, 11), (36, 38), (37, 39), (12, 24), (13, 25),
    (40, 42), (41, 43), (8, 34), (9, 35), (12, 22), (13, 23),
    (24, 44), (25, 45), (40, 24), (41, 25), (26, 46), (27, 47),
    (34, 48), (35, 49), (30, 50), (31, 51), (52, 54), (53, 55),
    (56, 46), (57, 47), (28, 32), (29, 33), (12, 50), (13, 51),
    (30, 20), (31, 21), (52, 22), (53, 23), (52, 18), (53, 19),
    (12, 42), (13, 43), (40, 30), (41, 31), (8, 48), (9, 49),
    (52, 42), (53, 43), (42, 20), (43, 21), (52, 40), (53, 41),
    (54, 50), (55, 51), (46, 50), (47, 51), (12, 30), (13, 31),
    (12, 56), (13, 57), (40, 14), (41, 15), (34, 36), (35, 37),
    (26, 50), (27, 51), (28, 48), (29, 49), (42, 18), (43, 19),
    (14, 30), (15, 31), (28, 34), (29, 35), (8, 32), (9, 33),
    (12, 18), (13, 19), (42, 22), (43, 23), (40, 50), (41, 51),
    (52, 26), (53, 27), (56, 22), (57, 23), (26, 22), (27, 23),
    (42, 54), (43, 55), (34, 32), (35, 33), (14, 24), (15, 25),
    (10, 36), (11, 37), (12, 46), (13, 47), (26, 30), (27, 31),
    (26, 54), (27, 55),
];

/// Aggregation windows (size index, x offset, y offset) over the rotated
/// samples. python-validity's comment calls the offsets (dy, dx), but its code
/// uses them as (x, y), and so does this port.
#[rustfmt::skip]
const AGGR_TABLE: [(usize, i64, i64); 29] = [
    (0, -7, -7), (0, 0, -7), (0, -7, 0), (0, 0, 0), (1, -2, -7),
    (1, -7, -2), (2, -3, -7), (2, -7, -3), (1, 3, 3), (2, 5, -3),
    (2, -3, 5), (2, 1, 1), (2, 1, -3), (2, -7, 1), (1, -7, -7),
    (2, -7, 5), (1, -2, -2), (1, 3, -7), (1, 3, -2), (1, -7, 3),
    (2, 5, -7), (2, -3, -3), (2, 5, 5), (2, 5, 1), (1, -2, 3),
    (2, 1, 5), (2, -7, -7), (2, -3, 1), (2, 1, -7),
];
const WIN_SIZES: [usize; 3] = [7, 5, 3];
/// Descriptor sampling half-width
const DESC_N: i64 = 7;

/// The chip-view WS body inside the envelope
const WS_SIZE: usize = 23056;
/// Where each section's records put their (x, y): a record is [16-byte
/// descriptor][x][y], so a section's records start 16 bytes earlier
const V30_REGIONS: [usize; 4] = [309, 4913, 9453, 13993];
const V30_SECTION_RECORDS: usize = 250;
const V30_SECTION_BYTES: usize = V30_SECTION_RECORDS * 18;
const V30_DESC_LEN: usize = 16;
/// The WS body's framing, taken from a chip-accepted Windows template with
/// its records zeroed (python-validity's `_WS_SCAFFOLD_CHUNKS`)
const WS_SCAFFOLD_CHUNKS: [(usize, &str); 11] = [
    (
        4,
        "40480000060205000200080103020100000000004c0000005a00000056000000590000000004\
         017b2389ff000046f0ffff5b7be8ff9561e8ff8821acff0000e7f2ffffda7af6ffb320eaff98\
         237fff0000c4efffff4e35fbffa559f1ffa11df0ff0000af0500004d290e00796d01008221fc\
         ff0000f00200003989130092630800a51e00000100e4feffff798a050098dd06",
    ),
    (280, "0400b811"),
    (292, "fa402d718170e4de301581828f410c2055"),
    (
        4809,
        "9e9fbcd8dfdfe1e6000000680004000000000003000400040000006900080070000000700000\
         006b000400050000006c0010",
    ),
    (4868, "01000000030000006a000400030000000500b811"),
    (4896, "fa608b73b2786c5fb8e38f82dfd0882757"),
    (9413, "9cabc1d0d3d5d8e80000000600b811"),
    (9436, "fa408f369278ee5f39eb9fa2df900c375b"),
    (13953, "979ebcd0d3d5d9e30000000700b811"),
    (13976, "fa40aabc9852c45a384cada20801086459"),
    (18493, "979ebed3d9dbdde0000000010004"),
];
/// Inter-section transform records the scaffold patch must find
const WS_SCAFFOLD_PRE_V30_RECORDS: usize = 6;

/// One keypoint in frame coordinates
#[derive(Clone, Debug, PartialEq)]
pub struct Keypoint {
    pub x: i64,
    pub y: i64,
    /// Radians, 0 up to 2π
    pub orientation: f64,
    pub descriptor: [u8; 16],
}

#[derive(Clone, Debug)]
pub struct Frame {
    /// At most [`FRAME_KP_CAP`], grouped by tile
    pub keypoints: Vec<Keypoint>,
    /// Keypoints found before the cap, which ranks placements
    pub pool: usize,
}

/// A row-major plane of floats
#[derive(Clone)]
struct Plane {
    h: usize,
    w: usize,
    v: Vec<f64>,
}

impl Plane {
    fn at(&self, y: usize, x: usize) -> f64 {
        self.v[y * self.w + x]
    }
}

/// Python's float `%`: the result takes the sign of the divisor
fn py_mod(x: f64, y: f64) -> f64 {
    let m = x % y;
    if m != 0.0 {
        if (y < 0.0) != (m < 0.0) {
            m + y
        } else {
            m
        }
    } else {
        0.0_f64.copysign(y)
    }
}

/// 1-D convolution along x or y. The taps are applied in order and zero taps
/// are skipped, as numpy accumulates them. Reads outside the plane give `fill`,
/// or with no `fill` they clamp to the edge.
fn conv(p: &Plane, kernel: &Kernel, along_x: bool, fill: Option<f64>) -> Plane {
    let n = (if along_x { p.w } else { p.h }) as isize;
    let mut out = Plane {
        h: p.h,
        w: p.w,
        v: vec![0.0; p.v.len()],
    };
    for y in 0..p.h {
        for x in 0..p.w {
            let mut acc = 0.0;
            for &(offset, tap) in kernel {
                if tap == 0.0 {
                    continue;
                }
                let i = (if along_x { x } else { y }) as isize - offset;
                let value = match fill {
                    Some(fill) if !(0..n).contains(&i) => fill,
                    _ => {
                        let i = i.clamp(0, n - 1) as usize;
                        if along_x {
                            p.at(y, i)
                        } else {
                            p.at(i, x)
                        }
                    }
                };
                acc += value * tap;
            }
            out.v[y * p.w + x] = acc;
        }
    }
    out
}

/// `kx` along x, then `ky` along y
fn separable(p: &Plane, kx: &Kernel, ky: &Kernel, fill: Option<f64>) -> Plane {
    conv(&conv(p, kx, true, fill), ky, false, fill)
}

/// Unit-sum 5-tap Gaussian. The sigma (about 1.10 px) comes from the DLL's
/// size-to-sigma relation.
fn gaussian() -> [(isize, f64); 5] {
    const N: i64 = 5;
    let sigma = (0x26600 * N + 0x59acd) as f64 / (1 << 20) as f64;
    let mut g = [0.0; 5];
    for (i, g) in g.iter_mut().enumerate() {
        let x = i as i64 - N / 2;
        *g = (-(x * x) as f64 / (2.0 * sigma * sigma)).exp();
    }
    let sum = g.iter().fold(0.0, |acc, v| acc + v);
    let mut taps = [(0, 0.0); 5];
    for (i, tap) in taps.iter_mut().enumerate() {
        *tap = (i as isize - 2, g[i] / sum);
    }
    taps
}

/// Origin (row, column) of tile (i, j). It may lie outside the frame.
fn tile_origin(i: usize, j: usize) -> (i64, i64) {
    let step = (SIDE / GRID) as i64;
    (i as i64 * step - GRID_X, j as i64 * step - GRID_X)
}

/// The last row and column of tiles absorb the remainder (58 px, not 57)
fn tile_size(i: usize, j: usize) -> (usize, usize) {
    let step = SIDE / GRID;
    let size = |k| {
        if k == GRID - 1 {
            SIDE - (GRID - 1) * step + 2 * GRID_X as usize
        } else {
            step + 2 * GRID_X as usize
        }
    };
    (size(i), size(j))
}

fn tile(image: &[u8], i: usize, j: usize) -> Plane {
    let (oy, ox) = tile_origin(i, j);
    let (h, w) = tile_size(i, j);
    let mut v = vec![FILL; h * w];
    for ty in 0..h {
        for tx in 0..w {
            let (y, x) = (oy + ty as i64, ox + tx as i64);
            if (0..SIDE as i64).contains(&y) && (0..SIDE as i64).contains(&x) {
                v[ty * w + tx] = image[y as usize * SIDE + x as usize] as f64;
            }
        }
    }
    Plane { h, w, v }
}

/// Determinant-of-Hessian response of the pre-smoothed tile (edges clamp)
fn doh(tile: &Plane, gauss: &Kernel) -> Plane {
    let smooth = separable(tile, gauss, gauss, None);
    let dx = separable(&smooth, &DERIV, &SMOOTH, None);
    let dy = separable(&smooth, &SMOOTH, &DERIV, None);
    let ixx = separable(&dx, &DERIV, &SMOOTH, None);
    let iyy = separable(&dy, &SMOOTH, &DERIV, None);
    let ixy = separable(&dx, &SMOOTH, &DERIV, None);
    let v = (0..smooth.v.len())
        .map(|k| (ixx.v[k] * iyy.v[k] - ixy.v[k] * ixy.v[k]) * RESP_SCALE)
        .collect();
    Plane {
        h: tile.h,
        w: tile.w,
        v,
    }
}

/// Gradients for orientation and descriptors. Reads outside the tile give 0.
fn gradients(tile: &Plane, gauss: &Kernel) -> (Plane, Plane) {
    let smooth = separable(tile, gauss, gauss, Some(0.0));
    (
        separable(&smooth, &DERIV, &SMOOTH, Some(0.0)),
        separable(&smooth, &SMOOTH, &DERIV, Some(0.0)),
    )
}

/// Strict 8-neighbour maxima above the thresholds, as (score, x, y) in raster
/// order
fn nms(resp: &Plane) -> Vec<(f64, usize, usize)> {
    let r2 = (((NMS_DEDUP_Q >> 6) * (NMS_DEDUP_Q >> 6)) >> 20) as usize;
    let mut kps: Vec<(f64, usize, usize)> = Vec::new();
    for y in NMS_MARGIN..resp.h - NMS_MARGIN {
        for x in NMS_MARGIN..resp.w - NMS_MARGIN {
            let v = resp.at(y, x);
            if v <= NMS_LOW || v < NMS_HIGH {
                continue;
            }
            let peak = (y - 1..=y + 1)
                .flat_map(|ny| (x - 1..=x + 1).map(move |nx| (ny, nx)))
                .all(|(ny, nx)| (ny, nx) == (y, x) || resp.at(ny, nx) < v);
            if !peak {
                continue;
            }
            let s = v.abs();
            let near = |&(_, kx, ky): &(f64, usize, usize)| {
                kx.abs_diff(x).pow(2) + ky.abs_diff(y).pow(2) <= r2
            };
            match kps.iter().position(near) {
                None => kps.push((s, x, y)),
                Some(dup) if s > kps[dup].0 => kps[dup] = (s, x, y),
                Some(_) => {}
            }
        }
    }
    kps
}

/// Solves the 2×2 system with numpy.linalg.solve's arithmetic (reference
/// LAPACK dgesv): partial pivoting, the multiplier scaled by a reciprocal,
/// then the two triangular solves. None where LAPACK reports a singular matrix.
fn solve2(a: [[f64; 2]; 2], r: [f64; 2]) -> Option<(f64, f64)> {
    let (mut top, mut bottom) = ((a[0], r[0]), (a[1], r[1]));
    if bottom.0[0].abs() > top.0[0].abs() {
        (top, bottom) = (bottom, top);
    }
    let ([a00, a01], r0) = top;
    let ([a10, a11], r1) = bottom;
    if a00 == 0.0 {
        return None;
    }
    let l = a10 * (1.0 / a00);
    let u = a11 - l * a01;
    if u == 0.0 {
        return None;
    }
    let x1 = (r1 - l * r0) / u;
    let x0 = (r0 - x1 * a01) / a00;
    Some((x0, x1))
}

/// Newton step on the response around an integer keypoint, in Q16. None
/// drops the keypoint: singular, or more than a pixel away.
fn subpixel(resp: &Plane, x: usize, y: usize) -> Option<(i64, i64)> {
    if !(1..=resp.w - 2).contains(&x) || !(1..=resp.h - 2).contains(&y) {
        return None;
    }
    let r = |dy: isize, dx: isize| resp.at((y as isize + dy) as usize, (x as isize + dx) as usize);
    let c = r(0, 0);
    let dxx = r(0, -1) + r(0, 1) - 2.0 * c;
    let dyy = r(-1, 0) + r(1, 0) - 2.0 * c;
    let dxy = (r(1, 1) - r(1, -1) - r(-1, 1) + r(-1, -1)) / 4.0;
    let gx = (r(0, 1) - r(0, -1)) / 2.0;
    let gy = (r(1, 0) - r(-1, 0)) / 2.0;
    if dxx * dyy - dxy * dxy == 0.0 {
        return None;
    }
    let (dx, dy) = solve2([[dxx, dxy], [dxy, dyy]], [-gx, -gy])?;
    if dx.abs() > 1.0 || dy.abs() > 1.0 {
        return None;
    }
    let q16 = |p: usize, d: f64| ((p as f64 + d) * 65536.0).round_ties_even() as i64;
    Some((q16(x, dx), q16(y, dy)))
}

/// The global-edge cull: 3 ≤ x < width − 3 and the same for y, except that
/// the bottom-right tile stops one row step below its origin (seen in the
/// Windows driver's enrollments)
fn inside_frame(sx: i64, sy: i64, i: usize, j: usize) -> bool {
    let (oy, ox) = tile_origin(i, j);
    let gx = ((ox << 16) + sx) >> 16;
    let gy = ((oy << 16) + sy) >> 16;
    let side = SIDE as i64;
    let mut gy_hi = side - 3;
    if i == GRID - 1 && j == GRID - 1 {
        gy_hi = oy + side - (GRID as i64 - 1) * (side / GRID as i64);
    }
    (3..side - 3).contains(&gx) && (3..gy_hi).contains(&gy)
}

/// Dominant gradient direction in a radius-6 disc around the keypoint: two
/// 42-bin histograms with a 7-bin smear, angle of the strongest bin
fn orientation(gx: &Plane, gy: &Plane, sx: i64, sy: i64) -> f64 {
    let cx = (sx + 0x8000) >> 16;
    let cy = (sy + 0x8000) >> 16;
    let mut hx = [0.0_f64; 42];
    let mut hy = [0.0_f64; 42];
    for dy in -6_i64..=6 {
        for dx in -6_i64..=6 {
            if dy * dy + dx * dx >= 36 {
                continue;
            }
            let (y, x) = (cy + dy, cx + dx);
            if !(0..gx.h as i64).contains(&y) || !(0..gx.w as i64).contains(&x) {
                continue;
            }
            let weight = GAUSS_Q[dy.unsigned_abs() as usize][dx.unsigned_abs() as usize];
            let ggx = gx.at(y as usize, x as usize) * weight;
            let ggy = gy.at(y as usize, x as usize) * weight;
            let angle = py_mod(ggy.atan2(ggx), TAU);
            let bin = ((angle / TAU * 42.0) as i64).rem_euclid(42);
            for k in 0..7 {
                let b = (bin - 6 + k).rem_euclid(42) as usize;
                hx[b] += ggx;
                hy[b] += ggy;
            }
        }
    }
    let mut best = 0;
    for b in 1..42 {
        if hx[b] * hx[b] + hy[b] * hy[b] > hx[best] * hx[best] + hy[best] * hy[best] {
            best = b;
        }
    }
    py_mod(hy[best].atan2(hx[best]), TAU)
}

/// Oriented BRIEF: gradients sampled on a 16×16 grid rotated by
/// `orientation`, summed over the aggregation windows, then compared in pairs
fn descriptor(gx: &Plane, gy: &Plane, sx: i64, sy: i64, orientation: f64) -> [u8; 16] {
    let span = (2 * DESC_N + 2) as usize;
    let (cos_o, sin_o) = (orientation.cos(), orientation.sin());
    let (fx, fy) = (sx as f64 / 65536.0, sy as f64 / 65536.0);
    // Column-major (x outer), as the aggregation table expects
    let mut rgx = vec![0.0; span * span];
    let mut rgy = vec![0.0; span * span];
    for xi in 0..span {
        let xl = (xi as i64 - DESC_N) as f64;
        for yi in 0..span {
            let yl = (yi as i64 - DESC_N) as f64;
            let px = (fx + xl * cos_o - yl * sin_o).floor();
            let py = (fy + xl * sin_o + yl * cos_o).floor();
            let (gxv, gyv) = if px >= 0.0 && px < gx.w as f64 && py >= 0.0 && py < gx.h as f64 {
                (
                    gx.at(py as usize, px as usize),
                    gy.at(py as usize, px as usize),
                )
            } else {
                // A flat extension has no gradient
                (0.0, 0.0)
            };
            rgx[xi * span + yi] = cos_o * gxv + sin_o * gyv;
            rgy[xi * span + yi] = cos_o * gyv - sin_o * gxv;
        }
    }
    let mut samples = [0.0; 2 * AGGR_TABLE.len()];
    for (k, &(size, dx_off, dy_off)) in AGGR_TABLE.iter().enumerate() {
        let w = WIN_SIZES[size];
        let x0 = (dx_off + DESC_N) as usize;
        let y0 = (dy_off + DESC_N) as usize;
        let (mut sum_x, mut sum_y) = (0.0, 0.0);
        for xx in 0..w {
            let base = (x0 + xx) * span + y0;
            sum_x += rgx[base..base + w].iter().fold(0.0, |acc, v| acc + v);
            sum_y += rgy[base..base + w].iter().fold(0.0, |acc, v| acc + v);
        }
        samples[2 * k] = sum_x;
        samples[2 * k + 1] = sum_y;
    }
    let mut out = [0u8; 16];
    for (j, &(a, b)) in BRIEF_TABLE.iter().enumerate() {
        if samples[a as usize] > samples[b as usize] {
            out[j / 8] |= 1 << (j % 8);
        }
    }
    out
}

/// Keypoints and descriptors of one 112×112 frame
pub fn extract(image: &[u8]) -> Result<Frame> {
    ensure!(
        image.len() == SIDE * SIDE,
        "a frame is {SIDE}×{SIDE} pixels, not {}",
        image.len()
    );
    let gauss = gaussian();
    struct Candidate {
        score: f64,
        tile: usize,
        sx: i64,
        sy: i64,
    }
    // Per tile: detect, refine, cull at the frame edge
    let mut grads = Vec::new();
    let mut pool = Vec::new();
    for i in 0..GRID {
        for j in 0..GRID {
            let tile = tile(image, i, j);
            grads.push(gradients(&tile, &gauss));
            let resp = doh(&tile, &gauss);
            for (score, x, y) in nms(&resp) {
                let Some((sx, sy)) = subpixel(&resp, x, y) else {
                    continue;
                };
                if inside_frame(sx, sy, i, j) {
                    pool.push(Candidate {
                        score,
                        tile: i * GRID + j,
                        sx,
                        sy,
                    });
                }
            }
        }
    }
    // The strongest frame-wide, then grouped by tile (stable sorts, as Python's)
    let found = pool.len();
    pool.sort_by(|a, b| b.score.total_cmp(&a.score));
    pool.truncate(FRAME_KP_CAP);
    pool.sort_by(|a, b| a.tile.cmp(&b.tile).then(b.score.total_cmp(&a.score)));

    let keypoints = pool
        .iter()
        .filter_map(|c| {
            let (gx, gy) = &grads[c.tile];
            let orientation = orientation(gx, gy, c.sx, c.sy);
            let descriptor = descriptor(gx, gy, c.sx, c.sy, orientation);
            let (oy, ox) = tile_origin(c.tile / GRID, c.tile % GRID);
            let (x, y) = (ox + (c.sx >> 16), oy + (c.sy >> 16));
            let range = MERGE_MARGIN..SIDE as i64 - MERGE_MARGIN;
            (range.contains(&x) && range.contains(&y)).then_some(Keypoint {
                x,
                y,
                orientation,
                descriptor,
            })
        })
        .collect();
    Ok(Frame {
        keypoints,
        pool: found,
    })
}

/// The WS-body framing. Its inter-section transforms are near-identity, or
/// `poses` when given (one per section pair, in header order)
fn ws_scaffold(poses: Option<&[Pose]>) -> Vec<u8> {
    let mut ws = vec![0u8; WS_SIZE];
    for (offset, chunk) in WS_SCAFFOLD_CHUNKS {
        let bytes: Vec<u8> = (0..chunk.len())
            .step_by(2)
            .map(|k| u8::from_str_radix(&chunk[k..k + 2], 16).expect("scaffold chunks are hex"))
            .collect();
        ws[offset..offset + bytes.len()].copy_from_slice(&bytes);
    }
    let records = pose_records(&ws);
    assert_eq!(
        records.len(),
        WS_SCAFFOLD_PRE_V30_RECORDS,
        "the WS scaffold patch found the wrong number of transforms"
    );
    for (k, &o) in records.iter().enumerate() {
        let mut body = Vec::with_capacity(16);
        match poses {
            Some(poses) => {
                // [b0][b1] at the record's start become the pair's fit counts
                ws[o - 2] = poses[k].inliers;
                ws[o - 1] = poses[k].quality;
                for v in poses[k].q16() {
                    body.extend(v.to_le_bytes());
                }
            }
            None => {
                for v in [0x10000_i32, 0, 1, 1] {
                    body.extend(v.to_le_bytes());
                }
            }
        }
        ws[o..o + 16].copy_from_slice(&body);
    }
    ws
}

/// Where the inter-section rigid transforms (a, b, tx, ty as Q16 i32) sit
/// outside the record areas. A record is [u8][u8][a][b][tx][ty]; the offsets
/// returned are of `a`. python-validity writes a = 1.0, b = 0, tx = ty = 1
/// over them: the chip's matcher skips a pure identity as its "unmatched"
/// sentinel, so a template whose sections share one geometry needs a
/// near-identity.
fn pose_records(ws: &[u8]) -> Vec<usize> {
    const ONE: i128 = 0x10000;
    let mut zones = Vec::new();
    let mut prev = 0;
    for base in V30_REGIONS {
        zones.push((prev, base));
        prev = base + V30_SECTION_BYTES;
    }
    zones.push((prev, ws.len()));

    let int_at =
        |at: usize| i32::from_le_bytes(ws[at..at + 4].try_into().expect("4 bytes")) as i128;
    // |a² + b² − 1| < 0.05 in Q16², exactly as Python compares an int with
    // ONE * ONE * 0.05
    let rigid = |a: i128, b: i128| (a * a + b * b - ONE * ONE).abs() * 20 < ONE * ONE;

    let mut found = Vec::new();
    for (z0, z1) in zones {
        let mut best = (0, 0);
        for start in z0..z1 {
            let (mut o, mut n) = (start, 0);
            while o + 18 <= z1 && rigid(int_at(o + 2), int_at(o + 6)) {
                n += 1;
                o += 18;
            }
            if n > best.0 {
                best = (n, start);
            }
        }
        let (n, start) = best;
        if n >= 2 {
            found.extend((0..n).map(|k| start + 18 * k + 2));
        }
    }
    found
}

/// TemplateId: K = SHA-256(ws_body), T1 = HMAC(K, info), TID = HMAC(K, T1 ‖
/// info), where info is "Template ID" padded with 32 zeros
pub fn template_id(ws_body: &[u8]) -> [u8; 32] {
    let mut info = b"Template ID".to_vec();
    info.extend([0u8; 32]);
    let key = Sha256::digest(ws_body);
    let hmac = |data: &[&[u8]]| {
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC takes any key size");
        for part in data {
            mac.update(part);
        }
        <[u8; 32]>::from(mac.finalize().into_bytes())
    };
    let t1 = hmac(&[&info]);
    hmac(&[&t1, &info])
}

/// The envelope (byte-identical to the DLL's sub_180036840): subtype,
/// version 3, payload size, trailer size; TLV 1 = WS body; TLV 2 = TemplateId;
/// 32 zeros
pub fn envelope(subtype: u16, ws_body: &[u8]) -> Vec<u8> {
    let tid = template_id(ws_body);
    let payload = 4 + ws_body.len() + 4 + tid.len();
    let mut out = Vec::with_capacity(ENVELOPE_SIZE);
    for v in [subtype, 3, payload as u16, 32, 1, ws_body.len() as u16] {
        out.extend(v.to_le_bytes());
    }
    out.extend(ws_body);
    for v in [2u16, tid.len() as u16] {
        out.extend(v.to_le_bytes());
    }
    out.extend(tid);
    out.extend([0u8; 32]);
    out
}

/// The envelope with section k holding `sections[k % len]`
pub fn assemble(sections: &[&[Keypoint]], subtype: u16) -> Vec<u8> {
    assemble_with(sections, subtype, None)
}

/// [`assemble`], with the section-pair poses written into the header when
/// given (see [`pose_table`])
pub fn assemble_with(sections: &[&[Keypoint]], subtype: u16, poses: Option<&[Pose]>) -> Vec<u8> {
    assert!(
        !sections.is_empty(),
        "a template needs at least one section"
    );
    let mut ws = ws_scaffold(poses);
    for (k, base) in V30_REGIONS.iter().enumerate() {
        let start = base - V30_DESC_LEN;
        let area = &mut ws[start..start + V30_SECTION_BYTES];
        area.fill(0);
        let records = area.as_chunks_mut::<18>().0;
        for (record, kp) in records.iter_mut().zip(sections[k % sections.len()]) {
            record[..16].copy_from_slice(&kp.descriptor);
            record[16] = kp.x as u8;
            record[17] = kp.y as u8;
        }
    }
    envelope(subtype, &ws)
}

/// The per-section values of the header's u32 table (offset 24): 76, 90, 86,
/// 89 in the Windows scaffold. Whether the chip reads them as a record count
/// is being tested.
pub fn section_counts(envelope: &[u8]) -> Result<[u32; 4]> {
    ensure!(
        envelope.len() == ENVELOPE_SIZE,
        "a MoH envelope is {ENVELOPE_SIZE} bytes, not {}",
        envelope.len()
    );
    let ws = &envelope[12..12 + WS_SIZE];
    Ok(std::array::from_fn(|k| {
        u32::from_le_bytes(ws[24 + 4 * k..28 + 4 * k].try_into().expect("4 bytes"))
    }))
}

/// The keypoints of each of an envelope's four sections (descriptor, x, y;
/// the orientation isn't stored), without the zero-filled unused records
pub fn sections(envelope: &[u8]) -> Result<Vec<Vec<Keypoint>>> {
    ensure!(
        envelope.len() == ENVELOPE_SIZE,
        "a MoH envelope is {ENVELOPE_SIZE} bytes, not {}",
        envelope.len()
    );
    let ws = &envelope[12..12 + WS_SIZE];
    Ok(V30_REGIONS
        .iter()
        .map(|base| {
            let start = base - V30_DESC_LEN;
            ws[start..start + V30_SECTION_BYTES]
                .as_chunks::<18>()
                .0
                .iter()
                .filter(|r| r.iter().any(|&b| b != 0))
                .map(|r| Keypoint {
                    x: r[16] as i64,
                    y: r[17] as i64,
                    orientation: 0.0,
                    descriptor: r[..16].try_into().expect("16 bytes"),
                })
                .collect()
        })
        .collect())
}

/// Picks placements for the template's sections: the four largest pools, in
/// capture order. This approximates the DLL, which picks by a learned quality
/// score and keeps only keypoints that agree across placements.
pub fn choose(frames: &[Frame]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..frames.len()).collect();
    order.sort_by(|&a, &b| frames[b].pool.cmp(&frames[a].pool));
    order.truncate(V30_REGIONS.len());
    order.sort();
    order
}

/// The envelope for `frames`, from the ones [`choose`] picks
pub fn template(frames: &[Frame], subtype: u16) -> Vec<u8> {
    let sections: Vec<&[Keypoint]> = choose(frames)
        .into_iter()
        .map(|k| frames[k].keypoints.as_slice())
        .collect();
    assemble(&sections, subtype)
}

/// The envelope a finger record was stored from, rebuilt from the record's
/// value as the sensor returns it (`0x49`): it finds TLV 1 (the WS body) and
/// TLV 2 (the TemplateId) and checks the TemplateId against the body, so a
/// rebuilt envelope is byte-exact or an error.
pub fn envelope_from_stored(subtype: u16, value: &[u8]) -> Result<Vec<u8>> {
    let mut tlv1 = vec![1, 0];
    tlv1.extend((WS_SIZE as u16).to_le_bytes());
    let tlv2 = [2, 0, 32, 0];
    let at = (0..value.len())
        .find(|&i| {
            value.len() >= i + 8 + WS_SIZE + 32
                && value[i..].starts_with(&tlv1)
                && value[i + 4 + WS_SIZE..].starts_with(&tlv2)
        })
        .context("no template body in the record value")?;
    let ws = &value[at + 4..at + 4 + WS_SIZE];
    let tid = &value[at + 8 + WS_SIZE..at + 8 + WS_SIZE + 32];
    ensure!(
        template_id(ws) == tid,
        "the record's TemplateId doesn't match its body"
    );
    Ok(envelope(subtype, ws))
}

/// [`template`], with the section poses estimated from the frames and the
/// placements chosen so that all of them register (see
/// [`crate::pose::choose_registered`]). Returns the envelope and the frame
/// indices used, or None when no four placements register. With
/// `write_poses` false the header keeps python-validity's near-identity (the
/// control for the same placements).
pub fn template_with_poses(
    frames: &[Frame],
    subtype: u16,
    write_poses: bool,
) -> Option<(Vec<u8>, Vec<usize>)> {
    let (used, poses) = choose_registered(frames)?;
    let sections: Vec<&[Keypoint]> = used
        .iter()
        .map(|&k| frames[k].keypoints.as_slice())
        .collect();
    let header = write_poses.then_some(poses.as_slice());
    Some((assemble_with(&sections, subtype, header), used))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    // Synthetic vectors from python-validity's moh_native (tools/moh_vectors.py)
    fn vectors() -> Value {
        serde_json::from_str(include_str!("../tests/vectors/moh.json")).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// tools/moh_vectors.py's `synthetic`: curved ridges plus LCG noise
    fn synthetic(spec: &Value) -> Vec<u8> {
        let p: Vec<i64> = spec
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_i64().unwrap())
            .collect();
        let (mut state, cx, cy, a, b, c) = (p[0] as u64, p[1], p[2], p[3], p[4], p[5]);
        let mut pixels = Vec::with_capacity(SIDE * SIDE);
        for y in 0..SIDE as i64 {
            for x in 0..SIDE as i64 {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let (dx, dy) = (x - cx, y - cy);
                let t = ((a * dx * dx + b * dy * dy + c * dx * dy) >> 5).rem_euclid(64);
                let ridge = if t < 32 { t } else { 63 - t };
                pixels.push((40 + ridge * 5 + (state >> 59) as i64) as u8);
            }
        }
        pixels
    }

    fn frames(v: &Value) -> Vec<Frame> {
        v["frames"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                let image = synthetic(&f["spec"]);
                assert_eq!(hex(&Sha256::digest(&image)), f["image_sha256"]);
                extract(&image).unwrap()
            })
            .collect()
    }

    #[test]
    fn frames_match_python_validity() {
        let v = vectors();
        for (frame, expected) in frames(&v).iter().zip(v["frames"].as_array().unwrap()) {
            assert_eq!(frame.pool as u64, expected["pool"].as_u64().unwrap());
            let keypoints: Vec<String> = frame
                .keypoints
                .iter()
                .map(|k| {
                    let mut row = vec![k.x as u8, k.y as u8];
                    row.extend(k.orientation.to_le_bytes());
                    row.extend(k.descriptor);
                    hex(&row)
                })
                .collect();
            let expected: Vec<&str> = expected["keypoints"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| k.as_str().unwrap())
                .collect();
            assert_eq!(keypoints.len(), expected.len());
            for (i, (got, want)) in keypoints.iter().zip(&expected).enumerate() {
                assert_eq!(got, want, "keypoint {i}");
            }
        }
    }

    #[test]
    fn envelope_matches_python_validity() {
        let v = vectors();
        let scaffold = ws_scaffold(None);
        assert_eq!(hex(&Sha256::digest(&scaffold)), v["scaffold_sha256"]);
        assert_eq!(hex(&template_id(&scaffold)), v["scaffold_template_id"]);

        let frames = frames(&v);
        let subtype = v["subtype"].as_u64().unwrap() as u16;
        let envelope = template(&frames, subtype);
        assert_eq!(envelope.len(), ENVELOPE_SIZE);
        assert_eq!(hex(&envelope[..16]), v["envelope_head"]);
        assert_eq!(hex(&envelope[envelope.len() - 80..]), v["envelope_tail"]);
        assert_eq!(hex(&Sha256::digest(&envelope)), v["envelope_sha256"]);
    }

    #[test]
    fn stored_envelopes_are_rebuilt_exactly() {
        let ws = ws_scaffold(None);
        let original = envelope(0x03, &ws);
        // The record value as stored, with a made-up wrapper around it
        let mut value = vec![0xaa; 24];
        value.extend(&original[8..original.len() - 32]);
        value.extend([0x55; 8]);
        assert_eq!(envelope_from_stored(0x03, &value).unwrap(), original);
        let tampered = value
            .iter()
            .enumerate()
            .map(|(i, &b)| if i == 600 { b ^ 1 } else { b })
            .collect::<Vec<_>>();
        assert!(envelope_from_stored(0x03, &tampered).is_err());
        assert!(envelope_from_stored(0x03, &value[..1000]).is_err());
        // Exactly the stored payload, no wrapper
        assert_eq!(
            envelope_from_stored(0x03, &original[8..original.len() - 32]).unwrap(),
            original
        );
    }

    #[test]
    fn chooses_the_four_largest_pools_in_capture_order() {
        let frames: Vec<Frame> = [480, 510, 300, 510, 495, 200]
            .into_iter()
            .map(|pool| Frame {
                keypoints: Vec::new(),
                pool,
            })
            .collect();
        assert_eq!(choose(&frames), [0, 1, 3, 4]);
        assert_eq!(choose(&frames[..3]), [0, 1, 2]);
    }

    #[test]
    fn solve2_matches_lapack_rounding() {
        // numpy.linalg.solve's result. Computing the multiplier as a10 / a00
        // instead of a10 * (1 / a00) changes the last bits here.
        let (x0, x1) = solve2([[7.0, 1.0], [5.0, 7.0]], [0.1, 0.2]).unwrap();
        assert_eq!((x0, x1), (0.011363636363636364, 0.020454545454545458));
        assert!(solve2([[0.0, 0.0], [0.0, 1.0]], [1.0, 1.0]).is_none());
    }

    #[test]
    fn python_float_modulo() {
        assert_eq!(py_mod(-0.5, TAU), TAU - 0.5);
        assert!(py_mod(-0.0, TAU).is_sign_positive());
        assert_eq!(py_mod(7.0, TAU), 7.0 - TAU);
    }
}
