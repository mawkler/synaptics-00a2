// SPDX-License-Identifier: LGPL-2.1-or-later
//! Rigid poses between the sections of a MoH template.
//!
//! The WS header holds one 18-byte record per section pair (i < j), in the
//! order (0,1) (0,2) (0,3) (1,2) (1,3) (2,3): `[u8 b0][u8 b1][a][b][tx][ty]`
//! with a, b, tx, ty as Q16 `i32`. The pose maps section i's keypoint
//! coordinates onto section j's: `p_j = R·p_i + t`, `R = [[a, -b], [b, a]]`
//! (a = cos θ, b = sin θ, about the coordinate origin).
//!
//! This follows the Windows DLL (`synaWudfBioUsb.dll`, decompiled):
//! `FUN_180006e10` solves the pose from two point pairs, `FUN_180007480` picks
//! the best pair by counting candidates within a squared distance of 8, and
//! `FUN_1800053e0` / `FUN_1800051f0` read and write the upper triangle. The
//! records are not known to be exact copies of the DLL's numbers. `b0` and
//! `b1` are taken to be an inlier count (valid above 30) and a mean error
//! (valid below 50); the DLL's own units for them are unverified.
//!
//! python-validity overwrites every record with a near-identity, which only
//! suits a template whose sections come from one placement.

use crate::moh::Keypoint;

/// Candidate correspondences kept for the pose search
const CANDIDATES: usize = 60;
/// Largest Hamming distance (of 128 bits) a candidate may have
const MAX_HAMMING: u32 = 40;
/// Squared distance, in frame pixels, within which a point agrees with a pose
const INLIER_R2: f64 = 9.0;
/// Valid records have more than this many inliers (DLL: `0x1e < b0`)
const MIN_INLIERS: usize = 30;
/// Valid records have a quality byte below this (DLL: `b1 < 0x32`)
const MAX_QUALITY: u8 = 50;
/// Quality byte per pixel of mean error (a guess, see the module notes)
const QUALITY_PER_PX: f64 = 32.0;

type Pt = (f64, f64);
/// A keypoint of section i with its counterpart in section j
type Pair = (Pt, Pt);

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Pose {
    pub inliers: u8,
    pub quality: u8,
    /// Radians
    pub theta: f64,
    pub tx: f64,
    pub ty: f64,
}

impl Pose {
    /// a, b, tx, ty as the header stores them
    pub fn q16(&self) -> [i32; 4] {
        let q = |v: f64| (v * 65536.0).round() as i32;
        [
            q(self.theta.cos()),
            q(self.theta.sin()),
            q(self.tx),
            q(self.ty),
        ]
    }

    fn apply(&self, (x, y): Pt) -> Pt {
        let (s, c) = self.theta.sin_cos();
        (c * x - s * y + self.tx, s * x + c * y + self.ty)
    }
}

/// Rigid transform from two point pairs (`FUN_180006e10`): the rotation takes
/// the vector p0→p1 onto q0→q1, and the translation centres the pairs
fn from_two(p: [Pt; 2], q: [Pt; 2]) -> Option<Pose> {
    let dp = (p[1].0 - p[0].0, p[1].1 - p[0].1);
    let dq = (q[1].0 - q[0].0, q[1].1 - q[0].1);
    let cross = dp.0 * dq.1 - dp.1 * dq.0;
    let dot = dp.0 * dq.0 + dp.1 * dq.1;
    let n = cross.hypot(dot);
    if n < 1e-9 {
        return None;
    }
    let (s, c) = (cross / n, dot / n);
    let tx = (q[0].0 + q[1].0 - (c * (p[0].0 + p[1].0) - s * (p[0].1 + p[1].1))) / 2.0;
    let ty = (q[0].1 + q[1].1 - (s * (p[0].0 + p[1].0) + c * (p[0].1 + p[1].1))) / 2.0;
    Some(Pose {
        inliers: 0,
        quality: 0,
        theta: s.atan2(c),
        tx,
        ty,
    })
}

/// Least-squares rigid transform over matched points (Kabsch, no scale)
fn least_squares(pairs: &[Pair]) -> Pose {
    let n = pairs.len() as f64;
    let mean = |f: fn(&Pair) -> f64| pairs.iter().map(f).sum::<f64>() / n;
    let (pcx, pcy) = (mean(|p| p.0 .0), mean(|p| p.0 .1));
    let (qcx, qcy) = (mean(|p| p.1 .0), mean(|p| p.1 .1));
    let (mut sxx, mut sxy, mut syx, mut syy) = (0.0, 0.0, 0.0, 0.0);
    for &((px, py), (qx, qy)) in pairs {
        let (px, py, qx, qy) = (px - pcx, py - pcy, qx - qcx, qy - qcy);
        sxx += px * qx;
        sxy += px * qy;
        syx += py * qx;
        syy += py * qy;
    }
    let theta = (sxy - syx).atan2(sxx + syy);
    let (s, c) = theta.sin_cos();
    Pose {
        inliers: 0,
        quality: 0,
        theta,
        tx: qcx - (c * pcx - s * pcy),
        ty: qcy - (s * pcx + c * pcy),
    }
}

fn point(k: &Keypoint) -> Pt {
    (k.x as f64, k.y as f64)
}

fn dist2(a: Pt, b: Pt) -> f64 {
    (a.0 - b.0).powi(2) + (a.1 - b.1).powi(2)
}

fn hamming(a: &[u8; 16], b: &[u8; 16]) -> u32 {
    a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

/// Whether `pose` is usable as a header record
pub fn valid(pose: &Pose) -> bool {
    pose.inliers as usize > MIN_INLIERS && pose.quality < MAX_QUALITY
}

/// How far the pose i→k is from i→j followed by j→k: degrees, then pixels
pub fn closure_error(ij: &Pose, jk: &Pose, ik: &Pose) -> (f64, f64) {
    let (s, c) = jk.theta.sin_cos();
    let (x, y) = (c * ij.tx - s * ij.ty + jk.tx, s * ij.tx + c * ij.ty + jk.ty);
    let dth = (ij.theta + jk.theta - ik.theta + std::f64::consts::PI)
        .rem_euclid(std::f64::consts::TAU)
        - std::f64::consts::PI;
    (dth.to_degrees().abs(), (x - ik.tx).hypot(y - ik.ty))
}

/// The pose taking section `a`'s keypoints onto `b`'s, or None when the two
/// placements don't overlap well enough (fewer than 4 agreeing candidates)
pub fn register(a: &[Keypoint], b: &[Keypoint]) -> Option<Pose> {
    // Each of a's keypoints with its closest descriptor in b
    let mut best: Vec<(u32, usize, usize)> = a
        .iter()
        .enumerate()
        .filter_map(|(i, ka)| {
            b.iter()
                .enumerate()
                .map(|(j, kb)| (hamming(&ka.descriptor, &kb.descriptor), i, j))
                .min_by_key(|&(h, _, j)| (h, j))
        })
        .filter(|&(h, _, _)| h <= MAX_HAMMING)
        .collect();
    best.sort_by_key(|&(h, i, _)| (h, i));
    best.truncate(CANDIDATES);
    let pairs: Vec<_> = best
        .iter()
        .map(|&(_, i, j)| (point(&a[i]), point(&b[j])))
        .collect();

    let agree = |pose: &Pose, pairs: &[Pair]| {
        pairs
            .iter()
            .filter(|&&(p, q)| dist2(pose.apply(p), q) <= INLIER_R2)
            .count()
    };
    let mut top: Option<(usize, Pose)> = None;
    for u in 0..pairs.len() {
        for v in u + 1..pairs.len() {
            let Some(pose) = from_two([pairs[u].0, pairs[v].0], [pairs[u].1, pairs[v].1]) else {
                continue;
            };
            let n = agree(&pose, &pairs);
            if top.is_none_or(|(m, _)| n > m) {
                top = Some((n, pose));
            }
        }
    }
    let (n, mut pose) = top?;
    if n < 4 {
        return None;
    }
    for _ in 0..5 {
        let inliers: Vec<_> = pairs
            .iter()
            .copied()
            .filter(|&(p, q)| dist2(pose.apply(p), q) <= INLIER_R2)
            .collect();
        if inliers.len() < 3 {
            break;
        }
        pose = least_squares(&inliers);
    }

    // Count every keypoint of a that lands on one of b's
    let near: Vec<f64> = a
        .iter()
        .map(|ka| {
            let p = pose.apply(point(ka));
            b.iter()
                .map(|kb| dist2(p, point(kb)))
                .fold(f64::INFINITY, f64::min)
        })
        .filter(|&d| d <= INLIER_R2)
        .collect();
    let mean_err = if near.is_empty() {
        0.0
    } else {
        near.iter().map(|d| d.sqrt()).sum::<f64>() / near.len() as f64
    };
    pose.inliers = near.len().min(255) as u8;
    pose.quality = ((mean_err * QUALITY_PER_PX).round() as u8).min(MAX_QUALITY - 1);
    Some(pose)
}

/// Closure error beyond which three placements don't fit one rigid story
const MAX_CLOSURE: (f64, f64) = (2.0, 3.0);

/// Four placements, in capture order, whose six pairs all register and whose
/// poses agree with each other (i→j→k = i→k), with the largest total pool.
/// Returns their indices and the six poses in header order. Like the DLL's
/// enrollment, which only takes a placement that registers against the ones
/// it holds.
pub fn choose_registered(frames: &[crate::moh::Frame]) -> Option<(Vec<usize>, Vec<Pose>)> {
    let n = frames.len();
    let mut reg = vec![vec![None; n]; n];
    for i in 0..n {
        for j in i + 1..n {
            reg[i][j] = register(&frames[i].keypoints, &frames[j].keypoints).filter(valid);
        }
    }
    let mut best: Option<(usize, Vec<usize>)> = None;
    for a in 0..n {
        for b in a + 1..n {
            for c in b + 1..n {
                for d in c + 1..n {
                    let set = [a, b, c, d];
                    let poses = |x: usize, y: usize| reg[set[x]][set[y]].as_ref();
                    let all = (0..4).all(|x| (x + 1..4).all(|y| poses(x, y).is_some()));
                    if !all {
                        continue;
                    }
                    let closes =
                        [(0, 1, 2), (0, 1, 3), (0, 2, 3), (1, 2, 3)]
                            .iter()
                            .all(|&(i, j, k)| {
                                let (dth, dt) = closure_error(
                                    poses(i, j).unwrap(),
                                    poses(j, k).unwrap(),
                                    poses(i, k).unwrap(),
                                );
                                dth <= MAX_CLOSURE.0 && dt <= MAX_CLOSURE.1
                            });
                    let pools: usize = set.iter().map(|&k| frames[k].pool).sum();
                    if closes && best.as_ref().is_none_or(|(p, _)| pools > *p) {
                        best = Some((pools, set.to_vec()));
                    }
                }
            }
        }
    }
    let (_, set) = best?;
    let mut table = Vec::with_capacity(6);
    for x in 0..4 {
        for y in x + 1..4 {
            table.push(reg[set[x]][set[y]]?);
        }
    }
    Some((set, table))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scatter of keypoints with distinct descriptors, and the same
    /// scatter moved by `pose` (descriptors kept, as for one real finger)
    fn scene(pose: &Pose) -> (Vec<Keypoint>, Vec<Keypoint>) {
        let mut state = 0x2545F4914F6CDD1D_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let a: Vec<Keypoint> = (0..120)
            .map(|_| {
                let r = next();
                let mut descriptor = [0u8; 16];
                descriptor[..8].copy_from_slice(&next().to_le_bytes());
                descriptor[8..].copy_from_slice(&next().to_le_bytes());
                Keypoint {
                    x: 10 + (r % 90) as i64,
                    y: 10 + ((r >> 16) % 90) as i64,
                    orientation: 0.0,
                    descriptor,
                }
            })
            .collect();
        let b = a
            .iter()
            .map(|k| {
                let (x, y) = pose.apply(point(k));
                Keypoint {
                    x: x.round() as i64,
                    y: y.round() as i64,
                    ..k.clone()
                }
            })
            .collect();
        (a, b)
    }

    #[test]
    fn recovers_a_known_pose() {
        let want = Pose {
            inliers: 0,
            quality: 0,
            theta: 5.0_f64.to_radians(),
            tx: -12.0,
            ty: 20.0,
        };
        let (a, b) = scene(&want);
        let got = register(&a, &b).expect("registers");
        assert!((got.theta - want.theta).abs() < 0.01, "{got:?}");
        assert!((got.tx - want.tx).abs() < 1.0 && (got.ty - want.ty).abs() < 1.0);
        assert!(got.inliers as usize > MIN_INLIERS);
        assert!(got.quality < MAX_QUALITY);
    }

    #[test]
    fn unrelated_sections_do_not_register() {
        let (a, _) = scene(&Pose {
            inliers: 0,
            quality: 0,
            theta: 0.0,
            tx: 0.0,
            ty: 0.0,
        });
        let mut other = a.clone();
        for k in &mut other {
            k.descriptor.iter_mut().for_each(|d| *d = !*d);
        }
        assert!(register(&a, &other).is_none());
    }

    #[test]
    fn q16_keeps_unit_rotation() {
        let p = Pose {
            inliers: 90,
            quality: 33,
            theta: -0.0614,
            tx: -23.5,
            ty: -23.6,
        };
        let [a, b, tx, ty] = p.q16();
        assert!((((a as f64).powi(2) + (b as f64).powi(2)).sqrt() / 65536.0 - 1.0).abs() < 1e-4);
        assert_eq!((tx, ty), (-1540096, -1546650));
    }
}
