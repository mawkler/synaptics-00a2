// SPDX-License-Identifier: LGPL-2.1-or-later
//! Host-side matcher: masked normalised cross-correlation of a probe against
//! the enrolled images, over rotations and all shifts. It separated this
//! sensor's 112×112 frames where libfprint's NBIS minutiae could not (M5).
//! Mirrors `tools/corr_check.py`.

use std::sync::Arc;

use anyhow::{ensure, Result};
use rustfft::{num_complex::Complex, Fft, FftPlanner};

pub const SIDE: usize = 112;
/// Zero-padded FFT size, so that shifts don't wrap around
const N: usize = 2 * SIDE;
/// Shifts whose overlap is smaller than this fraction of a frame are ignored
const MIN_OVERLAP: f64 = 0.35;
const ROTATIONS: std::ops::RangeInclusive<i32> = -6..=6;
const ROTATION_STEP_DEG: f64 = 5.0;
/// Accept at or above this score. M5b, 10 enrolled images: genuine ≥ 0.514
/// (18 attempts over 2 sessions), impostor ≤ 0.323 (35 attempts, 5 fingers),
/// ≤ 0.401 in a set-vs-set check.
pub const THRESHOLD: f64 = 0.46;

type Spectrum = Vec<Complex<f64>>;

struct Fft2 {
    forward: Arc<dyn Fft<f64>>,
    inverse: Arc<dyn Fft<f64>>,
}

impl Fft2 {
    fn new() -> Self {
        let mut planner = FftPlanner::new();
        Self {
            forward: planner.plan_fft_forward(N),
            inverse: planner.plan_fft_inverse(N),
        }
    }

    /// Rows, then columns, of an N×N array in row-major order
    fn transform(fft: &dyn Fft<f64>, data: &mut [Complex<f64>]) {
        for row in data.as_chunks_mut::<N>().0 {
            fft.process(row);
        }
        let mut column = vec![Complex::default(); N];
        for x in 0..N {
            for y in 0..N {
                column[y] = data[y * N + x];
            }
            fft.process(&mut column);
            for y in 0..N {
                data[y * N + x] = column[y];
            }
        }
    }

    /// Spectrum of a SIDE×SIDE image, zero-padded to N×N
    fn spectrum(&self, image: &[f64]) -> Spectrum {
        let mut data = vec![Complex::default(); N * N];
        for y in 0..SIDE {
            for x in 0..SIDE {
                data[y * N + x].re = image[y * SIDE + x];
            }
        }
        Self::transform(self.forward.as_ref(), &mut data);
        data
    }

    /// Circular cross-correlation of the images behind `a` and `b`
    fn correlate(&self, a: &Spectrum, b: &Spectrum) -> Vec<f64> {
        let mut data: Spectrum = a.iter().zip(b).map(|(x, y)| x * y.conj()).collect();
        Self::transform(self.inverse.as_ref(), &mut data);
        data.iter().map(|c| c.re / (N * N) as f64).collect()
    }
}

/// Rotates `image` about its centre with bilinear sampling; also returns
/// which output pixels came from inside the image
pub fn rotate(image: &[f64], degrees: f64) -> (Vec<f64>, Vec<f64>) {
    let (sin, cos) = degrees.to_radians().sin_cos();
    let centre = (SIDE as f64 - 1.0) / 2.0;
    let last = (SIDE - 1) as f64;
    let mut out = vec![0.0; SIDE * SIDE];
    let mut mask = vec![0.0; SIDE * SIDE];
    for y in 0..SIDE {
        for x in 0..SIDE {
            let (dx, dy) = (x as f64 - centre, y as f64 - centre);
            let (sx, sy) = (cos * dx + sin * dy + centre, -sin * dx + cos * dy + centre);
            let inside = (0.0..=last).contains(&sx) && (0.0..=last).contains(&sy);
            let x0 = (sx.floor().clamp(0.0, last - 1.0)) as usize;
            let y0 = (sy.floor().clamp(0.0, last - 1.0)) as usize;
            let fx = (sx - x0 as f64).clamp(0.0, 1.0);
            let fy = (sy - y0 as f64).clamp(0.0, 1.0);
            let at = |yy: usize, xx: usize| image[yy * SIDE + xx];
            out[y * SIDE + x] = at(y0, x0) * (1.0 - fx) * (1.0 - fy)
                + at(y0, x0 + 1) * fx * (1.0 - fy)
                + at(y0 + 1, x0) * (1.0 - fx) * fy
                + at(y0 + 1, x0 + 1) * fx * fy;
            mask[y * SIDE + x] = if inside { 1.0 } else { 0.0 };
        }
    }
    (out, mask)
}

/// The enrolled images of one finger, as stored in an FpPrint
#[derive(Debug, Default, PartialEq)]
pub struct Template {
    pub images: Vec<Vec<u8>>,
}

impl Template {
    const VERSION: u8 = 1;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![Self::VERSION, self.images.len() as u8];
        for image in &self.images {
            bytes.extend(image);
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= 2 && bytes[0] == Self::VERSION,
            "unknown template format"
        );
        let count = bytes[1] as usize;
        ensure!(
            bytes.len() == 2 + count * SIDE * SIDE,
            "template length doesn't match its image count"
        );
        Ok(Self {
            images: bytes[2..]
                .as_chunks::<{ SIDE * SIDE }>()
                .0
                .iter()
                .map(|image| image.to_vec())
                .collect(),
        })
    }
}

/// Per-template state: the spectra of each enrolled image and its square
pub struct Matcher {
    fft: Fft2,
    /// Spectrum of an all-ones mask (enrolled images are fully valid)
    full_mask: Spectrum,
    gallery: Vec<(Spectrum, Spectrum)>,
}

impl Matcher {
    pub fn new(template: &Template) -> Self {
        let fft = Fft2::new();
        let full_mask = fft.spectrum(&vec![1.0; SIDE * SIDE]);
        let gallery = template
            .images
            .iter()
            .map(|image| {
                let b: Vec<f64> = image.iter().map(|&p| p as f64).collect();
                let b2: Vec<f64> = b.iter().map(|v| v * v).collect();
                (fft.spectrum(&b), fft.spectrum(&b2))
            })
            .collect();
        Self {
            fft,
            full_mask,
            gallery,
        }
    }

    /// Best masked NCC of `probe` (SIDE×SIDE pixels) over rotations, shifts
    /// and enrolled images; -1 if nothing overlaps enough
    pub fn score(&self, probe: &[u8]) -> f64 {
        let probe: Vec<f64> = probe.iter().map(|&p| p as f64).collect();
        let steps: Vec<i32> = ROTATIONS.collect();
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(steps.len());
        // Scoped, so no thread outlives the call (the TOD loader may unload this module)
        std::thread::scope(|scope| {
            let workers: Vec<_> = steps
                .chunks(steps.len().div_ceil(threads))
                .map(|chunk| {
                    let probe = &probe;
                    scope.spawn(move || {
                        chunk
                            .iter()
                            .map(|&step| {
                                let (image, mask) = rotate(probe, step as f64 * ROTATION_STEP_DEG);
                                self.score_rotated(&image, &mask)
                            })
                            .fold(-1.0, f64::max)
                    })
                })
                .collect();
            workers.into_iter().map(|w| w.join().expect("matcher thread panicked")).fold(-1.0, f64::max)
        })
    }

    fn score_rotated(&self, a: &[f64], mask: &[f64]) -> f64 {
        let masked: Vec<f64> = a.iter().zip(mask).map(|(v, m)| v * m).collect();
        let squared: Vec<f64> = masked.iter().zip(a).map(|(m, v)| m * v).collect();
        let (fa, fa2, fma) = (
            self.fft.spectrum(&masked),
            self.fft.spectrum(&squared),
            self.fft.spectrum(mask),
        );
        // These depend only on the probe, as every enrolled image has a full mask
        let count = self.fft.correlate(&fma, &self.full_mask);
        let sum_a = self.fft.correlate(&fa, &self.full_mask);
        let sum_aa = self.fft.correlate(&fa2, &self.full_mask);
        let min_count = MIN_OVERLAP * (SIDE * SIDE) as f64;
        let mut best = -1.0f64;
        for (fb, fb2) in &self.gallery {
            let sum_b = self.fft.correlate(&fma, fb);
            let sum_bb = self.fft.correlate(&fma, fb2);
            let sum_ab = self.fft.correlate(&fa, fb);
            for k in 0..N * N {
                let c = count[k];
                if c <= min_count {
                    continue;
                }
                let covariance = sum_ab[k] - sum_a[k] * sum_b[k] / c;
                let variance =
                    (sum_aa[k] - sum_a[k] * sum_a[k] / c) * (sum_bb[k] - sum_b[k] * sum_b[k] / c);
                if variance > 0.0 {
                    best = best.max(covariance / variance.max(1e-9).sqrt());
                }
            }
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Expected values from tools/corr_check.py on the same synthetic images

    fn synth(seed: usize) -> Vec<f64> {
        let mut image = vec![0.0; SIDE * SIDE];
        for y in 0..SIDE {
            for x in 0..SIDE {
                image[y * SIDE + x] =
                    ((x * x * 7 + y * 13 + x * y * 3 + seed * 31 + (x / 5) * (y / 7) * seed) % 251)
                        as f64;
            }
        }
        image
    }

    /// `image` moved by (dx, dy) over unrelated content
    fn shifted(image: &[f64], dx: isize, dy: isize, seed: usize) -> Vec<f64> {
        let mut out = synth(seed);
        for y in 0..SIDE as isize {
            for x in 0..SIDE as isize {
                let (sx, sy) = (x - dx, y - dy);
                if (0..SIDE as isize).contains(&sx) && (0..SIDE as isize).contains(&sy) {
                    out[(y * SIDE as isize + x) as usize] =
                        image[(sy * SIDE as isize + sx) as usize];
                }
            }
        }
        out
    }

    fn bytes(image: &[f64]) -> Vec<u8> {
        image.iter().map(|&v| v as u8).collect()
    }

    fn assert_close(ours: f64, theirs: f64) {
        assert!(
            (ours - theirs).abs() < 1e-6,
            "{ours} vs python-side {theirs}"
        );
    }

    #[test]
    fn scores_match_corr_check() {
        let (g0, g1) = (synth(1), synth(2));
        let template = Template {
            images: vec![bytes(&g1), bytes(&g0)],
        };
        let matcher = Matcher::new(&template);
        assert_close(
            matcher.score(&bytes(&shifted(&g0, 9, -6, 5))),
            1.0000000000000013,
        );
        assert_close(
            Matcher::new(&Template {
                images: vec![bytes(&g0), bytes(&g1)],
            })
            .score(&bytes(&synth(7))),
            0.10151813857248324,
        );
        let mut noisy = shifted(&g0, -4, 3, 6);
        for y in 0..SIDE {
            for x in 0..SIDE {
                noisy[y * SIDE + x] += ((x * y + 3 * x) % 23) as f64;
            }
        }
        // corr_check rotated the float image, so compare at the same stage
        let (rotated, _) = rotate(&noisy, 12.0);
        let probe: Vec<f64> = rotated;
        let score = ROTATIONS
            .map(|step| {
                let (image, mask) = rotate(&probe, step as f64 * ROTATION_STEP_DEG);
                matcher.score_rotated(&image, &mask)
            })
            .fold(-1.0, f64::max);
        assert_close(score, 0.14193824573722225);
    }

    #[test]
    fn single_rotation_matches_corr_check() {
        let (g0, g1) = (synth(1), synth(2));
        let matcher = Matcher::new(&Template {
            images: vec![bytes(&g1)],
        });
        let (image, mask) = rotate(&shifted(&g0, 9, -6, 5), 10.0);
        assert_close(matcher.score_rotated(&image, &mask), 0.062054707113663385);
        let self_matcher = Matcher::new(&Template {
            images: vec![bytes(&g0)],
        });
        assert_close(
            self_matcher.score_rotated(&g0, &vec![1.0; SIDE * SIDE]),
            1.0000000000000013,
        );
    }

    #[test]
    fn template_round_trips() {
        let template = Template {
            images: vec![vec![7; SIDE * SIDE], vec![9; SIDE * SIDE]],
        };
        let bytes = template.to_bytes();
        assert_eq!(Template::from_bytes(&bytes).unwrap(), template);
        assert!(Template::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        assert!(Template::from_bytes(&[2, 0]).is_err());
    }
}
