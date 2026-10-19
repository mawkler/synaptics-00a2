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
/// Accept at or above this score (with [`PREPARE`]). Cross-session evaluation
/// on 2026-10-19, galleries of 5–10 images from one session: genuine ≥ 0.361
/// (71 attempts of one finger over two days, 65 at or above 0.42), impostor
/// ≤ 0.367 (633 attempts, 7 fingers, 99th percentile 0.347).
pub const THRESHOLD: f64 = 0.42;

type Spectrum = Vec<Complex<f64>>;

/// How images are prepared before correlation, mirroring the variants
/// evaluated on 2026-10-19 (cross-session scores fell with raw images)
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Prepare {
    Raw,
    /// A `smooth`×`smooth` box blur, then local contrast normalisation over a
    /// `window`×`window` box: zero mean and unit variance, mapped to 128 ± 48
    /// and clipped to 0..255
    Normalise {
        smooth: usize,
        window: usize,
    },
}

/// Best worst-case cross-session gap for single-session templates (+0.06,
/// against −0.04 raw), and the lowest impostor scores of the variants tried
pub const PREPARE: Prepare = Prepare::Normalise {
    smooth: 3,
    window: 21,
};

/// Mean over a k×k window (k odd), with numpy's "reflect" padding (the edge
/// pixel is not repeated)
fn box_mean(image: &[f64], k: usize) -> Vec<f64> {
    let half = (k / 2) as isize;
    let last = SIDE as isize - 1;
    let reflect = |i: isize| -> usize {
        let i = if i < 0 { -i } else { i };
        (if i > last { 2 * last - i } else { i }) as usize
    };
    // Separable: rows, then columns
    let mut rows = vec![0.0; SIDE * SIDE];
    for y in 0..SIDE {
        for x in 0..SIDE {
            let sum: f64 = (-half..=half)
                .map(|d| image[y * SIDE + reflect(x as isize + d)])
                .sum();
            rows[y * SIDE + x] = sum;
        }
    }
    let mut out = vec![0.0; SIDE * SIDE];
    for y in 0..SIDE {
        for x in 0..SIDE {
            let sum: f64 = (-half..=half)
                .map(|d| rows[reflect(y as isize + d) * SIDE + x])
                .sum();
            out[y * SIDE + x] = sum / (k * k) as f64;
        }
    }
    out
}

pub fn prepare(image: &[f64], how: Prepare) -> Vec<f64> {
    let Prepare::Normalise { smooth, window } = how else {
        return image.to_vec();
    };
    let image = box_mean(image, smooth);
    let squared: Vec<f64> = image.iter().map(|v| v * v).collect();
    let (mean, mean_sq) = (box_mean(&image, window), box_mean(&squared, window));
    image
        .iter()
        .zip(mean.iter().zip(&mean_sq))
        .map(|(v, (m, m2))| {
            (128.0 + 48.0 * (v - m) / (m2 - m * m).max(1e-6).sqrt()).clamp(0.0, 255.0)
        })
        .collect()
}

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
    prepare: Prepare,
    fft: Fft2,
    /// Spectrum of an all-ones mask (enrolled images are fully valid)
    full_mask: Spectrum,
    gallery: Vec<(Spectrum, Spectrum)>,
}

impl Matcher {
    pub fn new(template: &Template) -> Self {
        Self::with(template, PREPARE)
    }

    pub fn with(template: &Template, how: Prepare) -> Self {
        let fft = Fft2::new();
        let full_mask = fft.spectrum(&vec![1.0; SIDE * SIDE]);
        let gallery = template
            .images
            .iter()
            .map(|image| {
                let raw: Vec<f64> = image.iter().map(|&p| p as f64).collect();
                let b = prepare(&raw, how);
                let b2: Vec<f64> = b.iter().map(|v| v * v).collect();
                (fft.spectrum(&b), fft.spectrum(&b2))
            })
            .collect();
        Self {
            prepare: how,
            fft,
            full_mask,
            gallery,
        }
    }

    /// Best masked NCC of `probe` (SIDE×SIDE pixels) over rotations, shifts
    /// and enrolled images; -1 if nothing overlaps enough
    pub fn score(&self, probe: &[u8]) -> f64 {
        let raw: Vec<f64> = probe.iter().map(|&p| p as f64).collect();
        let probe = prepare(&raw, self.prepare);
        let steps: Vec<i32> = ROTATIONS.collect();
        let threads = std::thread::available_parallelism()
            .map_or(1, |n| n.get())
            .min(steps.len());
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
            workers
                .into_iter()
                .map(|w| w.join().expect("matcher thread panicked"))
                .fold(-1.0, f64::max)
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

    /// The tests below predate `Prepare`; their expected values are for raw images
    fn raw(template: &Template) -> Matcher {
        Matcher::with(template, Prepare::Raw)
    }

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
        let matcher = raw(&template);
        assert_close(
            matcher.score(&bytes(&shifted(&g0, 9, -6, 5))),
            1.0000000000000013,
        );
        assert_close(
            raw(&Template {
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
        let matcher = raw(&Template {
            images: vec![bytes(&g1)],
        });
        let (image, mask) = rotate(&shifted(&g0, 9, -6, 5), 10.0);
        assert_close(matcher.score_rotated(&image, &mask), 0.062054707113663385);
        let self_matcher = raw(&Template {
            images: vec![bytes(&g0)],
        });
        assert_close(
            self_matcher.score_rotated(&g0, &vec![1.0; SIDE * SIDE]),
            1.0000000000000013,
        );
    }

    #[test]
    fn prepare_matches_the_python_variants() {
        let g0 = synth(1);
        let k15 = prepare(
            &g0,
            Prepare::Normalise {
                smooth: 3,
                window: 15,
            },
        );
        assert!((k15.iter().sum::<f64>() - 1606009.4402667657).abs() < 1e-6);
        for (ours, theirs) in k15[..4].iter().zip([
            0.0,
            0.5624624754406113,
            41.89375882595071,
            108.55068355476556,
        ]) {
            assert_close(*ours, theirs);
        }
        assert_close(k15[SIDE * SIDE - 1], 49.94985297000002);
        let k21 = prepare(
            &g0,
            Prepare::Normalise {
                smooth: 3,
                window: 21,
            },
        );
        assert!((k21.iter().sum::<f64>() - 1605875.0858124434).abs() < 1e-6);
        assert_eq!(prepare(&g0, Prepare::Raw), g0);

        let template = Template {
            images: vec![bytes(&synth(1)), bytes(&synth(2))],
        };
        let matcher = Matcher::with(
            &template,
            Prepare::Normalise {
                smooth: 3,
                window: 15,
            },
        );
        assert_close(matcher.score(&bytes(&synth(7))), 0.12662702047552413);
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
