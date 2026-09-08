//! A secure random number generator that is safe to use for cryptographic purposes.
//! It is intentionally opinionated so that developers don't have to think about what Rng they should use
//! for cryptographic purposes.
//!
//! Internally it uses `ChaCha20Rng` from the RustCrypto `chacha20` crate (via `rand`), which supports zeroization.
use std::convert::Infallible;

use rand::{rngs::SysRng, Rng, SeedableRng, TryCryptoRng, TryRng};
use vitaminc_protected::Controlled;
use zeroize::Zeroize;

/// A secure random number generator that is safe to use for cryptographic purposes.
pub struct SafeRand(rand::rngs::ChaCha20Rng);

impl SafeRand {
    /// A uniformly distributed value in `0..n`: at least `0`, strictly below
    /// `n`. This is the bound every index-shaped use wants (`n` items, pick
    /// one) and the one `std` and `rand` ranges use.
    ///
    /// Exactly one 64-bit draw per call, reduced with Lemire's multiply-high
    /// method: no rejection loop and no branch on the value drawn, so the
    /// number of draws does not depend on the values drawn. That matters when
    /// the generator is seeded from secret material, as in permutation-key
    /// derivation, where a rejection loop's retry count would leak through
    /// timing.
    ///
    /// The reduction's statistical distance from uniform is at most
    /// `n / 2⁶⁴`: below 2⁻⁵⁵ for `n ≤ 256` and still at most 2⁻³² at
    /// `n = u32::MAX`. A protocol that needs exact uniformity must account
    /// for that term.
    ///
    /// The bound may be a plain `u32` or a [`Protected<u32>`]; this is the
    /// [`BoundedRng::next_below`] trait method, reachable here without
    /// importing the trait.
    ///
    /// # Panics
    ///
    /// Panics if `n == 0`: the range `0..0` is empty and has no value to
    /// return. Callers that compute `n` should check it first.
    ///
    /// [`Protected<u32>`]: vitaminc_protected::Protected
    /// [`BoundedRng::next_below`]: crate::BoundedRng::next_below
    pub fn next_below<T>(&mut self, n: T) -> T
    where
        Self: crate::BoundedRng<T>,
    {
        <Self as crate::BoundedRng<T>>::next_below(self, n)
    }

    /// A uniformly distributed value in `0..=max`, for every `max` up to and
    /// including `u32::MAX`, with the same fixed-count draw and the same
    /// `(max + 1) / 2⁶⁴` bias bound as [`next_below`](Self::next_below).
    ///
    /// Deprecated: earlier versions honoured the inclusive bound only when
    /// `max` was not a power of two and were exclusive otherwise, so callers
    /// written against either meaning were wrong for some inputs
    /// (cipherstash/vitaminc#198). The equivalent call is
    /// `next_below(max + 1)` (for `max == u32::MAX` that is the whole word:
    /// use [`Rng::next_u32`](rand::Rng::next_u32)), or `next_below(n)` when
    /// the caller has a length `n` rather than a maximum.
    #[deprecated(
        note = "inclusive `0..=max`; use `next_below(max + 1)`, or `next_below(n)` when you have a length `n`"
    )]
    pub fn next_bounded_u32(&mut self, max: u32) -> u32 {
        crate::bounded::upto_u32(self, max)
    }

    /// Creates a new `SafeRand` seeded from the OS random number generator.
    pub fn from_entropy() -> Result<Self, crate::RandomError> {
        Ok(Self::try_from_rng(&mut SysRng)?)
    }

    /// A safer alternative to `from_seed` that the seed is zeroized after use.
    pub fn from_controlled_seed<C>(seed: C) -> Self
    where
        C: Controlled<Inner = [u8; 32]>,
    {
        let mut seed = seed.risky_unwrap();
        let rng = Self(rand::rngs::ChaCha20Rng::from_seed(seed));
        seed.zeroize();
        rng
    }
}

impl TryCryptoRng for SafeRand {}

impl TryRng for SafeRand {
    type Error = Infallible;

    #[inline]
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }

    #[inline]
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }

    #[inline]
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(dst);
        Ok(())
    }
}

impl SeedableRng for SafeRand {
    // TODO: This should be a ProtectedSeed! Maybe a GAT?
    type Seed = [u8; 32];

    fn from_seed(seed: Self::Seed) -> Self {
        Self(rand::rngs::ChaCha20Rng::from_seed(seed))
    }
}

#[cfg(test)]
mod tests {
    use super::SafeRand;
    use rand::{rngs::ChaCha20Rng, Rng, SeedableRng, TryRng};

    const SEED: [u8; 32] = [7u8; 32];

    /// `SafeRand` is a transparent wrapper: for the same seed it must yield
    /// exactly the ChaCha20 stream, word for word and byte for byte. Pins the
    /// `TryRng` impl to real output rather than to "some value", which is
    /// what a mutant returning a constant would otherwise pass as.
    #[test]
    fn try_rng_yields_the_chacha20_stream_for_the_seed() {
        let mut safe = SafeRand::from_seed(SEED);
        let mut reference = ChaCha20Rng::from_seed(SEED);

        for _ in 0..4 {
            assert_eq!(safe.try_next_u32().unwrap(), reference.next_u32());
        }
        for _ in 0..4 {
            assert_eq!(safe.try_next_u64().unwrap(), reference.next_u64());
        }
        let mut got = [0u8; 40];
        let mut want = [0u8; 40];
        safe.try_fill_bytes(&mut got).unwrap();
        reference.fill_bytes(&mut want);
        assert_eq!(got, want);
        assert_ne!(got, [0u8; 40], "fill_bytes must write the buffer");
    }

    /// What `next_below` promises, spelled out over the same seed: one
    /// 64-bit draw, multiplied by `n`, high word kept. Comparing exact values
    /// (not just `< n`) pins the draw width, the reduction, and that exactly
    /// one draw is consumed per call, at powers of two, their neighbours, and
    /// both ends of the `u32` range.
    fn reference_below(rng: &mut ChaCha20Rng, n: u64) -> u32 {
        ((u128::from(rng.next_u64()) * u128::from(n)) >> 64) as u32
    }

    const BOUNDS: [u32; 14] = [
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        16,
        100,
        1000,
        (1 << 31) - 1,
        1 << 31,
        (1 << 31) + 1,
        u32::MAX,
    ];

    #[test]
    fn next_below_matches_the_lemire_reference() {
        for n in BOUNDS {
            let mut safe = SafeRand::from_seed(SEED);
            let mut reference = ChaCha20Rng::from_seed(SEED);
            for _ in 0..256 {
                let got = safe.next_below(n);
                assert_eq!(
                    got,
                    reference_below(&mut reference, u64::from(n)),
                    "n = {n}"
                );
                assert!(got < n, "n = {n}");
            }
        }
    }

    /// The deprecated inclusive form is `next_below(max + 1)` for every
    /// `max`, including `u32::MAX`, where `max + 1` does not fit a `u32`.
    #[test]
    #[allow(deprecated)]
    fn next_bounded_u32_is_the_inclusive_form_of_next_below() {
        for max in BOUNDS.map(|n| n - 1) {
            let mut safe = SafeRand::from_seed(SEED);
            let mut reference = ChaCha20Rng::from_seed(SEED);
            for _ in 0..256 {
                let got = safe.next_bounded_u32(max);
                assert_eq!(
                    got,
                    reference_below(&mut reference, u64::from(max) + 1),
                    "max = {max}"
                );
                assert!(got <= max, "max = {max}");
            }
        }
    }

    /// Every value in `0..n` is reachable and `n` itself never is; the
    /// power-of-two case is the one the old code got wrong.
    #[test]
    fn next_below_covers_exactly_the_half_open_range() {
        for n in [5usize, 8] {
            let mut rng = SafeRand::from_seed(SEED);
            let mut seen = vec![false; n + 1];
            for _ in 0..512 {
                seen[rng.next_below(n as u32) as usize] = true;
            }
            assert!(seen[..n].iter().all(|&s| s), "n = {n}");
            assert!(!seen[n], "n = {n}");
        }
    }

    #[test]
    #[should_panic(expected = "range must be non-zero")]
    fn next_below_zero_panics() {
        SafeRand::from_seed(SEED).next_below(0);
    }

    #[test]
    fn different_seeds_diverge_and_the_same_seed_repeats() {
        let mut a = SafeRand::from_seed(SEED);
        let mut b = SafeRand::from_seed(SEED);
        let mut c = SafeRand::from_seed([8u8; 32]);
        let (x, y, z) = (
            a.try_next_u64().unwrap(),
            b.try_next_u64().unwrap(),
            c.try_next_u64().unwrap(),
        );
        assert_eq!(x, y);
        assert_ne!(x, z);
    }

    #[test]
    fn next_below_from_entropy_is_half_open() -> Result<(), crate::RandomError> {
        let mut rng = SafeRand::from_entropy()?;
        for n in [1, 2, 4, 5, 52, 62, 64, 94, u32::MAX] {
            for _ in 0..1000 {
                assert!(rng.next_below(n) < n);
            }
        }
        Ok(())
    }

    #[test]
    fn next_below_is_uniform() {
        // Chi-squared test over a non-power-of-two range with a fixed seed.
        // Would catch a modulo-style bias or a broken reduction.
        const RANGE: u32 = 5;
        const SAMPLES: u32 = 100_000;
        let mut rng = SafeRand::from_seed([3u8; 32]);
        let mut counts = [0u32; RANGE as usize];
        for _ in 0..SAMPLES {
            counts[rng.next_below(RANGE) as usize] += 1;
        }
        let expected = f64::from(SAMPLES) / f64::from(RANGE);
        let chi2: f64 = counts
            .iter()
            .map(|&c| {
                let d = f64::from(c) - expected;
                d * d / expected
            })
            .sum();
        // 4 degrees of freedom; p = 0.001 critical value is 18.47. The seed is
        // fixed, so this is deterministic — no flakiness.
        assert!(chi2 < 18.47, "chi-squared too high: {chi2}");
    }
}
