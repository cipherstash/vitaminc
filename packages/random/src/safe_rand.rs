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
    /// Sampling is by rejection over the next power of two, so there is no
    /// modulo bias for any `n`, including `n == u32::MAX`; the expected
    /// number of 32-bit draws is below two.
    ///
    /// # Panics
    ///
    /// Panics if `n == 0`: the range `0..0` is empty and has no value to
    /// return. Callers that compute `n` should check it first. Also panics
    /// if the generator rejects 128 draws in a row, which has probability
    /// below 2⁻¹²⁸ for a working generator and so only ever means the
    /// generator is broken.
    pub fn next_below(&mut self, n: u32) -> u32 {
        assert!(n != 0, "SafeRand::next_below: the range 0..0 is empty");
        below(&mut self.0, u64::from(n))
    }

    /// A uniformly distributed value in `0..=max`.
    ///
    /// Deprecated: earlier versions applied the inclusive bound only when
    /// `max` was not a power of two and were exclusive otherwise, so callers
    /// written against either meaning were wrong for some inputs
    /// (cipherstash/vitaminc#321). This now does what its doc always said,
    /// for every `max` up to and including `u32::MAX`. New code should use
    /// [`next_below`](Self::next_below), whose bound matches how indices are
    /// counted.
    #[deprecated(note = "use `next_below(n)` for a value in `0..n`; see cipherstash/vitaminc#321")]
    pub fn next_bounded_u32(&mut self, max: u32) -> u32 {
        below(&mut self.0, u64::from(max) + 1)
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

/// A uniformly distributed value in `0..n` for `1 <= n <= 2^32`, by rejection
/// sampling: draw 32 bits, keep the low `ceil(log2 n)` of them, retry while
/// the result is `n` or more. Masking to a power of two is bias-free, and the
/// acceptance probability is above one half, so the loop ends quickly and
/// its expected draw count does not depend on the secret stream.
///
/// `n` is `u64` so that `n == 2^32` (the whole `u32` range) is expressible.
///
/// The loop is capped rather than unbounded: each attempt is accepted with
/// probability above one half, so 128 consecutive rejections has probability
/// below 2⁻¹²⁸ and can only mean the generator is not producing random
/// output. Panicking there is the right response for a CSPRNG, and it keeps
/// a fault in this function observable rather than a hang.
pub(crate) fn below<R: Rng>(rng: &mut R, n: u64) -> u32 {
    debug_assert!((1..=1u64 << 32).contains(&n), "below: n out of range");
    const MAX_ATTEMPTS: u32 = 128;
    let mask = n.next_power_of_two() - 1;
    for _ in 0..MAX_ATTEMPTS {
        let value = u64::from(rng.next_u32()) & mask;
        if value < n {
            // `value < n <= 2^32`, so it fits.
            return value as u32;
        }
    }
    panic!("SafeRand: {MAX_ATTEMPTS} consecutive rejections; the generator is not random");
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

    /// What `next_below` promises, spelled out over the same seed: keep the
    /// low bits of a 32-bit draw, retry while the result is `n` or more.
    /// Comparing exact values (not just `< n`) pins the mask and the
    /// comparison, for powers of two, their neighbours, and both ends of
    /// the `u32` range.
    fn reference_below(rng: &mut ChaCha20Rng, n: u64) -> u32 {
        let mask = n.next_power_of_two() - 1;
        loop {
            let value = u64::from(rng.next_u32()) & mask;
            if value < n {
                return value as u32;
            }
        }
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
    fn next_below_matches_reference_rejection_sampling() {
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

    /// Every value in `0..n` is reachable and `n` itself never is: the
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
    #[should_panic(expected = "the range 0..0 is empty")]
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
    fn next_below_from_entropy_stays_in_range() -> Result<(), crate::RandomError> {
        let mut rng = SafeRand::from_entropy()?;
        for n in [1u32, 4, 5, u32::MAX] {
            assert!(rng.next_below(n) < n);
        }
        Ok(())
    }
}
