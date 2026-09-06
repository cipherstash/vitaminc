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
    // TODO: Kani proof, tests, and possible paranoid argument
    /// Gets an unbiased random value up to and including the given maximum.
    /// It uses rejection sampling to avoid modulo bias.
    pub fn next_bounded_u32(&mut self, max: u32) -> u32 {
        if max.is_power_of_two() {
            // TODO: Is this constant time?
            self.0.next_u32() % max
        } else {
            let cap = max.next_power_of_two();
            // Use rejection sampling to avoid modulo bias
            let mut value = self.0.next_u32() % cap;
            while value > max {
                value = self.next_u32() % cap;
            }
            value
        }
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

    /// What `next_bounded_u32` does today for a bound that is not a power of
    /// two, spelled out over the same seed: draw mod the next power of two
    /// and reject until the draw is at most `max`. Comparing exact values
    /// (not just `<= max`) pins the modulus and the rejection comparison.
    ///
    /// Two inputs are deliberately absent, both tracked in the issue linked
    /// from the PR that added this test: a power-of-two `max` takes a branch
    /// that reduces mod `max` and so never returns `max`, contradicting the
    /// doc's "up to and including"; and any `max` above `1 << 31` overflows
    /// `next_power_of_two` and panics. Neither is pinned here because
    /// neither is the intended behaviour.
    #[test]
    fn next_bounded_u32_matches_reference_rejection_sampling() {
        fn reference(rng: &mut ChaCha20Rng, max: u32) -> u32 {
            let cap = max.next_power_of_two();
            loop {
                let value = rng.next_u32() % cap;
                if value <= max {
                    return value;
                }
            }
        }
        for max in [3u32, 5, 6, 100, 1000, (1 << 31) - 1] {
            let mut safe = SafeRand::from_seed(SEED);
            let mut reference_rng = ChaCha20Rng::from_seed(SEED);
            for _ in 0..256 {
                let got = safe.next_bounded_u32(max);
                assert_eq!(got, reference(&mut reference_rng, max), "max = {max}");
                assert!(got <= max, "max = {max}");
            }
        }
    }

    /// Every value in `0..=max` is reachable, including `max` itself, which a
    /// strict `<` in the rejection test would silently exclude.
    #[test]
    fn next_bounded_u32_covers_the_whole_inclusive_range() {
        let mut rng = SafeRand::from_seed(SEED);
        let mut seen = [false; 6];
        for _ in 0..512 {
            seen[rng.next_bounded_u32(5) as usize] = true;
        }
        assert_eq!(seen, [true; 6]);
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
    fn test_next_bounded_u32() -> Result<(), crate::RandomError> {
        let mut rng = SafeRand::from_entropy()?;
        let value = rng.next_bounded_u32(4);
        assert!(value < 4);
        Ok(())
    }

    #[test]
    fn test_next_bounded_u32_non_power_of_two() -> Result<(), crate::RandomError> {
        let mut rng = SafeRand::from_entropy()?;
        let value = rng.next_bounded_u32(5);
        assert!(value <= 5);
        Ok(())
    }
}
