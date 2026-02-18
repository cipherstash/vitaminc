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
