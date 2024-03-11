use rand::{CryptoRng, RngCore, SeedableRng};

/// A secure random number generator that is safe to use for cryptographic purposes.
/// It is intentionally opinionated so that developers don't have to think about what Rng they should use
/// for cryptographic purposes.
/// 
/// Internally it uses `rand_chacha` but this will be replaced with https://crates.io/crates/chacha20 in the future.
/// However, this implementation does not perform any zeroization and the authors of the `rand` crate
/// have explictly [stepped away](https://github.com/rust-random/rand/issues/1358) from making it a "cryptographically secure" random number generator.
pub struct SafeRand(rand_chacha::ChaCha20Rng);

impl SafeRand {
    // TODO: Kani proof, tests, and possible paranoid argument
    /// Gets an unbiased random value up to and including the given maximum using rejection sampling
    /// for non-power of two values.
    pub fn next_bounded_u32(&mut self, max: u32) -> u32 {
        if max.is_power_of_two() { // TODO: Is this constant time?
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
}

impl CryptoRng for SafeRand {}

impl RngCore for SafeRand {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    #[inline]
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.0.fill_bytes(bytes)
    }
    #[inline]
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand::Error> {
        self.0.try_fill_bytes(bytes)
    }
}

impl SeedableRng for SafeRand {
    type Seed = [u8; 32];

    fn from_seed(seed: Self::Seed) -> Self {
        Self(rand_chacha::ChaCha20Rng::from_seed(seed))
    }
}

#[cfg(test)]
mod tests {
    use super::SafeRand;
    use crate::SeedableRng;

    #[test]
    fn test_next_bounded_u32() {
        let mut rng = SafeRand::from_entropy();
        let value = rng.next_bounded_u32(4);
        assert!(value < 4);
    }

    #[test]
    fn test_next_bounded_u32_non_power_of_two() {
        let mut rng = SafeRand::from_entropy();
        let value = rng.next_bounded_u32(5);
        assert!(value < 5);
    }
}