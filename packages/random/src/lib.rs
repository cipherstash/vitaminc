#![doc = include_str!("../README.md")]
use thiserror::Error;
mod bounded;
mod generatable;
mod safe_rand;

pub use bounded::BoundedRng;
#[allow(deprecated)]
pub use bounded::BoundedRngInclusive;
#[doc(inline)]
pub use generatable::Generatable;
pub use safe_rand::SafeRand;

// Re-exports
pub use rand::{Fill, Rng, SeedableRng};

/// Derive macro for `Generatable`
pub use vitaminc_random_derives::Generatable;

#[derive(Error, Debug)]
pub enum RandomError {
    #[error("Generation failed")]
    GenerationFailed,
    #[error("Seeding from OS RNG failed: {0}")]
    SeedingFailed(#[from] rand::rngs::SysError),
    /// The seed produced an unusable batch of randomness (e.g. colliding
    /// sort keys during oblivious permutation generation). The seed must be
    /// discarded and a fresh one generated; retrying from the same seed's
    /// RNG stream would leak a predicate of the retained seed through timing
    /// and can never yield a stable derivation for it.
    ///
    /// For a generator seeded from the OS rather than from a retained seed
    /// ([`SafeRand::from_entropy`]) there is no seed to keep: build a new
    /// generator with `from_entropy` and call again. What must not happen
    /// is a second draw from the *same* generator.
    #[error("The seed produced an unusable batch; discard it and generate a fresh seed")]
    SeedRejected,
}

#[cfg(test)]
mod tests {
    use super::{Generatable, SafeRand};
    use std::num::NonZeroU16;

    #[test]
    fn test_generate_nonzerou16() -> Result<(), crate::RandomError> {
        let mut rng = SafeRand::from_entropy()?;
        let value: NonZeroU16 = Generatable::random(&mut rng)?;
        assert_ne!(value.get(), 0);
        Ok(())
    }
}
