#![doc = include_str!("../README.md")]
use thiserror::Error;
mod bounded;
mod generatable;
mod safe_rand;

pub use bounded::BoundedRng;
#[doc(inline)]
pub use generatable::Generatable;
pub use safe_rand::SafeRand;

// Re-exports
pub use rand::{Fill, RngCore, SeedableRng};

/// Derive macro for `Generatable`
pub use vitaminc_random_derives::Generatable;

#[derive(Error, Debug)]
pub enum RandomError {
    #[error("Generation failed")]
    GenerationFailed,
}

#[cfg(test)]
mod tests {
    use super::{Generatable, SafeRand, SeedableRng};
    use std::num::NonZeroU16;

    #[test]
    fn test_generate_nonzerou16() -> Result<(), crate::RandomError> {
        let mut rng = SafeRand::from_entropy();
        let value: NonZeroU16 = Generatable::random(&mut rng)?;
        assert_ne!(value.get(), 0);
        Ok(())
    }
}
