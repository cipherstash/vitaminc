//! A carefully designed random number generator that is safe to use for cryptographic purposes.
//!
//! # Bounded Random Numbers
//!
//! The `BoundedRng` trait provides a way to generate random numbers within a specific range.
//!
//! ```
//! use vitaminc_random::{BoundedRng, SafeRand, SeedableRng};
//!
//! let mut rng = SafeRand::from_entropy();
//! let value = rng.next_bounded(10);
//! assert!(value < 10);
//! ```
//!
//! Or using a `Protected` value:
//!
//! ```
//! use vitaminc_protected::Protected;
//! use vitaminc_random::{BoundedRng, SafeRand, SeedableRng};
//!
//! let mut rng = SafeRand::from_entropy();
//! let value: Protected<u32> = rng.next_bounded(Protected::new(10));
//! assert!(value.unwrap() < 10);
//! ```
//!
use thiserror::Error;
mod bounded;
mod generatable;
mod safe_rand;

pub use bounded::BoundedRng;
pub use generatable::Generatable;
pub use safe_rand::SafeRand;

// Re-exports
pub use rand::{Fill, RngCore, SeedableRng};

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
