use thiserror::Error;
mod impls;
mod safe_rand;

pub use safe_rand::SafeRand;

// Re-exports
pub use rand::{RngCore, SeedableRng};

#[derive(Error, Debug)]
pub enum RandomError {
    #[error("Generation failed")]
    GenerationFailed,
}

/// A trait for types that can be generated randomly.
/// The random number generator is passed as an argument to the `generate` method
/// and must implement the `SafeRand` trait.
pub trait Generatable: Sized {
    fn generate(rng: &mut SafeRand) -> Result<Self, RandomError>;
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;
    use super::{Generatable, SafeRand, SeedableRng};

    #[test]
    fn test_generate_nonzerou16() -> Result<(), crate::RandomError> {
        let mut rng = SafeRand::from_entropy();
        let value: NonZeroU16 = Generatable::generate(&mut rng)?;
        assert_ne!(value.get(), 0);
        Ok(())
    }
}