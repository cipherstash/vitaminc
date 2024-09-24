//! A trait for types that can be generated randomly.
//! The random number generator is passed as an argument to the `generate` method
//! and must be a [SafeRand].
//!
//! ## Example
//!
//! ```rust
//! use vitaminc_random::{Generatable, SafeRand, SeedableRng};
//! use std::num::NonZeroU16;
//!
//! let mut rng = SafeRand::from_entropy();
//! let value: NonZeroU16 = Generatable::random(&mut rng).unwrap();
//! ```
//!
use crate::{Fill, RandomError, SafeRand};
use std::num::NonZeroU16;
use vitaminc_protected::{Controlled, Equatable, Exportable, Protected, Usage};

/// A trait for types that can be generated randomly.
/// The random number generator is passed as an argument to the `generate` method
/// and must implement the `SafeRand` trait.
pub trait Generatable: Sized {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError>;
}

impl Generatable for NonZeroU16 {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        let mut buf: [u8; 2] = [0, 0];

        buf.try_fill(rng)
            .map_err(|_| RandomError::GenerationFailed)?;
        if let Some(value) = NonZeroU16::new(u16::from_be_bytes(buf)) {
            Ok(value)
        } else {
            // Because a 0 would be an invalid value we must try again (rejection sampling)
            Self::random(rng)
        }
    }
}

impl<const N: usize> Generatable for [u8; N] {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        // TODO: Consider using MaybeUninit or array::from_fn
        let mut buf: [u8; N] = [0; N];

        buf.try_fill(rng)
            .map_err(|_| RandomError::GenerationFailed)?;

        Ok(buf)
    }
}

impl<T> Generatable for Protected<T> where T: Generatable, Self: Controlled<Inner = T> {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        Self::generate_ok(|| Generatable::random(rng))
    }
}

impl<T> Generatable for Exportable<T> where T: Generatable, Self: Controlled<Inner = T> {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        Self::generate_ok(|| Generatable::random(rng))
    }
}

impl<T> Generatable for Equatable<T> where T: Generatable, Self: Controlled<Inner = T> {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        Self::generate_ok(|| Generatable::random(rng))
    }
}

impl<T, S> Generatable for Usage<T, S> where T: Generatable, Self: Controlled<Inner = T> {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        Self::generate_ok(|| Generatable::random(rng))
    }
}