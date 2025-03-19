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

macro_rules! impl_generatable_for_int {
    ($($t:ty),*) => {
        $(
            impl Generatable for $t {
                fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
                    use rand::Rng;
                    Ok(rng.gen())
                }
            }
        )*
    };
}

impl_generatable_for_int!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

impl<const N: usize> Generatable for [u8; N] {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        // TODO: Consider using MaybeUninit or array::from_fn
        let mut buf: [u8; N] = [0; N];

        buf.try_fill(rng)
            .map_err(|_| RandomError::GenerationFailed)?;

        Ok(buf)
    }
}

impl<T, G> Generatable for Protected<T>
where
    G: Generatable,
    Self: Controlled<Inner = G>,
{
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        Self::generate_ok(|| Generatable::random(rng))
    }
}

impl<T, G> Generatable for Exportable<T>
where
    G: Generatable,
    Self: Controlled<Inner = G>,
{
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        Self::generate_ok(|| Generatable::random(rng))
    }
}

impl<T, G> Generatable for Equatable<T>
where
    G: Generatable,
    Self: Controlled<Inner = G>,
{
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        Self::generate_ok(|| Generatable::random(rng))
    }
}

impl<T, S, G> Generatable for Usage<T, S>
where
    G: Generatable,
    Self: Controlled<Inner = G>,
{
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        Self::generate_ok(|| Generatable::random(rng))
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroize;

    use crate::{SafeRand, SeedableRng};

    use super::Generatable;

    fn assert_generatable<T>(rng: &mut SafeRand) -> T
    where
        T: super::Generatable,
    {
        T::random(rng).unwrap()
    }

    fn test_generate_controlled<T: Generatable + Zeroize>(rng: &mut SafeRand) {
        use super::*;
        let _: Protected<T> = assert_generatable(rng);
        let _: Exportable<Protected<T>> = assert_generatable(rng);
        let _: Equatable<Protected<T>> = assert_generatable(rng);
        let _: Exportable<Equatable<Protected<T>>> = assert_generatable(rng);
        let _: Usage<Protected<T>> = assert_generatable(rng);
        let _: Usage<Equatable<Protected<T>>> = assert_generatable(rng);
    }

    #[test]
    fn test_generate_array() {
        let mut rng = SafeRand::from_entropy();
        let _: [u8; 4] = assert_generatable(&mut rng);
        let _: [u8; 8] = assert_generatable(&mut rng);
        let _: [u8; 16] = assert_generatable(&mut rng);
        let _: [u8; 32] = assert_generatable(&mut rng);
        let _: [u8; 64] = assert_generatable(&mut rng);
        let _: [u8; 128] = assert_generatable(&mut rng);
        let _: [u8; 256] = assert_generatable(&mut rng);
        test_generate_controlled::<[u8; 4]>(&mut rng);
        test_generate_controlled::<[u8; 8]>(&mut rng);
        test_generate_controlled::<[u8; 16]>(&mut rng);
        test_generate_controlled::<[u8; 32]>(&mut rng);
        test_generate_controlled::<[u8; 64]>(&mut rng);
        test_generate_controlled::<[u8; 128]>(&mut rng);
        test_generate_controlled::<[u8; 256]>(&mut rng);
    }

    #[test]
    fn test_numeric_primitives() {
        let mut rng = SafeRand::from_entropy();
        let _: u8 = assert_generatable(&mut rng);
        let _: u16 = assert_generatable(&mut rng);
        let _: u32 = assert_generatable(&mut rng);
        let _: u64 = assert_generatable(&mut rng);
        let _: u128 = assert_generatable(&mut rng);
        let _: i8 = assert_generatable(&mut rng);
        let _: i16 = assert_generatable(&mut rng);
        let _: i32 = assert_generatable(&mut rng);
        let _: i64 = assert_generatable(&mut rng);
        let _: i128 = assert_generatable(&mut rng);
        test_generate_controlled::<u8>(&mut rng);
        test_generate_controlled::<u16>(&mut rng);
        test_generate_controlled::<u32>(&mut rng);
        test_generate_controlled::<u64>(&mut rng);
        test_generate_controlled::<u128>(&mut rng);
        test_generate_controlled::<i8>(&mut rng);
        test_generate_controlled::<i16>(&mut rng);
        test_generate_controlled::<i32>(&mut rng);
        test_generate_controlled::<i64>(&mut rng);
        test_generate_controlled::<i128>(&mut rng);
    }
}
