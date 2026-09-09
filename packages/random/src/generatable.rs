//! A trait for types that can be generated randomly.
//! The random number generator is passed as an argument to the `generate` method
//! and must be a [SafeRand].
//!
//! ## Example
//!
//! ```rust
//! # mod vitaminc { pub mod random { pub use vitaminc_random::*; } }
//! use vitaminc::random::{Generatable, SafeRand, SeedableRng};
//! use std::num::NonZeroU16;
//!
//! let mut rng = SafeRand::from_entropy().expect("Failed to seed RNG");
//! let value: NonZeroU16 = Generatable::random(&mut rng).unwrap();
//! ```
//!
use crate::{RandomError, SafeRand};
use std::num::NonZeroU16;
use vitaminc_protected::{Controlled, Equatable, Exportable, Protected, Usage};
use zeroize::Zeroize;

/// A trait for types that can be generated randomly.
/// The random number generator is passed as an argument to the `generate` method
/// and must implement the `SafeRand` trait.
pub trait Generatable: Sized {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError>;
}

impl Generatable for NonZeroU16 {
    /// Exactly one bounded draw: an offset in `0..u16::MAX` is drawn with
    /// [`SafeRand::next_below`] and added to one, so the result is uniform
    /// over `1..=u16::MAX` to within the `u16::MAX / 2⁶⁴` bias bound
    /// documented on [`BoundedRng`](crate::BoundedRng) (exactly 2⁻⁶⁴ here).
    /// Drawing a raw `u16` and retrying on zero would be just as
    /// deterministic for a given seed, but would consume a data-dependent
    /// number of words from the stream, and on a secret-seeded generator
    /// that draw count leaks through timing.
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        let offset = rng.next_below(u32::from(u16::MAX)) as u16;
        Ok(NonZeroU16::MIN.saturating_add(offset))
    }
}

macro_rules! impl_generatable_for_int {
    ($($t:ty),*) => {
        $(
            impl Generatable for $t {
                fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
                    use rand::RngExt;
                    Ok(rng.random())
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
        use rand::RngExt;
        rng.fill(&mut buf);
        Ok(buf)
    }
}

impl<T, G> Generatable for Protected<T>
where
    T: Zeroize,
    G: Generatable,
    Self: Controlled<Inner = G>,
{
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        Self::generate_ok(|| Generatable::random(rng))
    }
}

impl<T, G> Generatable for Exportable<T>
where
    T: Zeroize,
    G: Generatable,
    Self: Controlled<Inner = G>,
{
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        Self::generate_ok(|| Generatable::random(rng))
    }
}

impl<T, G> Generatable for Equatable<T>
where
    T: Zeroize,
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
    use super::Generatable;
    use crate::SafeRand;
    use zeroize::Zeroize;

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
    fn test_generate_array() -> Result<(), crate::RandomError> {
        let mut rng = SafeRand::from_entropy()?;
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
        Ok(())
    }

    /// `NonZeroU16` is `next_below(u16::MAX) + 1` over the same seed: one
    /// bounded draw per value, never a retry, and the offset covers exactly
    /// `1..=u16::MAX`.
    #[test]
    fn nonzero_u16_is_one_bounded_draw() {
        use rand::SeedableRng;
        use std::num::NonZeroU16;

        let mut got = SafeRand::from_seed([11u8; 32]);
        let mut reference = SafeRand::from_seed([11u8; 32]);
        for _ in 0..256 {
            let value: NonZeroU16 = Generatable::random(&mut got).unwrap();
            let want = reference.next_below(u32::from(u16::MAX)) as u16 + 1;
            assert_eq!(value.get(), want);
        }
    }

    #[test]
    fn test_numeric_primitives() -> Result<(), crate::RandomError> {
        let mut rng = SafeRand::from_entropy()?;
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
        Ok(())
    }
}
