#![doc = include_str!("../README.md")]
use vitaminc_protected::{Controlled, Zeroed};
mod aead;

pub use aead::{Aad, Aead, AeadCore, KeyInit, Nonce, NonceGenerator, RandomNonceGenerator};

/// Defines the size of the output of a hash function.
pub trait OutputSize<const N: usize> {
    const SIZE: usize;
}

/// Output size for Paranoid types with the same sized inner value.
impl<const N: usize, T> OutputSize<N> for T
where
    T: Controlled<Inner = [u8; N]>,
{
    const SIZE: usize = N;
}

pub trait KeySize {
    const SIZE: usize;
}

impl<const N: usize, T> KeySize for T
where
    T: Controlled<Inner = [u8; N]>,
{
    const SIZE: usize = N;
}

/*pub trait KeyInit: KeySize {
    type Key: Controlled;

    fn new(key: Self::Key) -> Self;
}*/

/// Trait for hash functions with fixed-size output.
pub trait FixedOutput<const N: usize, O>: Sized
where
    O: Sized + OutputSize<N>,
{
    /// Consume value and write result into provided array.
    fn finalize_into(self, out: &mut O);

    /// Retrieve result and consume the hasher instance.
    #[inline]
    fn finalize_fixed(self) -> O
    where
        O: Zeroed,
    {
        let mut out = Zeroed::zeroed();
        self.finalize_into(&mut out);
        out
    }
}

/// Trait for updating a hash with input data with a specific input type.
/// This differs from the `Update` trait in `digest` in that it takes a specific input type.
/// This allows us to reason about the input type and its sensitivity.
pub trait Update<T> {
    // TODO: Make this bound on a "tagged" value (i.e. sensitive or safe)
    fn update(&mut self, data: T);

    /// Digest input data in a chained manner.
    #[must_use]
    fn chain(mut self, data: T) -> Self
    where
        Self: Sized,
    {
        self.update(data);
        self
    }
}

/// Trait for hash functions with fixed-size output able to reset themselves.
pub trait FixedOutputReset<const N: usize, O>
where
    O: Controlled + OutputSize<N>,
{
    fn finalize_into_reset(&mut self, out: &mut O);

    fn finalize_reset(&mut self) -> O
    where
        O: Zeroed,
    {
        let mut out = Zeroed::zeroed();
        self.finalize_into_reset(&mut out);
        out
    }
}
