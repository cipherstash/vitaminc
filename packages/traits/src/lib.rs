// These definitions precede the README so rustdoc links to the version being built.
// The README supplies published-API URLs for GitHub. See docs/documentation.md.
//!
// Workspace crates release together; keep cross-crate links on that version.
#![deny(missing_docs)]
#![doc = concat!(
    "\n[Controlled]: https://docs.rs/vitaminc-protected/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_protected/trait.Controlled.html\n",
)]
#![deny(clippy::unwrap_used, clippy::todo, unsafe_code, unused_imports)]
#![doc = include_str!("../README.md")]
use vitaminc_protected::{Controlled, Zeroed};

/// Defines the size of the output of a hash function.
pub trait OutputSize<const N: usize> {
    /// Output length in bytes.
    const SIZE: usize;
}

/// Output size for Paranoid types with the same sized inner value.
impl<const N: usize, T> OutputSize<N> for T
where
    T: Controlled<Inner = [u8; N]>,
{
    const SIZE: usize = N;
}

/// The length of a cryptographic key in bytes.
pub trait KeySize {
    /// Key length in bytes.
    const SIZE: usize;
}

impl<const N: usize, T> KeySize for T
where
    T: Controlled<Inner = [u8; N]>,
{
    const SIZE: usize = N;
}

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
    /// Append `data` to the input accumulated by this hasher.
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
    /// Write the accumulated digest into `out`, then reset for another input.
    /// A keyed implementation retains its key when resetting.
    fn finalize_into_reset(&mut self, out: &mut O);

    /// Return the accumulated digest in a new output and reset the hasher.
    /// Uses [`finalize_into_reset`](Self::finalize_into_reset) with a zeroed output.
    fn finalize_reset(&mut self) -> O
    where
        O: Zeroed,
    {
        let mut out = Zeroed::zeroed();
        self.finalize_into_reset(&mut out);
        out
    }
}
