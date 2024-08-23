//! # VitaminC Protected
//!
//! ## Safe wrappers for sensitive data
//!
//! `Protected` is a set of types that remove some of the sharp edges of working with sensitive data in Rust.
//! Its interface is conceptually similar to `Option` or `Result`.
//!
//! ## Sensitive data footguns
//!
//! Rust is a safe language, but it's still possible to make mistakes when working with sensitive data.
//! These can include (but are not limited to):
//!
//! * Not zeroizing sensitive data when it's no longer needed
//! * Accidentally leaking sensitive data in logs or error messages
//! * Performing comparison operations on sensitive data in a way that leaks timing information
//! * Serializing sensitive data in a way that leaks information
//!
//! `Protected` and the other types in this crate aim to make it easier to avoid these mistakes.
//!
//! ## Usage
//!
//! The `Protected` type is the most basic building block in this crate.
//! You can use it to wrap any type that you want to protect so long as it implements the `Zeroize` trait.
//!
//! ```rust
//! use vitaminc_protected::Protected;
//!
//! let x = Protected::new([0u8; 32]);
//! ```
//!
//! `Protected` will call `zeroize` on the inner value when it goes out of scope.
//! It also provides an "opaque" implementation of the `Debug` trait so you can debug protected values
//! without accidentally leaking their innards.
//!
//! ```rust
//! # use vitaminc_protected::Protected;
//! let x = Protected::new([0u8; 32]);
//! assert_eq!(format!("{x:?}"), "Protected<[u8; 32]> { ... }");
//! ```
//!
//! The inner value is not accessible directly, but you can use the `unwrap` method as an escape hatch to get it back.
//! `unwrap` is defined in the `Paranoid` trait so you'll need to bring that in scope.
//!
//! ```rust
//! use vitaminc_protected::{Paranoid, Protected};
//!
//! let x = Protected::new([0u8; 32]);
//! assert_eq!(x.unwrap(), [0; 32]);
//! ```
//!
//! `Protected` does not implement `Deref` so you cannot access the data directly.
//! This is to prevent accidental leakage of the inner value.
//! It also means comparisons (like `PartialEq`) are not implemented for `Protected`.
//!
//! If you want to safely compare values, you can use [Equatable].
//!
//! ## Equatable
//!
//! The `Equatable` type is a wrapper around `Protected` that implements constant-time comparison.
//! It implements `PartialEq` for any inner type that implements [ConstantTimeEq].
//!
//! ```rust
//! use vitaminc_protected::{Equatable, Protected};
//!
//! let x: Equatable<Protected<u32>> = Equatable::new(100);
//! let y: Equatable<Protected<u32>> = Equatable::new(100);
//! assert_eq!(x, y);
//! ```
//!
//! ## Exportable
//!
//! The `Exportable` type is a wrapper around `Protected` that implements constant-time serialization.
//!
//! This adapter is WIP.
//!
//! ## Usage
//!
//! The `Usage` type is a wrapper around `Protected` that allows you to specify a scope for the data.
//!
//! This adapter is WIP.
//!
//! ## Working with wrapped values
//!
//! None of the adapters implement `Deref` so you can't access the inner value directly.
//! This is to prevent accidental leakage of the inner value by being explicit about when and how you want to work with the inner value.
//!
//! You can `map` over the inner value to transform it, so long as the adapter is the same type.
//! For example, you can map a `Protected<T>` to a `Protected<U>`.
//!
//! ```
//! use vitaminc_protected::{Paranoid, Protected};
//!
//! // Calculate the sum of values in the array with the result as a `Protected`
//! let x: Protected<[u8; 4]> = Protected::new([1, 2, 3, 4]);
//! let result: Protected<u8> = x.map(|arr| arr.as_slice().iter().sum());
//! assert_eq!(result.unwrap(), 10);
//! ```
//!
//! If you have a pair of `Protected` values, you can `zip` them together with a function that combines them.
//!
//! ```
//! use vitaminc_protected::{Paranoid, Protected};
//!
//! let x: Protected<u8> = Protected::new(1);
//! let y: Protected<u8> = Protected::new(2);
//! let z: Protected<u8> = x.zip(y, |a, b| a + b);
//! ```
//!
//! If the inner type is an `Option` you can call `transpose` to swap the `Protected` and the `Option`.
//!
//! ```
//! use vitaminc_protected::{Paranoid, Protected};
//!
//! let x = Protected::new(Some([0u8; 32]));
//! let y = x.transpose();
//! assert!(matches!(y, Some(Protected)));
//! ```
//!
//! A `Protected` of `Protected` can be "flattened" into a single `Protected`.
//!
//! ```
//! # use vitaminc_protected::{Paranoid, Protected};
//! let x = Protected::new(Protected::new([0u8; 32]));
//! let y = x.flatten();
//! assert_eq!(y.unwrap(), [0u8; 32]);
//! ```
//!
//! Use [flatten_array] to convert a `[Protected<T>; N]` into a `Protected<[T; N]>`.
//!
//! ## Generators
//!
//! `Protected` supports generating new values from functions that return the inner value.
//!
//! ```
//! # use vitaminc_protected::{Paranoid, Protected};
//! fn array_gen<const N: usize>() -> [u8; N] {
//!     core::array::from_fn(|i| (i + 1) as u8)
//! }
//!
//! let input: Protected<[u8; 8]> = Protected::generate(array_gen);
//! ```
//!
//! You can also generate values from functions that return a `Result` with the inner value.
//!
//! ```
//! # use vitaminc_protected::{Paranoid, Protected};
//! use std::string::FromUtf8Error;
//!
//! let input: Result<Protected<String>, FromUtf8Error> = Protected::generate_ok(|| {
//!   String::from_utf8(vec![1, 2, 3, 4, 5, 6, 7, 8])
//! });
//! ```
//!
mod conversions;
mod digest;
mod equatable;
mod exportable;
mod ops;
mod usage;

use private::ParanoidPrivate;
use std::marker::PhantomData;
use zeroize::{Zeroize, ZeroizeOnDrop};

mod private;

#[cfg(feature = "bitvec")]
pub mod bitvec;

pub mod slice_index;

// TODO: This trait is similar to the Iterator trait in std
// Implement for all "adapter" types - Equatable, Exportable, etc.
// Come up with a better name for it
pub trait Paranoid: private::ParanoidPrivate {
    /// Generate a new `Protected` from a function that returns the inner value.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_protected::{Paranoid, Protected};
    /// fn array_gen<const N: usize>() -> [u8; N] {
    ///     let mut input: [u8; N] = [0; N];
    ///     input.iter_mut().enumerate().for_each(|(i, x)| {
    ///         *x = (i + 1) as u8;
    ///     });
    ///     input
    /// }
    /// let input: Protected<[u8; 8]> = Protected::generate(array_gen);
    /// assert_eq!(input.unwrap(), [1, 2, 3, 4, 5, 6, 7, 8]);
    /// ```
    /// // TODO: A Generate Array could handle the MaybeUninit stuff
    fn generate<F>(f: F) -> Self
    where
        F: FnOnce() -> Self::Inner,
    {
        Self::init_from_inner(f())
    }

    /// Generate a new `Protected` from a function that returns a `Result` with the inner value.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_protected::{Paranoid, Protected};
    /// use std::string::FromUtf8Error;
    ///
    /// let input: Result<Protected<String>, FromUtf8Error> = Protected::generate_ok(|| {
    ///    String::from_utf8(vec![1, 2, 3, 4, 5, 6, 7, 8])
    /// });
    /// ```
    ///
    fn generate_ok<F, E>(f: F) -> Result<Self, E>
    where
        F: FnOnce() -> Result<Self::Inner, E>,
    {
        f().map(Self::init_from_inner)
    }

    /// Convert this `Protected` into one that is equatable in constant time.
    /// Returns a new `Equatable` adapter.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_protected::{Equatable, Paranoid, Protected};
    ///
    /// let x = Protected::new([0u8; 32]);
    /// let y: Equatable<Protected<[u8; 32]>> = x.equatable();
    /// ```
    fn equatable(self) -> Equatable<Self> {
        Equatable(self)
    }

    // TODO: This will have to be a trait to allow for multiple implementations - we can't make it generic or that would allow arbitrary conversion
    /// Map `Protected<Self::Inner>` value into a new `Protected<B>`.
    /// Conceptually similar to `Option::map`.
    fn map<B, F>(self, f: F) -> Protected<B>
    where
        F: FnOnce(<Self as ParanoidPrivate>::Inner) -> B,
        B: Zeroize,
    {
        Protected(f(self.unwrap()))
    }

    fn zip<Other, Out, F>(self, b: Other, f: F) -> Protected<Out>
    where
        Other: Paranoid,
        Out: Zeroize,
        F: FnOnce(Self::Inner, Other::Inner) -> Out,
    {
        Protected::init_from_inner(f(self.unwrap(), b.unwrap()))
    }

    /// Iterate over the inner value and wrap each element in a `Protected`.
    /// `I` must be `Copy` because [Protected] always takes ownership of the inner value.
    fn iter<'a, I>(&'a self) -> impl Iterator<Item = Protected<I>>
    where
        <Self as ParanoidPrivate>::Inner: AsRef<[I]>,
        I: Copy + 'a,
    {
        self.inner().as_ref().iter().copied().map(Protected)
    }

    // TODO: Consider renaming this to `risky_unwrap`
    fn unwrap(self) -> Self::Inner;
}

// TODO: Implement Collect for Protected (or Paranoid) so we can use collect() on iterators

// Exports
pub use digest::ProtectedDigest;
pub use equatable::{ConstantTimeEq, Equatable};
pub use exportable::Exportable;
pub use usage::{Acceptable, DefaultScope, Scope, Usage};

/// Basic building block for Paranoid.
/// It uses a similar design "adapter" pattern to `std::slide::Iter`.
/// `Protected` adds Zeroize and OpaqueDebug.
#[derive(Zeroize)]
pub struct Protected<T>(T);

opaque_debug::implement!(Protected<T>);

impl<T> Protected<T> {
    /// Create a new `Protected` from an inner value.
    pub const fn new(x: T) -> Self
    where
        T: Zeroize,
    {
        Self(x)
    }

    /// Convert this `Protected` into one that is exportable in constant time using Serde.
    /// Returns a new `Exportable` adapter.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_protected::{Exportable, Protected};
    ///
    /// let x = Protected::new([0u8; 32]);
    /// let y: Exportable<Protected<[u8; 32]>> = x.exportable();
    /// ```
    pub fn exportable(self) -> Exportable<Self> {
        Exportable(self)
    }

    // TODO: This needs to be implemented for all types (put on the Paranoid trait)
    pub fn for_scope<S: Scope>(self) -> Usage<Self, S> {
        Usage(self, PhantomData)
    }
}

impl<T> Protected<Protected<T>> {
    #[inline]
    /// Flatten a `Protected` of `Protected` into a single `Protected`.
    /// Similar to `Option::flatten`.
    ///
    /// ```
    /// use vitaminc_protected::{Paranoid, Protected};
    /// let x = Protected::new(Protected::new([0u8; 32]));
    /// let y = x.flatten();
    /// assert_eq!(y.unwrap(), [0u8; 32]);
    /// ```
    ///
    /// Like [Option], flattening only removes one level of nesting at a time.
    ///
    pub fn flatten(self) -> Protected<T> {
        self.0
    }
}

impl<T> Protected<Option<T>> {
    #[inline]
    /// Transpose a `Protected` of `Option` into an `Option` of `Protected`.
    /// Similar to `Option::transpose`.
    ///
    /// ```
    /// use vitaminc_protected::Protected;
    /// let x = Protected::new(Some([0u8; 32]));
    /// let y = x.transpose();
    /// assert!(y.is_some())
    /// ```
    pub fn transpose(self) -> Option<Protected<T>> {
        self.0.map(Protected)
    }
}

impl<T: Zeroize> ZeroizeOnDrop for Protected<T> {}

impl<T> ParanoidPrivate for Protected<T>
where
    T: Zeroize,
{
    type Inner = T;

    fn init_from_inner(x: Self::Inner) -> Self {
        Self(x)
    }

    fn inner(&self) -> &T {
        &self.0
    }

    fn inner_mut(&mut self) -> &mut Self::Inner {
        &mut self.0
    }
}

impl<T> Paranoid for Protected<T>
where
    T: Zeroize,
{
    fn unwrap(self) -> Self::Inner {
        self.0
    }
}

impl<T> Copy for Protected<T> where T: Copy {}

impl<T> Clone for Protected<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Convenience function to flatten an array of `Protected` into a `Protected` array.
///
/// # Example
///
/// ```
/// use vitaminc_protected::{flatten_array, Paranoid, Protected};
/// let x = Protected::new(1);
/// let y = Protected::new(2);
/// let z = Protected::new(3);
/// let array: [Protected<u8>; 3] = [x, y, z];
/// let flattened = flatten_array(array);
/// assert!(matches!(flattened, Protected));
/// assert_eq!(flattened.unwrap(), [1, 2, 3]);
/// ```
pub fn flatten_array<const N: usize, T>(array: [Protected<T>; N]) -> Protected<[T; N]>
where
    T: Zeroize + Default + Copy, // TODO: Default won't be needed if we use MaybeUninit
{
    let mut out: [T; N] = [Default::default(); N];
    array.iter().enumerate().for_each(|(i, x)| {
        out[i] = x.unwrap();
    });
    Protected::new(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_array() {
        let x = Protected::new([0u8; 32]);
        assert_eq!(x.0, [0u8; 32]);
    }

    #[test]
    fn test_opaque_debug() {
        let x = Protected::new([0u8; 32]);
        assert_eq!(format!("{:?}", x), "Protected<[u8; 32]> { ... }");
    }

    #[test]
    fn test_flatten() {
        let x = Protected::new(Protected::new([0u8; 32]));
        let y = x.flatten();
        assert_eq!(y.unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_flatten_array() {
        let x = Protected::new(1);
        let y = Protected::new(2);
        let z = Protected::new(3);
        let array: [Protected<u8>; 3] = [x, y, z];
        let flattened = flatten_array(array);
        assert!(matches!(flattened, Protected(_)));
        assert_eq!(flattened.unwrap(), [1, 2, 3]);
    }
}
