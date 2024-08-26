#![doc = include_str!("../README.md")]
mod as_protected_ref;
mod conversions;
mod digest;
mod equatable;
mod exportable;
mod ops;
mod usage;

use as_protected_ref::ProtectedRef;
use private::ParanoidPrivate;
use std::marker::PhantomData;
use zeroize::{Zeroize, ZeroizeOnDrop};

mod private;

#[cfg(feature = "bitvec")]
pub mod bitvec;

pub mod slice_index;

pub use as_protected_ref::AsProtectedRef;

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
        Self: Sized,
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
        Self: Sized,
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
    fn equatable(self) -> Equatable<Self>
    where
        Self: Sized,
    {
        Equatable(self)
    }

    /// Map `Protected<Self::Inner>` value into a new `Protected<B>`.
    /// Conceptually similar to `Option::map`.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_protected::{Paranoid, Protected};
    /// let x = Protected::new(100u8);
    /// let y = x.map(|x| x + 10);
    /// assert_eq!(y.unwrap(), 110);
    /// ```
    ///
    /// TODO: Apply Usage trait bounds to prevent accidental broadening of scope
    /// e.g. `other` must have the same, or broader scope as `self`
    fn map<B, F>(self, f: F) -> Protected<B>
    where
        Self: Sized,
        F: FnOnce(<Self as ParanoidPrivate>::Inner) -> B,
        B: Zeroize,
    {
        Protected(f(self.unwrap()))
    }

    /// Zip two `Protected` values together with a function that combines them.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_protected::{Paranoid, Protected};
    /// let x = Protected::new(1);
    /// let y = Protected::new(2);
    /// let z = x.zip(y, |x, y| x + y);
    /// assert_eq!(z.unwrap(), 3);
    /// ```
    ///
    /// TODO: Apply Usage trait bounds to prevent accidental broadening of scope
    /// e.g. `other` must have the same, or broader scope as `self`
    fn zip<Other, Out, F>(self, b: Other, f: F) -> Protected<Out>
    where
        Self: Sized,
        Other: Paranoid,
        Out: Zeroize,
        F: FnOnce(Self::Inner, Other::Inner) -> Out,
    {
        Protected::init_from_inner(f(self.unwrap(), b.unwrap()))
    }

    /// Like `zip` but the second argument is a reference.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_protected::{Paranoid, Protected};
    /// let x = Protected::new(String::from("hello "));
    /// let y = Protected::new(String::from("world"));
    /// let z = x.zip_ref(&y, |x, y| x + y);
    /// assert_eq!(z.unwrap(), "hello world");
    /// ```
    ///
    fn zip_ref<'a, A, Other, Out, F>(self, other: &'a Other, f: F) -> Protected<Out>
    where
        Self: Sized,
        A: ?Sized + 'a,
        Other: AsProtectedRef<'a, A>,
        Out: Zeroize,
        F: FnOnce(Self::Inner, &A) -> Out,
    {
        let arg: ProtectedRef<'a, A> = other.as_protected_ref();
        Protected::init_from_inner(f(self.unwrap(), arg.inner_ref()))
    }

    /// Similar to `map` but using references to that the inner value is updated in place.
    ///
    /// # Example
    ///
    /// ```
    /// # use vitaminc_protected::{Paranoid, Protected};
    /// let mut x = Protected::new([0u8; 4]);
    /// x.update(|x| {
    ///   x.iter_mut().for_each(|x| {
    ///    *x += 1;
    ///  });
    /// });
    /// assert_eq!(x.unwrap(), [1, 1, 1, 1]);
    /// ```
    ///
    fn update<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut Self::Inner),
    {
        f(self.inner_mut());
    }

    /// Update the inner value with another Paranoid value.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_protected::{Paranoid, Protected};
    /// let mut x = Protected::new([0u8; 32]);
    /// let y = Protected::new([1u8; 32]);
    /// x.update_with(y, |x, y| {
    ///    x.copy_from_slice(&y);
    /// });
    /// assert_eq!(x.unwrap(), [1u8; 32]);
    /// ```
    ///
    /// TODO: Apply Usage trait bounds to prevent accidental broadening of scope
    /// e.g. `other` must have the same, or broader scope as `self`
    fn update_with<Other, F>(&mut self, other: Other, mut f: F)
    where
        F: FnMut(&mut Self::Inner, Other::Inner),
        Other: Paranoid,
    {
        f(self.inner_mut(), other.unwrap());
    }

    /// Like `update_with` but the second argument is a reference.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_protected::{Paranoid, Protected};
    /// let mut x = Protected::new([0u8; 32]);
    /// let y = Protected::new([1u8; 32]);
    /// x.update_with_ref(&y, |x, y| {
    ///   x.copy_from_slice(y);
    /// });
    /// assert_eq!(x.unwrap(), [1u8; 32]);
    /// ```
    ///
    fn update_with_ref<'a, Other, A, F>(&mut self, other: &'a Other, mut f: F)
    where
        A: ?Sized + 'a,
        Other: AsProtectedRef<'a, A> + ?Sized,
        F: FnMut(&mut Self::Inner, &A),
    {
        let arg: ProtectedRef<'a, A> = other.as_protected_ref();
        f(self.inner_mut(), arg.inner_ref());
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
