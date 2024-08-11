mod conversions;
mod digest;
mod equatable;
mod exportable;
mod indexable;
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
    /// use protected::Protected;
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
    /// use protected::Protected;
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
    /// use protected::{Equatable, Protected};
    ///
    /// let x = Protected::new([0u8; 32]);
    /// let y: Equatable<Protected<[u8; 32]>> = x.equatable();
    /// ```
    fn equatable(self) -> Equatable<Self> {
        Equatable(self)
    }

    fn indexable(self) -> Indexable<Self> {
        Indexable(self)
    }

    // TODO: Make this behave like Option and Result where the caller only has to worry about the inner type
    // TODO: This will have to be a trait to allow for multiple implementations - we can't make it generic or that would allow arbitrary conversion
    fn map<B, F>(self, f: F) -> B
    where
        F: FnOnce(<Self as ParanoidPrivate>::Inner) -> B,
        B: Paranoid,
    {
        f(self.unwrap())
    }

    fn zip<Other, Out, F>(self, b: Other, f: F) -> Self
    where
        Other: Paranoid,
        Out: Paranoid,
        F: FnOnce(Self::Inner, Other::Inner) -> Self::Inner,
    {
        Self::init_from_inner(f(self.unwrap(), b.unwrap()))
    }

    // TODO: A transpose method would be helpful, too! Like Option<Result<T, E>> -> Result<Option<T>, E>

    /// Iterate over the inner value and wrap each element in a `Protected`.
    /// `I` must be `Copy` because [Protected] always takes ownership of the inner value.
    fn iter<'a, I>(&'a self) -> impl Iterator<Item = Protected<I>>
    where
        <Self as ParanoidPrivate>::Inner: AsRef<[I]>,
        I: Copy + 'a,
    {
        self.inner().as_ref().iter().copied().map(Protected)
    }

    // TODO: into_iter will be handy for recipher
    //fn into_iter(self) -> impl Iterator<Item = Self::Inner> where Self::Inner: IntoIterator;

    // TODO: Consider making this unsafe
    fn unwrap(self) -> Self::Inner;
}

// TODO: Implement Collect for Protected (or Paranoid) so we can use collect() on iterators

// Exports
pub use digest::ProtectedDigest;
pub use equatable::Equatable;
pub use exportable::Exportable;
pub use indexable::Indexable;
pub use usage::{Acceptable, DefaultScope, Scope, Usage};

// TODO: Add compile tests

/// Basic building block for Paranoid.
/// It uses a similar design "adapter" pattern to `std::slide::Iter`.
/// `Protected` adds Zeroize and OpaqueDebug.
#[derive(Zeroize)]
pub struct Protected<T>(T);

opaque_debug::implement!(Protected<T>);

// TODO: Docs
impl<T> Protected<T> {
    /// Create a new `Protected` from an inner value.
    pub fn new(x: T) -> Self
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
    /// use protected::{Exportable, Protected};
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
/// use protected::{flatten_array, Protected};
/// let x = Protected::new([0u8; 32]);
/// let y = Protected::new([1u8; 32]);
/// let z = Protected::new([2u8; 32]);
/// let array = [x, y, z];
/// let flattened = flatten_array(array);
/// assert_eq!(flattened.unwrap(), [0u8; 32, 1u8; 32, 2u8; 32]);
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
}
