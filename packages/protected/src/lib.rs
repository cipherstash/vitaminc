#![recursion_limit = "256"]
#![doc = include_str!("../README.md")]
mod as_protected_ref;
mod conversions;
//mod digest;
mod equatable;
mod exportable;
mod ops;
mod protected;
mod usage;
mod zeroed;

use zeroize::Zeroize;

mod private;

#[cfg(feature = "bitvec")]
pub mod bitvec;

pub mod slice_index;

// Exports
pub use as_protected_ref::{AsProtectedRef, ProtectedRef};
//pub use digest::ProtectedDigest;
pub use equatable::{ConstantTimeEq, Equatable};
pub use exportable::Exportable;
pub use protected::{flatten_array, Protected};
pub use usage::{Acceptable, DefaultScope, Scope, Usage};
pub use zeroed::Zeroed;

pub trait Protect: private::ProtectSealed {
    type RawType;

    /// Unwraps the raw inner value.
    fn risky_unwrap(self) -> Self::RawType;
}

impl<T> Protect for T where T: ProtectInit, <T as ProtectInit>::Inner: Protect {
    type RawType = <T::Inner as Protect>::RawType;

    fn risky_unwrap(self) -> Self::RawType {
        self.into_inner().risky_unwrap()
    }
}

pub trait ProtectNew<T>: Protect {
    fn new(raw: T) -> Self;
}

impl<T, I> ProtectNew<I> for T where T: ProtectInit, T::Inner: ProtectNew<I> {
    fn new(raw: I) -> Self {
        T::init(T::Inner::new(raw))
    }
}

/// A trait for types that can be initialized from a `Protect` value.
/// This is only used by user defined types that wrap a `Protect` value
/// as it must take a concrete type.
/// Internal adapters like `Equatable` and `Exportable` are able to wrap any protected type so
/// they do not implement [ProtectInit].
pub trait ProtectInit {
    type Inner: Protect;

    fn init(safe: Self::Inner) -> Self;

    /// Returns the inner value which implements [Protect].
    fn into_inner(self) -> Self::Inner;
}


// TODO: This trait is similar to the Iterator trait in std
// Implement for all "adapter" types - Equatable, Exportable, etc.
// Come up with a better name for it
pub trait ProtectMethods: Protect {
    /// Generate a new `Protected` from a function that returns the inner value.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_protected::{Protected, Protect, ProtectMethods};
    /// fn array_gen<const N: usize>() -> [u8; N] {
    ///     let mut input: [u8; N] = [0; N];
    ///     input.iter_mut().enumerate().for_each(|(i, x)| {
    ///         *x = (i + 1) as u8;
    ///     });
    ///     input
    /// }
    /// let input: Protected<[u8; 8]> = Protected::generate(array_gen);
    /// assert_eq!(input.risky_unwrap(), [1, 2, 3, 4, 5, 6, 7, 8]);
    /// ```
    /// // TODO: A Generate Array could handle the MaybeUninit stuff
    fn generate<F, FunOut>(f: F) -> Self
    where
        Self: Sized + ProtectNew<FunOut>,
        F: FnOnce() -> FunOut,
    {
        Self::new(f())
    }

    /// Generate a new `Protected` from a function that returns a `Result` with the inner value.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_protected::{Protected, ProtectMethods};
    /// use std::string::FromUtf8Error;
    ///
    /// let input: Result<Protected<String>, FromUtf8Error> = Protected::generate_ok(|| {
    ///    String::from_utf8(vec![1, 2, 3, 4, 5, 6, 7, 8])
    /// });
    /// ```
    ///
    fn generate_ok<F, FunOut, E>(f: F) -> Result<Self, E>
    where
        Self: Sized + ProtectNew<FunOut>,
        F: FnOnce() -> Result<FunOut, E>,
    {
        f().map(Self::new)
    }

    /// Map `Protected<Self::Inner>` value into a new `Protected<B>`.
    /// Conceptually similar to `Option::map`.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_protected::{Protected, Protect, ProtectNew, ProtectMethods};
    /// let x = Protected::new(100u8);
    /// let y = x.map(|x| x + 10);
    /// assert_eq!(y.risky_unwrap(), 110);
    /// ```
    ///
    /// TODO: Apply Usage trait bounds to prevent accidental broadening of scope
    /// e.g. `other` must have the same, or broader scope as `self`
    fn map<B, F>(self, f: F) -> Protected<B>
    where
        Self: Sized,
        F: FnOnce(Self::RawType) -> B,
        B: Zeroize,
    {
        Protected(f(self.risky_unwrap()))
    }

    /// Zip two `Protected` values together with a function that combines them.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_protected::{Protected, Protect, ProtectNew, ProtectMethods};
    /// let x = Protected::new(1);
    /// let y = Protected::new(2);
    /// let z: Protected<u32> = x.zip(y, |x, y| x + y);
    /// assert_eq!(z.risky_unwrap(), 3);
    /// ```
    ///
    /// TODO: Apply Usage trait bounds to prevent accidental broadening of scope
    /// e.g. `other` must have the same, or broader scope as `self`
    fn zip<Other, Out, F, FunOut>(self, b: Other, f: F) -> Out
    where
        Self: Sized,
        Other: ProtectMethods,
        Out: ProtectNew<FunOut>,
        F: FnOnce(Self::RawType, Other::RawType) -> FunOut,
    {
        Out::new(f(self.risky_unwrap(), b.risky_unwrap()))
    }

   /*/// Like `zip` but the second argument is a reference.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_protected::Protected;
    /// let x = Protected::new(String::from("hello "));
    /// let y = Protected::new(String::from("world"));
    /// let z = x.zip_ref(&y, |x, y| x + y);
    /// assert_eq!(z.risky_unwrap(), "hello world");
    /// ```
    ///
    fn zip_ref<'a, A, Other, Out, F>(self, other: &'a Other, f: F) -> Protected<Out>
    where
        Self: Sized,
        A: ?Sized + 'a,
        Other: AsProtectedRef<'a, A>,
        Out: ProtectSealed,
        F: FnOnce(Self::Inner, &A) -> Out,
    {
        let arg: ProtectedRef<'a, A> = other.as_protected_ref();
        Protected::init_from_inner(f(self.risky_unwrap(), arg.inner_ref()))
    }*/

    /// Similar to `map` but using references to that the inner value is updated in place.
    ///
    /// # Example
    ///
    /// ```
    /// # use vitaminc_protected::{Protected, Protect, ProtectNew, ProtectMethods};
    /// let mut x = Protected::new([0u8; 4]);
    /// x.update(|x| {
    ///   x.iter_mut().for_each(|x| {
    ///    *x += 1;
    ///  });
    /// });
    /// assert_eq!(x.risky_unwrap(), [1, 1, 1, 1]);
    /// ```
    ///
    fn update<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut Self::RawType),
    {
        f(self.inner_mut());
    }

    /// Update the inner value with another Paranoid value.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_protected::{Protected, Protect, ProtectNew, ProtectMethods};
    /// let mut x = Protected::new([0u8; 32]);
    /// let y = Protected::new([1u8; 32]);
    /// x.update_with(y, |x, y| {
    ///    x.copy_from_slice(&y);
    /// });
    /// assert_eq!(x.risky_unwrap(), [1u8; 32]);
    /// ```
    ///
    /// TODO: Apply Usage trait bounds to prevent accidental broadening of scope
    /// e.g. `other` must have the same, or broader scope as `self`
    fn update_with<Other, F>(&mut self, other: Other, mut f: F)
    where
        F: FnMut(&mut Self::RawType, Other::RawType),
        Other: ProtectMethods,
    {
        // FIXME: There's a chance here that other will be dropped and not zeroized correctly
        // But not all Zeroize types are ZeroizeOnDrop - we may need to yield a wrapper type that Derefs to the inner value
        // Ditto for the zip method
        // Either that or just make sure the caller uses zeroize() on the other value :/
        f(self.inner_mut(), other.risky_unwrap());
    }

    /// Like `update_with` but the second argument is a reference.
    ///
    /// # Example
    ///
    /// ```
    /// # use vitaminc_protected::{Protected, Protect, ProtectNew, ProtectMethods};
    /// use vitaminc_protected::AsProtectedRef;
    ///
    /// let mut x = Protected::new([0u8; 32]);
    /// let y = Protected::new([1u8; 32]);
    /// x.update_with_ref(y.as_protected_ref(), |x, y| {
    ///   x.copy_from_slice(y);
    /// });
    /// assert_eq!(x.risky_unwrap(), [1u8; 32]);
    /// ```
    ///
    fn update_with_ref<'a, A, F>(&mut self, other: ProtectedRef<'a, A>, mut f: F)
    where
        A: ?Sized + 'a,
        F: FnMut(&mut Self::RawType, &A),
    {
        //let arg: ProtectedRef<'a, A> = other.as_protected_ref();
        f(self.inner_mut(), other.inner_ref());
    }

    /// Iterate over the inner value and wrap each element in a `Protected`.
    /// `I` must be `Copy` because [Protected] always takes ownership of the inner value.
    fn iter<'a, I>(&'a self) -> impl Iterator<Item = Protected<I>>
    where
        Self::RawType: AsRef<[I]>,
        I: Copy + 'a,
    {
        self.inner().as_ref().iter().copied().map(Protected)
    }

    // TODO: Consider making this a separate trait and only usable within the crate
    fn inner(&self) -> &Self::RawType;
    fn inner_mut(&mut self) -> &mut Self::RawType;
}

// TODO: Implement Collect for Protected (or Paranoid) so we can use collect() on iterators

#[cfg(test)]
mod tests {
    use protected::flatten_array;

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
        assert_eq!(y.risky_unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_flatten_array() {
        let x = Protected::new(1);
        let y = Protected::new(2);
        let z = Protected::new(3);
        let array: [Protected<u8>; 3] = [x, y, z];
        let flattened = flatten_array(array);
        assert!(matches!(flattened, Protected(_)));
        assert_eq!(flattened.risky_unwrap(), [1, 2, 3]);
    }
}
