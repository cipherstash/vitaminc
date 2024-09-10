#![doc = include_str!("../README.md")]
mod as_protected_ref;
mod controlled;
mod conversions;
mod digest;
mod equatable;
mod exportable;
mod ops;
mod usage;
mod zeroed;

use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "bitvec")]
pub mod bitvec;

pub mod slice_index;

pub use as_protected_ref::{AsProtectedRef, ProtectedRef};
pub use zeroed::Zeroed;

// Exports
pub use controlled::Controlled;
pub use digest::ProtectedDigest;
pub use equatable::{ConstantTimeEq, Equatable};
pub use exportable::Exportable;
pub use usage::{Acceptable, DefaultScope, Scope, Usage};

/// The most basic controlled type.
/// It ensures inner types are `Zeroize` and implements `Debug` and `Display` safely (i.e. inner sensitive values are redacted).
#[derive(Zeroize)]
pub struct Protected<T>(T);

opaque_debug::implement!(Protected<T>);

impl<T> Protected<T> {
    /// Create a new [Protected] from an inner value.
    pub const fn new(x: T) -> Self
    where
        T: Zeroize,
    {
        Self(x)
    }
}

impl<T> Protected<Protected<T>> {
    #[inline]
    /// Flatten a [Protected] of [Protected] into a single [Protected].
    /// Similar to `Option::flatten`.
    ///
    /// ```
    /// use vitaminc_protected::{Controlled, Protected};
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
    /// Transpose a [Protected] of `Option` into an `Option` of [Protected].
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

impl<T> private::ControlledPrivate for Protected<T>
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

impl<T> Controlled for Protected<T>
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

/// Convenience function to flatten an array of [Protected] into a [Protected] array.
///
/// # Example
///
/// ```
/// use vitaminc_protected::{flatten_array, Controlled, Protected};
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

mod private {
    /// Private trait that is used to hide the inner value of a Controlled type
    /// as well as preventing consumers from implementing Controlled themselves.
    pub trait ControlledPrivate {
        type Inner;

        fn init_from_inner(x: Self::Inner) -> Self;
        fn inner(&self) -> &Self::Inner;
        fn inner_mut(&mut self) -> &mut Self::Inner;
    }
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
