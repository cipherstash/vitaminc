use crate::{private::ParanoidPrivate, Paranoid};
use private::Sealed;
use std::borrow::Cow;

/// Trait for types that can be converted to a `ProtectedRef`.
/// Conceptually similar to the `AsRef` trait in `std` but for `Protected` types.
/// This prevents the inner value from being accessed directly.
/// The trait is sealed so it cannot be implemented outside of this crate.
pub trait AsProtectedRef<'a, A: ?Sized>: Sealed {
    fn as_protected_ref(&'a self) -> ProtectedRef<'a, A>;
}

impl<'a, T, A: ?Sized> AsProtectedRef<'a, A> for T
where
    <T as ParanoidPrivate>::Inner: AsRef<A>,
    T: Paranoid,
{
    fn as_protected_ref(&'a self) -> ProtectedRef<'a, A> {
        ProtectedRef(self.inner().as_ref())
    }
}

/// String references cannot be zeroized, so we can't implement `Zeroize` for `Protected<&str>`.
/// Instead, we implement `AsProtectedRef` to allow the use of string references in functions that take them.
impl<'a> AsProtectedRef<'a, [u8]> for str {
    fn as_protected_ref(&'a self) -> ProtectedRef<'a, [u8]> {
        ProtectedRef(self.as_bytes())
    }
}

impl<'a> AsProtectedRef<'a, [u8]> for Cow<'a, str> {
    fn as_protected_ref(&'a self) -> ProtectedRef<'a, [u8]> {
        ProtectedRef(self.as_bytes())
    }
}

/// A wrapper around a reference to prevent inner access.
/// Conceptually similar to `&T` but prevents direct access to the inner value outside of this crate.
pub struct ProtectedRef<'a, T>(&'a T)
where
    T: ?Sized;

impl<'a, T: ?Sized> ProtectedRef<'a, T> {
    pub(crate) fn inner_ref(&self) -> &T {
        self.0
    }
}

mod private {
    use super::*;

    pub trait Sealed {}

    // All paranoids are sealed so can implement AsProtectedRef
    impl<T> Sealed for T where T: ParanoidPrivate {}

    impl Sealed for str {}
    impl<'a> Sealed for Cow<'a, str> {}
}
