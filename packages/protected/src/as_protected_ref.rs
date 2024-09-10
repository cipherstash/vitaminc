use crate::{private::ParanoidPrivate, Controlled};
use std::borrow::Cow;

/// Trait for types that can be converted to a `ProtectedRef`.
/// Conceptually similar to the `AsRef` trait in `std` but for `Protected` types.
/// This prevents the inner value from being accessed directly.
/// The trait is sealed so it cannot be implemented outside of this crate.
///
/// # Implementing `AsProtectedRef`
///
/// Implementing `AsProtectedRef` for a type allows it to be used in functions that take a `ProtectedRef`.
/// Note, that such implementations must be defined on inner types that already implement `AsProtectedRef`
/// because `ProtectedRef` cannot be constructed from the inner type directly.
///
/// ```
/// use vitaminc_protected::{AsProtectedRef, Protected, ProtectedRef};
///
/// pub struct SensitiveData(Protected<Vec<u8>>);
///
/// impl AsProtectedRef<'_, [u8]> for SensitiveData {
///    fn as_protected_ref(&self) -> ProtectedRef<[u8]> {
///       self.0.as_protected_ref()
///   }
/// }
///
/// let data = SensitiveData(Protected::new(Vec::new()));
/// let pref: ProtectedRef<[u8]> = data.as_protected_ref();
/// ```
///
pub trait AsProtectedRef<'a, A: ?Sized> {
    fn as_protected_ref(&'a self) -> ProtectedRef<'a, A>;
}

impl<'a, T, A: ?Sized> AsProtectedRef<'a, A> for T
where
    <T as ParanoidPrivate>::Inner: AsRef<A>,
    T: Controlled,
{
    fn as_protected_ref(&'a self) -> ProtectedRef<'a, A> {
        ProtectedRef(self.inner().as_ref())
    }
}

// TODO: This is only really needed for compatability (so that types not using this API don't have to be moved).
// It might make sense to put this behind a feature flag.
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
