use crate::{private::Lends, Controlled};
use std::borrow::Cow;

/// Trait for types that can be converted to a `ProtectedRef`.
/// Conceptually similar to the `AsRef` trait in `std` but for `Protected` types.
/// This prevents the inner value from being accessed directly.
/// `ProtectedRef` cannot be constructed outside this crate, so downstream
/// implementations must delegate to an existing protected source rather than
/// wrapping an arbitrary reference.
///
/// # Implementing `AsProtectedRef`
///
/// Implementing `AsProtectedRef` for a type allows it to be used in functions that take a `ProtectedRef`.
/// Note, that such implementations must be defined on inner types that already implement `AsProtectedRef`
/// because `ProtectedRef` cannot be constructed from the inner type directly.
///
/// ```
/// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
/// use vitaminc::protected::{AsProtectedRef, Protected, ProtectedRef};
///
/// pub struct SensitiveData(Protected<Vec<u8>>);
///
/// impl AsProtectedRef<'_, Vec<u8>> for SensitiveData {
///    fn as_protected_ref(&self) -> ProtectedRef<Vec<u8>> {
///       self.0.as_protected_ref()
///   }
/// }
///
/// let data = SensitiveData(Protected::new(Vec::new()));
/// let pref: ProtectedRef<Vec<u8>> = data.as_protected_ref();
/// ```
///
pub trait AsProtectedRef<'a, A: ?Sized> {
    /// Borrow the value behind the protected-reference interface for lifetime `'a`.
    /// This does not allocate, wipe the source, or extend its lifetime.
    fn as_protected_ref(&'a self) -> ProtectedRef<'a, A>;
}

/// `Protected`, and `Equatable` and `Exportable` around a type that lends,
/// lend their inner value. A [`Usage`](crate::Usage) does not: its scope
/// says which code may take the value, and a `ProtectedRef` would carry the
/// value to any consumer, whatever the scope. Reach it through
/// [`Controlled::risky_ref`] instead, which says so at the call site.
impl<'a, T> AsProtectedRef<'a, <T as Controlled>::Inner> for T
where
    T: Controlled + Lends,
{
    fn as_protected_ref(&'a self) -> ProtectedRef<'a, <T as Controlled>::Inner> {
        ProtectedRef(self.risky_ref())
    }
}

impl<'a, const N: usize> AsProtectedRef<'a, [u8; N]> for [u8; N] {
    fn as_protected_ref(&'a self) -> ProtectedRef<'a, [u8; N]> {
        ProtectedRef(self)
    }
}

/// String references cannot be zeroized, so we can't implement `Zeroize` for `Protected<&str>`.
/// Instead, a string lends a `ProtectedRef`, so it can be passed to functions that take one.
/// It lends its bytes here, and its text below; a caller whose target type does not
/// already say which must annotate it.
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

/// A string can also lend itself as text, for a consumer that cares which
/// it is (such as `vitaminc-aead`, which seals text and bytes as different
/// leaves). With both impls, an unannotated `"pw".as_protected_ref()` does
/// not compile, so a caller always picks one.
impl<'a> AsProtectedRef<'a, str> for str {
    fn as_protected_ref(&'a self) -> ProtectedRef<'a, str> {
        ProtectedRef(self)
    }
}

impl<'a> AsProtectedRef<'a, str> for Cow<'a, str> {
    fn as_protected_ref(&'a self) -> ProtectedRef<'a, str> {
        ProtectedRef(self)
    }
}

/// A wrapper around a reference to prevent inner access.
/// Conceptually similar to `&T`, but it can only be made inside this crate,
/// through [`AsProtectedRef`], and the inner value is reached only through
/// the combinators that take it or through [`risky_ref`](Self::risky_ref).
///
/// A `ProtectedRef` does not mean the value behind it is wiped. One lent by
/// a [`Controlled`] owner or a [`Locked`](crate::Locked) is wiped when that
/// owner drops. One lent by a bare `[u8; N]`, `str` or `Cow<str>` is a plain
/// borrow that nothing wipes.
pub struct ProtectedRef<'a, T>(pub(crate) &'a T)
where
    T: ?Sized;

impl<'a, T: ?Sized> ProtectedRef<'a, T> {
    /// Provides the borrow this wraps, for its full lifetime.
    ///
    /// This is the borrow's counterpart to [`Controlled::risky_ref`]. It
    /// exists so another crate can read through a protected borrow
    /// deliberately: `vitaminc-aead` uses it to walk a `ProtectedRef` as
    /// plaintext, and it can only do that through a public method.
    ///
    /// Code that receives a `ProtectedRef` could already read it, because
    /// [`Controlled::risky_update_with_ref`] hands its closure the same `&T`. This
    /// method makes that one explicit step, under the `risky_` name, rather
    /// than a detour through a throwaway `Protected`.
    ///
    /// Dropping the `ProtectedRef` wipes nothing. Whatever lent it is
    /// responsible for wiping (see [`ProtectedRef`]).
    ///
    /// This is a risky operation because it bypasses the protections that
    /// the wrapper provides.
    /// **Use with caution!**
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// use vitaminc::protected::{AsProtectedRef, Protected};
    ///
    /// let secret = Protected::new([7u8; 4]);
    /// let pref = secret.as_protected_ref();
    /// assert_eq!(pref.risky_ref(), &[7u8; 4]);
    /// ```
    pub fn risky_ref(&self) -> &'a T {
        self.0
    }
}
