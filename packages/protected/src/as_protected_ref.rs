use crate::{private::Lends, Buffer, Controlled};
use core::ops::Deref;
use std::borrow::Cow;

/// Trait for types that can be converted to a `ProtectedRef`.
/// Conceptually similar to the `AsRef` trait in `std` but for `Protected` types.
/// This prevents the inner value from being accessed directly.
/// `ProtectedRef` cannot be constructed outside this crate, so a downstream
/// implementation delegates to a value that already lends one.
///
/// Not every lender wipes what it lends. A `Protected` does, and so does a
/// [`Buffer`]. A plain `[u8]`, `Vec<u8>` or `str` lends a plain borrow, and
/// so does a downstream type that delegates to one of them. See
/// [`ProtectedRef`] for the full list.
///
/// # Implementing `AsProtectedRef`
///
/// Implementing `AsProtectedRef` for a type allows it to be used in functions that take a `ProtectedRef`.
/// The implementation delegates to a field that already implements `AsProtectedRef`,
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

/// A [`Buffer`] lends its bytes, so a function that reads bytes can take a
/// `Buffer` without the caller reading it through
/// [`risky_ref`](Controlled::risky_ref). The `Buffer` still wipes its bytes
/// when it drops.
///
/// A function that reads bytes takes a `ProtectedRef<[u8]>`. Then a
/// `Buffer`, a byte slice and a protected `Vec<u8>` all reach it. A
/// `Protected<Vec<u8>>` lends a `ProtectedRef<Vec<u8>>`, which
/// [`as_deref`](ProtectedRef::as_deref) narrows to its bytes.
///
/// ```
/// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
/// use vitaminc::protected::{AsProtectedRef, Buffer, Protected, ProtectedRef};
///
/// fn length(bytes: ProtectedRef<'_, [u8]>) -> usize {
///     bytes.risky_ref().len()
/// }
///
/// let mut out = Buffer::new();
/// out.extend_from_slice(b"secret");
/// assert_eq!(length(out.as_protected_ref()), 6);
///
/// let kept = Protected::new(b"secret".to_vec());
/// assert_eq!(length(kept.as_protected_ref().as_deref()), 6);
/// ```
impl<'a> AsProtectedRef<'a, [u8]> for Buffer {
    fn as_protected_ref(&'a self) -> ProtectedRef<'a, [u8]> {
        ProtectedRef(self.risky_ref())
    }
}

/// A byte slice lends itself, as a `str` does, so a function that takes
/// protected bytes also takes bytes that arrive unprotected, such as input
/// from another process. Nothing wipes a slice lent this way. To pass
/// protected bytes held as a `Vec<u8>`, narrow the borrow with
/// [`as_deref`](ProtectedRef::as_deref).
impl<'a> AsProtectedRef<'a, [u8]> for [u8] {
    fn as_protected_ref(&'a self) -> ProtectedRef<'a, [u8]> {
        ProtectedRef(self)
    }
}

/// A `Vec<u8>` lends its bytes, as a byte slice does. Nothing wipes a `Vec`
/// lent this way.
impl<'a> AsProtectedRef<'a, [u8]> for Vec<u8> {
    fn as_protected_ref(&'a self) -> ProtectedRef<'a, [u8]> {
        ProtectedRef(self.as_slice())
    }
}

/// A `Cow<[u8]>` lends its bytes, as a `Cow<str>` does. Nothing wipes a
/// `Cow` lent this way. The borrow it lends can be shorter than the `Cow`'s
/// own lifetime, so a function that takes
/// `impl for<'a> AsProtectedRef<'a, [u8]>` takes a borrowed `Cow` too.
impl<'a, 'c> AsProtectedRef<'a, [u8]> for Cow<'c, [u8]> {
    fn as_protected_ref(&'a self) -> ProtectedRef<'a, [u8]> {
        ProtectedRef(self.as_ref())
    }
}

/// A wrapper around a reference to prevent inner access.
/// Conceptually similar to `&T`, but it can only be made inside this crate,
/// through [`AsProtectedRef`], and the inner value is reached only through
/// the combinators that take it or through [`risky_ref`](Self::risky_ref).
///
/// A `ProtectedRef` does not mean the value behind it is wiped. One lent by
/// a [`Controlled`] owner, such as a `Protected` or a [`Buffer`], or by a
/// [`Locked`](crate::Locked), is wiped when that owner drops. One lent by a
/// bare `[u8; N]`, `[u8]`, `Vec<u8>`, `Cow<[u8]>`, `str` or `Cow<str>` is a
/// plain borrow that nothing wipes. A `ProtectedRef` narrowed through
/// [`as_deref`](Self::as_deref) is wiped exactly when the one it came from
/// is.
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
    /// [`Controlled::update_with_ref`] hands its closure the same `&T`. This
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

impl<'a, T: ?Sized + Deref> ProtectedRef<'a, T> {
    /// Narrows the borrow through `Deref`, and keeps it protected. A
    /// `ProtectedRef<Vec<u8>>` becomes a `ProtectedRef<[u8]>`, and a
    /// `ProtectedRef<String>` becomes a `ProtectedRef<str>`. Whatever lent
    /// the original borrow still owns the value behind it, and still wipes
    /// it.
    ///
    /// The name follows `Option::as_deref`. It needs no `risky_` name,
    /// because the value never leaves a `ProtectedRef`.
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// use vitaminc::protected::{AsProtectedRef, Protected, ProtectedRef};
    ///
    /// let secret = Protected::new(b"secret".to_vec());
    /// let bytes: ProtectedRef<[u8]> = secret.as_protected_ref().as_deref();
    /// assert_eq!(bytes.risky_ref(), b"secret");
    /// ```
    pub fn as_deref(&self) -> ProtectedRef<'a, T::Target> {
        ProtectedRef(Deref::deref(self.0))
    }
}

#[cfg(test)]
mod byte_lender_tests {
    use super::*;
    use crate::{Equatable, Locked, Protected};

    fn lent(bytes: ProtectedRef<'_, [u8]>) -> Vec<u8> {
        bytes.risky_ref().to_vec()
    }

    #[test]
    fn a_buffer_lends_the_bytes_it_holds() {
        let mut buffer = Buffer::new();
        buffer.extend_from_slice(b"frame");
        assert_eq!(lent(buffer.as_protected_ref()), b"frame");
    }

    #[test]
    fn a_slice_and_a_vec_lend_themselves() {
        assert_eq!(lent(b"frame"[..].as_protected_ref()), b"frame");
        assert_eq!(lent(b"frame".to_vec().as_protected_ref()), b"frame");
    }

    #[test]
    fn a_cow_of_bytes_lends_its_bytes() {
        assert_eq!(
            lent(Cow::Borrowed(&b"frame"[..]).as_protected_ref()),
            b"frame"
        );
        assert_eq!(
            lent(Cow::<[u8]>::Owned(b"frame".to_vec()).as_protected_ref()),
            b"frame"
        );
    }

    #[test]
    fn a_protected_vec_still_lends_without_an_annotation() {
        // Protected<Vec<u8>> keeps its one AsProtectedRef impl, so existing
        // unannotated calls still infer `Vec<u8>`.
        let protected = Protected::new(b"frame".to_vec());
        let pref = protected.as_protected_ref();
        assert_eq!(pref.risky_ref().as_slice(), b"frame");
    }

    #[test]
    fn protected_owners_reach_a_byte_reader_through_as_deref() {
        let protected = Protected::new(b"frame".to_vec());
        let equatable: Equatable<Protected<Vec<u8>>> = Equatable::new(b"frame".to_vec());
        let locked = Locked::new(b"frame".to_vec()).unwrap();

        assert_eq!(lent(protected.as_protected_ref().as_deref()), b"frame");
        assert_eq!(lent(equatable.as_protected_ref().as_deref()), b"frame");
        assert_eq!(lent(locked.as_protected_ref().as_deref()), b"frame");
        assert_eq!(lent(b"frame"[..].as_protected_ref()), b"frame");
    }

    #[test]
    fn as_deref_narrows_without_a_copy() {
        let protected = Protected::new(b"frame".to_vec());
        let address = protected.risky_ref().as_ptr();
        let bytes = protected.as_protected_ref().as_deref();
        assert_eq!(bytes.risky_ref().as_ptr(), address);

        let text = Protected::new(String::from("frame"));
        let narrowed: ProtectedRef<str> = text.as_protected_ref().as_deref();
        assert_eq!(narrowed.risky_ref(), "frame");
    }
}
