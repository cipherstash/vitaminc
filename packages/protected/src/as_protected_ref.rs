use crate::{private::Lends, Buffer, Controlled};
use core::ops::Deref;

/// Trait for types that can be converted to a `ProtectedRef`.
/// Conceptually similar to the `AsRef` trait in `std` but for `Protected` types.
/// This prevents the inner value from being accessed directly.
/// `ProtectedRef` cannot be constructed outside this crate, so downstream
/// implementations must delegate to an existing protected source rather than
/// wrapping an arbitrary reference.
///
/// Only an owner that wipes lends: a `Protected`, an `Equatable` or
/// `Exportable` around one, a [`Locked`](crate::Locked) and a [`Buffer`].
/// No plain value does, such as a `Vec<u8>`, `[u8]`, `[u8; N]`, `str` or
/// `Cow<str>`, so a consumer that receives a `ProtectedRef` knows an owner
/// that wipes stands behind it. Bytes held plain go into a `Protected` or a
/// `Buffer` first, and that owner lends; text goes into a
/// `Protected<String>`, whose borrow [`as_deref`](ProtectedRef::as_deref)
/// narrows to `str` and [`as_ref_of`](ProtectedRef::as_ref_of) to bytes.
///
/// ```
/// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
/// use vitaminc::protected::{AsProtectedRef, Protected, ProtectedRef};
///
/// let arrived: &str = "secret";
/// let text = Protected::new(String::from(arrived));
/// let as_text: ProtectedRef<str> = text.as_protected_ref().as_deref();
/// assert_eq!(as_text.risky_ref(), "secret");
/// let as_bytes: ProtectedRef<[u8]> = text.as_protected_ref().as_ref_of();
/// assert_eq!(as_bytes.risky_ref(), b"secret");
/// ```
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

/// A [`Buffer`] lends its bytes, so a function that reads bytes can take a
/// `Buffer` without the caller reading it through
/// [`risky_ref`](Controlled::risky_ref). The `Buffer` still wipes its bytes
/// when it drops.
///
/// A function that reads bytes takes a `ProtectedRef<[u8]>`. Then a
/// `Buffer` and a protected `Vec<u8>` both reach it. A
/// `Protected<Vec<u8>>` lends a `ProtectedRef<Vec<u8>>`, which
/// [`as_deref`](ProtectedRef::as_deref) narrows to its bytes, and a
/// `Protected<[u8; N]>` lends a `ProtectedRef<[u8; N]>`, which
/// [`as_ref_of`](ProtectedRef::as_ref_of) narrows the same way. Bytes that
/// arrive as a plain `Vec<u8>` or `&[u8]`, such as input from another
/// process, go into a `Protected` or a `Buffer` first; a plain `Vec<u8>`
/// does not lend, because nothing would wipe it.
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
///
/// let key = Protected::new(*b"secret");
/// assert_eq!(length(key.as_protected_ref().as_ref_of()), 6);
///
/// let arrived: &[u8] = b"secret";
/// let owned = Protected::new(arrived.to_vec());
/// assert_eq!(length(owned.as_protected_ref().as_deref()), 6);
/// ```
impl<'a> AsProtectedRef<'a, [u8]> for Buffer {
    fn as_protected_ref(&'a self) -> ProtectedRef<'a, [u8]> {
        ProtectedRef(self.risky_ref())
    }
}

/// A wrapper around a reference to prevent inner access.
/// Conceptually similar to `&T`, but it can only be made inside this crate,
/// through [`AsProtectedRef`], and the inner value is reached only through
/// the combinators that take it or through [`risky_ref`](Self::risky_ref).
///
/// Whatever lends a `ProtectedRef` owns the value behind it and wipes it
/// when it drops: a [`Controlled`] owner such as a `Protected` or a
/// [`Buffer`], or a [`Locked`](crate::Locked), runs the value's
/// [`Zeroize`](zeroize::Zeroize) impl. The borrow is wiped as far as that
/// impl reaches. For `Vec`, `String`, `Box` and arrays that is the whole
/// value; a hand-written impl that leaves memory it points at untouched
/// leaves it untouched behind the borrow too. Dropping the `ProtectedRef`
/// itself wipes nothing. One narrowed through [`as_deref`](Self::as_deref)
/// or [`as_ref_of`](Self::as_ref_of) borrows the same memory as the one it
/// came from, and is wiped with it.
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
    /// the original borrow still owns the value behind it, and wipes it as
    /// far as its `Zeroize` impl reaches (see [`ProtectedRef`]).
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

impl<'a, T: ?Sized> ProtectedRef<'a, T> {
    /// Narrows the borrow through `AsRef`, and keeps it protected. This is
    /// how a fixed-size key reaches a function that reads bytes: a
    /// `ProtectedRef<[u8; 32]>` becomes a `ProtectedRef<[u8]>` with no copy,
    /// where [`as_deref`](Self::as_deref) cannot, because an array does not
    /// implement `Deref`. Whatever lent the original borrow still owns the
    /// value behind it, and wipes it as far as its `Zeroize` impl reaches
    /// (see [`ProtectedRef`]).
    ///
    /// `AsRef` has more than one target for some types (`String` is
    /// `AsRef<str>` and `AsRef<[u8]>`), so a call site names the target
    /// when nothing else does. A parameter of type `ProtectedRef<[u8]>`
    /// already does.
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// use vitaminc::protected::{AsProtectedRef, Protected, ProtectedRef};
    ///
    /// fn length(bytes: ProtectedRef<'_, [u8]>) -> usize {
    ///     bytes.risky_ref().len()
    /// }
    ///
    /// let key = Protected::new([7u8; 32]);
    /// assert_eq!(length(key.as_protected_ref().as_ref_of()), 32);
    /// ```
    pub fn as_ref_of<U: ?Sized>(&self) -> ProtectedRef<'a, U>
    where
        T: AsRef<U>,
    {
        ProtectedRef(self.0.as_ref())
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
    fn plain_bytes_reach_a_byte_reader_through_a_protected_owner() {
        // A plain Vec<u8> or &[u8] does not lend (see tests/ui); it goes
        // into an owner that wipes it, and that owner lends. The same holds
        // for a plain &str, Cow<str> or [u8; N]: the tests below reach
        // text and arrays only through a Protected owner.
        let arrived: &[u8] = b"frame";
        let owned = Protected::new(arrived.to_vec());
        assert_eq!(lent(owned.as_protected_ref().as_deref()), b"frame");

        let mut buffer = Buffer::new();
        buffer.extend_from_slice(arrived);
        assert_eq!(lent(buffer.as_protected_ref()), b"frame");
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
    }

    #[test]
    fn array_owners_reach_a_byte_reader_through_as_ref_of() {
        // An array does not implement Deref, so as_deref cannot narrow it;
        // as_ref_of does, for every owner that lends one.
        let protected = Protected::new(*b"frame");
        let equatable: Equatable<Protected<[u8; 5]>> = Equatable::new(*b"frame");
        let locked = Locked::new(*b"frame").unwrap();

        assert_eq!(lent(protected.as_protected_ref().as_ref_of()), b"frame");
        assert_eq!(lent(equatable.as_protected_ref().as_ref_of()), b"frame");
        assert_eq!(lent(locked.as_protected_ref().as_ref_of()), b"frame");
    }

    #[test]
    fn as_ref_of_narrows_without_a_copy() {
        let key = Protected::new([7u8; 32]);
        let address = key.risky_ref().as_ptr();
        let bytes: ProtectedRef<[u8]> = key.as_protected_ref().as_ref_of();
        assert_eq!(bytes.risky_ref().as_ptr(), address);
        assert_eq!(bytes.risky_ref().len(), 32);
    }

    #[test]
    fn as_ref_of_covers_what_as_deref_does() {
        // The target is named because String is AsRef<str> and AsRef<[u8]>.
        let text = Protected::new(String::from("frame"));
        let narrowed: ProtectedRef<str> = text.as_protected_ref().as_ref_of();
        assert_eq!(narrowed.risky_ref(), "frame");
        let bytes: ProtectedRef<[u8]> = text.as_protected_ref().as_ref_of();
        assert_eq!(bytes.risky_ref(), b"frame");

        let vec = Protected::new(b"frame".to_vec());
        assert_eq!(lent(vec.as_protected_ref().as_ref_of()), b"frame");
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
