#![doc = include_str!("../README.md")]
#![warn(unused_results)]
#![cfg_attr(test, allow(unused_results))]
mod as_protected_ref;
mod controlled;
mod conversions;
mod debug;
mod digest;
mod equatable;
mod exportable;
mod non_empty;
mod ops;
mod protected;
mod timing_safe;
mod usage;
mod zeroed;
use zeroize::Zeroize;

#[cfg(feature = "bitvec")]
pub mod bitvec;

pub mod slice_index;

pub use as_protected_ref::{AsProtectedRef, ProtectedRef};
pub use zeroed::Zeroed;

// Exports
pub use controlled::Controlled;
pub use digest::ProtectedDigest;
// Re-exported so callers can name the error from `ProtectedDigest::new_with_key`
// without taking their own version-matched dependency on `digest`.
pub use ::digest::InvalidLength;
pub use equatable::{ConstantTimeEq, Equatable};
pub use exportable::{Exportable, SafeDeserialize, SafeSerialize};
pub use non_empty::{EmptyError, IsEmpty, NonEmpty, TryIntoNonEmpty};
pub use protected::{flatten_array, Protected};
pub use usage::{Acceptable, DefaultScope, Scope, Usage};

pub use debug::{OpaqueDebug, Redacted};
pub use timing_safe::{Choice, TimingSafeEq};
pub use vitaminc_protected_derive::{OpaqueDebug, TimingSafeEq};

/// A controlled wrapper whose single owned inner field can be moved out without
/// running the wrapper's zeroizing `Drop`. Implemented only for this crate's
/// controlled wrappers (`Protected` / `Equatable` / `Exportable`); it backs
/// [`move_inner_out`] and, through it, `risky_unwrap` / `flatten` / `transpose`.
///
/// # Safety
///
/// `inner_ptr` must return a valid, well-aligned pointer to the wrapper's live,
/// owned inner field (i.e. `&self.0`), and the implementing type's `Drop` must do
/// nothing but zeroize — so that [`move_inner_out`] skipping it leaks only the
/// wipe, never a resource.
pub(crate) unsafe trait MoveInner {
    /// The owned inner field type.
    type Inner;
    /// Pointer to the live, owned inner field (see the trait's safety contract).
    fn inner_ptr(&self) -> *const Self::Inner;
}

/// Move the single owned field out of a controlled wrapper (e.g. `Protected<T>`)
/// **without** running its zeroizing `Drop`.
///
/// The inner field is bit-copied to the caller and `wrapper` is forgotten so its
/// `Drop` never runs against the now-moved-out field (no double-free, no
/// use-after-zeroize). This is the shared primitive behind
/// `risky_unwrap` / `flatten` / `transpose`.
///
/// This is a *safe* function: the only soundness obligation — that `inner_ptr`
/// names the wrapper's live, owned field — is discharged by the [`MoveInner`]
/// `unsafe` trait, and the pointer is derived from `wrapper` *after* this
/// function owns it, so no pointer outlives the move that produced it.
///
/// # Why the source slot is deliberately NOT scrubbed
///
/// `ptr::read` produces a **bitwise** copy. For heap-backed inners (`Vec`,
/// `String`, `Box`, …) the returned value and `wrapper`'s field then alias the
/// *same* heap allocation. Scrubbing the source semantically (e.g.
/// `inner.zeroize()` against the source) would wipe the heap the returned value
/// still owns — a use-after-zeroize that hands the caller corrupted data (a
/// decrypted `Protected<Vec<u8>>` would come back all zeroes). For inline inners
/// (`[u8; N]`) the abandoned stack copy is the inherent cost of an explicit
/// move-out: `risky_unwrap` & friends transfer ownership — and the wiping
/// obligation — to the caller by contract.
pub(crate) fn move_inner_out<W: MoveInner>(wrapper: W) -> W::Inner {
    // SAFETY: by `MoveInner`'s contract, `inner_ptr` points to `wrapper`'s live,
    // owned inner field. It is read exactly once and `wrapper` is then forgotten,
    // so the returned value is the sole owner — no double-free, and the wrapper's
    // zeroizing `Drop` never wipes the moved-out value.
    let inner = unsafe { core::ptr::read(wrapper.inner_ptr()) };
    core::mem::forget(wrapper);
    inner
}

/// ReplaceT is a sealed trait that is used to replace the inner value of a type.
/// It is only implemented for types that are Controlled.
pub trait ReplaceT<K>: private::Sealed {
    type Output: Controlled;
}

impl<T, K> ReplaceT<K> for Protected<T>
where
    T: Zeroize,
    K: Zeroize,
    Protected<K>: Controlled,
{
    type Output = Protected<K>;
}

impl<T, K> ReplaceT<K> for Equatable<Protected<T>>
where
    T: Zeroize,
    K: Zeroize,
    Equatable<Protected<K>>: Controlled,
{
    type Output = Equatable<Protected<K>>;
}

impl<T, K> ReplaceT<K> for Equatable<Exportable<Protected<T>>>
where
    T: Zeroize,
    K: Zeroize,
    Equatable<Exportable<Protected<K>>>: Controlled,
{
    type Output = Equatable<Exportable<Protected<K>>>;
}

impl<T, K> ReplaceT<K> for Exportable<Protected<T>>
where
    T: Zeroize,
    K: Zeroize,
{
    type Output = Exportable<Protected<K>>;
}

impl<T, K> ReplaceT<K> for Exportable<Equatable<Protected<T>>>
where
    T: Zeroize,
    K: Zeroize,
{
    type Output = Exportable<Equatable<Protected<K>>>;
}

// Its reasonable to "restrict" a Usage by replacing it with an unscoped type
// because any we are not increasing the scope of the type.
impl<T, K, S> ReplaceT<K> for Usage<Protected<T>, S>
where
    T: Zeroize,
    K: Zeroize,
    Protected<K>: Controlled,
{
    type Output = Protected<K>;
}

mod private {
    use crate::{Equatable, Exportable, Protected, Usage};
    use zeroize::Zeroize;

    pub trait Sealed {}
    impl<T: Zeroize> Sealed for Protected<T> {}
    impl<T: Zeroize> Sealed for Equatable<T> {}
    impl<T: Zeroize> Sealed for Exportable<T> {}
    impl<T, S> Sealed for Usage<T, S> {}

    /// Private trait that is used to hide the inner value of a Controlled type
    /// as well as preventing consumers from implementing Controlled themselves.
    /// Marker trait used to seal the `Controlled` trait, preventing external implementations.
    /// This trait is only implemented within this crate.
    pub trait ControlledPrivate {}
}
