#![doc = include_str!("../README.md")]
mod as_protected_ref;
mod controlled;
mod conversions;
mod digest;
mod equatable;
mod exportable;
mod ops;
mod protected;
mod usage;
mod zeroed;

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
pub use protected::{flatten_array, Protected};
pub use usage::{Acceptable, DefaultScope, Scope, Usage};
use zeroize::Zeroize;

/// ReplaceT is a sealed trait that is used to replace the inner value of a type.
/// It is only implemented for types that are Controlled.
pub trait ReplaceT<K>: private::Sealed {
    type Output: Controlled;
}

impl<T, K> ReplaceT<K> for Protected<T> where Protected<K>: Controlled {
    type Output = Protected<K>;
}

impl<T, K> ReplaceT<K> for Equatable<Protected<T>> where Equatable<Protected<K>>: Controlled {
    type Output = Equatable<Protected<K>>;
}

impl<T, K> ReplaceT<K> for Equatable<Exportable<Protected<T>>> where Equatable<Exportable<Protected<K>>>: Controlled {
    type Output = Equatable<Exportable<Protected<K>>>;
}

impl<T, K> ReplaceT<K> for Exportable<Protected<T>> where K: Zeroize {
    type Output = Exportable<Protected<K>>;
}

impl<T, K> ReplaceT<K> for Exportable<Equatable<Protected<T>>> where K: Zeroize {
    type Output = Exportable<Equatable<Protected<K>>>;
}

mod private {
    use crate::{Equatable, Exportable, Protected};

    pub trait Sealed {}
    impl<T> Sealed for Protected<T> {}
    impl<T> Sealed for Equatable<T> {}
    impl<T> Sealed for Exportable<T> {}

    /// Private trait that is used to hide the inner value of a Controlled type
    /// as well as preventing consumers from implementing Controlled themselves.
    pub trait ControlledPrivate {
        type Inner;

        // FIXME: We shouldn't be able to call these outside of the crate (but I think we can!)
        fn init_from_inner(x: Self::Inner) -> Self;
        fn inner(&self) -> &Self::Inner;
        fn inner_mut(&mut self) -> &mut Self::Inner;
    }
}
