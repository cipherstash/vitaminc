#![doc = include_str!("../README.md")]
mod as_protected_ref;
mod controlled;
mod conversions;
mod debug;
mod digest;
mod equatable;
mod exportable;
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
pub use equatable::{ConstantTimeEq, Equatable};
pub use exportable::{Exportable, SafeDeserialize, SafeSerialize};
pub use protected::{flatten_array, Protected};
pub use usage::{Acceptable, DefaultScope, Scope, Usage};

pub use debug::{OpaqueDebug, Redacted};
pub use timing_safe::{Choice, TimingSafeEq};
pub use vitaminc_protected_derive::{OpaqueDebug, TimingSafeEq};

/// ReplaceT is a sealed trait that is used to replace the inner value of a type.
/// It is only implemented for types that are Controlled.
pub trait ReplaceT<K>: private::Sealed {
    type Output: Controlled;
}

impl<T, K> ReplaceT<K> for Protected<T>
where
    Protected<K>: Controlled,
{
    type Output = Protected<K>;
}

impl<T, K> ReplaceT<K> for Equatable<Protected<T>>
where
    Equatable<Protected<K>>: Controlled,
{
    type Output = Equatable<Protected<K>>;
}

impl<T, K> ReplaceT<K> for Equatable<Exportable<Protected<T>>>
where
    Equatable<Exportable<Protected<K>>>: Controlled,
{
    type Output = Equatable<Exportable<Protected<K>>>;
}

impl<T, K> ReplaceT<K> for Exportable<Protected<T>>
where
    K: Zeroize,
{
    type Output = Exportable<Protected<K>>;
}

impl<T, K> ReplaceT<K> for Exportable<Equatable<Protected<T>>>
where
    K: Zeroize,
{
    type Output = Exportable<Equatable<Protected<K>>>;
}

// Its reasonable to "restrict" a Usage by replacing it with an unscoped type
// because any we are not increasing the scope of the type.
impl<T, K, S> ReplaceT<K> for Usage<Protected<T>, S>
where
    Protected<K>: Controlled,
{
    type Output = Protected<K>;
}

mod private {
    use crate::{Equatable, Exportable, Protected, Usage};

    pub trait Sealed {}
    impl<T> Sealed for Protected<T> {}
    impl<T> Sealed for Equatable<T> {}
    impl<T> Sealed for Exportable<T> {}
    impl<T, S> Sealed for Usage<T, S> {}

    /// Private trait that is used to hide the inner value of a Controlled type
    /// as well as preventing consumers from implementing Controlled themselves.
    /// Marker trait used to seal the `Controlled` trait, preventing external implementations.
    /// This trait is only implemented within this crate.
    pub trait ControlledPrivate {}
}
