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
