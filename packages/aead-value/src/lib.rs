#![deny(clippy::unwrap_used, clippy::todo, unsafe_code, unused_imports)]
#![doc = include_str!("../README.md")]
pub mod aad;
pub mod kind;
mod scalar;
pub mod tagged;
pub mod tags;
pub mod transport;
mod value;

pub use aad::LeafTypeAad;
pub use kind::{ParseValueKindError, ValueKind};
pub use value::{Utf8String, Value};

/// Deprecated name for [`Value`], retained for one release.
#[deprecated(note = "renamed to `Value`; use `Value` instead")]
pub type FfiValue = Value;
