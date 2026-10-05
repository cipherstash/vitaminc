#![deny(clippy::unwrap_used, clippy::todo, unsafe_code, unused_imports)]
#![doc = include_str!("../README.md")]
pub mod aad;
pub mod kind;
pub mod tagged;
pub mod tags;
pub mod transport;
mod value;

pub use aad::LeafTypeAad;
pub use kind::{ParseValueKindError, ValueKind};
pub use value::{FfiValue, Utf8String};
