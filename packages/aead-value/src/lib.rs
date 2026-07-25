#![deny(clippy::unwrap_used, clippy::todo, unsafe_code, unused_imports)]
#![doc = include_str!("../README.md")]
pub mod tagged;
pub mod tags;
mod value;

pub use value::FfiValue;
