#![deny(clippy::unwrap_used, clippy::todo, unused_imports)]
#![doc = include_str!("../README.md")]
mod ciphertext;
mod convert;
mod scalar;
mod value;
pub use scalar::ConversionError;

pub use ciphertext::JsCipherText;
pub use value::NapiValue;
// Re-exported so addon crates need not depend on the value crate directly.
pub use vitaminc_aead_value::Value;

// Keep the old re-export available for the same compatibility window.
#[allow(deprecated)]
pub use vitaminc_aead_value::FfiValue;
