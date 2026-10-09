#![deny(clippy::unwrap_used, clippy::todo, unused_imports)]
// The only unsafe left is where napi-rs's conversion traits require it.
// Each block has to say why it is sound, and unsafe calls inside those trait
// methods still need their own block.
#![deny(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks)]
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
