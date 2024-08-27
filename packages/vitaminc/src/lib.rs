#![doc = include_str!("../../../README.md")]

#[cfg(feature = "protected")]
pub use vitaminc_protected::*;

#[cfg(feature = "random")]
pub use vitaminc_random::*;

#[cfg(feature = "permutation")]
pub use vitaminc_permutation::*;
