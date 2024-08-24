#![doc = include_str!("../../../README.md")]
use thiserror::Error;

#[cfg(feature = "protected")]
pub use vitaminc_protected as protected;

#[cfg(feature = "random")]
pub use vitaminc_random as random;

#[cfg(feature = "permutation")]
pub use vitaminc_permutation as permutation;

#[derive(Error, Debug)]
pub enum VitaminCError {
    #[cfg(feature = "random")]
    #[error(transparent)]
    RandomError(#[from] random::RandomError),
    // The other crates don't have any errors yet
}
