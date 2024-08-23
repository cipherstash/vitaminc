#![doc = include_str!("../../../README.md")]

#[cfg(feature = "protected")]
pub use vitaminc_protected::{Equatable, Exportable, Paranoid, Protected, Usage};

#[cfg(feature = "random")]
pub use vitaminc_random::{BoundedRng, Fill, Generatable, RngCore, SafeRand, SeedableRng};

#[cfg(feature = "permutation")]
pub use vitaminc_permutation::{BitwisePermute, Depermute, PermutationKey, Permute};
