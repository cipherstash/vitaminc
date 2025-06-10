#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
#[cfg(feature = "protected")]
pub use vitaminc_protected as protected;

#[cfg(feature = "random")]
#[cfg_attr(docsrs, doc(cfg(feature = "encrypt")))]
#[doc(inline)]
pub use vitaminc_random::{Generatable, SafeRand, RandomError, SeedableRng};

#[cfg(feature = "permutation")]
pub use vitaminc_permutation as permutation;

#[cfg(feature = "traits")]
pub use vitaminc_traits as traits;

#[cfg(feature = "async-traits")]
pub use vitaminc_async_traits as async_traits;

#[cfg(feature = "aws-kms")]
pub use vitaminc_kms as aws_kms;

#[cfg(feature = "encrypt")]
#[cfg_attr(docsrs, doc(cfg(feature = "encrypt")))]
#[doc(inline)]
pub use vitaminc_encrypt::*;
