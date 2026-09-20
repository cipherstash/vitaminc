#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]

#[cfg(feature = "aead")]
#[cfg_attr(docsrs, doc(cfg(feature = "aead")))]
pub use vitaminc_aead as aead;

#[cfg(feature = "async-traits")]
#[cfg_attr(docsrs, doc(cfg(feature = "async-traits")))]
pub use vitaminc_async_traits as async_traits;

#[cfg(feature = "context")]
#[cfg_attr(docsrs, doc(cfg(feature = "context")))]
pub use vitaminc_context as context;

#[cfg(feature = "encrypt")]
#[cfg_attr(docsrs, doc(cfg(feature = "encrypt")))]
pub use vitaminc_encrypt as encrypt;

#[cfg(feature = "aws-kms")]
#[cfg_attr(docsrs, doc(cfg(feature = "aws-kms")))]
pub use vitaminc_kms as aws_kms;

#[cfg(feature = "permutation")]
#[cfg_attr(docsrs, doc(cfg(feature = "permutation")))]
pub use vitaminc_permutation as permutation;

#[cfg(feature = "prf")]
#[cfg_attr(docsrs, doc(cfg(feature = "prf")))]
pub use vitaminc_prf as prf;

#[cfg(feature = "hmac")]
#[cfg_attr(docsrs, doc(cfg(feature = "hmac")))]
pub use vitaminc_hmac as hmac;

#[cfg(feature = "protected")]
#[cfg_attr(docsrs, doc(cfg(feature = "protected")))]
pub use vitaminc_protected as protected;

#[cfg(feature = "random")]
#[cfg_attr(docsrs, doc(cfg(feature = "random")))]
pub use vitaminc_random as random;

#[cfg(feature = "traits")]
#[cfg_attr(docsrs, doc(cfg(feature = "traits")))]
pub use vitaminc_traits as traits;
