#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// The README links to the latest published API for GitHub. These definitions come
// first, so rustdoc links to the version being built. See docs/documentation.md.
#![doc = concat!(
    "\n[`AlphaNumericPassword`]: https://docs.rs/vitaminc-password/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_password/struct.AlphaNumericPassword.html\n",
    "\n[`AlphaPassword`]: https://docs.rs/vitaminc-password/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_password/struct.AlphaPassword.html\n",
    "\n[`Controlled`]: https://docs.rs/vitaminc-protected/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_protected/trait.Controlled.html\n",
    "\n[`Decrypt`]: https://docs.rs/vitaminc-aead/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_aead/trait.Decrypt.html\n",
    "\n[`Encrypt`]: https://docs.rs/vitaminc-aead/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_aead/trait.Encrypt.html\n",
    "\n[`Equatable`]: https://docs.rs/vitaminc-protected/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_protected/struct.Equatable.html\n",
    "\n[`Generatable::random`]: https://docs.rs/vitaminc-random/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_random/trait.Generatable.html#tymethod.random\n",
    "\n[`Locked`]: https://docs.rs/vitaminc-protected/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_protected/struct.Locked.html\n",
    "\n[`Locked::require_locked`]: https://docs.rs/vitaminc-protected/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_protected/struct.Locked.html#method.require_locked\n",
    "\n[`OpaqueDebug`]: https://docs.rs/vitaminc-protected/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_protected/trait.OpaqueDebug.html\n",
    "\n[`Password`]: https://docs.rs/vitaminc-password/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_password/struct.Password.html\n",
    "\n[`Protected`]: https://docs.rs/vitaminc-protected/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_protected/struct.Protected.html\n",
    "\n[`SafeRand::from_entropy`]: https://docs.rs/vitaminc-random/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_random/struct.SafeRand.html#method.from_entropy\n",
    "\n[`TimingSafeEq`]: https://docs.rs/vitaminc-protected/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_protected/trait.TimingSafeEq.html\n",
)]
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

#[cfg(feature = "normalize")]
#[cfg_attr(docsrs, doc(cfg(feature = "normalize")))]
pub use vitaminc_normalize as normalize;

#[cfg(feature = "ore")]
#[cfg_attr(docsrs, doc(cfg(feature = "ore")))]
pub use vitaminc_ore as ore;

#[cfg(feature = "password")]
#[cfg_attr(docsrs, doc(cfg(feature = "password")))]
pub use vitaminc_password as password;

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
