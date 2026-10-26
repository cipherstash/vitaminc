// These definitions precede the README so rustdoc links to the version being built.
// The README supplies published-API URLs for GitHub. See docs/documentation.md.
//! [`PrfEncoding`]: crate::PrfEncoding
//! [`PrfKeyInit`]: crate::PrfKeyInit
//! [`PrfValue`]: crate::PrfValue
//! [`Prf`]: crate::Prf
//!
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod context;
mod encoding;
mod error;
mod impls;
#[cfg(feature = "normalize")]
#[cfg_attr(docsrs, doc(cfg(feature = "normalize")))]
mod normalize;
mod ready;
mod traits;
mod visitor;

#[cfg(feature = "normalize")]
#[cfg_attr(docsrs, doc(cfg(feature = "normalize")))]
pub use normalize::EqualityTerm;
#[cfg(feature = "normalize")]
#[cfg_attr(docsrs, doc(cfg(feature = "normalize")))]
pub use vitaminc_normalize::{NormalizeError, Normalized};

#[cfg(test)]
mod test_backend;

#[allow(deprecated)]
pub use context::PrfContext;
pub use context::{Context, ContextPiece, IntoContext, IntoPrfContext};
pub use encoding::PrfEncoding;
pub use error::{PrfBuildError, PrfError, PrfVisitorError};
pub use impls::Passthrough;
pub use ready::ReadyPrf;
pub use traits::{MapPrf, Prf, PrfKeyInit, PrfValue, SeqPrf};
pub use visitor::{BlockVisitor, MapAccess, PrfVisitor, ResolvedPrf, ResolvedVisitor, SeqAccess};
