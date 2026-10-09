#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod context;
mod encoding;
mod error;
mod impls;
mod ready;
mod traits;
#[cfg(feature = "value")]
mod value;
mod visitor;

#[cfg(feature = "value")]
pub use vitaminc_aead_value::canonical::CanonicalError;

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
