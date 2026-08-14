#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod context;
mod encoding;
mod error;
mod impls;
mod ready;
mod traits;
mod visitor;

#[cfg(test)]
mod test_backend;

pub use context::{IntoPrfContext, PrfContext};
pub use encoding::PrfEncoding;
pub use error::{PrfBuildError, PrfError, PrfVisitorError};
pub use impls::Passthrough;
pub use ready::ReadyPrf;
pub use traits::{MapPrf, Prf, PrfValue, SeqPrf};
pub use visitor::{BlockVisitor, MapAccess, PrfVisitor, ResolvedPrf, ResolvedVisitor, SeqAccess};
