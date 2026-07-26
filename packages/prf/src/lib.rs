#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod context;
mod error;
mod hmac_sha256;
mod impls;
mod traits;
mod visitor;

pub use context::{IntoPrfContext, PrfContext};
pub use error::{PrfBuildError, PrfError, PrfVisitorError};
pub use hmac_sha256::{HmacSha256Prf, ReadyPrf};
pub use impls::Passthrough;
pub use traits::{MapPrf, Prf, PrfValue, SeqPrf};
pub use visitor::{BlockVisitor, MapAccess, PrfVisitor, ResolvedPrf, SeqAccess};

#[cfg(test)]
mod tests;
