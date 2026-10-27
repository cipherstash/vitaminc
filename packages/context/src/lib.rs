// These definitions precede the README so rustdoc links to the version being built.
// The README supplies published-API URLs for GitHub. See docs/documentation.md.
//! [`Context::for_map_entry`]: crate::Context::for_map_entry
//! [`ContextPiece`]: crate::ContextPiece
//! [`IntoContext`]: crate::IntoContext
//!
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::todo, unused_imports)]
#![doc = include_str!("../README.md")]

mod context;
mod into_context;
mod pae;
mod piece;

pub use context::Context;
pub use into_context::IntoContext;
pub use piece::ContextPiece;
