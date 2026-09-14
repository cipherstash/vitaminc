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
