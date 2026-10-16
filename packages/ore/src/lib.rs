#![deny(clippy::unwrap_used, clippy::todo, unsafe_code, unused_imports)]
#![doc = include_str!("../README.md")]

mod casefold_unicode16;
mod fold;
mod order;
mod scheme;

pub use order::{domain, domain_of, float, int, order, order_terms, text, Order};
pub use scheme::{order_term, OrderError, OrderKeyInit, OrderPlaintext, OrderScheme};
// The types in this crate's signatures, so a caller needs no second import:
// a scheme crate's tests build plaintexts from the data model through
// `order` without depending on vitaminc-aead themselves.
pub use vitaminc_aead::{Float, Int, Logical, Physical, TimeUnit};
pub use vitaminc_context::{Context, IntoContext};
pub use vitaminc_normalize::{NormalizeError, Term, TermsError};
