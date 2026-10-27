// These definitions precede the README so rustdoc links to the version being built.
// The README supplies published-API URLs for GitHub. See docs/documentation.md.
//! [`NullOrder`]: crate::NullOrder
//! [`OrderEncrypt`]: crate::OrderEncrypt
//! [`OrderError::Unsupported`]: crate::OrderError::Unsupported
//! [`OrderKeyInit`]: crate::OrderKeyInit
//! [`OrderPlaintext`]: crate::OrderPlaintext
//! [`OrderScheme::compare`]: crate::OrderScheme::compare
//! [`OrderScheme`]: crate::OrderScheme
//!
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(clippy::unwrap_used, clippy::todo, unsafe_code, unused_imports)]
#![doc = include_str!("../README.md")]

mod casefold_unicode16;
mod fold;
mod order;
mod query;
mod scheme;
pub mod target;
#[cfg(feature = "test-support")]
pub mod test_support;

pub use order::{
    domain, order, order_terms, order_with_nulls, text, NullOrder, Order, OrderTarget,
    VARIABLE_WIDTH_MARKER,
};
pub use query::{OrderQuery, QueryTerm};
#[allow(deprecated)]
pub use scheme::OrderColumn;
pub use scheme::{
    OrderContext, OrderEncrypt, OrderError, OrderKeyInit, OrderPlaintext, OrderScheme, OrderSpace,
    OrderTerm,
};
pub use target::{FitsIn, FixedWidth, OwnTarget, StaticTarget, Supports, Target};
// The types in this crate's signatures, so a caller needs no second import:
// a scheme encrypts values of the data model, and a typed scalar goes in
// as `Raw(ty, physical)`, without depending on vitaminc-aead.
pub use vitaminc_aead::{Encrypt, Float, Int, Logical, Physical, Raw, TimeUnit};
pub use vitaminc_context::{Context, IntoContext};
pub use vitaminc_normalize::{NormalizeError, Term, TermsError};
