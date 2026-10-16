#![deny(clippy::unwrap_used, clippy::todo, unsafe_code, unused_imports)]
#![doc = include_str!("../README.md")]

mod decimal;
mod scalar;
mod terms;

pub use scalar::{
    bytes, date, decimal, domain, domain_of, float, integer, normalize, text, timestamp, uuid,
    NormalizeError, Normalized,
};
pub use terms::{
    encrypt_with_terms, encrypt_with_terms_async, plan_with_terms, terms, terms_by, Equality,
    Normalize, Term, TermError, Terms, TermsError, TermsMap, TermsSeq, WithTerms,
};
pub use vitaminc_aead::plaintext::{Path, Step};
