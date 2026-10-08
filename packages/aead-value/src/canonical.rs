//! Canonical scalar plaintext for search terms, separate from reversible ciphertext.
//!
//! Numeric encodings come from `orderable-bytes` at their natural widths.
//! Text uses Unicode 16 NFC. These bytes are protocol data: changing them
//! requires a new term domain. Text processing is variable-time; this module
//! makes no constant-time claim for Unicode normalization.

use orderable_bytes::ToOrderableBytes;
use unicode_general_category::{get_general_category, GeneralCategory};
use unicode_normalization::UnicodeNormalization;
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

use crate::{Value, ValueKind};

/// A refused search-term input. Errors never include plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CanonicalError {
    /// A known kind has no search terms (booleans and containers).
    UnsupportedKind(ValueKind),
    /// Null, undefined and passthrough values have no search terms.
    UnsupportedValue,
    /// Text contains a code point unassigned in Unicode 16.
    UnassignedCodePoint,
    /// Invalid UTF-8 (defensive validation of a protected string).
    InvalidText,
}

impl std::fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedKind(kind) => write!(f, "{kind} has no search terms"),
            Self::UnsupportedValue => f.write_str("this value has no search terms"),
            Self::UnassignedCodePoint => {
                f.write_str("text contains a code point unassigned in Unicode 16")
            }
            Self::InvalidText => f.write_str("invalid UTF-8"),
        }
    }
}

impl std::error::Error for CanonicalError {}

/// Encode a scalar for equality. Every owned byte buffer remains protected.
///
/// Float zero signs and NaN payloads are folded. Timestamps truncate their
/// fractional second to microseconds (also before the epoch and during leap
/// seconds), retaining the upstream 12-byte seconds/nanoseconds layout.
/// Decimal encoding itself normalizes scale, including signed zero, without
/// a variable-iteration call to `Decimal::normalize`.
pub fn equality_bytes(value: &Value) -> Result<Protected<Vec<u8>>, CanonicalError> {
    // This match lives alongside Value so additions cannot silently fall into
    // a downstream non_exhaustive wildcard. Both term layers reuse it.
    Ok(match value {
        Value::Int8(v) => fixed(v),
        Value::UInt8(v) => fixed(v),
        Value::Int16(v) => fixed(v),
        Value::UInt16(v) => fixed(v),
        Value::Int32(v) => fixed(v),
        Value::UInt32(v) => fixed(v),
        Value::Int64(v) => fixed(v),
        Value::UInt64(v) => fixed(v),
        Value::Int128(v) => fixed(v),
        Value::UInt128(v) => fixed(v),
        Value::Float32(v) => fixed(&canonical_f32(*v)),
        Value::Float64(v) => fixed(&canonical_f64(*v)),
        #[cfg(feature = "chrono")]
        Value::Date(v) => fixed(v),
        #[cfg(feature = "chrono")]
        Value::Timestamp(v) => timestamp(v),
        #[cfg(feature = "rust_decimal")]
        Value::Decimal(v) => fixed(v),
        Value::String(v) => text_nfc(v.risky_ref())?,
        Value::Bytes(v) => Protected::new(v.risky_ref().to_orderable_bytes().to_vec()),
        Value::Bool(_) => return Err(CanonicalError::UnsupportedKind(ValueKind::Bool)),
        Value::Array(_) => return Err(CanonicalError::UnsupportedKind(ValueKind::Array)),
        Value::Object(_) => return Err(CanonicalError::UnsupportedKind(ValueKind::Object)),
        Value::Null | Value::Undefined | Value::Passthrough(_) => {
            return Err(CanonicalError::UnsupportedValue)
        }
    })
}

fn fixed<T: ToOrderableBytes>(value: &T) -> Protected<Vec<u8>>
where
    for<'a> T::Bytes<'a>: Zeroize,
{
    let bytes = Protected::new(value.to_orderable_bytes());
    Protected::new(bytes.risky_ref().as_ref().to_vec())
}

fn canonical_f32(value: f32) -> f32 {
    let bits = value.to_bits();
    let magnitude = bits & 0x7fff_ffff;
    let nan = 0u32.wrapping_sub((magnitude > 0x7f80_0000) as u32);
    let nonzero = 0u32.wrapping_sub((magnitude != 0) as u32);
    f32::from_bits(((bits & !nan) | (0x7fc0_0000 & nan)) & nonzero)
}

fn canonical_f64(value: f64) -> f64 {
    let bits = value.to_bits();
    let magnitude = bits & 0x7fff_ffff_ffff_ffff;
    let nan = 0u64.wrapping_sub((magnitude > 0x7ff0_0000_0000_0000) as u64);
    let nonzero = 0u64.wrapping_sub((magnitude != 0) as u64);
    f64::from_bits(((bits & !nan) | (0x7ff8_0000_0000_0000 & nan)) & nonzero)
}

#[cfg(feature = "chrono")]
fn timestamp(value: &chrono::DateTime<chrono::Utc>) -> Protected<Vec<u8>> {
    // Truncate the subsecond field, not an epoch count: this preserves the
    // full chrono range and its leap-second representation without overflow.
    let mut bytes = Protected::new(value.to_orderable_bytes());
    let nanos = value.timestamp_subsec_nanos() / 1_000 * 1_000;
    bytes.risky_inner_mut()[8..].copy_from_slice(&nanos.to_be_bytes());
    Protected::new(bytes.risky_ref().to_vec())
}

/// NFC in the pinned Unicode version, without case or accent folding.
pub fn text_nfc(bytes: &[u8]) -> Result<Protected<Vec<u8>>, CanonicalError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CanonicalError::InvalidText)?;
    if text
        .chars()
        .any(|c| get_general_category(c) == GeneralCategory::Unassigned)
    {
        return Err(CanonicalError::UnassignedCodePoint);
    }
    let mut result = Protected::new(Vec::with_capacity(bytes.len()));
    for c in text.nfc() {
        let mut encoded = Protected::new([0u8; 4]);
        result
            .risky_inner_mut()
            .extend_from_slice(c.encode_utf8(encoded.risky_inner_mut()).as_bytes());
    }
    Ok(result)
}

#[cfg(test)]
#[path = "canonical_tests.rs"]
mod tests;
