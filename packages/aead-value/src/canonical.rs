//! Canonical scalar plaintext for search terms, separate from reversible ciphertext.
//!
//! Every integer kind shares one 17-byte encoding and domain, and both float
//! kinds share one 8-byte encoding and domain, so equal numbers match
//! whichever width wrote them. Other encodings come from `orderable-bytes` at
//! their natural widths. Text uses Unicode 16 NFC.
//! These bytes and their [`domain`] labels are protocol data: changing either
//! requires a new domain. Text processing is variable-time; this module makes
//! no constant-time claim for Unicode normalization.

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

/// Frozen PRF domain labels for equality terms, one per [`equality_domain`].
pub mod domain {
    /// Every integer kind, `int8` through `uint128`.
    pub const INTEGER: &str = "vitaminc/prf/value/integer-orderable/v1";
    /// `float32` and `float64`, as `float64`.
    pub const FLOAT: &str = "vitaminc/prf/value/float-orderable/v1";
    /// `date`.
    pub const DATE: &str = "vitaminc/prf/value/date-orderable/v1";
    /// `timestamp`, truncated to microseconds.
    pub const TIMESTAMP: &str = "vitaminc/prf/value/timestamp-micros-orderable/v1";
    /// `decimal`, with scale and signed zero normalized.
    pub const DECIMAL: &str = "vitaminc/prf/value/decimal-orderable/v1";
    /// `string`, as Unicode 16 NFC.
    pub const TEXT: &str = "vitaminc/prf/value/text-nfc/unicode-16/v1";
    /// `bytes`.
    pub const BYTES: &str = "vitaminc/prf/value/bytes/v1";
}

/// The canonical bytes for one equality term and the domain they belong to.
#[derive(Debug)]
pub struct EqualityInput {
    /// The frozen domain label, one of the [`domain`] constants.
    pub domain: &'static str,
    /// The canonical plaintext, protected.
    pub bytes: Protected<Vec<u8>>,
}

/// The equality domain for a kind, or `None` for a kind without terms.
///
/// This match is exhaustive inside `ValueKind`'s own crate, so adding a kind
/// fails to compile until it is given a domain or explicitly refused.
pub const fn equality_domain(kind: ValueKind) -> Option<&'static str> {
    match kind {
        ValueKind::Int8
        | ValueKind::UInt8
        | ValueKind::Int16
        | ValueKind::UInt16
        | ValueKind::Int32
        | ValueKind::UInt32
        | ValueKind::Int64
        | ValueKind::UInt64
        | ValueKind::Int128
        | ValueKind::UInt128 => Some(domain::INTEGER),
        ValueKind::Float32 | ValueKind::Float64 => Some(domain::FLOAT),
        ValueKind::Date => Some(domain::DATE),
        ValueKind::Timestamp => Some(domain::TIMESTAMP),
        ValueKind::Decimal => Some(domain::DECIMAL),
        ValueKind::String => Some(domain::TEXT),
        ValueKind::Bytes => Some(domain::BYTES),
        ValueKind::Bool | ValueKind::Array | ValueKind::Object => None,
    }
}

/// Encode a scalar for equality, with the domain its term belongs to.
/// Every owned byte buffer remains protected.
///
/// Integers of every width share [`domain::INTEGER`]: a sign byte (`0x00`
/// negative, `0x01` otherwise) then the value as a big-endian 128-bit
/// two's-complement word, which orders correctly across `i128::MIN` to
/// `u128::MAX`. Both float widths share [`domain::FLOAT`]: a `float32` widens
/// exactly to `float64`, so it matches a `float64` only when the numbers are
/// equal (`float32` 1.5 matches, `float32` 0.1 does not match `float64` 0.1).
/// Float zero signs and NaN payloads are folded. Timestamps truncate their
/// fractional second to microseconds (also before the epoch and during leap
/// seconds), retaining the upstream 12-byte seconds/nanoseconds layout.
/// Decimal encoding itself normalizes scale, including signed zero, without
/// a variable-iteration call to `Decimal::normalize`.
pub fn equality_input(value: &Value) -> Result<EqualityInput, CanonicalError> {
    // This match lives alongside Value so additions cannot silently fall into
    // a downstream non_exhaustive wildcard. Both term layers reuse it.
    let (domain, bytes) = match value {
        Value::Int8(v) => (domain::INTEGER, signed((*v).into())),
        Value::UInt8(v) => (domain::INTEGER, unsigned((*v).into())),
        Value::Int16(v) => (domain::INTEGER, signed((*v).into())),
        Value::UInt16(v) => (domain::INTEGER, unsigned((*v).into())),
        Value::Int32(v) => (domain::INTEGER, signed((*v).into())),
        Value::UInt32(v) => (domain::INTEGER, unsigned((*v).into())),
        Value::Int64(v) => (domain::INTEGER, signed((*v).into())),
        Value::UInt64(v) => (domain::INTEGER, unsigned((*v).into())),
        Value::Int128(v) => (domain::INTEGER, signed(*v)),
        Value::UInt128(v) => (domain::INTEGER, unsigned(*v)),
        Value::Float32(v) => (domain::FLOAT, fixed(&canonical_f64(widen_f32(*v)))),
        Value::Float64(v) => (domain::FLOAT, fixed(&canonical_f64(*v))),
        #[cfg(feature = "chrono")]
        Value::Date(v) => (domain::DATE, fixed(v)),
        #[cfg(feature = "chrono")]
        Value::Timestamp(v) => (domain::TIMESTAMP, timestamp(v)),
        #[cfg(feature = "rust_decimal")]
        Value::Decimal(v) => (domain::DECIMAL, fixed(v)),
        Value::String(v) => (domain::TEXT, text_nfc(v.risky_ref())?),
        Value::Bytes(v) => (
            domain::BYTES,
            Protected::new(v.risky_ref().to_orderable_bytes().to_vec()),
        ),
        Value::Bool(_) => return Err(CanonicalError::UnsupportedKind(ValueKind::Bool)),
        Value::Array(_) => return Err(CanonicalError::UnsupportedKind(ValueKind::Array)),
        Value::Object(_) => return Err(CanonicalError::UnsupportedKind(ValueKind::Object)),
        Value::Null | Value::Undefined | Value::Passthrough(_) => {
            return Err(CanonicalError::UnsupportedValue)
        }
    };
    Ok(EqualityInput { domain, bytes })
}

fn signed(value: i128) -> Protected<Vec<u8>> {
    // The arithmetic shift is all ones for a negative value, zero otherwise.
    integer((!(value >> 127) & 1) as u8, value as u128)
}

fn unsigned(value: u128) -> Protected<Vec<u8>> {
    integer(1, value)
}

fn integer(sign: u8, word: u128) -> Protected<Vec<u8>> {
    let word = Protected::new(word.to_be_bytes());
    let mut bytes = Protected::new(Vec::with_capacity(17));
    bytes.risky_inner_mut().push(sign);
    bytes.risky_inner_mut().extend_from_slice(word.risky_ref());
    bytes
}

fn fixed<T: ToOrderableBytes>(value: &T) -> Protected<Vec<u8>>
where
    for<'a> T::Bytes<'a>: Zeroize,
{
    let bytes = Protected::new(value.to_orderable_bytes());
    Protected::new(bytes.risky_ref().as_ref().to_vec())
}

/// `f64::from(f32)` in integer operations only. A hardware conversion can
/// take a slow path on subnormal inputs, which would leak timing; this keeps
/// the float path free of floating-point arithmetic.
fn widen_f32(value: f32) -> f64 {
    let bits = value.to_bits();
    let sign = u64::from(bits >> 31) << 63;
    let exponent = (bits >> 23) & 0xff;
    let mantissa = u64::from(bits & 0x7f_ffff);
    let zero_exponent = 0u64.wrapping_sub((exponent == 0) as u64);
    let max_exponent = 0u64.wrapping_sub((exponent == 0xff) as u64);
    let nonzero = 0u64.wrapping_sub((mantissa != 0) as u64);
    // Normal, infinite and NaN: rebias the exponent (127 to 1023, or all
    // ones stays all ones) and left-align the mantissa.
    let rebiased = ((u64::from(exponent) + 896) & !max_exponent) | (0x7ff & max_exponent);
    let normal = (rebiased << 52) | (mantissa << 29);
    // Subnormal: the highest set bit becomes the implicit leading one.
    let top = highest_set_bit(mantissa);
    let subnormal = ((top + 874) << 52) | ((mantissa << (52 - top)) & ((1 << 52) - 1));
    f64::from_bits(sign | (normal & !zero_exponent) | (subnormal & zero_exponent & nonzero))
}

/// Index of the highest set bit of a subnormal f32 mantissa. `| 1` keeps the
/// result in range for a zero mantissa, which `widen_f32` masks out.
///
/// Kept out of `widen_f32` so the `.cargo/mutants.toml` exclusion of that
/// function's equivalent `|`-to-`^` mutants cannot reach this `|`, whose
/// operands overlap and whose mutant a test does catch.
fn highest_set_bit(mantissa: u64) -> u64 {
    u64::from(63 - (mantissa | 1).leading_zeros())
}

fn canonical_f64(value: f64) -> f64 {
    let bits = value.to_bits();
    let magnitude = bits & 0x7fff_ffff_ffff_ffff;
    let nan = 0u64.wrapping_sub((magnitude > 0x7ff0_0000_0000_0000) as u64);
    let nonzero = 0u64.wrapping_sub((magnitude != 0) as u64);
    f64::from_bits((bits & !nan).wrapping_add(0x7ff8_0000_0000_0000 & nan) & nonzero)
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
///
/// The result is written into one protected buffer sized exactly up front,
/// so it never reallocates and frees an unwiped partial copy. The
/// `unicode-normalization` iterator keeps its own small buffers of pending
/// code points (inline for four, spilling to the heap for longer combining
/// sequences); those are not wiped and are out of this crate's control.
pub fn text_nfc(bytes: &[u8]) -> Result<Protected<Vec<u8>>, CanonicalError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CanonicalError::InvalidText)?;
    if text
        .chars()
        .any(|c| get_general_category(c) == GeneralCategory::Unassigned)
    {
        return Err(CanonicalError::UnassignedCodePoint);
    }
    // NFC can grow UTF-8 (U+0344 is two bytes, its NFC form four), so measure
    // the output first rather than sizing from the input.
    let len = text.nfc().map(char::len_utf8).sum();
    let mut result = Protected::new(Vec::with_capacity(len));
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
