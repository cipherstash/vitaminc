//! One normalized equality term per scalar.
//!
//! [`normalize`] turns a physical value and its optional logical type into
//! the bytes an equality index derives under, and the frozen domain label
//! those bytes belong to. The encoders are public, one per kind, so an index
//! layer that already knows a value's kind can call them directly.
//!
//! Every integer width shares one 17-byte encoding and domain, and both
//! float widths share one 8-byte encoding and domain, so equal numbers
//! match whichever width wrote them. Text is Unicode 16 NFC. These bytes
//! and their [`domain`] labels are protocol data: changing either requires
//! a new domain. Text processing is variable-time; this module makes no
//! constant-time claim for Unicode normalization.
//!
//! Logical types opt in. A date, a timestamp, a decimal and a uuid each
//! have a domain of their own, separate from the physical value they are
//! stored as, so a date's day count never matches the integer it equals and
//! a uuid never matches the same sixteen bytes written as bytes. Every other
//! logical type, [`Logical::Unknown`] included, has no term and is refused
//! with [`NormalizeError::NoDomain`].

use unicode_general_category::{get_general_category, GeneralCategory};
use unicode_normalization::UnicodeNormalization;
use vitaminc_aead::plaintext::kinds::{
    timestamp_nanos, MAX_DATE_DAYS, MAX_DECIMAL_SCALE, MIN_DATE_DAYS,
};
use vitaminc_aead::{Float, Int, Logical, Physical, TimeUnit};
use vitaminc_protected::{Controlled, OpaqueDebug, Protected};

/// Frozen domain labels for equality terms, one per kind that has one.
pub mod domain {
    /// Every integer width, `i8` through `u128`.
    pub const INTEGER: &str = "vitaminc/prf/value/integer-orderable/v1";
    /// `f32` and `f64`, as `f64`.
    pub const FLOAT: &str = "vitaminc/prf/value/float-orderable/v1";
    /// A date, over its day count.
    pub const DATE: &str = "vitaminc/prf/value/date-orderable/v1";
    /// A timestamp, truncated to microseconds.
    pub const TIMESTAMP: &str = "vitaminc/prf/value/timestamp-micros-orderable/v1";
    /// A decimal, with scale and signed zero normalized.
    pub const DECIMAL: &str = "vitaminc/prf/value/decimal-orderable/v1";
    /// Text, as Unicode 16 NFC.
    pub const TEXT: &str = "vitaminc/prf/value/text-nfc/unicode-16/v1";
    /// Bytes.
    pub const BYTES: &str = "vitaminc/prf/value/bytes/v1";
    /// A uuid, over its sixteen raw bytes.
    pub const UUID: &str = "vitaminc/prf/value/uuid/v1";
    /// Every domain, for a test or an index layer that enumerates them. A
    /// slice, so a domain added later does not change its type.
    pub const ALL: &[&str] = &[INTEGER, FLOAT, DATE, TIMESTAMP, DECIMAL, TEXT, BYTES, UUID];
}

/// The normalized bytes for one equality term and the domain they belong
/// to.
///
/// The fields are public so an index layer can build a term of its own,
/// and whatever consumes a `Normalized` trusts them: a PRF derives under
/// the `domain` it is handed. The only way to get the frozen encodings is
/// through [`normalize`] or the per-kind encoders here.
///
/// `Debug` shows the domain and masks the bytes.
#[derive(OpaqueDebug)]
pub struct Normalized {
    /// The frozen domain label, one of the [`domain`] constants.
    #[non_sensitive]
    pub domain: &'static str,
    /// The normalized plaintext, protected.
    pub bytes: Protected<Vec<u8>>,
}

/// Why a scalar has no term. Never includes plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NormalizeError {
    /// The scalar has no equality domain: a null, an `undefined`, a
    /// boolean, or a logical type outside the opt-in table.
    #[error("no equality domain for this kind of value")]
    NoDomain,
    /// The value is not valid for its logical type.
    #[error("the value is not valid for its logical type")]
    Invalid,
    /// Text contains a code point unassigned in Unicode 16.
    #[error("text contains a code point unassigned in Unicode 16")]
    UnassignedCodePoint,
}

/// The opt-in table: the domain for a scalar, or `None` for one that has
/// no term. A logical type decides on its own; a value without one goes by
/// its kind. Neither looks at the value: [`normalize`] checks that.
pub fn domain_of(ty: Option<Logical>, v: &Physical<'_>) -> Option<&'static str> {
    match (ty, v) {
        (None, Physical::Int(_)) => Some(domain::INTEGER),
        (None, Physical::Float(_)) => Some(domain::FLOAT),
        (None, Physical::Text(_)) => Some(domain::TEXT),
        (None, Physical::Bytes(_)) => Some(domain::BYTES),
        (None, Physical::Null | Physical::Bool(_)) => None,
        (Some(Logical::Date), _) => Some(domain::DATE),
        (Some(Logical::Timestamp(_)), _) => Some(domain::TIMESTAMP),
        (Some(Logical::Decimal { .. }), _) => Some(domain::DECIMAL),
        (Some(Logical::Uuid), _) => Some(domain::UUID),
        // `Logical` is non-exhaustive: a type this build does not know, and
        // any added later, has no term until it is given a domain here.
        (Some(_), _) => None,
    }
}

/// Encode one scalar for equality, with the domain its term belongs to.
///
/// Integers of every width share [`domain::INTEGER`]: a sign byte (`0x00`
/// negative, `0x01` otherwise) then the value as a big-endian 128-bit
/// two's-complement word, which orders correctly across `i128::MIN` to
/// `u128::MAX`. Both float widths share [`domain::FLOAT`]: an `f32` widens
/// exactly to `f64`, so it matches an `f64` only when the numbers are equal
/// (`f32` 1.5 matches, `f32` 0.1 does not match `f64` 0.1). Float zero
/// signs and NaN payloads are folded. A timestamp in any unit is truncated
/// to microseconds. A decimal's scale is normalized, so `1.50` and `1.5`
/// are one term, as are `-0.00` and `0`.
pub fn normalize(ty: Option<Logical>, v: Physical<'_>) -> Result<Normalized, NormalizeError> {
    // A value that does not fit its logical type is refused as invalid
    // before the type is looked up, so `undefined` over an int is `Invalid`
    // rather than "nothing to index".
    if ty.is_some_and(|ty| !ty.admits(&v)) {
        return Err(NormalizeError::Invalid);
    }
    let domain = domain_of(ty, &v).ok_or(NormalizeError::NoDomain)?;
    let bytes = match (ty, v) {
        (None, Physical::Int(i)) => Some(integer(i)),
        (None, Physical::Float(f)) => Some(float(f)),
        (None, Physical::Text(s)) => Some(text(s)?),
        (None, Physical::Bytes(b)) => Some(bytes(b)),
        (Some(Logical::Date), Physical::Int(days)) => date(days),
        (Some(Logical::Timestamp(unit)), Physical::Int(count)) => timestamp(unit, count),
        (Some(Logical::Decimal { scale }), Physical::Int(mantissa)) => decimal(scale, mantissa),
        (Some(Logical::Uuid), Physical::Bytes(b)) => uuid(b),
        // `admits` has already refused a logical type over the wrong kind,
        // and `domain_of` everything without a term. Each encoder checks
        // its own range as well, for a caller that goes to it directly.
        _ => None,
    }
    .ok_or(NormalizeError::Invalid)?;
    Ok(Normalized { domain, bytes })
}

/// An integer of any width: a sign byte, then the big-endian 128-bit word.
pub fn integer(value: Int) -> Protected<Vec<u8>> {
    let (negative, word) = value.sign_and_word();
    let word = Protected::new(word.to_be_bytes());
    let mut bytes = Protected::new(Vec::with_capacity(17));
    bytes.risky_inner_mut().push(u8::from(!negative));
    bytes.risky_inner_mut().extend_from_slice(word.risky_ref());
    bytes
}

/// A float of either width, as the orderable bytes of its `f64` value with
/// zero signs and NaN payloads folded.
pub fn float(value: Float) -> Protected<Vec<u8>> {
    let value = match value {
        Float::F32(f) => widen_f32(f),
        Float::F64(f) => f,
    };
    Protected::new(orderable_f64(canonical_f64(value)).to_vec())
}

/// A date's day count since 1970-01-01, as the orderable bytes of its
/// count of days from 0001-01-01 (the same bytes chrono's `NaiveDate`
/// orders by). `None` outside the date range.
pub fn date(days: Int) -> Option<Protected<Vec<u8>>> {
    let days = i32::try_from(days.to_i128()?).ok()?;
    if !(MIN_DATE_DAYS..=MAX_DATE_DAYS).contains(&days) {
        return None;
    }
    let from_ce = days.checked_add(EPOCH_DAYS_FROM_CE)?;
    Some(Protected::new(
        ((from_ce as u32) ^ (1u32 << 31)).to_be_bytes().to_vec(),
    ))
}

/// A count of `unit`s since the Unix epoch, as orderable seconds then
/// big-endian nanoseconds truncated to microseconds (the same bytes
/// chrono's `DateTime<Utc>` orders by, truncated). `None` outside the
/// timestamp range.
pub fn timestamp(unit: TimeUnit, count: Int) -> Option<Protected<Vec<u8>>> {
    let nanos = timestamp_nanos(unit, count)?;
    let seconds = i64::try_from(nanos.div_euclid(NANOS_PER_SECOND)).ok()?;
    let sub = (nanos.rem_euclid(NANOS_PER_SECOND) as u32) / 1_000 * 1_000;
    let mut bytes = Protected::new(Vec::with_capacity(12));
    bytes
        .risky_inner_mut()
        .extend_from_slice(&((seconds as u64) ^ (1u64 << 63)).to_be_bytes());
    bytes
        .risky_inner_mut()
        .extend_from_slice(&sub.to_be_bytes());
    Some(bytes)
}

/// A decimal's mantissa and scale, as the 14-byte orderable encoding of
/// its value, ported from the frozen `orderable-bytes` release and checked
/// against it, which normalizes the scale and a signed zero. `None`
/// if the mantissa does not fit 96 bits or the scale is above 28, the
/// range `rust_decimal` represents.
pub fn decimal(scale: u8, mantissa: Int) -> Option<Protected<Vec<u8>>> {
    let mantissa = mantissa.to_i128()?;
    if scale > MAX_DECIMAL_SCALE || mantissa.unsigned_abs() >= 1 << 96 {
        return None;
    }
    let bytes = Protected::new(crate::decimal::orderable(mantissa, u32::from(scale)));
    Some(Protected::new(bytes.risky_ref().to_vec()))
}

/// NFC in the pinned Unicode version, without case or accent folding.
///
/// The result is written into one protected buffer sized exactly up front,
/// so it never reallocates and frees an unwiped partial copy. The
/// `unicode-normalization` iterator keeps its own small buffers of pending
/// code points (inline for four, spilling to the heap for longer combining
/// sequences); those are not wiped and are out of this crate's control.
pub fn text(text: &str) -> Result<Protected<Vec<u8>>, NormalizeError> {
    if text
        .chars()
        .any(|c| get_general_category(c) == GeneralCategory::Unassigned)
    {
        return Err(NormalizeError::UnassignedCodePoint);
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

/// Bytes, as they are.
pub fn bytes(value: &[u8]) -> Protected<Vec<u8>> {
    Protected::new(value.to_vec())
}

/// A uuid's sixteen raw bytes. `None` for any other length.
pub fn uuid(value: &[u8]) -> Option<Protected<Vec<u8>>> {
    (value.len() == 16).then(|| Protected::new(value.to_vec()))
}

/// Days from 0001-01-01 (day 1, chrono's "days from CE") to 1970-01-01.
const EPOCH_DAYS_FROM_CE: i32 = 719_163;
const NANOS_PER_SECOND: i128 = 1_000_000_000;

/// The orderable bytes of an `f64`: negatives flip every bit, positives
/// the sign bit, so the bytes sort as the numbers do. Expects a value
/// [`canonical_f64`] has already folded.
fn orderable_f64(value: f64) -> [u8; 8] {
    let bits = value.to_bits();
    let sign_extension = ((bits as i64) >> 63) as u64;
    (bits ^ (sign_extension | (1u64 << 63))).to_be_bytes()
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

/// Folds every NaN to one quiet NaN and `-0.0` to `0.0`, in integer
/// operations only.
fn canonical_f64(value: f64) -> f64 {
    let bits = value.to_bits();
    let magnitude = bits & 0x7fff_ffff_ffff_ffff;
    let nan = 0u64.wrapping_sub((magnitude > 0x7ff0_0000_0000_0000) as u64);
    let nonzero = 0u64.wrapping_sub((magnitude != 0) as u64);
    f64::from_bits((bits & !nan).wrapping_add(0x7ff8_0000_0000_0000 & nan) & nonzero)
}

#[cfg(test)]
#[path = "scalar_tests.rs"]
mod tests;
