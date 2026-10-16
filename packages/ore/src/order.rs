//! One order term per scalar.
//!
//! [`order`] turns a physical value and its optional logical type into
//! the sealed [`OrderPlaintext`] a scheme encrypts: bytes whose
//! lexicographic order is the value's order, and the frozen domain label
//! they belong to. The encoders this crate adds are public, as
//! [`vitaminc_normalize`]'s are, for an index layer that already knows a
//! value's kind; only [`order`] can seal them.
//!
//! Where an equality term folds every integer width into one encoding and
//! both float widths into `f64`, an order term keeps each kind at its
//! natural width, so block ORE over an `i32` costs four blocks, not
//! seventeen. A date, a timestamp, a decimal, bytes and a uuid order by
//! the same bytes they are matched by, so those come from
//! `vitaminc_normalize` unchanged. Text alone folds further: an order term
//! drops accents and case, which equality must not. See the crate docs for
//! the table.

use vitaminc_aead::{Encrypt, Float, Int, Logical, Physical};
use vitaminc_normalize::{terms_by, Normalize, NormalizeError, Term, TermsError};
use vitaminc_protected::{Controlled, Protected};

use crate::{fold, OrderPlaintext};

/// Frozen domain labels for order terms, one per kind that has one.
pub mod domain {
    /// An `i8`, one byte.
    pub const INT8: &str = "vitaminc/ore/value/int8/v1";
    /// A `u8`, one byte.
    pub const UINT8: &str = "vitaminc/ore/value/uint8/v1";
    /// An `i16`, two bytes.
    pub const INT16: &str = "vitaminc/ore/value/int16/v1";
    /// A `u16`, two bytes.
    pub const UINT16: &str = "vitaminc/ore/value/uint16/v1";
    /// An `i32`, four bytes.
    pub const INT32: &str = "vitaminc/ore/value/int32/v1";
    /// A `u32`, four bytes.
    pub const UINT32: &str = "vitaminc/ore/value/uint32/v1";
    /// An `i64`, eight bytes.
    pub const INT64: &str = "vitaminc/ore/value/int64/v1";
    /// A `u64`, eight bytes.
    pub const UINT64: &str = "vitaminc/ore/value/uint64/v1";
    /// An `i128`, sixteen bytes.
    pub const INT128: &str = "vitaminc/ore/value/int128/v1";
    /// A `u128`, sixteen bytes.
    pub const UINT128: &str = "vitaminc/ore/value/uint128/v1";
    /// An `f32`, four bytes, zero signs and NaN payloads folded.
    pub const FLOAT32: &str = "vitaminc/ore/value/float32/v1";
    /// An `f64`, eight bytes, zero signs and NaN payloads folded.
    pub const FLOAT64: &str = "vitaminc/ore/value/float64/v1";
    /// A date, four bytes, over its day count.
    pub const DATE: &str = "vitaminc/ore/value/date/v1";
    /// A timestamp, twelve bytes, truncated to microseconds.
    pub const TIMESTAMP: &str = "vitaminc/ore/value/timestamp-micros/v1";
    /// A decimal, fourteen bytes, scale and signed zero normalized.
    pub const DECIMAL: &str = "vitaminc/ore/value/decimal/v1";
    /// Text, as Unicode 16 NFC with accents and case folded.
    pub const TEXT: &str = "vitaminc/ore/value/text-folded/unicode-16/v1";
    /// Bytes.
    pub const BYTES: &str = "vitaminc/ore/value/bytes/v1";
    /// A uuid, over its sixteen raw bytes.
    pub const UUID: &str = "vitaminc/ore/value/uuid/v1";
    /// Every domain, for a test or an index layer that enumerates them. A
    /// slice, so a domain added later does not change its type.
    pub const ALL: &[&str] = &[
        INT8, UINT8, INT16, UINT16, INT32, UINT32, INT64, UINT64, INT128, UINT128, FLOAT32,
        FLOAT64, DATE, TIMESTAMP, DECIMAL, TEXT, BYTES, UUID,
    ];
}

/// The opt-in table: the order domain for a scalar, or `None` for one
/// that has no order term. A logical type decides on its own; a value
/// without one goes by its kind and, for an int or a float, its width.
/// Neither looks at the value: [`order`] checks that.
pub fn domain_of(ty: Option<Logical>, v: &Physical<'_>) -> Option<&'static str> {
    match (ty, v) {
        (None, Physical::Int(i)) => Some(match i {
            Int::I8(_) => domain::INT8,
            Int::U8(_) => domain::UINT8,
            Int::I16(_) => domain::INT16,
            Int::U16(_) => domain::UINT16,
            Int::I32(_) => domain::INT32,
            Int::U32(_) => domain::UINT32,
            Int::I64(_) => domain::INT64,
            Int::U64(_) => domain::UINT64,
            Int::I128(_) => domain::INT128,
            Int::U128(_) => domain::UINT128,
        }),
        (None, Physical::Float(Float::F32(_))) => Some(domain::FLOAT32),
        (None, Physical::Float(Float::F64(_))) => Some(domain::FLOAT64),
        (None, Physical::Text(_)) => Some(domain::TEXT),
        (None, Physical::Bytes(_)) => Some(domain::BYTES),
        // A boolean orders two groups of rows and hides nothing; a null
        // has no order.
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

/// Encode one scalar for ordering, sealed with the domain its term
/// belongs to. The one exhaustive match over the data model.
///
/// An integer encodes at its own width, big-endian, with the sign bit
/// flipped when signed, so the bytes sort as the numbers do; a float the
/// same, with every bit of a negative flipped, zero signs and NaN payloads
/// folded first. A date, a timestamp, a decimal, bytes and a uuid encode
/// exactly as [`vitaminc_normalize::normalize`] encodes them for equality.
/// Text is Unicode 16 NFC with accents and case folded, so `É` and `e` tie.
///
/// # Errors
///
/// [`NormalizeError::NoDomain`] for a null, a boolean, an `undefined` or a
/// logical type outside the table; [`NormalizeError::Invalid`] for a value
/// that does not fit its logical type;
/// [`NormalizeError::UnassignedCodePoint`] for text holding a code point
/// Unicode 16 does not assign.
pub fn order(ty: Option<Logical>, v: Physical<'_>) -> Result<OrderPlaintext, NormalizeError> {
    // As `normalize`: a value that does not fit its logical type is refused
    // before the type is looked up.
    if ty.is_some_and(|ty| !ty.admits(&v)) {
        return Err(NormalizeError::Invalid);
    }
    let domain = domain_of(ty, &v).ok_or(NormalizeError::NoDomain)?;
    let bytes = match (ty, v) {
        (None, Physical::Int(i)) => Some(int(i)),
        (None, Physical::Float(f)) => Some(float(f)),
        (None, Physical::Text(s)) => Some(text(s)?),
        (None, Physical::Bytes(b)) => Some(vitaminc_normalize::bytes(b)),
        (Some(Logical::Date), Physical::Int(days)) => vitaminc_normalize::date(days),
        (Some(Logical::Timestamp(unit)), Physical::Int(count)) => {
            vitaminc_normalize::timestamp(unit, count)
        }
        (Some(Logical::Decimal { scale }), Physical::Int(mantissa)) => {
            vitaminc_normalize::decimal(scale, mantissa)
        }
        (Some(Logical::Uuid), Physical::Bytes(b)) => vitaminc_normalize::uuid(b),
        // `admits` has already refused a logical type over the wrong kind,
        // and `domain_of` everything without a term.
        _ => None,
    }
    .ok_or(NormalizeError::Invalid)?;
    Ok(OrderPlaintext::new(domain, bytes))
}

/// An integer at its own width: big-endian, with the sign bit flipped for
/// a signed width, so two's complement sorts as the numbers do. The same
/// bytes `orderable-bytes` produces, checked against it in the tests.
pub fn int(value: Int) -> Protected<Vec<u8>> {
    match value {
        Int::I8(v) => fixed(((v as u8) ^ (1 << 7)).to_be_bytes()),
        Int::U8(v) => fixed(v.to_be_bytes()),
        Int::I16(v) => fixed(((v as u16) ^ (1 << 15)).to_be_bytes()),
        Int::U16(v) => fixed(v.to_be_bytes()),
        Int::I32(v) => fixed(((v as u32) ^ (1 << 31)).to_be_bytes()),
        Int::U32(v) => fixed(v.to_be_bytes()),
        Int::I64(v) => fixed(((v as u64) ^ (1 << 63)).to_be_bytes()),
        Int::U64(v) => fixed(v.to_be_bytes()),
        Int::I128(v) => fixed(((v as u128) ^ (1 << 127)).to_be_bytes()),
        Int::U128(v) => fixed(v.to_be_bytes()),
    }
}

/// A float at its own width, zero signs and NaN payloads folded: an `f64`
/// as [`vitaminc_normalize::float`] encodes it, an `f32` by the same rule
/// over its own four bytes. Both paths use integer operations only.
pub fn float(value: Float) -> Protected<Vec<u8>> {
    match value {
        Float::F32(f) => fixed(orderable_f32(canonical_f32(f))),
        Float::F64(_) => vitaminc_normalize::float(value),
    }
}

/// Text as Unicode 16 NFC with accents and case folded. See the crate
/// docs for the exact steps.
///
/// # Errors
///
/// [`NormalizeError::UnassignedCodePoint`] if `text` holds a code point
/// Unicode 16 does not assign: its folding is not known.
pub fn text(text: &str) -> Result<Protected<Vec<u8>>, NormalizeError> {
    fold::folded(text)
}

/// A fixed-width encoding as a protected vector, with the array wrapped
/// before it is copied so neither copy is dropped bare.
fn fixed<const N: usize>(bytes: [u8; N]) -> Protected<Vec<u8>> {
    let bytes = Protected::new(bytes);
    Protected::new(bytes.risky_ref().to_vec())
}

/// Folds every NaN to one quiet NaN and `-0.0` to `0.0`, in integer
/// operations only: `vitaminc_normalize`'s `f64` rule at `f32` width.
fn canonical_f32(value: f32) -> f32 {
    let bits = value.to_bits();
    let magnitude = bits & 0x7fff_ffff;
    let nan = 0u32.wrapping_sub((magnitude > 0x7f80_0000) as u32);
    let nonzero = 0u32.wrapping_sub((magnitude != 0) as u32);
    f32::from_bits((bits & !nan).wrapping_add(0x7fc0_0000 & nan) & nonzero)
}

/// The orderable bytes of an `f32`: negatives flip every bit, positives
/// the sign bit, so the bytes sort as the numbers do. Expects a value
/// [`canonical_f32`] has already folded.
fn orderable_f32(value: f32) -> [u8; 4] {
    let bits = value.to_bits();
    let sign_extension = ((bits as i32) >> 31) as u32;
    (bits ^ (sign_extension | (1u32 << 31))).to_be_bytes()
}

/// The order normalizer, for [`vitaminc_normalize::Terms::by`]: [`order`]
/// as a [`Normalize`], whose terms are sealed [`OrderPlaintext`]s.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Order;

impl Normalize for Order {
    type Term = OrderPlaintext;

    fn normalize(
        &self,
        ty: Option<Logical>,
        value: Physical<'_>,
    ) -> Result<OrderPlaintext, NormalizeError> {
        order(ty, value)
    }
}

/// Every order term of `value`, in walk order, without encrypting it:
/// [`vitaminc_normalize::terms`] under the [`Order`] normalizer.
///
/// A null, a boolean or an `undefined` produces no term and does not stop
/// the walk; a logical type with no order domain stops it, and so does a
/// value encryption would refuse, for the same reason at the same path.
/// [`vitaminc_normalize::Terms`] has the rules.
///
/// # Examples
///
/// ```
/// use std::collections::BTreeMap;
/// use vitaminc_normalize::Step;
/// use vitaminc_ore::{domain, order_terms};
///
/// let mut user = BTreeMap::new();
/// user.insert("name", "Ada");
/// let found = order_terms(&user)?;
/// assert_eq!(found[0].path.steps(), [Step::Key("name".into())]);
/// assert_eq!(found[0].normalized.domain(), domain::TEXT);
/// # Ok::<(), vitaminc_ore::TermsError>(())
/// ```
///
/// # Errors
///
/// [`TermsError`]: what the walk refuses, a value encryption would refuse
/// included, or the source's own failure.
pub fn order_terms<P: Encrypt>(value: P) -> Result<Vec<Term<OrderPlaintext>>, TermsError> {
    terms_by(Order, value)
}

#[cfg(test)]
#[path = "order_tests.rs"]
mod tests;
