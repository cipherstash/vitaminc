//! One order term per scalar, encoded as the index's declared type.
//!
//! An order index declares the type of what it holds: an `i32` column,
//! say, as [`OrderTarget::I32`]. [`order`] turns a physical value and its
//! optional logical type into the sealed [`OrderPlaintext`] a scheme
//! encrypts, encoded as that target: bytes whose lexicographic order is
//! the value's order, and the frozen domain label of the target. The
//! target, not the value, decides the domain and the width, so values
//! from every host compare in one space. A JavaScript `BigInt` arrives as
//! the narrowest integer that holds it, and a Rust field at its own type;
//! both widen to the target, and a value outside it is refused.
//!
//! Where an equality term folds every integer width into one encoding, an
//! order term keeps the declared width, so block ORE over an `i32` column
//! costs four blocks, not seventeen. A float, a date, a timestamp, a
//! decimal and a uuid order by the same bytes they are matched by, so
//! those come from `vitaminc_normalize` unchanged. Bytes are the equality
//! encoding behind [`VARIABLE_WIDTH_MARKER`], and text folds further: an
//! order term drops accents and case, which equality must not. See the
//! crate docs for the table.

use vitaminc_aead::{Encrypt, Int, Logical, Physical};
use vitaminc_normalize::{terms_by, Normalize, NormalizeError, Term, TermsError};
use vitaminc_protected::{Controlled, Protected};

use crate::{fold, OrderPlaintext};

/// The byte every text and bytes order encoding starts with, so that no
/// order plaintext is ever empty.
///
/// An empty string and an empty byte string are values with an order,
/// and without the marker they encoded to nothing. Both scheme crates
/// then encrypted them into a term that never touched the key or the
/// salt: the same term under every key and context, which anyone could
/// write into any index. A constant leading byte keeps the order of the
/// encodings, and a fixed-width encoding is never empty, so it goes in
/// unchanged. The scheme crates added this byte themselves before it
/// moved here; see the README's Encodings section for why the domain
/// labels did not change with it.
pub const VARIABLE_WIDTH_MARKER: u8 = 0x01;

/// Frozen domain labels for order terms, one per [`OrderTarget`].
pub mod domain {
    // Retired in 0.7, never to be reused with another meaning:
    // `vitaminc/ore/value/int8/v1` and `vitaminc/ore/value/uint8/v1`, the
    // one-byte targets 0.6 published. See `OrderTarget` for why.

    /// An `i16`, two bytes. The narrowest integer target: see
    /// [`OrderTarget`](super::OrderTarget) for why there is no 8-bit one.
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
    /// An `f64`, eight bytes, zero signs and NaN payloads folded.
    pub const FLOAT64: &str = "vitaminc/ore/value/float64/v1";
    /// A date, four bytes, over its day count.
    pub const DATE: &str = "vitaminc/ore/value/date/v1";
    /// A timestamp, twelve bytes, truncated to microseconds.
    pub const TIMESTAMP: &str = "vitaminc/ore/value/timestamp-micros/v1";
    /// A decimal, fourteen bytes, scale and signed zero normalized.
    pub const DECIMAL: &str = "vitaminc/ore/value/decimal/v1";
    /// Text: [`VARIABLE_WIDTH_MARKER`](super::VARIABLE_WIDTH_MARKER), then
    /// Unicode 16 NFC with accents and case folded.
    pub const TEXT: &str = "vitaminc/ore/value/text-folded/unicode-16/v1";
    /// Bytes: [`VARIABLE_WIDTH_MARKER`](super::VARIABLE_WIDTH_MARKER), then
    /// the bytes as they are.
    pub const BYTES: &str = "vitaminc/ore/value/bytes/v1";
    /// A uuid, over its sixteen raw bytes.
    pub const UUID: &str = "vitaminc/ore/value/uuid/v1";
    /// Every domain, for a test or an index layer that enumerates them. A
    /// slice, so a domain added later does not change its type.
    pub const ALL: &[&str] = &[
        INT16, UINT16, INT32, UINT32, INT64, UINT64, INT128, UINT128, FLOAT64, DATE, TIMESTAMP,
        DECIMAL, TEXT, BYTES, UUID,
    ];
}

/// The type an order index declares, which every value it holds is
/// encoded as. A layer above maps its own column types onto these: an
/// EQL `int` column is [`OrderTarget::I32`], whatever language the value
/// comes from.
///
/// An integer of any width is accepted by an integer target it fits,
/// and refused with [`NormalizeError::OutOfRange`] otherwise. An `f32` is
/// widened exactly to [`OrderTarget::F64`]. Every other target takes only
/// its own kind; anything else is [`NormalizeError::Mismatch`]. An
/// integer is not a float, a date or a decimal, so none of those take
/// one.
///
/// # What has no target
///
/// An order term reveals the order of the values it encrypts. That is
/// the point of the scheme, and it is safe only when the set of possible
/// values is large enough that knowing the order of the rows does not
/// give the values away. A boolean has two values, so an order term over
/// a boolean column says which rows are `true`: [`order`] refuses one
/// with [`NormalizeError::NoDomain`]. An 8-bit integer has 256, so an
/// order index over such a column is a frequency table of the column with
/// the order on top, and anyone who knows a handful of rows' values, or
/// the rough distribution of the data (ages, quantities, ratings), reads
/// the rest off. So the narrowest integer target is sixteen bits. An
/// `i8` or `u8` **value** still goes into any wider target it fits; what
/// there is not is a one-byte space.
///
/// The floor removes only the case where the *type* guarantees few
/// values. An `I16` or `I32` column that holds ages or ratings leaks the
/// same frequency table, since the leak is a property of how many
/// distinct values the column holds, not of the width. Whether a column
/// should have an order index at all is a question about its data; a
/// column of few distinct values wants an equality index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OrderTarget {
    /// An `i16`. The narrowest integer target; see above for why.
    I16,
    /// A `u16`.
    U16,
    /// An `i32`.
    I32,
    /// A `u32`.
    U32,
    /// An `i64`.
    I64,
    /// A `u64`.
    U64,
    /// An `i128`.
    I128,
    /// A `u128`.
    U128,
    /// An `f64`; an `f32` widens to it exactly.
    F64,
    /// A [`Logical::Date`].
    Date,
    /// A [`Logical::Timestamp`] in any unit, truncated to microseconds.
    Timestamp,
    /// A [`Logical::Decimal`] at any scale.
    Decimal,
    /// Text.
    Text,
    /// Bytes.
    Bytes,
    /// A [`Logical::Uuid`].
    Uuid,
}

impl OrderTarget {
    /// Every target, for a test or an index layer that enumerates them.
    pub const ALL: &[OrderTarget] = &[
        Self::I16,
        Self::U16,
        Self::I32,
        Self::U32,
        Self::I64,
        Self::U64,
        Self::I128,
        Self::U128,
        Self::F64,
        Self::Date,
        Self::Timestamp,
        Self::Decimal,
        Self::Text,
        Self::Bytes,
        Self::Uuid,
    ];

    /// The frozen domain label of every term of this target.
    pub fn domain(self) -> &'static str {
        match self {
            Self::I16 => domain::INT16,
            Self::U16 => domain::UINT16,
            Self::I32 => domain::INT32,
            Self::U32 => domain::UINT32,
            Self::I64 => domain::INT64,
            Self::U64 => domain::UINT64,
            Self::I128 => domain::INT128,
            Self::U128 => domain::UINT128,
            Self::F64 => domain::FLOAT64,
            Self::Date => domain::DATE,
            Self::Timestamp => domain::TIMESTAMP,
            Self::Decimal => domain::DECIMAL,
            Self::Text => domain::TEXT,
            Self::Bytes => domain::BYTES,
            Self::Uuid => domain::UUID,
        }
    }

    /// The width of every term of this target, or `None` for text and
    /// bytes, whose terms vary in length. Never one byte: see the type's
    /// docs.
    pub fn width(self) -> Option<usize> {
        match self {
            Self::I16 | Self::U16 => Some(2),
            Self::I32 | Self::U32 | Self::Date => Some(4),
            Self::I64 | Self::U64 | Self::F64 => Some(8),
            Self::Timestamp => Some(12),
            Self::Decimal => Some(14),
            Self::I128 | Self::U128 | Self::Uuid => Some(16),
            Self::Text | Self::Bytes => None,
        }
    }
}

/// Encode one scalar as `target`, sealed with the target's domain. The one
/// place a value meets the data model.
///
/// An integer is converted to the target's width, then encoded
/// big-endian, with the sign bit flipped when signed, so the bytes sort
/// as the numbers do. A float, a date, a timestamp, a decimal and a uuid
/// encode exactly as [`vitaminc_normalize::normalize`] encodes them for
/// equality. Bytes are the equality encoding behind
/// [`VARIABLE_WIDTH_MARKER`], and text is the marker, then Unicode 16 NFC
/// with accents and case folded, so `É` and `e` tie. The marker keeps a
/// variable-width encoding from ever being empty.
///
/// # Examples
///
/// ```
/// use vitaminc_ore::{domain, order, Int, NormalizeError, OrderTarget, Physical};
///
/// // Every integer width widens to the target.
/// let small = order(OrderTarget::I32, None, Physical::Int(Int::I8(100)))?;
/// let large = order(OrderTarget::I32, None, Physical::Int(Int::U64(300)))?;
/// assert_eq!(small.domain(), domain::INT32);
/// assert_eq!(large.domain(), domain::INT32);
///
/// // A value the target cannot hold is refused, not truncated.
/// let big = Physical::Int(Int::I64(1 << 40));
/// assert_eq!(order(OrderTarget::I32, None, big).err(), Some(NormalizeError::OutOfRange));
/// assert_eq!(
///     order(OrderTarget::I32, None, Physical::Text("1")).err(),
///     Some(NormalizeError::Mismatch)
/// );
/// # Ok::<(), NormalizeError>(())
/// ```
///
/// # Errors
///
/// [`NormalizeError::NoDomain`] for a null, a boolean (see [`OrderTarget`]
/// for why), an `undefined` or a logical type this build does not know; [`NormalizeError::Invalid`] for
/// a value that does not fit its own logical type;
/// [`NormalizeError::Mismatch`] for a value of another kind than
/// `target`; [`NormalizeError::OutOfRange`] for an integer outside
/// `target`'s width; [`NormalizeError::UnassignedCodePoint`] for text
/// holding a code point Unicode 16 does not assign.
pub fn order(
    target: OrderTarget,
    ty: Option<Logical>,
    v: Physical<'_>,
) -> Result<OrderPlaintext, NormalizeError> {
    use OrderTarget as T;
    // As `normalize`: a value that does not fit its logical type is refused
    // before the target is looked at.
    if ty.is_some_and(|ty| !ty.admits(&v)) {
        return Err(NormalizeError::Invalid);
    }
    let bytes = match (target, ty, v) {
        // A null, a boolean or an `undefined` has no order, whatever the
        // target, and a walk skips it.
        (_, None, Physical::Null | Physical::Bool(_)) | (_, Some(Logical::Undefined), _) => {
            return Err(NormalizeError::NoDomain)
        }
        (_, Some(Logical::Unknown(_)), _) => return Err(NormalizeError::NoDomain),
        (target, None, Physical::Int(i)) if target.is_int() => {
            int(target, i).ok_or(NormalizeError::OutOfRange)?
        }
        (T::F64, None, Physical::Float(f)) => vitaminc_normalize::float(f),
        (T::Text, None, Physical::Text(s)) => text(s)?,
        (T::Bytes, None, Physical::Bytes(b)) => variable_width(b),
        (T::Date, Some(Logical::Date), Physical::Int(days)) => {
            vitaminc_normalize::date(days).ok_or(NormalizeError::Invalid)?
        }
        (T::Timestamp, Some(Logical::Timestamp(unit)), Physical::Int(count)) => {
            vitaminc_normalize::timestamp(unit, count).ok_or(NormalizeError::Invalid)?
        }
        (T::Decimal, Some(Logical::Decimal { scale }), Physical::Int(mantissa)) => {
            vitaminc_normalize::decimal(scale, mantissa).ok_or(NormalizeError::Invalid)?
        }
        (T::Uuid, Some(Logical::Uuid), Physical::Bytes(b)) => {
            vitaminc_normalize::uuid(b).ok_or(NormalizeError::Invalid)?
        }
        // Another kind than the target's, including a logical type added
        // to the data model later: it has no term here until it is given
        // a target.
        _ => return Err(NormalizeError::Mismatch),
    };
    Ok(OrderPlaintext::new(target, bytes))
}

impl OrderTarget {
    /// Whether this is an integer target.
    fn is_int(self) -> bool {
        matches!(
            self,
            Self::I16
                | Self::U16
                | Self::I32
                | Self::U32
                | Self::I64
                | Self::U64
                | Self::I128
                | Self::U128
        )
    }
}

/// `value` at integer `target`'s width: big-endian, with the sign bit
/// flipped for a signed width, so two's complement sorts as the numbers
/// do. The same bytes `orderable-bytes` produces, checked against it in
/// the tests. `None` if `value` does not fit `target`, or `target` is not
/// an integer target.
///
/// Every width converts through `i128`, except a `u128` above
/// `i128::MAX`, which only a `u128` target holds.
///
/// The value is converted and written in one step, rather than first made
/// into an [`Int`] at the target's width and then encoded. An `Int` is 32
/// bytes, so passing one to a function that is not inlined puts a copy of
/// the value in a slot on the caller's stack, and nothing wipes that slot.
/// Done in one step, the converted value stays in a register until it is
/// written to the protected buffer. This was checked in the compiled code
/// for AArch64; Rust does not promise it.
fn int(target: OrderTarget, value: Int) -> Option<Protected<Vec<u8>>> {
    use OrderTarget as T;
    let Some(v) = value.to_i128() else {
        return match (target, value) {
            (T::U128, Int::U128(v)) => Some(fixed(|b| *b = v.to_be_bytes())),
            _ => None,
        };
    };
    Some(match target {
        T::I16 => {
            let v = i16::try_from(v).ok()?;
            fixed(|b| *b = ((v as u16) ^ (1 << 15)).to_be_bytes())
        }
        T::U16 => {
            let v = u16::try_from(v).ok()?;
            fixed(|b| *b = v.to_be_bytes())
        }
        T::I32 => {
            let v = i32::try_from(v).ok()?;
            fixed(|b| *b = ((v as u32) ^ (1 << 31)).to_be_bytes())
        }
        T::U32 => {
            let v = u32::try_from(v).ok()?;
            fixed(|b| *b = v.to_be_bytes())
        }
        T::I64 => {
            let v = i64::try_from(v).ok()?;
            fixed(|b| *b = ((v as u64) ^ (1 << 63)).to_be_bytes())
        }
        T::U64 => {
            let v = u64::try_from(v).ok()?;
            fixed(|b| *b = v.to_be_bytes())
        }
        T::I128 => fixed(|b| *b = ((v as u128) ^ (1 << 127)).to_be_bytes()),
        T::U128 => {
            let v = u128::try_from(v).ok()?;
            fixed(|b| *b = v.to_be_bytes())
        }
        _ => return None,
    })
}

/// The text order encoding: [`VARIABLE_WIDTH_MARKER`], then `text` as
/// Unicode 16 NFC with accents and case folded. See the crate docs for
/// the exact steps.
///
/// # Errors
///
/// [`NormalizeError::UnassignedCodePoint`] if `text` holds a code point
/// Unicode 16 does not assign: its folding is not known.
pub fn text(text: &str) -> Result<Protected<Vec<u8>>, NormalizeError> {
    let folded = fold::folded(text)?;
    Ok(variable_width(folded.risky_ref()))
    // `folded` drops here and is wiped.
}

/// A variable-width encoding: the marker, then `bytes`, in one protected
/// buffer sized up front so it never reallocates and frees an unwiped
/// partial copy. Never empty.
fn variable_width(bytes: &[u8]) -> Protected<Vec<u8>> {
    let mut out = Protected::new(Vec::with_capacity(bytes.len() + 1));
    out.risky_inner_mut().push(VARIABLE_WIDTH_MARKER);
    out.risky_inner_mut().extend_from_slice(bytes);
    out
}

/// A fixed-width encoding, written by `write` straight into the protected
/// vector that is returned.
///
/// The vector is allocated once at its final size, so it never
/// reallocates, and `write` fills it in place. No separate array of the
/// encoding is made and copied, so there is no extra copy to wipe. The
/// compiler can still make short-lived temporaries while `write` runs, for
/// example the array that `to_be_bytes` returns, and Rust cannot promise
/// to wipe those.
fn fixed<const N: usize>(mut write: impl FnMut(&mut [u8; N])) -> Protected<Vec<u8>> {
    let mut bytes = Protected::new(vec![0u8; N]);
    bytes.update(|bytes| {
        let array = <&mut [u8; N]>::try_from(bytes.as_mut_slice())
            .expect("the vector was made with exactly N bytes");
        write(array);
    });
    bytes
}

/// The order normalizer, for [`vitaminc_normalize::Terms::by`]: [`order`]
/// at one target, whose terms are sealed [`OrderPlaintext`]s. Every scalar
/// of the walk is encoded as that target, so it suits a value of one kind
/// throughout, such as an array column; a scalar of another kind stops
/// the walk with [`NormalizeError::Mismatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Order(pub OrderTarget);

impl Normalize for Order {
    type Term = OrderPlaintext;

    const INDEX: &'static str = "order";

    fn normalize(
        &self,
        ty: Option<Logical>,
        value: Physical<'_>,
    ) -> Result<OrderPlaintext, NormalizeError> {
        order(self.0, ty, value)
    }
}

/// Every order term of `value` as `target`, in walk order, without
/// encrypting it: [`vitaminc_normalize::terms`] under the [`Order`]
/// normalizer.
///
/// A null, a boolean or an `undefined` produces no term and does not stop
/// the walk; a scalar of another kind than `target`, or one outside it,
/// stops it, and so does a value encryption would refuse, for the same
/// reason at the same path. [`vitaminc_normalize::Terms`] has the rules.
///
/// # Examples
///
/// ```
/// use vitaminc_normalize::Step;
/// use vitaminc_ore::{domain, order_terms, OrderTarget};
///
/// let scores: Vec<u16> = vec![7, 9];
/// let found = order_terms(OrderTarget::I32, &scores)?;
/// assert_eq!(found[1].path.steps(), [Step::Index(1)]);
/// assert_eq!(found[1].normalized.domain(), domain::INT32);
/// # Ok::<(), vitaminc_ore::TermsError>(())
/// ```
///
/// # Errors
///
/// [`TermsError`]: what the walk refuses, a value encryption would refuse
/// included, or the source's own failure.
pub fn order_terms<P: Encrypt>(
    target: OrderTarget,
    value: P,
) -> Result<Vec<Term<OrderPlaintext>>, TermsError> {
    terms_by(Order(target), value)
}

#[cfg(test)]
#[path = "order_tests.rs"]
mod tests;
