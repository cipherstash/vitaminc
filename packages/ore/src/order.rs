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

    // A space that places nulls is a space of its own, with a label of its
    // own: it admits other values than the plain space and gives a meaning
    // to a code the plain space leaves unused. One pair per fixed-width
    // target; text and bytes take no null policy.

    /// An `i16` in a space that places nulls first: see
    /// [`NullOrder::First`](super::NullOrder::First).
    pub const INT16_NULLS_FIRST: &str = "vitaminc/ore/value/int16/nulls-first/v1";
    /// An `i16` in a space that places nulls last: see
    /// [`NullOrder::Last`](super::NullOrder::Last).
    pub const INT16_NULLS_LAST: &str = "vitaminc/ore/value/int16/nulls-last/v1";
    /// A `u16` in a space that places nulls first: see
    /// [`NullOrder::First`](super::NullOrder::First).
    pub const UINT16_NULLS_FIRST: &str = "vitaminc/ore/value/uint16/nulls-first/v1";
    /// A `u16` in a space that places nulls last: see
    /// [`NullOrder::Last`](super::NullOrder::Last).
    pub const UINT16_NULLS_LAST: &str = "vitaminc/ore/value/uint16/nulls-last/v1";
    /// An `i32` in a space that places nulls first: see
    /// [`NullOrder::First`](super::NullOrder::First).
    pub const INT32_NULLS_FIRST: &str = "vitaminc/ore/value/int32/nulls-first/v1";
    /// An `i32` in a space that places nulls last: see
    /// [`NullOrder::Last`](super::NullOrder::Last).
    pub const INT32_NULLS_LAST: &str = "vitaminc/ore/value/int32/nulls-last/v1";
    /// A `u32` in a space that places nulls first: see
    /// [`NullOrder::First`](super::NullOrder::First).
    pub const UINT32_NULLS_FIRST: &str = "vitaminc/ore/value/uint32/nulls-first/v1";
    /// A `u32` in a space that places nulls last: see
    /// [`NullOrder::Last`](super::NullOrder::Last).
    pub const UINT32_NULLS_LAST: &str = "vitaminc/ore/value/uint32/nulls-last/v1";
    /// An `i64` in a space that places nulls first: see
    /// [`NullOrder::First`](super::NullOrder::First).
    pub const INT64_NULLS_FIRST: &str = "vitaminc/ore/value/int64/nulls-first/v1";
    /// An `i64` in a space that places nulls last: see
    /// [`NullOrder::Last`](super::NullOrder::Last).
    pub const INT64_NULLS_LAST: &str = "vitaminc/ore/value/int64/nulls-last/v1";
    /// A `u64` in a space that places nulls first: see
    /// [`NullOrder::First`](super::NullOrder::First).
    pub const UINT64_NULLS_FIRST: &str = "vitaminc/ore/value/uint64/nulls-first/v1";
    /// A `u64` in a space that places nulls last: see
    /// [`NullOrder::Last`](super::NullOrder::Last).
    pub const UINT64_NULLS_LAST: &str = "vitaminc/ore/value/uint64/nulls-last/v1";
    /// An `i128` in a space that places nulls first: see
    /// [`NullOrder::First`](super::NullOrder::First).
    pub const INT128_NULLS_FIRST: &str = "vitaminc/ore/value/int128/nulls-first/v1";
    /// An `i128` in a space that places nulls last: see
    /// [`NullOrder::Last`](super::NullOrder::Last).
    pub const INT128_NULLS_LAST: &str = "vitaminc/ore/value/int128/nulls-last/v1";
    /// A `u128` in a space that places nulls first: see
    /// [`NullOrder::First`](super::NullOrder::First).
    pub const UINT128_NULLS_FIRST: &str = "vitaminc/ore/value/uint128/nulls-first/v1";
    /// A `u128` in a space that places nulls last: see
    /// [`NullOrder::Last`](super::NullOrder::Last).
    pub const UINT128_NULLS_LAST: &str = "vitaminc/ore/value/uint128/nulls-last/v1";
    /// An `f64` in a space that places nulls first: see
    /// [`NullOrder::First`](super::NullOrder::First).
    pub const FLOAT64_NULLS_FIRST: &str = "vitaminc/ore/value/float64/nulls-first/v1";
    /// An `f64` in a space that places nulls last: see
    /// [`NullOrder::Last`](super::NullOrder::Last).
    pub const FLOAT64_NULLS_LAST: &str = "vitaminc/ore/value/float64/nulls-last/v1";
    /// A date in a space that places nulls first: see
    /// [`NullOrder::First`](super::NullOrder::First).
    pub const DATE_NULLS_FIRST: &str = "vitaminc/ore/value/date/nulls-first/v1";
    /// A date in a space that places nulls last: see
    /// [`NullOrder::Last`](super::NullOrder::Last).
    pub const DATE_NULLS_LAST: &str = "vitaminc/ore/value/date/nulls-last/v1";
    /// A timestamp in a space that places nulls first: see
    /// [`NullOrder::First`](super::NullOrder::First).
    pub const TIMESTAMP_NULLS_FIRST: &str = "vitaminc/ore/value/timestamp-micros/nulls-first/v1";
    /// A timestamp in a space that places nulls last: see
    /// [`NullOrder::Last`](super::NullOrder::Last).
    pub const TIMESTAMP_NULLS_LAST: &str = "vitaminc/ore/value/timestamp-micros/nulls-last/v1";
    /// A decimal in a space that places nulls first: see
    /// [`NullOrder::First`](super::NullOrder::First).
    pub const DECIMAL_NULLS_FIRST: &str = "vitaminc/ore/value/decimal/nulls-first/v1";
    /// A decimal in a space that places nulls last: see
    /// [`NullOrder::Last`](super::NullOrder::Last).
    pub const DECIMAL_NULLS_LAST: &str = "vitaminc/ore/value/decimal/nulls-last/v1";
    /// A uuid in a space that places nulls first: see
    /// [`NullOrder::First`](super::NullOrder::First).
    pub const UUID_NULLS_FIRST: &str = "vitaminc/ore/value/uuid/nulls-first/v1";
    /// A uuid in a space that places nulls last: see
    /// [`NullOrder::Last`](super::NullOrder::Last).
    pub const UUID_NULLS_LAST: &str = "vitaminc/ore/value/uuid/nulls-last/v1";

    /// Every domain, for a test or an index layer that enumerates them: the
    /// fifteen plain labels in [`OrderTarget::ALL`](super::OrderTarget::ALL)
    /// order, then the thirteen nulls-first labels and the thirteen
    /// nulls-last labels, each in the same order. A slice, so a domain
    /// added later does not change its type.
    pub const ALL: &[&str] = &[
        INT16,
        UINT16,
        INT32,
        UINT32,
        INT64,
        UINT64,
        INT128,
        UINT128,
        FLOAT64,
        DATE,
        TIMESTAMP,
        DECIMAL,
        TEXT,
        BYTES,
        UUID,
        INT16_NULLS_FIRST,
        UINT16_NULLS_FIRST,
        INT32_NULLS_FIRST,
        UINT32_NULLS_FIRST,
        INT64_NULLS_FIRST,
        UINT64_NULLS_FIRST,
        INT128_NULLS_FIRST,
        UINT128_NULLS_FIRST,
        FLOAT64_NULLS_FIRST,
        DATE_NULLS_FIRST,
        TIMESTAMP_NULLS_FIRST,
        DECIMAL_NULLS_FIRST,
        UUID_NULLS_FIRST,
        INT16_NULLS_LAST,
        UINT16_NULLS_LAST,
        INT32_NULLS_LAST,
        UINT32_NULLS_LAST,
        INT64_NULLS_LAST,
        UINT64_NULLS_LAST,
        INT128_NULLS_LAST,
        UINT128_NULLS_LAST,
        FLOAT64_NULLS_LAST,
        DATE_NULLS_LAST,
        TIMESTAMP_NULLS_LAST,
        DECIMAL_NULLS_LAST,
        UUID_NULLS_LAST,
    ];
}

/// Where the nulls of an order space sort: below every value or above
/// every value, as SQL's `NULLS FIRST` and `NULLS LAST`.
///
/// A space takes a policy when it is made, like its target and context,
/// and every term of it agrees: `scheme.target(I32).nulls(NullOrder::Last)`.
/// Without one, a null has no order term, as before. With one, every null
/// in the space, typed or plain, encodes to the space's sentinel: the
/// lowest code the target's width holds (all `0x00`) for
/// [`First`](Self::First), the highest (all `0xFF`) for
/// [`Last`](Self::Last). Only a fixed-width target takes a policy.
///
/// For an integer or uuid target the policy costs one value: the target's
/// maximum, whose code the nulls-last sentinel already is, is refused with
/// [`NormalizeError::Reserved`]. Under nulls-first every code moves up by
/// one, so zero, the minimum and the nil uuid stay encodable and the
/// maximum is again the one refused. A column that places nulls cannot
/// hold its type's maximum. Float, date, timestamp and decimal codes never
/// reach either extreme, so those targets shift nothing and refuse
/// nothing.
///
/// Each policy is its own set of domain labels, and the salt binds the
/// label, so a term of a space that places nulls never compares with a
/// term of a plain space of the same target.
///
/// # What a placed null reveals
///
/// In any order index whose stored terms compare with each other, the
/// nulls are visible as the tied group at one end, and in a sparse domain
/// as the group that differs from every value at the top of the encoding.
/// That is never more than the SQL `NULL` it replaces, which needs no
/// inference to read.
///
/// # Examples
///
/// ```
/// use vitaminc_ore::{domain, order_with_nulls, Int, NormalizeError, NullOrder, OrderTarget, Physical};
/// use vitaminc_protected::Controlled;
///
/// let null = order_with_nulls(OrderTarget::U16, NullOrder::First, None, Physical::Null)?;
/// assert_eq!(null.domain(), domain::UINT16_NULLS_FIRST);
/// assert_eq!(null.bytes().risky_ref(), &[0x00, 0x00]);
///
/// // Zero moves up by one, so it stays above the null.
/// let zero = order_with_nulls(OrderTarget::U16, NullOrder::First, None, Physical::Int(Int::U16(0)))?;
/// assert_eq!(zero.bytes().risky_ref(), &[0x00, 0x01]);
///
/// // The maximum is the one value refused.
/// let max = Physical::Int(Int::U16(u16::MAX));
/// assert_eq!(
///     order_with_nulls(OrderTarget::U16, NullOrder::First, None, max).err(),
///     Some(NormalizeError::Reserved)
/// );
/// # Ok::<(), NormalizeError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NullOrder {
    /// Nulls sort below every value, as `NULLS FIRST`.
    First,
    /// Nulls sort above every value, as `NULLS LAST`.
    Last,
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

    /// The frozen domain label of every term of this target in a space
    /// that places nulls as `nulls` says, or `None` for text and bytes,
    /// which take no null policy.
    ///
    /// ```
    /// use vitaminc_ore::{domain, NullOrder, OrderTarget};
    ///
    /// assert_eq!(
    ///     OrderTarget::I32.domain_with_nulls(NullOrder::Last),
    ///     Some(domain::INT32_NULLS_LAST)
    /// );
    /// assert_eq!(OrderTarget::Text.domain_with_nulls(NullOrder::Last), None);
    /// ```
    pub fn domain_with_nulls(self, nulls: NullOrder) -> Option<&'static str> {
        Some(match (self, nulls) {
            (Self::I16, NullOrder::First) => domain::INT16_NULLS_FIRST,
            (Self::I16, NullOrder::Last) => domain::INT16_NULLS_LAST,
            (Self::U16, NullOrder::First) => domain::UINT16_NULLS_FIRST,
            (Self::U16, NullOrder::Last) => domain::UINT16_NULLS_LAST,
            (Self::I32, NullOrder::First) => domain::INT32_NULLS_FIRST,
            (Self::I32, NullOrder::Last) => domain::INT32_NULLS_LAST,
            (Self::U32, NullOrder::First) => domain::UINT32_NULLS_FIRST,
            (Self::U32, NullOrder::Last) => domain::UINT32_NULLS_LAST,
            (Self::I64, NullOrder::First) => domain::INT64_NULLS_FIRST,
            (Self::I64, NullOrder::Last) => domain::INT64_NULLS_LAST,
            (Self::U64, NullOrder::First) => domain::UINT64_NULLS_FIRST,
            (Self::U64, NullOrder::Last) => domain::UINT64_NULLS_LAST,
            (Self::I128, NullOrder::First) => domain::INT128_NULLS_FIRST,
            (Self::I128, NullOrder::Last) => domain::INT128_NULLS_LAST,
            (Self::U128, NullOrder::First) => domain::UINT128_NULLS_FIRST,
            (Self::U128, NullOrder::Last) => domain::UINT128_NULLS_LAST,
            (Self::F64, NullOrder::First) => domain::FLOAT64_NULLS_FIRST,
            (Self::F64, NullOrder::Last) => domain::FLOAT64_NULLS_LAST,
            (Self::Date, NullOrder::First) => domain::DATE_NULLS_FIRST,
            (Self::Date, NullOrder::Last) => domain::DATE_NULLS_LAST,
            (Self::Timestamp, NullOrder::First) => domain::TIMESTAMP_NULLS_FIRST,
            (Self::Timestamp, NullOrder::Last) => domain::TIMESTAMP_NULLS_LAST,
            (Self::Decimal, NullOrder::First) => domain::DECIMAL_NULLS_FIRST,
            (Self::Decimal, NullOrder::Last) => domain::DECIMAL_NULLS_LAST,
            (Self::Uuid, NullOrder::First) => domain::UUID_NULLS_FIRST,
            (Self::Uuid, NullOrder::Last) => domain::UUID_NULLS_LAST,
            (Self::Text | Self::Bytes, _) => return None,
        })
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
/// This is the plain space, which places no nulls: a null has no term
/// here. [`order_with_nulls`] encodes for a space that places them.
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
    encode(target, None, ty, v)
}

/// Encode one scalar as `target` in a space that places nulls as `nulls`
/// says, sealed with that space's domain: [`order`] for a space with a
/// [`NullOrder`].
///
/// A null, typed or plain, is the space's sentinel: all `0x00` for
/// [`NullOrder::First`], all `0xFF` for [`NullOrder::Last`], at the
/// target's width. A value encodes as in [`order`], except that under
/// nulls-first an integer's or a uuid's code is one higher, as a
/// big-endian number over the target's width, so the lowest code is free
/// for the sentinel. See [`NullOrder`] for the whole rule.
///
/// # Examples
///
/// ```
/// use vitaminc_ore::{domain, order_with_nulls, Int, NormalizeError, NullOrder, OrderTarget, Physical};
/// use vitaminc_protected::Controlled;
///
/// let null = order_with_nulls(OrderTarget::I16, NullOrder::Last, None, Physical::Null)?;
/// assert_eq!(null.domain(), domain::INT16_NULLS_LAST);
/// assert_eq!(null.bytes().risky_ref(), &[0xFF, 0xFF]);
/// assert_eq!(
///     order_with_nulls(OrderTarget::I16, NullOrder::Last, None, Physical::Int(Int::I16(i16::MAX))).err(),
///     Some(NormalizeError::Reserved)
/// );
/// // Text takes no null policy.
/// assert_eq!(
///     order_with_nulls(OrderTarget::Text, NullOrder::Last, None, Physical::Text("a")).err(),
///     Some(NormalizeError::NoDomain)
/// );
/// # Ok::<(), NormalizeError>(())
/// ```
///
/// # Errors
///
/// As [`order`], except that a null is not refused, and:
/// [`NormalizeError::NoDomain`] for every value when `target` is text or
/// bytes, which take no null policy; [`NormalizeError::Reserved`] for the
/// maximum of an integer or uuid target, whose code is the nulls-last
/// sentinel or would overflow after the nulls-first shift. An `undefined`
/// is still [`NormalizeError::NoDomain`]: it is not a value and not a
/// null.
pub fn order_with_nulls(
    target: OrderTarget,
    nulls: NullOrder,
    ty: Option<Logical>,
    v: Physical<'_>,
) -> Result<OrderPlaintext, NormalizeError> {
    encode(target, Some(nulls), ty, v)
}

/// The domain label of a space: the target's own, or the one its null
/// policy names. `None` for a null policy on text or bytes.
pub(crate) fn label(target: OrderTarget, nulls: Option<NullOrder>) -> Option<&'static str> {
    match nulls {
        None => Some(target.domain()),
        Some(nulls) => target.domain_with_nulls(nulls),
    }
}

/// The sealed sentinel of a space that places nulls: every null of it.
/// `None` for text and bytes, which take no policy.
pub(crate) fn null_plaintext(target: OrderTarget, nulls: NullOrder) -> Option<OrderPlaintext> {
    let domain = target.domain_with_nulls(nulls)?;
    let width = target.width()?;
    Some(OrderPlaintext::new(
        target,
        Some(nulls),
        domain,
        sentinel(width, nulls),
    ))
}

/// [`order`] and [`order_with_nulls`]: one scalar as `target`, in the plain
/// space when `nulls` is `None`.
pub(crate) fn encode(
    target: OrderTarget,
    nulls: Option<NullOrder>,
    ty: Option<Logical>,
    v: Physical<'_>,
) -> Result<OrderPlaintext, NormalizeError> {
    use OrderTarget as T;
    // As `normalize`: a value that does not fit its logical type is refused
    // before the target is looked at.
    if ty.is_some_and(|ty| !ty.admits(&v)) {
        return Err(NormalizeError::Invalid);
    }
    // A null policy on text or bytes has no label, so no value has a term
    // there.
    let domain = label(target, nulls).ok_or(NormalizeError::NoDomain)?;
    let bytes = match (target, ty, v) {
        // A null is the sentinel of a space that places nulls, and has no
        // order in one that does not, where a walk skips it.
        (_, None, Physical::Null) => {
            return match nulls.and_then(|nulls| null_plaintext(target, nulls)) {
                Some(sentinel) => Ok(sentinel),
                None => Err(NormalizeError::NoDomain),
            }
        }
        // A boolean or an `undefined` has no order, whatever the target or
        // the null policy, and a walk skips it.
        (_, None, Physical::Bool(_)) | (_, Some(Logical::Undefined), _) => {
            return Err(NormalizeError::NoDomain)
        }
        (_, Some(Logical::Unknown(_)), _) => return Err(NormalizeError::NoDomain),
        (target, None, Physical::Int(i)) if target.is_int() => {
            int(convert(target, i).ok_or(NormalizeError::OutOfRange)?)
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
    let bytes = match nulls {
        None => bytes,
        Some(nulls) => make_room(target, nulls, bytes)?,
    };
    Ok(OrderPlaintext::new(target, nulls, domain, bytes))
}

/// The sentinel of a space that places nulls: the extreme code of the
/// target's width, all `0x00` for nulls-first and all `0xFF` for
/// nulls-last, in one protected buffer allocated at its final size.
fn sentinel(width: usize, nulls: NullOrder) -> Protected<Vec<u8>> {
    let fill = match nulls {
        NullOrder::First => 0x00,
        NullOrder::Last => 0xFF,
    };
    Protected::new(vec![fill; width])
}

/// A value's code in a space that places nulls, so that no value is the
/// sentinel.
///
/// An integer or a uuid owns every code of its width, so the maximum,
/// whose code is all `0xFF`, is refused under both policies, and under
/// nulls-first every other code moves up by one to free all `0x00`. A
/// float, a date, a timestamp and a decimal never reach either extreme
/// (the tests walk each encoder's range), so their codes stay as they
/// are; a code that did reach the sentinel is refused rather than tied
/// with the nulls.
fn make_room(
    target: OrderTarget,
    nulls: NullOrder,
    mut code: Protected<Vec<u8>>,
) -> Result<Protected<Vec<u8>>, NormalizeError> {
    let all = |code: &Protected<Vec<u8>>, byte: u8| code.risky_ref().iter().all(|b| *b == byte);
    if target.owns_every_code() {
        if all(&code, 0xFF) {
            return Err(NormalizeError::Reserved);
        }
        if nulls == NullOrder::First {
            code.update(|code| increment(code));
        }
        return Ok(code);
    }
    let reserved = match nulls {
        NullOrder::First => 0x00,
        NullOrder::Last => 0xFF,
    };
    if all(&code, reserved) {
        return Err(NormalizeError::Reserved);
    }
    Ok(code)
}

/// Add one to `code` as a big-endian unsigned number, in place. The caller
/// has refused all `0xFF`, so it never overflows.
fn increment(code: &mut [u8]) {
    let mut carry = 1u8;
    for byte in code.iter_mut().rev() {
        let (sum, over) = byte.overflowing_add(carry);
        *byte = sum;
        carry = u8::from(over);
    }
}

impl OrderTarget {
    /// Whether every code of the target's width is some value's: an
    /// integer or a uuid. Such a target gives up its maximum to a null
    /// policy.
    fn owns_every_code(self) -> bool {
        self.is_int() || self == Self::Uuid
    }

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

/// `value` at an integer target's width, or `None` if it does not fit.
/// Every width converts through `i128`, except a `u128` above
/// `i128::MAX`, which only a `u128` target holds.
fn convert(target: OrderTarget, value: Int) -> Option<Int> {
    let Some(v) = value.to_i128() else {
        return match (target, value) {
            (OrderTarget::U128, Int::U128(v)) => Some(Int::U128(v)),
            _ => None,
        };
    };
    match target {
        OrderTarget::I16 => i16::try_from(v).ok().map(Int::I16),
        OrderTarget::U16 => u16::try_from(v).ok().map(Int::U16),
        OrderTarget::I32 => i32::try_from(v).ok().map(Int::I32),
        OrderTarget::U32 => u32::try_from(v).ok().map(Int::U32),
        OrderTarget::I64 => i64::try_from(v).ok().map(Int::I64),
        OrderTarget::U64 => u64::try_from(v).ok().map(Int::U64),
        OrderTarget::I128 => Some(Int::I128(v)),
        OrderTarget::U128 => u128::try_from(v).ok().map(Int::U128),
        _ => None,
    }
}

/// An integer at its own width: big-endian, with the sign bit flipped for
/// a signed width, so two's complement sorts as the numbers do. The same
/// bytes `orderable-bytes` produces, checked against it in the tests.
fn int(value: Int) -> Protected<Vec<u8>> {
    match value {
        // `convert` widens every 8-bit value to its target, so no
        // one-byte encoding is ever made: there is no 8-bit target.
        Int::I8(_) | Int::U8(_) => unreachable!("convert widens every 8-bit value to its target"),
        Int::I16(v) => fixed(|b| *b = ((v as u16) ^ (1 << 15)).to_be_bytes()),
        Int::U16(v) => fixed(|b| *b = v.to_be_bytes()),
        Int::I32(v) => fixed(|b| *b = ((v as u32) ^ (1 << 31)).to_be_bytes()),
        Int::U32(v) => fixed(|b| *b = v.to_be_bytes()),
        Int::I64(v) => fixed(|b| *b = ((v as u64) ^ (1 << 63)).to_be_bytes()),
        Int::U64(v) => fixed(|b| *b = v.to_be_bytes()),
        Int::I128(v) => fixed(|b| *b = ((v as u128) ^ (1 << 127)).to_be_bytes()),
        Int::U128(v) => fixed(|b| *b = v.to_be_bytes()),
    }
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
///
/// Made with [`Order::new`], which places no nulls, so a null has no term
/// and the walk skips it. [`Order::nulls`] places them, as a space does:
/// every null of the walk is then the space's sentinel, at its path.
///
/// ```
/// use vitaminc_normalize::terms_by;
/// use vitaminc_ore::{domain, NullOrder, Order, OrderTarget};
///
/// let ages = vec![Some(36i32), None];
/// let plain = terms_by(Order::new(OrderTarget::I32), &ages)?;
/// assert_eq!(plain.len(), 1);
///
/// let last = Order::new(OrderTarget::I32).nulls(NullOrder::Last).expect("fixed width");
/// let placed = terms_by(last, &ages)?;
/// assert_eq!(placed.len(), 2);
/// assert_eq!(placed[1].normalized.domain(), domain::INT32_NULLS_LAST);
/// # Ok::<(), vitaminc_ore::TermsError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Order {
    target: OrderTarget,
    nulls: Option<NullOrder>,
}

impl Order {
    /// The normalizer for `target`, placing no nulls.
    pub const fn new(target: OrderTarget) -> Self {
        Self {
            target,
            nulls: None,
        }
    }

    /// This normalizer, placing nulls as `nulls` says.
    ///
    /// # Errors
    ///
    /// [`NormalizeError::NoDomain`] for a text or bytes target, which takes
    /// no null policy, rather than a normalizer that refuses every value.
    pub fn nulls(self, nulls: NullOrder) -> Result<Self, NormalizeError> {
        self.target
            .domain_with_nulls(nulls)
            .map(|_| Self {
                nulls: Some(nulls),
                ..self
            })
            .ok_or(NormalizeError::NoDomain)
    }

    /// The target every scalar is encoded as.
    pub fn target(self) -> OrderTarget {
        self.target
    }

    /// Where the normalizer places nulls, or `None` if it gives them no
    /// term.
    pub fn null_order(self) -> Option<NullOrder> {
        self.nulls
    }
}

impl Normalize for Order {
    type Term = OrderPlaintext;

    const INDEX: &'static str = "order";

    fn normalize(
        &self,
        ty: Option<Logical>,
        value: Physical<'_>,
    ) -> Result<OrderPlaintext, NormalizeError> {
        encode(self.target, self.nulls, ty, value)
    }
}

/// Every order term of `value` as `target`, in walk order, without
/// encrypting it: [`vitaminc_normalize::terms`] under the [`Order`]
/// normalizer.
///
/// A null, a boolean or an `undefined` produces no term and does not stop
/// the walk (for nulls placed first or last, walk with
/// [`Order::nulls`] through [`vitaminc_normalize::terms_by`]); a scalar of another kind than `target`, or one outside it,
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
    terms_by(Order::new(target), value)
}

#[cfg(test)]
#[path = "order_tests.rs"]
mod tests;
