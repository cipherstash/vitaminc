//! Physical kinds and logical types.
//!
//! A scalar is a [`Physical`] value, optionally annotated with the
//! [`Logical`] type it represents. The split is Arrow's and Parquet's:
//!
//! - **Physical kinds are a small closed set**: null, bool, int, float, text,
//!   bytes. `Physical` is an exhaustive enum, so adding one is a breaking
//!   change that fails to compile in every sink. That's deliberate: a new
//!   physical kind changes what every consumer has to handle.
//! - **Logical types are open.** A timestamp is an int with a unit, a date
//!   is an int, a uuid is 16 bytes. `Logical` is `#[non_exhaustive]`, so a
//!   sink outside this crate has to say what it does with a logical type it
//!   doesn't know. Structural sinks (encrypt, frames, host builders) carry
//!   the annotation through. Index sinks refuse it.
//!
//! The int's width ([`Int`]'s variant) is a host-fidelity hint, not a kind:
//! every width shares one equality domain, and only the frame, the leaf and
//! the host builders look at it.

use std::fmt;

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use rust_decimal::Decimal;

/// One scalar value, as stored. Borrowed, so a source can hand over text
/// and bytes without copying.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Physical<'a> {
    Null,
    Bool(bool),
    Int(Int),
    Float(Float),
    Text(&'a str),
    Bytes(&'a [u8]),
}

/// An integer, with the width it came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Int {
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
}

impl Int {
    /// The value as an `i128`, unless it's a `u128` above `i128::MAX`.
    pub fn to_i128(self) -> Option<i128> {
        match self {
            Int::I8(v) => Some(v.into()),
            Int::I16(v) => Some(v.into()),
            Int::I32(v) => Some(v.into()),
            Int::I64(v) => Some(v.into()),
            Int::I128(v) => Some(v),
            Int::U8(v) => Some(v.into()),
            Int::U16(v) => Some(v.into()),
            Int::U32(v) => Some(v.into()),
            Int::U64(v) => Some(v.into()),
            Int::U128(v) => i128::try_from(v).ok(),
        }
    }

    /// The value as a `u128`, unless it's negative.
    pub fn to_u128(self) -> Option<u128> {
        match self {
            Int::U128(v) => Some(v),
            other => other.to_i128().and_then(|v| u128::try_from(v).ok()),
        }
    }

    /// The value as a sign and a two's-complement 128-bit word: the layout
    /// the equality encoding uses, covering `i128::MIN` to `u128::MAX`.
    pub fn sign_and_word(self) -> (bool, u128) {
        match self.to_i128() {
            Some(v) => (v < 0, v as u128),
            None => (false, self.to_u128().unwrap_or_default()),
        }
    }
}

macro_rules! int_from {
    ($($ty:ty => $variant:ident),* $(,)?) => {
        $(
            impl From<$ty> for Int {
                fn from(v: $ty) -> Self {
                    Int::$variant(v)
                }
            }
        )*
    };
}

int_from! {
    i8 => I8, i16 => I16, i32 => I32, i64 => I64, i128 => I128,
    u8 => U8, u16 => U16, u32 => U32, u64 => U64, u128 => U128,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Float {
    F32(f32),
    F64(f64),
}

/// What a physical value means. Carried per value, so a parameter like a
/// decimal's scale can differ from one value to the next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Logical {
    /// JavaScript's `undefined`. Over null.
    Undefined,
    /// Days since 1970-01-01. Over int.
    Date,
    /// A count of `unit`s since the Unix epoch, UTC, with no leap seconds.
    /// Over int.
    Timestamp(TimeUnit),
    /// `int × 10^-scale`, scale at most 28 and `|int| < 2^96`. Over int.
    Decimal { scale: u8 },
    /// Sixteen bytes. Over bytes. Today's tag table has no uuid; this is
    /// the "add a logical type" example.
    Uuid,
    /// A logical type this build doesn't know. Structural sinks carry it
    /// through unchanged.
    Unknown(UnknownLogical),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeUnit {
    Seconds,
    Millis,
    Micros,
    Nanos,
}

impl TimeUnit {
    fn nanos(self) -> i128 {
        match self {
            TimeUnit::Seconds => 1_000_000_000,
            TimeUnit::Millis => 1_000_000,
            TimeUnit::Micros => 1_000,
            TimeUnit::Nanos => 1,
        }
    }
}

/// An id and parameter from the wire that this build has no meaning for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownLogical {
    id: u8,
    param: u8,
}

impl UnknownLogical {
    pub fn id(self) -> u8 {
        self.id
    }

    pub fn param(self) -> u8 {
        self.param
    }
}

impl Logical {
    /// The wire id and parameter, for the generic logical envelope.
    pub fn to_wire(self) -> (u8, u8) {
        match self {
            Logical::Undefined => (1, 0),
            Logical::Date => (2, 0),
            Logical::Timestamp(unit) => (3, unit as u8),
            Logical::Decimal { scale } => (4, scale),
            Logical::Uuid => (5, 0),
            Logical::Unknown(u) => (u.id, u.param),
        }
    }

    /// `None` for id 0, or a known id with a parameter it can't take.
    pub fn from_wire(id: u8, param: u8) -> Option<Self> {
        let unit = |p| {
            [TimeUnit::Seconds, TimeUnit::Millis, TimeUnit::Micros, TimeUnit::Nanos]
                .get(usize::from(p))
                .copied()
        };
        match (id, param) {
            (0, _) => None,
            (1, 0) => Some(Logical::Undefined),
            (2, 0) => Some(Logical::Date),
            (3, p) => unit(p).map(Logical::Timestamp),
            (4, scale) => (scale <= 28).then_some(Logical::Decimal { scale }),
            (5, 0) => Some(Logical::Uuid),
            (1..=5, _) => None,
            (id, param) => Some(Logical::Unknown(UnknownLogical { id, param })),
        }
    }

    /// Whether `v` is a valid value of this logical type.
    pub fn admits(self, v: &Physical<'_>) -> bool {
        match (self, *v) {
            (Logical::Undefined, Physical::Null) => true,
            (Logical::Date, Physical::Int(i)) => date(i).is_some(),
            (Logical::Timestamp(unit), Physical::Int(i)) => timestamp(unit, i).is_some(),
            (Logical::Decimal { scale }, Physical::Int(i)) => decimal(scale, i).is_some(),
            (Logical::Uuid, Physical::Bytes(b)) => b.len() == 16,
            (Logical::Unknown(_), _) => true,
            _ => false,
        }
    }
}

const EPOCH_DAYS_FROM_CE: i32 = 719_163;

pub fn date(days: Int) -> Option<NaiveDate> {
    let days = i32::try_from(days.to_i128()?).ok()?;
    NaiveDate::from_num_days_from_ce_opt(days.checked_add(EPOCH_DAYS_FROM_CE)?)
}

pub fn date_days(date: NaiveDate) -> i32 {
    date.num_days_from_ce() - EPOCH_DAYS_FROM_CE
}

pub fn timestamp(unit: TimeUnit, count: Int) -> Option<DateTime<Utc>> {
    let nanos = count.to_i128()?.checked_mul(unit.nanos())?;
    let seconds = i64::try_from(nanos.div_euclid(1_000_000_000)).ok()?;
    DateTime::from_timestamp(seconds, nanos.rem_euclid(1_000_000_000) as u32)
}

/// `None` for a leap second, which has no count.
pub fn timestamp_nanos(ts: DateTime<Utc>) -> Option<i128> {
    let sub = ts.timestamp_subsec_nanos();
    (sub < 1_000_000_000).then(|| i128::from(ts.timestamp()) * 1_000_000_000 + i128::from(sub))
}

pub fn decimal(scale: u8, mantissa: Int) -> Option<Decimal> {
    Decimal::try_from_i128_with_scale(mantissa.to_i128()?, scale.into()).ok()
}

/// Scale and mantissa. A negative zero comes out as zero.
pub fn decimal_parts(d: Decimal) -> (u8, i128) {
    (d.scale() as u8, d.mantissa())
}

impl fmt::Display for Int {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Int::I8(v) => write!(f, "i8 {v}"),
            Int::I16(v) => write!(f, "i16 {v}"),
            Int::I32(v) => write!(f, "i32 {v}"),
            Int::I64(v) => write!(f, "i64 {v}"),
            Int::I128(v) => write!(f, "i128 {v}"),
            Int::U8(v) => write!(f, "u8 {v}"),
            Int::U16(v) => write!(f, "u16 {v}"),
            Int::U32(v) => write!(f, "u32 {v}"),
            Int::U64(v) => write!(f, "u64 {v}"),
            Int::U128(v) => write!(f, "u128 {v}"),
        }
    }
}

impl fmt::Display for Physical<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Physical::Null => f.write_str("null"),
            Physical::Bool(v) => write!(f, "{v}"),
            Physical::Int(v) => write!(f, "{v}"),
            Physical::Float(Float::F32(v)) => write!(f, "f32 {v}"),
            Physical::Float(Float::F64(v)) => write!(f, "f64 {v}"),
            Physical::Text(v) => write!(f, "{v:?}"),
            Physical::Bytes(v) => {
                f.write_str("0x")?;
                v.iter().try_for_each(|b| write!(f, "{b:02x}"))
            }
        }
    }
}

impl fmt::Display for Logical {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Logical::Undefined => f.write_str("undefined"),
            Logical::Date => f.write_str("date"),
            Logical::Timestamp(unit) => {
                let unit = match unit {
                    TimeUnit::Seconds => "s",
                    TimeUnit::Millis => "ms",
                    TimeUnit::Micros => "us",
                    TimeUnit::Nanos => "ns",
                };
                write!(f, "timestamp({unit})")
            }
            Logical::Decimal { scale } => write!(f, "decimal({scale})"),
            Logical::Uuid => f.write_str("uuid"),
            Logical::Unknown(u) => write!(f, "logical({}, {})", u.id, u.param),
        }
    }
}
