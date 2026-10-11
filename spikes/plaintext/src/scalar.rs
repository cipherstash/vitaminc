//! Scalars on the wire, in a transport frame and in a sealed leaf.
//!
//! Today's tag table is read as **shorthand** for physical plus logical:
//! `UINT32` is a plain int, `DATE` is `Logical::Date` over an int, and so
//! on. So every existing frame and leaf is still valid, byte for byte.
//!
//! A logical type with no tag of its own travels in a **generic envelope**:
//! `LOGICAL, id, param`, then the plain physical scalar. A reader that
//! doesn't know `id` still reads the physical value and keeps the
//! annotation. There's one encoding per value: an envelope is refused where
//! a shorthand tag exists.
//!
//! A frame gives text and bytes a `u32` length. A leaf doesn't: the sealed
//! plaintext ends where the payload does.

use chrono::{DateTime, Datelike, NaiveDate};
use rust_decimal::Decimal;
use vitaminc_aead_value::tags;

use crate::frame::{Cursor, FrameError};
use crate::kinds::{self, Float, Int, Logical, Physical, TimeUnit};

/// The generic logical envelope. Next to the container tags.
pub const LOGICAL: u8 = 0xF3;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Form {
    Frame,
    Leaf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarError {
    /// The value isn't a valid value of its logical type.
    Invalid,
    /// Text or bytes longer than a `u32` length.
    TooLong,
}

pub(crate) fn write(ty: Option<Logical>, v: Physical<'_>, out: &mut Vec<u8>, form: Form) -> Result<(), ScalarError> {
    let Some(ty) = ty else {
        return write_physical(v, out, form);
    };
    if !ty.admits(&v) {
        return Err(ScalarError::Invalid);
    }
    match (ty, v) {
        (Logical::Undefined, _) => out.push(tags::UNDEFINED),
        (Logical::Date, Physical::Int(days)) => {
            let date = kinds::date(days).ok_or(ScalarError::Invalid)?;
            out.push(tags::DATE);
            out.extend_from_slice(&date.num_days_from_ce().to_le_bytes());
        }
        (Logical::Timestamp(TimeUnit::Nanos), Physical::Int(count)) => {
            let ts = kinds::timestamp(TimeUnit::Nanos, count).ok_or(ScalarError::Invalid)?;
            out.push(tags::TIMESTAMP);
            out.extend_from_slice(&ts.timestamp().to_le_bytes());
            out.extend_from_slice(&ts.timestamp_subsec_nanos().to_le_bytes());
        }
        (Logical::Decimal { scale }, Physical::Int(mantissa)) => {
            let d = kinds::decimal(scale, mantissa).ok_or(ScalarError::Invalid)?;
            out.push(tags::DECIMAL);
            out.extend_from_slice(&d.serialize());
        }
        (ty, v) => {
            let (id, param) = ty.to_wire();
            out.extend_from_slice(&[LOGICAL, id, param]);
            write_physical(v, out, form)?;
        }
    }
    Ok(())
}

/// Whether `ty` is written with one of today's tags rather than the
/// envelope.
fn has_shorthand(ty: Logical) -> bool {
    matches!(
        ty,
        Logical::Undefined | Logical::Date | Logical::Timestamp(TimeUnit::Nanos) | Logical::Decimal { .. }
    )
}

fn write_physical(v: Physical<'_>, out: &mut Vec<u8>, form: Form) -> Result<(), ScalarError> {
    let mut variable = |tag, bytes: &[u8]| {
        out.push(tag);
        if form == Form::Frame {
            let len = u32::try_from(bytes.len()).map_err(|_| ScalarError::TooLong)?;
            out.extend_from_slice(&len.to_le_bytes());
        }
        out.extend_from_slice(bytes);
        Ok(())
    };
    match v {
        Physical::Null => out.push(tags::NULL),
        Physical::Bool(false) => out.push(tags::BOOL_FALSE),
        Physical::Bool(true) => out.push(tags::BOOL_TRUE),
        Physical::Int(i) => write_int(i, out),
        Physical::Float(Float::F32(f)) => {
            out.push(tags::FLOAT32);
            out.extend_from_slice(&f.to_bits().to_le_bytes());
        }
        Physical::Float(Float::F64(f)) => {
            out.push(tags::FLOAT64);
            out.extend_from_slice(&f.to_bits().to_le_bytes());
        }
        Physical::Text(s) => variable(tags::STRING, s.as_bytes())?,
        Physical::Bytes(b) => variable(tags::BYTES, b)?,
    }
    Ok(())
}

fn write_int(i: Int, out: &mut Vec<u8>) {
    macro_rules! le {
        ($tag:ident, $v:expr) => {{
            out.push(tags::$tag);
            out.extend_from_slice(&$v.to_le_bytes());
        }};
    }
    match i {
        Int::I8(v) => le!(INT8, v),
        Int::I16(v) => le!(INT16, v),
        Int::I32(v) => le!(INT32, v),
        Int::I64(v) => le!(INT64, v),
        Int::I128(v) => le!(INT128, v),
        Int::U8(v) => le!(UINT8, v),
        Int::U16(v) => le!(UINT16, v),
        Int::U32(v) => le!(UINT32, v),
        Int::U64(v) => le!(UINT64, v),
        Int::U128(v) => le!(UINT128, v),
    }
}

/// Read one scalar node, validating it.
pub(crate) fn read<'a>(c: &mut Cursor<'a>, form: Form) -> Result<(Option<Logical>, Physical<'a>), FrameError> {
    let tag = c.byte()?;
    if tag == LOGICAL {
        let ty = Logical::from_wire(c.byte()?, c.byte()?).ok_or(FrameError)?;
        let tag = c.byte()?;
        let v = read_physical(tag, c, form)?.ok_or(FrameError)?;
        if has_shorthand(ty) || !ty.admits(&v) {
            return Err(FrameError);
        }
        return Ok((Some(ty), v));
    }
    if let Some(v) = read_physical(tag, c, form)? {
        return Ok((None, v));
    }
    Ok(match tag {
        tags::UNDEFINED => (Some(Logical::Undefined), Physical::Null),
        tags::DATE => {
            let days = i32::from_le_bytes(fixed(c)?);
            let date = NaiveDate::from_num_days_from_ce_opt(days).ok_or(FrameError)?;
            (Some(Logical::Date), Physical::Int(Int::I32(kinds::date_days(date))))
        }
        tags::TIMESTAMP => {
            let seconds = i64::from_le_bytes(fixed(c)?);
            let nanos = u32::from_le_bytes(fixed(c)?);
            // A leap second (nanos past 999,999,999) has no count of nanos.
            let ts = DateTime::from_timestamp(seconds, nanos).ok_or(FrameError)?;
            let count = kinds::timestamp_nanos(ts).ok_or(FrameError)?;
            (Some(Logical::Timestamp(TimeUnit::Nanos)), Physical::Int(Int::I128(count)))
        }
        tags::DECIMAL => {
            let bytes: [u8; 16] = fixed(c)?;
            let d = Decimal::deserialize(bytes);
            // deserialize() masks reserved bits and rounds bad scales, and
            // (scale, int) has no negative zero. Refuse all three.
            if d.serialize() != bytes || (d.is_zero() && d.is_sign_negative()) {
                return Err(FrameError);
            }
            let (scale, mantissa) = kinds::decimal_parts(d);
            (Some(Logical::Decimal { scale }), Physical::Int(Int::I128(mantissa)))
        }
        _ => return Err(FrameError),
    })
}

/// A whole sealed leaf.
pub(crate) fn read_leaf(bytes: &[u8]) -> Result<(Option<Logical>, Physical<'_>), FrameError> {
    let mut c = Cursor::new(bytes);
    let scalar = read(&mut c, Form::Leaf)?;
    if !c.finished() {
        return Err(FrameError);
    }
    Ok(scalar)
}

fn fixed<const N: usize>(c: &mut Cursor<'_>) -> Result<[u8; N], FrameError> {
    c.take(N)?.try_into().map_err(|_| FrameError)
}

/// `None` for a tag that isn't a plain physical scalar.
fn read_physical<'a>(tag: u8, c: &mut Cursor<'a>, form: Form) -> Result<Option<Physical<'a>>, FrameError> {
    let variable = |c: &mut Cursor<'a>| match form {
        Form::Frame => {
            let n = c.count()?;
            c.take(n)
        }
        Form::Leaf => Ok(c.rest()),
    };
    Ok(Some(match tag {
        tags::NULL => Physical::Null,
        tags::BOOL_FALSE => Physical::Bool(false),
        tags::BOOL_TRUE => Physical::Bool(true),
        tags::INT8 => Physical::Int(Int::I8(i8::from_le_bytes(fixed(c)?))),
        tags::INT16 => Physical::Int(Int::I16(i16::from_le_bytes(fixed(c)?))),
        tags::INT32 => Physical::Int(Int::I32(i32::from_le_bytes(fixed(c)?))),
        tags::INT64 => Physical::Int(Int::I64(i64::from_le_bytes(fixed(c)?))),
        tags::INT128 => Physical::Int(Int::I128(i128::from_le_bytes(fixed(c)?))),
        tags::UINT8 => Physical::Int(Int::U8(u8::from_le_bytes(fixed(c)?))),
        tags::UINT16 => Physical::Int(Int::U16(u16::from_le_bytes(fixed(c)?))),
        tags::UINT32 => Physical::Int(Int::U32(u32::from_le_bytes(fixed(c)?))),
        tags::UINT64 => Physical::Int(Int::U64(u64::from_le_bytes(fixed(c)?))),
        tags::UINT128 => Physical::Int(Int::U128(u128::from_le_bytes(fixed(c)?))),
        // Raw bit patterns, so signalling NaNs survive.
        tags::FLOAT32 => Physical::Float(Float::F32(f32::from_bits(u32::from_le_bytes(fixed(c)?)))),
        tags::FLOAT64 => Physical::Float(Float::F64(f64::from_bits(u64::from_le_bytes(fixed(c)?)))),
        tags::STRING => Physical::Text(std::str::from_utf8(variable(c)?).map_err(|_| FrameError)?),
        tags::BYTES => Physical::Bytes(variable(c)?),
        _ => return Ok(None),
    }))
}
