//! The scalar half of the frozen tag table, as this spike needs it.
//!
//! SPIKE: aead-value keeps its scalar decoder `pub(crate)`, so the table is
//! repeated here. The corpus tests check this copy accepts and rejects
//! exactly what `transport::decode_value` does. In a real change this would
//! be aead-value's own table, shared.

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use vitaminc_aead_value::tags;

use crate::model::{Error, Sink, SourceError};

/// Payload width of a fixed-width scalar tag, or `None` for STRING, BYTES
/// and unknown tags.
pub(crate) fn fixed_len(tag: u8) -> Option<usize> {
    match tag {
        tags::NULL | tags::UNDEFINED | tags::BOOL_FALSE | tags::BOOL_TRUE => Some(0),
        tags::INT8 | tags::UINT8 => Some(1),
        tags::INT16 | tags::UINT16 => Some(2),
        tags::INT32 | tags::UINT32 | tags::FLOAT32 | tags::DATE => Some(4),
        tags::INT64 | tags::UINT64 | tags::FLOAT64 => Some(8),
        tags::TIMESTAMP => Some(12),
        tags::INT128 | tags::UINT128 | tags::DECIMAL => Some(16),
        _ => None,
    }
}

pub(crate) fn date(bytes: &[u8]) -> Option<NaiveDate> {
    let days = i32::from_le_bytes(bytes.try_into().ok()?);
    NaiveDate::from_num_days_from_ce_opt(days)
}

pub(crate) fn timestamp(bytes: &[u8]) -> Option<DateTime<Utc>> {
    let seconds = i64::from_le_bytes(bytes.get(..8)?.try_into().ok()?);
    let nanos = u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?);
    DateTime::from_timestamp(seconds, nanos)
}

pub(crate) fn timestamp_bytes(value: DateTime<Utc>) -> [u8; 12] {
    let mut bytes = [0; 12];
    bytes[..8].copy_from_slice(&value.timestamp().to_le_bytes());
    bytes[8..].copy_from_slice(&value.timestamp_subsec_nanos().to_le_bytes());
    bytes
}

pub(crate) fn decimal(bytes: &[u8]) -> Option<Decimal> {
    let bytes: [u8; 16] = bytes.try_into().ok()?;
    let value = Decimal::deserialize(bytes);
    // deserialize() masks reserved bits and rounds bad scales; refuse those.
    (value.serialize() == bytes).then_some(value)
}

/// Whether `payload` is a valid payload for scalar `tag`.
pub(crate) fn valid(tag: u8, payload: &[u8]) -> bool {
    match tag {
        tags::STRING => std::str::from_utf8(payload).is_ok(),
        tags::BYTES => true,
        tags::DATE => date(payload).is_some(),
        tags::TIMESTAMP => timestamp(payload).is_some(),
        tags::DECIMAL => decimal(payload).is_some(),
        tag => fixed_len(tag) == Some(payload.len()),
    }
}

/// Feed one scalar, given as `tag` and its payload, to a sink. Shared by the
/// frame source and by decryption, whose leaf plaintext is `tag ++ payload`.
pub(crate) fn visit<S: Sink>(tag: u8, p: &[u8], sink: S) -> Result<S::Ok, S::Error> {
    try_visit(tag, p, sink).unwrap_or_else(|| Err(S::Error::source(SourceError::msg("invalid scalar"))))
}

/// `None` for an invalid scalar.
pub(crate) fn try_visit<S: Sink>(tag: u8, p: &[u8], sink: S) -> Option<Result<S::Ok, S::Error>> {
    if !valid(tag, p) {
        return None;
    }
    macro_rules! le {
        ($ty:ty) => {
            <$ty>::from_le_bytes(p.try_into().ok()?)
        };
    }
    Some(match tag {
        tags::NULL => sink.null(),
        tags::UNDEFINED => sink.undefined(),
        tags::BOOL_FALSE => sink.bool(false),
        tags::BOOL_TRUE => sink.bool(true),
        tags::INT8 => sink.i8(le!(i8)),
        tags::INT16 => sink.i16(le!(i16)),
        tags::INT32 => sink.i32(le!(i32)),
        tags::INT64 => sink.i64(le!(i64)),
        tags::INT128 => sink.i128(le!(i128)),
        tags::UINT8 => sink.u8(le!(u8)),
        tags::UINT16 => sink.u16(le!(u16)),
        tags::UINT32 => sink.u32(le!(u32)),
        tags::UINT64 => sink.u64(le!(u64)),
        tags::UINT128 => sink.u128(le!(u128)),
        tags::FLOAT32 => sink.f32(f32::from_bits(le!(u32))),
        tags::FLOAT64 => sink.f64(f64::from_bits(le!(u64))),
        tags::DATE => sink.date(date(p)?),
        tags::TIMESTAMP => sink.timestamp(timestamp(p)?),
        tags::DECIMAL => sink.decimal(decimal(p)?),
        tags::STRING => sink.str(std::str::from_utf8(p).ok()?),
        tags::BYTES => sink.bytes(p),
        _ => return None,
    })
}
