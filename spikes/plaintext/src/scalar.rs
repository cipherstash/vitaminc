//! The scalar half of the frozen tag table, as this spike needs it.
//!
//! SPIKE: aead-value keeps its scalar decoder `pub(crate)`, so the table is
//! repeated here. The corpus tests check this copy accepts and rejects
//! exactly what `transport::decode_value` does. In a real change this would
//! be aead-value's own table, shared.

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use vitaminc_aead_value::tags;

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
