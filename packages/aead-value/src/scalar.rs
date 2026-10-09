//! Shared scalar decoding for sealed plaintext and transport leaves.
use crate::{tags, Utf8String, Value};
use vitaminc_aead::Unspecified;
use vitaminc_protected::Protected;

/// Decode one scalar payload, with exact widths and identical validation
/// whether it arrived in an authenticated envelope or a transport frame.
pub(crate) fn decode_leaf(tag: u8, payload: &[u8]) -> Result<Value, Unspecified> {
    match (tag, payload) {
        (tags::NULL, []) => Ok(Value::Null),
        (tags::UNDEFINED, []) => Ok(Value::Undefined),
        (tags::BOOL_FALSE, []) => Ok(Value::Bool(false)),
        (tags::BOOL_TRUE, []) => Ok(Value::Bool(true)),
        (tags::INT8, bytes) => fixed(bytes, i8::from_le_bytes).map(Value::Int8),
        (tags::UINT8, bytes) => fixed(bytes, u8::from_le_bytes).map(Value::UInt8),
        (tags::INT16, bytes) => fixed(bytes, i16::from_le_bytes).map(Value::Int16),
        (tags::UINT16, bytes) => fixed(bytes, u16::from_le_bytes).map(Value::UInt16),
        (tags::INT32, bytes) => fixed(bytes, i32::from_le_bytes).map(Value::Int32),
        (tags::UINT32, bytes) => fixed(bytes, u32::from_le_bytes).map(Value::UInt32),
        (tags::INT64, bytes) => fixed(bytes, i64::from_le_bytes).map(Value::Int64),
        (tags::UINT64, bytes) => fixed(bytes, u64::from_le_bytes).map(Value::UInt64),
        (tags::INT128, bytes) => fixed(bytes, i128::from_le_bytes).map(Value::Int128),
        (tags::UINT128, bytes) => fixed(bytes, u128::from_le_bytes).map(Value::UInt128),
        (tags::FLOAT32, bytes) => fixed(bytes, f32::from_le_bytes).map(Value::Float32),
        (tags::FLOAT64, bytes) => fixed(bytes, f64::from_le_bytes).map(Value::Float64),
        #[cfg(feature = "chrono")]
        (tags::DATE, bytes) => decode_date(bytes).map(Value::Date),
        #[cfg(feature = "chrono")]
        (tags::TIMESTAMP, bytes) => decode_timestamp(bytes).map(Value::Timestamp),
        #[cfg(feature = "rust_decimal")]
        (tags::DECIMAL, bytes) => decode_decimal(bytes).map(Value::Decimal),
        (tags::STRING, bytes) => {
            Utf8String::try_from(Protected::new(bytes.to_vec())).map(Value::String)
        }
        (tags::BYTES, bytes) => Ok(Value::Bytes(Protected::new(bytes.to_vec()))),
        _ => Err(Unspecified),
    }
}

/// Fixed-width decoding keeps malformed-length handling out of the dispatch
/// table. `try_into` rejects both truncated and overlong payloads.
fn fixed<const N: usize, T>(
    bytes: &[u8],
    decode: impl FnOnce([u8; N]) -> T,
) -> Result<T, Unspecified> {
    bytes.try_into().map(decode).map_err(|_| Unspecified)
}

/// Length of a fixed-width scalar payload. Variable-length leaves get their
/// lengths from transport framing; unknown tags are refused.
pub(crate) fn fixed_payload_len(tag: u8) -> Option<usize> {
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

#[cfg(feature = "chrono")]
pub(crate) fn decode_date(bytes: &[u8]) -> Result<chrono::NaiveDate, Unspecified> {
    let days = i32::from_le_bytes(bytes.try_into().map_err(|_| Unspecified)?);
    chrono::NaiveDate::from_num_days_from_ce_opt(days).ok_or(Unspecified)
}

#[cfg(feature = "chrono")]
pub(crate) fn timestamp_bytes(value: chrono::DateTime<chrono::Utc>) -> [u8; 12] {
    let mut bytes = [0; 12];
    bytes[..8].copy_from_slice(&value.timestamp().to_le_bytes());
    bytes[8..].copy_from_slice(&value.timestamp_subsec_nanos().to_le_bytes());
    bytes
}

#[cfg(feature = "chrono")]
pub(crate) fn decode_timestamp(bytes: &[u8]) -> Result<chrono::DateTime<chrono::Utc>, Unspecified> {
    let bytes: &[u8; 12] = bytes.try_into().map_err(|_| Unspecified)?;
    let seconds = i64::from_le_bytes(bytes[..8].try_into().map_err(|_| Unspecified)?);
    let nanos = u32::from_le_bytes(bytes[8..].try_into().map_err(|_| Unspecified)?);
    chrono::DateTime::from_timestamp(seconds, nanos).ok_or(Unspecified)
}

#[cfg(feature = "rust_decimal")]
pub(crate) fn decode_decimal(bytes: &[u8]) -> Result<rust_decimal::Decimal, Unspecified> {
    let bytes = bytes.try_into().map_err(|_| Unspecified)?;
    let decimal = rust_decimal::Decimal::deserialize(bytes);
    // deserialize() masks reserved bits and rounds invalid scales. Reject
    // those representations instead of silently changing the encrypted value.
    if decimal.serialize() != bytes {
        return Err(Unspecified);
    }
    Ok(decimal)
}
