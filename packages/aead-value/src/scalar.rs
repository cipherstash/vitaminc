//! Shared validation for the optional fixed-width scalar payloads.
use vitaminc_aead::Unspecified;

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
