use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use vitaminc_aead_value::Value;

/// Host scalar conversion errors. Node receives a TypeError with the same
/// stable code; errors contain no user plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConversionError {
    #[error("BigInt is outside the signed/unsigned 128-bit range")]
    IntegerRange,
    #[error("invalid calendar date")]
    InvalidDate,
    #[error("invalid or out-of-range timestamp")]
    InvalidTimestamp,
    #[error("invalid or out-of-range decimal")]
    InvalidDecimal,
    #[error("decimal must be finite")]
    NonFiniteDecimal,
}

impl ConversionError {
    pub fn code(self) -> &'static str {
        match self {
            Self::IntegerRange => "ERR_INTEGER_RANGE",
            Self::InvalidDate => "ERR_INVALID_DATE",
            Self::InvalidTimestamp => "ERR_INVALID_TIMESTAMP",
            Self::InvalidDecimal => "ERR_INVALID_DECIMAL",
            Self::NonFiniteDecimal => "ERR_NON_FINITE_DECIMAL",
        }
    }
}

pub(crate) fn bigint(negative: bool, words: &[u64]) -> Result<Value, ConversionError> {
    if words
        .get(2..)
        .is_some_and(|tail| tail.iter().any(|&word| word != 0))
    {
        return Err(ConversionError::IntegerRange);
    }
    let magnitude = u128::from(words.first().copied().unwrap_or(0))
        .wrapping_add(u128::from(words.get(1).copied().unwrap_or(0)) << 64);
    if negative && magnitude != 0 {
        if magnitude > (1u128 << 127) {
            return Err(ConversionError::IntegerRange);
        }
        Ok(signed((magnitude as i128).wrapping_neg()))
    } else {
        Ok(unsigned(magnitude))
    }
}

fn signed(value: i128) -> Value {
    if let Ok(v) = i8::try_from(value) {
        Value::Int8(v)
    } else if let Ok(v) = i16::try_from(value) {
        Value::Int16(v)
    } else if let Ok(v) = i32::try_from(value) {
        Value::Int32(v)
    } else if let Ok(v) = i64::try_from(value) {
        Value::Int64(v)
    } else {
        Value::Int128(value)
    }
}

fn unsigned(value: u128) -> Value {
    // Smallest width first, preferring signed when both signed and unsigned
    // at that width fit. This rule is frozen for JS BigInt host conversion.
    if let Ok(v) = i8::try_from(value) {
        Value::Int8(v)
    } else if let Ok(v) = u8::try_from(value) {
        Value::UInt8(v)
    } else if let Ok(v) = i16::try_from(value) {
        Value::Int16(v)
    } else if let Ok(v) = u16::try_from(value) {
        Value::UInt16(v)
    } else if let Ok(v) = i32::try_from(value) {
        Value::Int32(v)
    } else if let Ok(v) = u32::try_from(value) {
        Value::UInt32(v)
    } else if let Ok(v) = i64::try_from(value) {
        Value::Int64(v)
    } else if let Ok(v) = u64::try_from(value) {
        Value::UInt64(v)
    } else if let Ok(v) = i128::try_from(value) {
        Value::Int128(v)
    } else {
        Value::UInt128(value)
    }
}

pub(crate) fn date(text: &str) -> Result<Value, ConversionError> {
    let value =
        NaiveDate::parse_from_str(text, "%Y-%m-%d").map_err(|_| ConversionError::InvalidDate)?;
    if value.to_string() != text {
        return Err(ConversionError::InvalidDate);
    }
    Ok(Value::Date(value))
}

pub(crate) fn timestamp(text: &str) -> Result<Value, ConversionError> {
    // RFC 3339 only spells years 0000-9999. Outside that range decryption
    // emits an ISO 8601 expanded year (`+12000-…`, `-0005-…`), so accept that
    // form too or a decrypted timestamp could not be encrypted again.
    let parsed = if text.starts_with(['+', '-']) {
        DateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S%.f%#z")
    } else {
        DateTime::parse_from_rfc3339(text)
    };
    parsed
        .map(|value| Value::Timestamp(value.with_timezone(&Utc)))
        .map_err(|_| ConversionError::InvalidTimestamp)
}

pub(crate) fn date_millis(ms: f64) -> Result<Value, ConversionError> {
    // Chrono checks its own range below, which is narrower than JS Date's.
    if !ms.is_finite() || ms.fract() != 0.0 {
        return Err(ConversionError::InvalidTimestamp);
    }
    DateTime::from_timestamp_millis(ms as i64)
        .map(Value::Timestamp)
        .ok_or(ConversionError::InvalidTimestamp)
}

pub(crate) fn decimal(text: &str) -> Result<Value, ConversionError> {
    match text.to_ascii_lowercase().as_str() {
        "nan" | "+nan" | "-nan" | "inf" | "+inf" | "-inf" | "infinity" | "+infinity"
        | "-infinity" => return Err(ConversionError::NonFiniteDecimal),
        _ => {}
    }
    // Fixed-point only, matching Go. Refuse separators/exponents rather than
    // letting a library parser choose rounding or representation policy.
    let unsigned = text.strip_prefix(['+', '-']).unwrap_or(text);
    let mut parts = unsigned.split('.');
    let integral = parts.next().unwrap_or("");
    let fraction = parts.next();
    if integral.is_empty()
        || !integral.bytes().all(|c| c.is_ascii_digit())
        || fraction.is_some_and(|part| {
            part.is_empty() || part.len() > 28 || !part.bytes().all(|c| c.is_ascii_digit())
        })
        || parts.next().is_some()
    {
        return Err(ConversionError::InvalidDecimal);
    }
    Decimal::from_str_exact(text)
        .map(|mut value| {
            // rust_decimal's parser canonicalizes negative zero; the binding
            // preserves the sign bit just as the transport and Go model do.
            value.set_sign_negative(text.starts_with('-'));
            Value::Decimal(value)
        })
        .map_err(|_| ConversionError::InvalidDecimal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_aead_value::ValueKind;

    #[test]
    fn bigint_boundaries_choose_the_smallest_kind() {
        let positive = [
            (0, ValueKind::Int8),
            (127, ValueKind::Int8),
            (128, ValueKind::UInt8),
            (255, ValueKind::UInt8),
            (256, ValueKind::Int16),
            (32767, ValueKind::Int16),
            (32768, ValueKind::UInt16),
            (65535, ValueKind::UInt16),
            (65536, ValueKind::Int32),
            (i32::MAX as u128, ValueKind::Int32),
            (i32::MAX as u128 + 1, ValueKind::UInt32),
            (u32::MAX as u128, ValueKind::UInt32),
            (u32::MAX as u128 + 1, ValueKind::Int64),
            (i64::MAX as u128, ValueKind::Int64),
            (i64::MAX as u128 + 1, ValueKind::UInt64),
            (u64::MAX as u128, ValueKind::UInt64),
            (u64::MAX as u128 + 1, ValueKind::Int128),
            (i128::MAX as u128, ValueKind::Int128),
            (i128::MAX as u128 + 1, ValueKind::UInt128),
            (u128::MAX, ValueKind::UInt128),
        ];
        for (value, kind) in positive {
            let words = [value as u64, (value >> 64) as u64];
            assert_eq!(bigint(false, &words).expect("in range").kind(), Some(kind));
        }
        let negative = [
            (128u128, ValueKind::Int8),
            (129, ValueKind::Int16),
            (32768, ValueKind::Int16),
            (32769, ValueKind::Int32),
            (1 << 31, ValueKind::Int32),
            ((1 << 31) + 1, ValueKind::Int64),
            (1 << 63, ValueKind::Int64),
            ((1 << 63) + 1, ValueKind::Int128),
            (1 << 127, ValueKind::Int128),
        ];
        for (magnitude, kind) in negative {
            assert_eq!(
                bigint(true, &[magnitude as u64, (magnitude >> 64) as u64])
                    .expect("in range")
                    .kind(),
                Some(kind)
            );
        }
        assert!(matches!(
            bigint(true, &[0, 1 << 63]).expect("i128 min"),
            Value::Int128(i128::MIN)
        ));
        assert!(matches!(bigint(false, &[]).expect("zero"), Value::Int8(0)));
        assert!(matches!(
            bigint(true, &[0]).expect("negative zero"),
            Value::Int8(0)
        ));
        assert!(matches!(
            bigint(false, &[1, 0, 0]).expect("leading zero"),
            Value::Int8(1)
        ));
        assert_eq!(
            bigint(true, &[1, 1 << 63]).err().expect("underflow"),
            ConversionError::IntegerRange
        );
        assert_eq!(
            bigint(false, &[0, 0, 1]).err().expect("overflow"),
            ConversionError::IntegerRange
        );
    }

    #[test]
    fn dates_and_timestamps_reject_invalid_or_lossy_inputs() {
        assert!(date("2024-02-29").is_ok());
        assert!(date("0000-01-01").is_ok());
        for invalid in ["2023-02-29", "2024-2-9", "", "2024-01-01T00:00:00Z"] {
            assert_eq!(
                date(invalid).err().expect("invalid date"),
                ConversionError::InvalidDate
            );
        }
        assert!(timestamp("2016-12-31T23:59:60.123456789Z").is_ok());
        // Decryption spells years outside 0000-9999 in ISO 8601 expanded form;
        // each must parse back to the same instant.
        for value in [
            DateTime::<Utc>::MIN_UTC,
            DateTime::<Utc>::MAX_UTC,
            "+12000-01-01T00:00:00.000000001Z".parse().expect("valid"),
            "-0005-03-01T12:00:00.000000001Z".parse().expect("valid"),
        ] {
            let text = value.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
            assert!(
                matches!(timestamp(&text), Ok(Value::Timestamp(v)) if v == value),
                "{text}"
            );
        }
        assert!(matches!(
            timestamp("-0005-03-01T12:00:00+01:00"),
            Ok(Value::Timestamp(v)) if v.to_rfc3339() == "-0005-03-01T11:00:00+00:00"
        ));
        for invalid in [
            "+12000-01-01",
            "+12000-13-01T00:00:00Z",
            "-0005-03-01T12:00:00",
        ] {
            assert_eq!(
                timestamp(invalid).err().expect("invalid timestamp"),
                ConversionError::InvalidTimestamp
            );
        }
        assert_eq!(
            timestamp("bad").err().expect("invalid timestamp"),
            ConversionError::InvalidTimestamp
        );
        assert!(date_millis(-1.0).is_ok());
        assert!(date_millis(0.0).is_ok());
        for invalid in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            0.5,
            8_640_000_000_000_001.0,
            8_640_000_000_000_000.0,
        ] {
            assert_eq!(
                date_millis(invalid).err().expect("invalid timestamp"),
                ConversionError::InvalidTimestamp
            );
        }
    }

    #[test]
    fn decimal_is_exact_and_non_finite_errors_are_distinct() {
        for text in ["NaN", "+nan", "-NaN", "inf", "+Infinity", "-Infinity"] {
            assert_eq!(
                decimal(text).err().expect("non finite"),
                ConversionError::NonFiniteDecimal
            );
        }
        for text in [
            "",
            "1e2",
            "1_000",
            "1.5_0",
            ".1",
            "1.",
            "1.2.3",
            " 1",
            "1a",
            "1.a",
            "0.00000000000000000000000000001",
            "79228162514264337593543950336",
        ] {
            assert_eq!(
                decimal(text).err().expect("invalid decimal"),
                ConversionError::InvalidDecimal
            );
        }
        assert!(matches!(decimal("1.50").expect("finite"), Value::Decimal(v) if v.scale() == 2));
        assert!(decimal("+1.50").is_ok());
        for error in [
            ConversionError::IntegerRange,
            ConversionError::InvalidDate,
            ConversionError::InvalidTimestamp,
            ConversionError::InvalidDecimal,
            ConversionError::NonFiniteDecimal,
        ] {
            assert!(error.code().starts_with("ERR_"));
            assert!(!error.to_string().is_empty());
        }
    }
}
