//! Host scalars as the ints and bytes their logical types are stored over,
//! and back: BigInt widths, and the text of a calendar date, a timestamp,
//! a decimal and a UUID.
//!
//! Nothing here touches a `napi_env`, so it is all unit-tested natively.

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use vitaminc_aead::plaintext::kinds::{chrono as kinds_chrono, decimal as kinds_decimal};
use vitaminc_aead::{Int, Logical, TimeUnit};

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
    #[error("invalid UUID")]
    InvalidUuid,
}

impl ConversionError {
    pub fn code(self) -> &'static str {
        match self {
            Self::IntegerRange => "ERR_INTEGER_RANGE",
            Self::InvalidDate => "ERR_INVALID_DATE",
            Self::InvalidTimestamp => "ERR_INVALID_TIMESTAMP",
            Self::InvalidDecimal => "ERR_INVALID_DECIMAL",
            Self::NonFiniteDecimal => "ERR_NON_FINITE_DECIMAL",
            Self::InvalidUuid => "ERR_INVALID_UUID",
        }
    }
}

/// A BigInt as the narrowest int that holds it. Smallest width first,
/// preferring signed when both signed and unsigned at that width fit. This
/// rule is frozen for JS BigInt host conversion.
pub(crate) fn bigint(negative: bool, words: &[u64]) -> Result<Int, ConversionError> {
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

fn signed(value: i128) -> Int {
    if let Ok(v) = i8::try_from(value) {
        Int::I8(v)
    } else if let Ok(v) = i16::try_from(value) {
        Int::I16(v)
    } else if let Ok(v) = i32::try_from(value) {
        Int::I32(v)
    } else if let Ok(v) = i64::try_from(value) {
        Int::I64(v)
    } else {
        Int::I128(value)
    }
}

fn unsigned(value: u128) -> Int {
    if let Ok(v) = i8::try_from(value) {
        Int::I8(v)
    } else if let Ok(v) = u8::try_from(value) {
        Int::U8(v)
    } else if let Ok(v) = i16::try_from(value) {
        Int::I16(v)
    } else if let Ok(v) = u16::try_from(value) {
        Int::U16(v)
    } else if let Ok(v) = i32::try_from(value) {
        Int::I32(v)
    } else if let Ok(v) = u32::try_from(value) {
        Int::U32(v)
    } else if let Ok(v) = i64::try_from(value) {
        Int::I64(v)
    } else if let Ok(v) = u64::try_from(value) {
        Int::U64(v)
    } else if let Ok(v) = i128::try_from(value) {
        Int::I128(v)
    } else {
        Int::U128(value)
    }
}

/// A nanosecond count as the narrowest int the leaf codec can carry it in.
fn nanos_int(nanos: i128) -> Int {
    match i64::try_from(nanos) {
        Ok(v) => Int::I64(v),
        Err(_) => Int::I128(nanos),
    }
}

/// `YYYY-MM-DD` as days since 1970-01-01.
pub(crate) fn date(text: &str) -> Result<Int, ConversionError> {
    let value =
        NaiveDate::parse_from_str(text, "%Y-%m-%d").map_err(|_| ConversionError::InvalidDate)?;
    if value.to_string() != text {
        return Err(ConversionError::InvalidDate);
    }
    Ok(Int::I32(kinds_chrono::date_days(value)))
}

/// A day count as `YYYY-MM-DD`, if it is a date chrono can represent.
pub(crate) fn date_text(days: Int) -> Option<String> {
    kinds_chrono::date(days).map(|date| date.to_string())
}

/// RFC 3339 text, or an ISO 8601 expanded year outside 0000-9999, as
/// nanoseconds since the epoch. A leap second has no count and is refused,
/// as the leaf codec refuses it.
pub(crate) fn timestamp(text: &str) -> Result<Int, ConversionError> {
    // RFC 3339 only spells years 0000-9999. Outside that range decryption
    // emits an ISO 8601 expanded year (`+12000-…`, `-0005-…`), so accept that
    // form too or a decrypted timestamp could not be encrypted again.
    let parsed = if text.starts_with(['+', '-']) {
        DateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S%.f%#z")
    } else {
        DateTime::parse_from_rfc3339(text)
    };
    let instant = parsed
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| ConversionError::InvalidTimestamp)?;
    kinds_chrono::timestamp_nanos(instant)
        .map(nanos_int)
        .ok_or(ConversionError::InvalidTimestamp)
}

/// A JavaScript `Date`'s millisecond count, as the `I64` it is stored as
/// under `Timestamp(Millis)`. Refused when it is not a whole number of
/// milliseconds (`Invalid Date` is NaN) or lies outside chrono's range.
pub(crate) fn date_millis(ms: f64) -> Result<Int, ConversionError> {
    if !ms.is_finite() || ms.fract() != 0.0 {
        return Err(ConversionError::InvalidTimestamp);
    }
    // `as` saturates, and anything that saturates is out of range anyway.
    let count = Int::I64(ms as i64);
    if Logical::Timestamp(TimeUnit::Millis).admits(&vitaminc_aead::Physical::Int(count)) {
        Ok(count)
    } else {
        Err(ConversionError::InvalidTimestamp)
    }
}

/// The millisecond count a stored timestamp has as a JavaScript `Date`, if
/// it is whole milliseconds. Every stored timestamp is inside chrono's
/// range, which is narrower than `Date`'s, so the count always fits.
pub(crate) fn timestamp_js_millis(unit: TimeUnit, count: Int) -> Option<f64> {
    let nanos = vitaminc_aead::plaintext::kinds::timestamp_nanos(unit, count)?;
    let millis = kinds_chrono::timestamp_count(TimeUnit::Millis, nanos)?;
    Some(millis as f64)
}

/// A stored timestamp as RFC 3339 text with nanoseconds, for the
/// `VcTimestamp` wrapper.
pub(crate) fn timestamp_text(unit: TimeUnit, count: Int) -> Option<String> {
    kinds_chrono::timestamp(unit, count)
        .map(|instant| instant.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
}

/// Fixed-point decimal text as a scale and mantissa.
pub(crate) fn decimal(text: &str) -> Result<(u8, Int), ConversionError> {
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
    // A negative zero parses as zero, which is what the leaf codec stores.
    let (scale, mantissa) = Decimal::from_str_exact(text)
        .map(kinds_decimal::parts)
        .map_err(|_| ConversionError::InvalidDecimal)?;
    Ok((scale, Int::I128(mantissa)))
}

/// A stored decimal as fixed-point text with its scale, for the `VcDecimal`
/// wrapper.
pub(crate) fn decimal_text(scale: u8, mantissa: Int) -> Option<String> {
    kinds_decimal::decimal(scale, mantissa).map(|value| value.to_string())
}

/// Hyphenated hexadecimal UUID text as its sixteen bytes. Case is accepted
/// either way; braces, URNs and other spellings are not.
pub(crate) fn uuid(text: &str) -> Result<[u8; 16], ConversionError> {
    let bytes = text.as_bytes();
    if bytes.len() != 36 || [8, 13, 18, 23].iter().any(|&i| bytes[i] != b'-') {
        return Err(ConversionError::InvalidUuid);
    }
    let mut out = [0u8; 16];
    let mut digits = bytes.iter().filter(|&&b| b != b'-');
    for byte in &mut out {
        let hi = digits.next().and_then(|&d| (d as char).to_digit(16));
        let lo = digits.next().and_then(|&d| (d as char).to_digit(16));
        match (hi, lo) {
            (Some(hi), Some(lo)) => *byte = (hi * 16 + lo) as u8,
            _ => return Err(ConversionError::InvalidUuid),
        }
    }
    Ok(out)
}

/// Sixteen bytes as lowercase hyphenated UUID text.
pub(crate) fn uuid_text(bytes: &[u8]) -> Option<String> {
    let bytes: &[u8; 16] = bytes.try_into().ok()?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_aead::plaintext::kinds::{MAX_TIMESTAMP_NANOS, MIN_TIMESTAMP_NANOS};

    fn width(int: Int) -> &'static str {
        match int {
            Int::I8(_) => "i8",
            Int::U8(_) => "u8",
            Int::I16(_) => "i16",
            Int::U16(_) => "u16",
            Int::I32(_) => "i32",
            Int::U32(_) => "u32",
            Int::I64(_) => "i64",
            Int::U64(_) => "u64",
            Int::I128(_) => "i128",
            Int::U128(_) => "u128",
        }
    }

    #[test]
    fn bigint_boundaries_choose_the_smallest_width() {
        let positive = [
            (0, "i8"),
            (127, "i8"),
            (128, "u8"),
            (255, "u8"),
            (256, "i16"),
            (32767, "i16"),
            (32768, "u16"),
            (65535, "u16"),
            (65536, "i32"),
            (i32::MAX as u128, "i32"),
            (i32::MAX as u128 + 1, "u32"),
            (u32::MAX as u128, "u32"),
            (u32::MAX as u128 + 1, "i64"),
            (i64::MAX as u128, "i64"),
            (i64::MAX as u128 + 1, "u64"),
            (u64::MAX as u128, "u64"),
            (u64::MAX as u128 + 1, "i128"),
            (i128::MAX as u128, "i128"),
            (i128::MAX as u128 + 1, "u128"),
            (u128::MAX, "u128"),
        ];
        for (value, expected) in positive {
            let words = [value as u64, (value >> 64) as u64];
            let int = bigint(false, &words).expect("in range");
            assert_eq!(width(int), expected, "{value}");
            assert_eq!(int.to_u128(), Some(value));
        }
        let negative = [
            (128u128, "i8"),
            (129, "i16"),
            (32768, "i16"),
            (32769, "i32"),
            (1 << 31, "i32"),
            ((1 << 31) + 1, "i64"),
            (1 << 63, "i64"),
            ((1 << 63) + 1, "i128"),
            (1 << 127, "i128"),
        ];
        for (magnitude, expected) in negative {
            let int =
                bigint(true, &[magnitude as u64, (magnitude >> 64) as u64]).expect("in range");
            assert_eq!(width(int), expected, "-{magnitude}");
            assert_eq!(int.to_i128(), Some((magnitude as i128).wrapping_neg()));
        }
        assert_eq!(bigint(true, &[0, 1 << 63]), Ok(Int::I128(i128::MIN)));
        assert_eq!(bigint(false, &[]), Ok(Int::I8(0)));
        assert_eq!(bigint(true, &[0]), Ok(Int::I8(0)), "negative zero");
        assert_eq!(
            bigint(false, &[1, 0, 0]),
            Ok(Int::I8(1)),
            "leading zero word"
        );
        assert_eq!(
            bigint(true, &[1, 1 << 63]),
            Err(ConversionError::IntegerRange)
        );
        assert_eq!(
            bigint(false, &[0, 0, 1]),
            Err(ConversionError::IntegerRange)
        );
    }

    #[test]
    fn dates_are_day_counts_and_round_trip_as_text() {
        assert_eq!(date("1970-01-01"), Ok(Int::I32(0)));
        assert_eq!(date("2024-02-29"), Ok(Int::I32(19782)));
        assert_eq!(date("0000-01-01"), Ok(Int::I32(-719_528)));
        for text in ["2024-02-29", "0000-01-01", "9999-12-31"] {
            assert_eq!(date_text(date(text).expect("valid")).as_deref(), Some(text));
        }
        for invalid in ["2023-02-29", "2024-2-9", "", "2024-01-01T00:00:00Z"] {
            assert_eq!(
                date(invalid),
                Err(ConversionError::InvalidDate),
                "{invalid}"
            );
        }
        assert_eq!(date_text(Int::I128(i128::MAX)), None);
    }

    #[test]
    fn timestamps_are_nanosecond_counts_and_refuse_leap_seconds() {
        assert_eq!(
            timestamp("1970-01-01T00:00:00.123Z"),
            Ok(Int::I64(123_000_000))
        );
        assert_eq!(
            timestamp("1969-12-31T23:59:59.999999999Z"),
            Ok(Int::I64(-1))
        );
        // ADR 0001 section 3: a leap second has no count and is refused.
        assert_eq!(
            timestamp("2016-12-31T23:59:60.123456789Z"),
            Err(ConversionError::InvalidTimestamp)
        );
        // Decryption spells years outside 0000-9999 in ISO 8601 expanded form;
        // each must parse back to the same count, in i128 when i64 is too narrow.
        for (text, expected_width) in [
            ("+12000-01-01T00:00:00.000000001Z", "i128"),
            ("-0005-03-01T12:00:00.000000001Z", "i128"),
            ("2262-04-11T23:47:16.854775807Z", "i64"),
            ("2262-04-11T23:47:16.854775808Z", "i128"),
        ] {
            let count = timestamp(text).expect("valid");
            assert_eq!(width(count), expected_width, "{text}");
            assert_eq!(
                timestamp_text(TimeUnit::Nanos, count).as_deref(),
                Some(text)
            );
        }
        assert!(matches!(
            timestamp("-0005-03-01T12:00:00+01:00"),
            Ok(count) if timestamp_text(TimeUnit::Nanos, count).as_deref()
                == Some("-0005-03-01T11:00:00.000000000Z")
        ));
        for invalid in [
            "+12000-01-01",
            "+12000-13-01T00:00:00Z",
            "-0005-03-01T12:00:00",
            "bad",
        ] {
            assert_eq!(
                timestamp(invalid),
                Err(ConversionError::InvalidTimestamp),
                "{invalid}"
            );
        }
    }

    #[test]
    fn a_js_date_is_its_millisecond_count() {
        assert_eq!(date_millis(-1.0), Ok(Int::I64(-1)));
        assert_eq!(date_millis(0.0), Ok(Int::I64(0)));
        assert_eq!(
            date_millis(1_700_000_000_000.0),
            Ok(Int::I64(1_700_000_000_000))
        );
        for invalid in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            0.5,
            // Inside `Date`'s range but outside chrono's.
            8_640_000_000_000_000.0,
            -8_640_000_000_000_000.0,
        ] {
            assert_eq!(
                date_millis(invalid),
                Err(ConversionError::InvalidTimestamp),
                "{invalid}"
            );
        }
    }

    #[test]
    fn a_stored_timestamp_is_a_js_date_only_when_it_is_whole_milliseconds() {
        assert_eq!(
            timestamp_js_millis(TimeUnit::Millis, Int::I64(123)),
            Some(123.0)
        );
        assert_eq!(
            timestamp_js_millis(TimeUnit::Nanos, Int::I64(123_000_000)),
            Some(123.0)
        );
        assert_eq!(
            timestamp_js_millis(TimeUnit::Micros, Int::I64(-1_000)),
            Some(-1.0)
        );
        // Sub-millisecond precision needs the wrapper.
        assert_eq!(timestamp_js_millis(TimeUnit::Nanos, Int::I64(-1)), None);
        assert_eq!(timestamp_js_millis(TimeUnit::Micros, Int::I64(1)), None);
        // chrono's whole range fits a `Date`: its limits are about ±8.2e15
        // milliseconds, inside `Date`'s ±8.64e15.
        for limit in [MIN_TIMESTAMP_NANOS, MAX_TIMESTAMP_NANOS] {
            let ms = timestamp_js_millis(TimeUnit::Millis, Int::I64((limit / 1_000_000) as i64))
                .expect("whole milliseconds at the bound");
            assert!(ms.abs() <= 8_640_000_000_000_000.0, "{ms}");
        }
        // Out of chrono's range entirely.
        assert_eq!(
            timestamp_js_millis(TimeUnit::Nanos, Int::I128(i128::MAX)),
            None
        );
        assert_eq!(timestamp_text(TimeUnit::Nanos, Int::I128(i128::MAX)), None);
    }

    #[test]
    fn decimals_are_exact_and_negative_zero_is_zero() {
        for text in ["NaN", "+nan", "-NaN", "inf", "+Infinity", "-Infinity"] {
            assert_eq!(
                decimal(text),
                Err(ConversionError::NonFiniteDecimal),
                "{text}"
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
                decimal(text),
                Err(ConversionError::InvalidDecimal),
                "{text}"
            );
        }
        assert_eq!(decimal("1.50"), Ok((2, Int::I128(150))));
        assert_eq!(decimal("+1.50"), Ok((2, Int::I128(150))));
        assert_eq!(decimal("-1.50"), Ok((2, Int::I128(-150))));
        // ADR 0001 section 3: a negative zero reads back as zero, scale kept.
        assert_eq!(decimal("-0.00"), Ok((2, Int::I128(0))));
        assert_eq!(decimal_text(2, Int::I128(0)).as_deref(), Some("0.00"));
        for text in [
            "1.50",
            "-79228162514264337593543950335",
            "0.0000000000000000000000000001",
        ] {
            let (scale, mantissa) = decimal(text).expect("valid");
            assert_eq!(decimal_text(scale, mantissa).as_deref(), Some(text));
        }
        assert_eq!(decimal_text(29, Int::I128(1)), None);
    }

    #[test]
    fn uuids_are_sixteen_bytes_in_hyphenated_hex() {
        let text = "123e4567-e89b-12d3-a456-426614174000";
        let bytes = uuid(text).expect("valid");
        assert_eq!(bytes[0..4], [0x12, 0x3e, 0x45, 0x67]);
        assert_eq!(uuid_text(&bytes).as_deref(), Some(text));
        assert_eq!(uuid(&text.to_uppercase()), Ok(bytes));
        for invalid in [
            "",
            "123e4567e89b12d3a456426614174000",
            "{123e4567-e89b-12d3-a456-426614174000}",
            "123e4567-e89b-12d3-a456-42661417400g",
            "123e4567-e89b-12d3-a456-4266141740000",
            "123e4567-e89b-12d3-a456-42661417400",
            "123e4567-e89b-12d3-a456-4266141740\u{e9}",
        ] {
            assert_eq!(
                uuid(invalid),
                Err(ConversionError::InvalidUuid),
                "{invalid:?}"
            );
        }
        assert_eq!(uuid_text(&[0; 15]), None);
    }

    #[test]
    fn every_error_has_a_stable_code_and_a_message() {
        for error in [
            ConversionError::IntegerRange,
            ConversionError::InvalidDate,
            ConversionError::InvalidTimestamp,
            ConversionError::InvalidDecimal,
            ConversionError::NonFiniteDecimal,
            ConversionError::InvalidUuid,
        ] {
            assert!(error.code().starts_with("ERR_"));
            assert!(!error.to_string().is_empty());
        }
    }
}
