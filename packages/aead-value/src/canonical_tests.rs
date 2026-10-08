use super::*;
use quickcheck_macros::quickcheck;

fn bytes(value: Value) -> Vec<u8> {
    equality_bytes(&value)
        .expect("valid test value")
        .risky_ref()
        .clone()
}

#[test]
fn unicode_version_and_equivalence_are_frozen() {
    assert_eq!(unicode_normalization::UNICODE_VERSION, (16, 0, 0));
    assert_eq!(unicode_general_category::UNICODE_VERSION, (16, 0, 0));
    assert_eq!(bytes(Value::String("e\u{301}".into())), "é".as_bytes());
    assert_ne!(
        bytes(Value::String("É".into())),
        bytes(Value::String("é".into()))
    );
    assert_ne!(
        bytes(Value::String("e".into())),
        bytes(Value::String("é".into()))
    );
    for text in ["\u{378}", "\u{10ffff}", "\u{1faea}"] {
        assert_eq!(
            text_nfc(text.as_bytes()).expect_err("unsupported input"),
            CanonicalError::UnassignedCodePoint
        );
    }
    assert_eq!(
        text_nfc(&[0xff]).expect_err("unsupported input"),
        CanonicalError::InvalidText
    );
    assert_eq!(
        text_nfc(b"a\0").expect("valid test value").risky_ref(),
        b"a\0"
    );
}

#[test]
fn every_non_scalar_is_explicitly_refused() {
    let cases = [
        (
            Value::Bool(false),
            CanonicalError::UnsupportedKind(ValueKind::Bool),
        ),
        (
            Value::Array(vec![]),
            CanonicalError::UnsupportedKind(ValueKind::Array),
        ),
        (
            Value::Object(vec![]),
            CanonicalError::UnsupportedKind(ValueKind::Object),
        ),
        (Value::Null, CanonicalError::UnsupportedValue),
        (Value::Undefined, CanonicalError::UnsupportedValue),
        (
            Value::Passthrough(Box::new(Value::Int32(1))),
            CanonicalError::UnsupportedValue,
        ),
    ];
    for (value, error) in cases {
        assert_eq!(
            equality_bytes(&value).expect_err("unsupported input"),
            error
        );
        assert!(!error.to_string().is_empty());
    }
    assert!(!CanonicalError::InvalidText.to_string().is_empty());
    assert!(!CanonicalError::UnassignedCodePoint.to_string().is_empty());
}

#[test]
fn floats_have_postgres_zero_and_nan_ordering() {
    assert_eq!(bytes(Value::Float64(-0.0)), bytes(Value::Float64(0.0)));
    assert_eq!(bytes(Value::Float32(-0.0)), bytes(Value::Float32(0.0)));
    for bits in [0x7fc0_0000, 0xff80_0001, 0xffff_ffff, 0x7f80_0001] {
        assert_eq!(
            bytes(Value::Float32(f32::from_bits(bits))),
            [0xff, 0xc0, 0, 0]
        );
    }
    for bits in [0x7ff8_0000_0000_0000, 0xfff0_0000_0000_0001, u64::MAX] {
        assert_eq!(
            bytes(Value::Float64(f64::from_bits(bits))),
            [0xff, 0xf8, 0, 0, 0, 0, 0, 0]
        );
    }
    let ascending = [f64::NEG_INFINITY, -1.0, 0.0, 1.0, f64::INFINITY, f64::NAN];
    for pair in ascending.windows(2) {
        assert!(bytes(Value::Float64(pair[0])) < bytes(Value::Float64(pair[1])));
    }
}

#[quickcheck]
fn f64_order_agrees_with_numeric_order(a: f64, b: f64) -> bool {
    a.is_nan()
        || b.is_nan()
        || bytes(Value::Float64(a)).cmp(&bytes(Value::Float64(b)))
            == a.partial_cmp(&b).expect("valid test value")
}

#[quickcheck]
fn f32_canonicalisation_is_idempotent(bits: u32) -> bool {
    let value = canonical_f32(f32::from_bits(bits));
    canonical_f32(value).to_bits() == value.to_bits()
}

#[quickcheck]
fn f64_canonicalisation_is_idempotent(bits: u64) -> bool {
    let value = canonical_f64(f64::from_bits(bits));
    canonical_f64(value).to_bits() == value.to_bits()
}

#[quickcheck]
fn nfc_is_idempotent(text: String) -> bool {
    match text_nfc(text.as_bytes()) {
        Ok(first) => {
            text_nfc(first.risky_ref())
                .expect("valid test value")
                .risky_ref()
                == first.risky_ref()
        }
        Err(_) => text
            .chars()
            .any(|c| get_general_category(c) == GeneralCategory::Unassigned),
    }
}

#[cfg(feature = "chrono")]
#[test]
fn timestamps_truncate_fractional_seconds_across_epoch_and_leap_seconds() {
    use chrono::{DateTime, Utc};
    for seconds in [-1, 0, 59] {
        let value =
            DateTime::<Utc>::from_timestamp(seconds, 123_456_789).expect("valid test value");
        let canonical =
            DateTime::<Utc>::from_timestamp(seconds, 123_456_000).expect("valid test value");
        assert_eq!(
            bytes(Value::Timestamp(value)),
            canonical.to_orderable_bytes()
        );
    }
    let leap = DateTime::<Utc>::from_timestamp(59, 1_123_456_789).expect("valid test value");
    let canonical = DateTime::<Utc>::from_timestamp(59, 1_123_456_000).expect("valid test value");
    assert_eq!(
        bytes(Value::Timestamp(leap)),
        canonical.to_orderable_bytes()
    );
    assert!(
        bytes(Value::Timestamp(leap))
            < bytes(Value::Timestamp(
                DateTime::from_timestamp(60, 0).expect("valid test value")
            ))
    );
    for value in [DateTime::<Utc>::MIN_UTC, DateTime::<Utc>::MAX_UTC] {
        assert_eq!(bytes(Value::Timestamp(value)).len(), 12);
    }
}

#[cfg(feature = "rust_decimal")]
#[test]
fn decimals_normalize_scale_and_signed_zero_without_touching_ciphertext() {
    use rust_decimal::Decimal;
    for spelling in ["1", "1.0", "1.00"] {
        let value = spelling.parse::<Decimal>().expect("valid test value");
        assert_eq!(
            bytes(Value::Decimal(value)),
            bytes(Value::Decimal(Decimal::ONE))
        );
    }
    assert_eq!(
        bytes(Value::Decimal("-0.00".parse().expect("valid test value"))),
        bytes(Value::Decimal(Decimal::ZERO))
    );
    assert!(bytes(Value::Decimal(Decimal::MIN)) < bytes(Value::Decimal(Decimal::MAX)));
}
