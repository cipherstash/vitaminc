use super::*;
use quickcheck_macros::quickcheck;

fn bytes(value: Value) -> Vec<u8> {
    equality_input(&value)
        .expect("valid test value")
        .bytes
        .risky_ref()
        .clone()
}

fn integer_bytes(sign: u8, word: u128) -> Vec<u8> {
    let mut expected = vec![sign];
    expected.extend_from_slice(&word.to_be_bytes());
    expected
}

#[test]
fn integers_share_one_domain_whatever_their_width() {
    let five = [
        Value::Int8(5),
        Value::UInt8(5),
        Value::Int16(5),
        Value::UInt16(5),
        Value::Int32(5),
        Value::UInt32(5),
        Value::Int64(5),
        Value::UInt64(5),
        Value::Int128(5),
        Value::UInt128(5),
    ];
    for value in five {
        assert_eq!(bytes(value), integer_bytes(1, 5));
    }
    let minus_seven = [
        Value::Int8(-7),
        Value::Int16(-7),
        Value::Int32(-7),
        Value::Int64(-7),
        Value::Int128(-7),
    ];
    for value in minus_seven {
        assert_eq!(bytes(value), integer_bytes(0, -7i128 as u128));
    }
    assert_eq!(bytes(Value::Int128(i128::MIN)), integer_bytes(0, 1 << 127));
    assert_eq!(bytes(Value::Int128(-1)), integer_bytes(0, u128::MAX));
    assert_eq!(bytes(Value::Int128(0)), integer_bytes(1, 0));
    assert_eq!(
        bytes(Value::UInt128(u128::MAX)),
        integer_bytes(1, u128::MAX)
    );
    let ascending = [
        Value::Int128(i128::MIN),
        Value::Int64(i64::MIN),
        Value::Int8(-1),
        Value::UInt8(0),
        Value::Int8(i8::MAX),
        Value::UInt64(u64::MAX),
        Value::Int128(i128::MAX),
        Value::UInt128(u128::MAX),
    ];
    for pair in ascending.windows(2) {
        assert!(bytes(pair[0].clone()) < bytes(pair[1].clone()));
    }
}

#[quickcheck]
fn signed_and_unsigned_integers_agree_when_equal(value: u64) -> bool {
    bytes(Value::UInt64(value)) == bytes(Value::Int128(value.into()))
        && bytes(Value::UInt128(value.into())) == bytes(Value::Int128(value.into()))
}

#[quickcheck]
fn integer_order_agrees_with_numeric_order(a: i64, b: u64) -> bool {
    let (wide_a, wide_b) = (i128::from(a), i128::from(b));
    bytes(Value::Int64(a)).cmp(&bytes(Value::UInt64(b))) == wide_a.cmp(&wide_b)
        && bytes(Value::Int128(wide_a * wide_b)).cmp(&bytes(Value::Int64(a)))
            == (wide_a * wide_b).cmp(&wide_a)
}

#[test]
fn every_value_reports_its_kinds_domain() {
    #[allow(unused_mut)] // optional features extend the list
    let mut values = vec![
        Value::Int8(1),
        Value::UInt8(1),
        Value::Int16(1),
        Value::UInt16(1),
        Value::Int32(1),
        Value::UInt32(1),
        Value::Int64(1),
        Value::UInt64(1),
        Value::Int128(1),
        Value::UInt128(1),
        Value::Float32(1.0),
        Value::Float64(1.0),
        Value::String("a".into()),
        Value::Bytes(Protected::new(vec![1])),
    ];
    #[cfg(feature = "chrono")]
    values.extend([
        Value::Date(chrono::NaiveDate::MIN),
        Value::Timestamp(chrono::DateTime::UNIX_EPOCH),
    ]);
    #[cfg(feature = "rust_decimal")]
    values.push(Value::Decimal(rust_decimal::Decimal::ONE));
    for value in values {
        let kind = value.kind().expect("scalar");
        let input = equality_input(&value).expect("valid test value");
        assert_eq!(Some(input.domain), equality_domain(kind), "{kind}");
    }
    for &kind in ValueKind::ALL {
        let refused = matches!(kind, ValueKind::Bool | ValueKind::Array | ValueKind::Object);
        assert_eq!(equality_domain(kind).is_none(), refused, "{kind}");
    }
}

#[test]
fn nfc_expansion_fills_an_exactly_sized_buffer() {
    // U+0344 is two UTF-8 bytes; its NFC form U+0308 U+0301 is four.
    let normalized = text_nfc("\u{344}".as_bytes()).expect("valid test value");
    assert_eq!(normalized.risky_ref(), "\u{308}\u{301}".as_bytes());
    assert_eq!(normalized.risky_ref().capacity(), 4);
}

#[test]
fn unicode_version_and_equivalence_are_frozen() {
    // Normalization stability makes newer NFC tables safe for text that is
    // assigned in Unicode 16; the assignment table is the exact pin.
    assert!(unicode_normalization::UNICODE_VERSION >= (16, 0, 0));
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
            equality_input(&value).expect_err("unsupported input"),
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
    assert_eq!(bytes(Value::Float32(1.5)), [0xbf, 0xc0, 0, 0]);
    assert_eq!(bytes(Value::Float32(-1.5)), [0x40, 0x3f, 0xff, 0xff]);
    assert_eq!(bytes(Value::Float32(f32::INFINITY)), [0xff, 0x80, 0, 0]);
    assert_eq!(
        bytes(Value::Float32(f32::NEG_INFINITY)),
        [0, 0x7f, 0xff, 0xff]
    );
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
