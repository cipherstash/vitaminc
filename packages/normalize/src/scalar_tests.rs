use super::*;
use orderable_bytes::OrderableBytes;
use quickcheck_macros::quickcheck;
use vitaminc_aead::UnknownLogical;

fn term(ty: Option<Logical>, v: Physical<'_>) -> Vec<u8> {
    normalize(ty, v)
        .expect("valid test value")
        .bytes
        .risky_ref()
        .clone()
}

fn int(ty: Option<Logical>, i: Int) -> Vec<u8> {
    term(ty, Physical::Int(i))
}

fn integer_bytes(sign: u8, word: u128) -> Vec<u8> {
    let mut expected = vec![sign];
    expected.extend_from_slice(&word.to_be_bytes());
    expected
}

#[test]
fn integers_share_one_domain_whatever_their_width() {
    let five = [
        Int::I8(5),
        Int::U8(5),
        Int::I16(5),
        Int::U16(5),
        Int::I32(5),
        Int::U32(5),
        Int::I64(5),
        Int::U64(5),
        Int::I128(5),
        Int::U128(5),
    ];
    for value in five {
        let n = normalize(None, Physical::Int(value)).expect("int");
        assert_eq!(n.domain, domain::INTEGER);
        assert_eq!(n.bytes.risky_ref(), &integer_bytes(1, 5));
    }
    for value in [
        Int::I8(-7),
        Int::I16(-7),
        Int::I32(-7),
        Int::I64(-7),
        Int::I128(-7),
    ] {
        assert_eq!(int(None, value), integer_bytes(0, -7i128 as u128));
    }
    assert_eq!(int(None, Int::I128(i128::MIN)), integer_bytes(0, 1 << 127));
    assert_eq!(int(None, Int::I128(-1)), integer_bytes(0, u128::MAX));
    assert_eq!(int(None, Int::I128(0)), integer_bytes(1, 0));
    assert_eq!(int(None, Int::U128(u128::MAX)), integer_bytes(1, u128::MAX));
    let ascending = [
        Int::I128(i128::MIN),
        Int::I64(i64::MIN),
        Int::I8(-1),
        Int::U8(0),
        Int::I8(i8::MAX),
        Int::U64(u64::MAX),
        Int::I128(i128::MAX),
        Int::U128(u128::MAX),
    ];
    for pair in ascending.windows(2) {
        assert!(int(None, pair[0]) < int(None, pair[1]));
    }
}

#[quickcheck]
fn signed_and_unsigned_integers_agree_when_equal(value: u64) -> bool {
    int(None, Int::U64(value)) == int(None, Int::I128(value.into()))
        && int(None, Int::U128(value.into())) == int(None, Int::I128(value.into()))
}

#[quickcheck]
fn integer_order_agrees_with_numeric_order(a: i64, b: u64) -> bool {
    let (wide_a, wide_b) = (i128::from(a), i128::from(b));
    int(None, Int::I64(a)).cmp(&int(None, Int::U64(b))) == wide_a.cmp(&wide_b)
        && int(None, Int::I128(wide_a * wide_b)).cmp(&int(None, Int::I64(a)))
            == (wide_a * wide_b).cmp(&wide_a)
}

#[test]
fn the_opt_in_table_names_every_domain_and_nothing_else() {
    let one = Physical::Int(Int::I32(1));
    assert_eq!(domain_of(None, &one), Some(domain::INTEGER));
    assert_eq!(
        domain_of(None, &Physical::Float(Float::F32(1.0))),
        Some(domain::FLOAT)
    );
    assert_eq!(domain_of(None, &Physical::Text("a")), Some(domain::TEXT));
    assert_eq!(domain_of(None, &Physical::Bytes(&[1])), Some(domain::BYTES));
    assert_eq!(domain_of(Some(Logical::Date), &one), Some(domain::DATE));
    assert_eq!(
        domain_of(Some(Logical::Timestamp(TimeUnit::Millis)), &one),
        Some(domain::TIMESTAMP)
    );
    assert_eq!(
        domain_of(Some(Logical::Decimal { scale: 2 }), &one),
        Some(domain::DECIMAL)
    );
    assert_eq!(
        domain_of(Some(Logical::Uuid), &Physical::Bytes(&[0; 16])),
        Some(domain::UUID)
    );
    assert_eq!(domain_of(None, &Physical::Null), None);
    assert_eq!(domain_of(None, &Physical::Bool(true)), None);
    assert_eq!(domain_of(Some(Logical::Undefined), &Physical::Null), None);
    let unknown = Logical::from_wire(200, 1).expect("unknown");
    assert!(matches!(unknown, Logical::Unknown(UnknownLogical { .. })));
    assert_eq!(domain_of(Some(unknown), &one), None);
    assert_eq!(domain::ALL.len(), 8);
    for label in domain::ALL {
        assert!(label.starts_with("vitaminc/prf/value/"), "{label}");
    }
}

#[test]
fn a_scalar_with_no_domain_is_refused_with_no_domain() {
    let unknown = Logical::from_wire(200, 1).expect("unknown");
    for (ty, v) in [
        (None, Physical::Null),
        (None, Physical::Bool(false)),
        (Some(Logical::Undefined), Physical::Null),
        (Some(unknown), Physical::Int(Int::I32(1))),
        (Some(unknown), Physical::Text("x")),
    ] {
        assert_eq!(
            normalize(ty, v).expect_err("no term"),
            NormalizeError::NoDomain
        );
    }
    for error in [
        NormalizeError::NoDomain,
        NormalizeError::Invalid,
        NormalizeError::UnassignedCodePoint,
    ] {
        assert!(!error.to_string().is_empty());
    }
}

#[test]
fn a_value_that_does_not_fit_its_logical_type_is_invalid() {
    for (ty, v) in [
        (Logical::Date, Physical::Text("2024-01-01")),
        (Logical::Date, Physical::Int(Int::I64(i64::MAX))),
        (
            Logical::Timestamp(TimeUnit::Nanos),
            Physical::Int(Int::I128(i128::MAX)),
        ),
        (Logical::Decimal { scale: 29 }, Physical::Int(Int::I32(1))),
        (
            Logical::Decimal { scale: 1 },
            Physical::Int(Int::I128(1 << 100)),
        ),
        (Logical::Uuid, Physical::Bytes(&[0; 15])),
        (Logical::Uuid, Physical::Int(Int::I32(1))),
    ] {
        assert_eq!(
            normalize(Some(ty), v).expect_err("invalid"),
            NormalizeError::Invalid
        );
    }
    // `undefined` over anything but a null is a value that does not fit
    // its type, not one with nothing to index.
    assert_eq!(
        normalize(Some(Logical::Undefined), Physical::Int(Int::I32(1))).expect_err("invalid"),
        NormalizeError::Invalid
    );
    // The encoders say the same without going through `admits`, one day
    // past chrono's range on either side included.
    assert!(date(Int::I64(i64::MAX)).is_none());
    assert!(date(Int::I32(MAX_DATE_DAYS + 1)).is_none());
    assert!(date(Int::I32(MIN_DATE_DAYS - 1)).is_none());
    assert!(date(Int::I32(MAX_DATE_DAYS)).is_some());
    assert!(date(Int::I32(MIN_DATE_DAYS)).is_some());
    for days in [MAX_DATE_DAYS + 1, MIN_DATE_DAYS - 1] {
        assert_eq!(
            normalize(Some(Logical::Date), Physical::Int(Int::I32(days))).expect_err("invalid"),
            NormalizeError::Invalid
        );
    }
    assert!(timestamp(TimeUnit::Nanos, Int::I128(i128::MAX)).is_none());
    assert!(decimal(29, Int::I32(1)).is_none());
    assert!(decimal(1, Int::U128(u128::MAX)).is_none());
    assert!(uuid(&[0; 15]).is_none());
}

#[test]
fn a_logical_value_never_shares_a_term_with_its_physical_value() {
    let days = Int::I32(19_000);
    assert_ne!(int(Some(Logical::Date), days), int(None, days));
    let count = Int::I64(1_700_000_000_000);
    assert_ne!(
        int(Some(Logical::Timestamp(TimeUnit::Millis)), count),
        int(None, count)
    );
    let mantissa = Int::I128(150);
    assert_ne!(
        int(Some(Logical::Decimal { scale: 2 }), mantissa),
        int(None, mantissa)
    );
    // A uuid is its sixteen bytes, so the domain alone keeps it apart from
    // the same bytes written as bytes.
    let id = [5u8; 16];
    assert_eq!(uuid(&id).expect("uuid").risky_ref(), bytes(&id).risky_ref());
    assert_ne!(
        normalize(Some(Logical::Uuid), Physical::Bytes(&id))
            .expect("uuid")
            .domain,
        normalize(None, Physical::Bytes(&id)).expect("bytes").domain
    );
}

#[test]
fn dates_are_orderable_days_from_the_common_era() {
    // 0001-01-01 is day 1 from CE; 1970-01-01 is day 719163.
    assert_eq!(
        int(Some(Logical::Date), Int::I32(1 - EPOCH_DAYS_FROM_CE)),
        [0x80, 0x00, 0x00, 0x01]
    );
    assert_eq!(
        int(Some(Logical::Date), Int::I32(0)),
        ((EPOCH_DAYS_FROM_CE as u32) ^ (1 << 31)).to_be_bytes()
    );
    assert!(int(Some(Logical::Date), Int::I32(-1)) < int(Some(Logical::Date), Int::I32(0)));
    assert!(int(Some(Logical::Date), Int::I32(0)) < int(Some(Logical::Date), Int::I32(1)));
}

#[test]
fn timestamps_in_any_unit_truncate_to_microseconds() {
    let nanos = Int::I128(1_700_000_000_123_456_789);
    let micros = Int::I64(1_700_000_000_123_456);
    let millis = Int::I64(1_700_000_000_123);
    let seconds = Int::I64(1_700_000_000);
    let by = |unit, count| int(Some(Logical::Timestamp(unit)), count);
    assert_eq!(by(TimeUnit::Nanos, nanos), by(TimeUnit::Micros, micros));
    assert_eq!(
        by(TimeUnit::Millis, millis),
        by(TimeUnit::Micros, Int::I64(1_700_000_000_123_000))
    );
    assert_eq!(
        by(TimeUnit::Seconds, seconds),
        by(TimeUnit::Nanos, Int::I128(1_700_000_000_000_000_000))
    );
    let mut expected = ((1_700_000_000u64) ^ (1 << 63)).to_be_bytes().to_vec();
    expected.extend_from_slice(&123_456_000u32.to_be_bytes());
    assert_eq!(by(TimeUnit::Nanos, nanos), expected);
    // Before the epoch the seconds floor and the fraction stays positive.
    let before = by(TimeUnit::Nanos, Int::I128(-1_000_000_000 + 123_456_789));
    let mut expected = ((-1i64 as u64) ^ (1 << 63)).to_be_bytes().to_vec();
    expected.extend_from_slice(&123_456_000u32.to_be_bytes());
    assert_eq!(before, expected);
    assert!(before < by(TimeUnit::Seconds, Int::I64(0)));
}

#[test]
fn decimals_normalize_scale_and_signed_zero() {
    let by = |scale, mantissa| int(Some(Logical::Decimal { scale }), Int::I128(mantissa));
    assert_eq!(by(0, 1), by(1, 10));
    assert_eq!(by(0, 1), by(2, 100));
    assert_eq!(by(2, 150), by(1, 15));
    assert_eq!(by(2, 0), by(0, 0));
    assert_eq!(by(0, -0), by(0, 0));
    assert!(by(0, -1) < by(0, 0));
    assert!(by(0, 0) < by(0, 1));
    assert!(by(2, 150) < by(0, 2));
}

#[test]
fn nfc_expansion_fills_an_exactly_sized_buffer() {
    // U+0344 is two UTF-8 bytes; its NFC form U+0308 U+0301 is four.
    let normalized = text("\u{344}").expect("valid test value");
    assert_eq!(normalized.risky_ref(), "\u{308}\u{301}".as_bytes());
    assert_eq!(normalized.risky_ref().capacity(), 4);
}

#[test]
fn unicode_version_and_equivalence_are_frozen() {
    // Normalization stability makes newer NFC tables safe for text that is
    // assigned in Unicode 16; the assignment table is the exact pin.
    assert!(unicode_normalization::UNICODE_VERSION >= (16, 0, 0));
    assert_eq!(unicode_general_category::UNICODE_VERSION, (16, 0, 0));
    assert_eq!(term(None, Physical::Text("e\u{301}")), "é".as_bytes());
    assert_ne!(
        term(None, Physical::Text("É")),
        term(None, Physical::Text("é"))
    );
    assert_ne!(
        term(None, Physical::Text("e")),
        term(None, Physical::Text("é"))
    );
    for s in ["\u{378}", "\u{10ffff}", "\u{1faea}"] {
        assert_eq!(
            normalize(None, Physical::Text(s)).expect_err("unsupported input"),
            NormalizeError::UnassignedCodePoint
        );
    }
    assert_eq!(text("a\0").expect("valid test value").risky_ref(), b"a\0");
}

#[quickcheck]
fn nfc_is_idempotent(s: String) -> bool {
    match text(&s) {
        Ok(first) => {
            let first = String::from_utf8(first.risky_ref().clone()).expect("utf-8");
            text(&first).expect("valid test value").risky_ref() == first.as_bytes()
        }
        Err(_) => s
            .chars()
            .any(|c| get_general_category(c) == GeneralCategory::Unassigned),
    }
}

fn f32_term(v: f32) -> Vec<u8> {
    term(None, Physical::Float(Float::F32(v)))
}

fn f64_term(v: f64) -> Vec<u8> {
    term(None, Physical::Float(Float::F64(v)))
}

#[test]
fn floats_have_postgres_zero_and_nan_ordering() {
    assert_eq!(f64_term(-0.0), f64_term(0.0));
    assert_eq!(f32_term(-0.0), f64_term(0.0));
    for bits in [0x7fc0_0000, 0xff80_0001, 0xffff_ffff, 0x7f80_0001] {
        assert_eq!(
            f32_term(f32::from_bits(bits)),
            [0xff, 0xf8, 0, 0, 0, 0, 0, 0]
        );
    }
    for bits in [0x7ff8_0000_0000_0000, 0xfff0_0000_0000_0001, u64::MAX] {
        assert_eq!(
            f64_term(f64::from_bits(bits)),
            [0xff, 0xf8, 0, 0, 0, 0, 0, 0]
        );
    }
    assert_eq!(f32_term(1.5), [0xbf, 0xf8, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        f32_term(-1.5),
        [0x40, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
    assert_eq!(f32_term(f32::INFINITY), [0xff, 0xf0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        f32_term(f32::NEG_INFINITY),
        [0, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
    let ascending = [f64::NEG_INFINITY, -1.0, 0.0, 1.0, f64::INFINITY, f64::NAN];
    for pair in ascending.windows(2) {
        assert!(f64_term(pair[0]) < f64_term(pair[1]));
    }
}

#[quickcheck]
fn f64_order_agrees_with_numeric_order(a: f64, b: f64) -> bool {
    a.is_nan()
        || b.is_nan()
        || f64_term(a).cmp(&f64_term(b)) == a.partial_cmp(&b).expect("valid test value")
}

#[test]
fn float_widths_share_one_domain_for_equal_numbers() {
    for value in [
        0.0f32,
        1.5,
        -0.25,
        16_777_216.0,
        f32::MAX,
        f32::MIN_POSITIVE,
    ] {
        assert_eq!(f32_term(value), f64_term(value.into()));
    }
    // 0.1 is a different number in each width, so the terms differ.
    assert_ne!(f32_term(0.1), f64_term(0.1));
}

fn widen_matches_hardware(bits: u32) -> bool {
    let value = f32::from_bits(bits);
    let (ours, hardware) = (widen_f32(value), f64::from(value));
    // NaN payload bits are folded later; only NaN-ness must agree for them.
    if value.is_nan() {
        ours.is_nan() && ours.is_sign_negative() == hardware.is_sign_negative()
    } else {
        ours.to_bits() == hardware.to_bits()
    }
}

#[test]
fn widening_matches_hardware_at_every_exponent_and_subnormal_bit() {
    for sign in [0, 1u32 << 31] {
        for exponent in 0..=0xffu32 {
            for mantissa in [0, 1, 0x40_0000, 0x7f_ffff, 0x2a_aaaa] {
                let bits = sign | (exponent << 23) | mantissa;
                assert!(widen_matches_hardware(bits), "{bits:#010x}");
            }
        }
        for shift in 0..23 {
            let bits = sign | 1 << shift;
            assert!(widen_matches_hardware(bits), "{bits:#010x}");
            assert!(
                widen_matches_hardware(bits | ((1 << shift) - 1)),
                "{bits:#010x}"
            );
        }
    }
}

#[quickcheck]
fn widening_matches_hardware_conversion(bits: u32) -> bool {
    widen_matches_hardware(bits)
}

/// Every f32 bit pattern; slow in debug builds, so run on demand with
/// `cargo test --release -p vitaminc-normalize -- --ignored`.
#[test]
#[ignore]
fn widening_matches_hardware_for_every_f32() {
    assert!((0..=u32::MAX).all(widen_matches_hardware));
}

#[quickcheck]
fn f64_canonicalisation_is_idempotent(bits: u64) -> bool {
    let value = canonical_f64(f64::from_bits(bits));
    canonical_f64(value).to_bits() == value.to_bits()
}

/// Whether `bytes` holds exactly `expected`, compared inside the
/// protected value with `zip_ref` so the encoding never leaves its
/// wrapper. Only the answer, which is not secret, is taken out.
fn holds(bytes: &Protected<Vec<u8>>, expected: &[u8]) -> bool {
    Protected::new(expected.to_vec())
        .zip_ref(bytes, |expected, bytes: &Vec<u8>| *bytes == expected)
        .risky_unwrap()
}

mod given_any_canonical_f64 {
    use super::*;

    #[quickcheck]
    fn returns_the_bytes_orderable_bytes_gives(bits: u64) -> bool {
        let value = canonical_f64(f64::from_bits(bits));
        holds(&orderable_f64(value), &value.to_orderable_bytes())
    }
}

#[test]
fn timestamps_one_past_chronos_range_are_invalid() {
    use vitaminc_aead::plaintext::kinds::{MAX_TIMESTAMP_NANOS, MIN_TIMESTAMP_NANOS};
    let ns = Logical::Timestamp(TimeUnit::Nanos);
    assert!(timestamp(TimeUnit::Nanos, Int::I128(MAX_TIMESTAMP_NANOS)).is_some());
    assert!(timestamp(TimeUnit::Nanos, Int::I128(MIN_TIMESTAMP_NANOS)).is_some());
    for nanos in [MAX_TIMESTAMP_NANOS + 1, MIN_TIMESTAMP_NANOS - 1] {
        assert!(timestamp(TimeUnit::Nanos, Int::I128(nanos)).is_none());
        assert_eq!(
            normalize(Some(ns), Physical::Int(Int::I128(nanos))).expect_err("invalid"),
            NormalizeError::Invalid
        );
    }
}

/// Whether `bytes` holds exactly `len` bytes in a buffer with room for
/// exactly `len`, checked inside the protected value with `zip_ref` so
/// the encoding never leaves its wrapper. Only the answer, which is not
/// secret, is taken out.
fn fills_exactly(bytes: &Protected<Vec<u8>>, len: usize) -> bool {
    Protected::new(len)
        .zip_ref(bytes, |len, bytes: &Vec<u8>| {
            bytes.len() == len && bytes.capacity() == len
        })
        .risky_unwrap()
}

/// A `Vec` that grows frees its old buffer without wiping it, and spare
/// capacity is a sign the buffer was not made at its final size. So every
/// fixed-width encoder must return a buffer whose length is its capacity.
mod given_a_fixed_width_encoder {
    use super::*;

    #[test]
    fn returns_a_buffer_with_no_spare_capacity() {
        for value in [Int::I8(-1), Int::U128(u128::MAX), Int::I128(i128::MIN)] {
            assert!(fills_exactly(&integer(value), 17), "integer {value:?}");
        }
        for value in [Float::F32(-1.5), Float::F64(f64::MAX), Float::F64(f64::NAN)] {
            assert!(fills_exactly(&float(value), 8), "float {value:?}");
        }
        for days in [Int::I32(-1), Int::I32(0), Int::I32(20_000)] {
            let bytes = date(days).expect("in range");
            assert!(fills_exactly(&bytes, 4), "date {days:?}");
        }
        for count in [Int::I64(-1), Int::I64(1_700_000_000_123)] {
            let bytes = timestamp(TimeUnit::Millis, count).expect("in range");
            assert!(fills_exactly(&bytes, 12), "timestamp {count:?}");
        }
        for (scale, mantissa) in [(0, Int::I64(0)), (2, Int::I64(-12_345)), (28, Int::I128(1))] {
            let bytes = decimal(scale, mantissa).expect("in range");
            assert!(
                fills_exactly(&bytes, 14),
                "decimal {mantissa:?} at scale {scale}"
            );
        }
    }
}

#[test]
fn debug_output_does_not_show_the_normalized_bytes() {
    let n = normalize(None, Physical::Text("secret")).expect("text");
    let v = format!("{n:?}");
    assert!(v.contains(domain::TEXT), "{v}");
    assert!(v.contains("***"), "{v}");
    // "secret" as a `Vec<u8>` would print as [115, 101, 99, ...].
    assert!(!v.contains("secret") && !v.contains("115, 101, 99"), "{v}");
}

/// The widths an `i16` fits, each holding `n`.
fn every_width(n: i16) -> Vec<Int> {
    let mut widths = vec![
        Int::I16(n),
        Int::I32(n.into()),
        Int::I64(n.into()),
        Int::I128(n.into()),
    ];
    if let Ok(v) = i8::try_from(n) {
        widths.push(Int::I8(v));
    }
    if let Ok(v) = u16::try_from(n) {
        widths.extend([
            Int::U16(v),
            Int::U32(v.into()),
            Int::U64(v.into()),
            Int::U128(v.into()),
        ]);
    }
    if let Ok(v) = u8::try_from(n) {
        widths.push(Int::U8(v));
    }
    widths
}

/// A logical term is over the number, not the width that carried it, as
/// the plain integer term is.
#[quickcheck]
fn a_logical_term_is_the_same_at_every_integer_width(n: i16) -> bool {
    [
        Logical::Date,
        Logical::Timestamp(TimeUnit::Seconds),
        Logical::Decimal { scale: 2 },
    ]
    .into_iter()
    .all(|ty| {
        let widths = every_width(n);
        let first = int(Some(ty), widths[0]);
        widths.iter().all(|&w| int(Some(ty), w) == first)
    })
}

/// The 96-bit check is the only one between a direct caller and the
/// encoder, which would otherwise drop a mantissa's top bits and give it
/// the term of another value.
#[test]
fn decimal_refuses_a_mantissa_outside_96_bits_by_itself() {
    let limit = 1i128 << 96;
    assert!(
        decimal(0, Int::I128(limit - 1)).is_some(),
        "the largest mantissa"
    );
    assert!(
        decimal(0, Int::I128(1 - limit)).is_some(),
        "the smallest mantissa"
    );
    assert!(
        decimal(0, Int::I128(limit)).is_none(),
        "one past the largest"
    );
    assert!(
        decimal(0, Int::I128(-limit)).is_none(),
        "one past the smallest"
    );
    assert!(
        decimal(5, Int::I128((1i128 << 104) + 10i128.pow(28))).is_none(),
        "above 104 bits this would take the term of 10^23"
    );
    assert!(decimal(0, Int::I128(i128::MAX)).is_none());
    assert!(decimal(0, Int::I128(i128::MIN)).is_none());
}
