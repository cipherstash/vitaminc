use super::*;
use quickcheck_macros::quickcheck;
use vitaminc_aead::{Float, TimeUnit};
use vitaminc_normalize::normalize;

use OrderTarget as T;

fn term(target: OrderTarget, ty: Option<Logical>, v: Physical<'_>) -> OrderPlaintext {
    order(target, ty, v).expect("valid test value")
}

fn bytes(target: OrderTarget, ty: Option<Logical>, v: Physical<'_>) -> Vec<u8> {
    term(target, ty, v).bytes().risky_ref().clone()
}

fn int_bytes(target: OrderTarget, i: Int) -> Vec<u8> {
    bytes(target, None, Physical::Int(i))
}

/// Every integer width of the data model, holding `v`.
fn every_width(v: u8) -> [Int; 10] {
    [
        Int::I8(v as i8),
        Int::U8(v),
        Int::I16(v.into()),
        Int::U16(v.into()),
        Int::I32(v.into()),
        Int::U32(v.into()),
        Int::I64(v.into()),
        Int::U64(v.into()),
        Int::I128(v.into()),
        Int::U128(v.into()),
    ]
}

const INT_TARGETS: [(OrderTarget, &str, usize); 8] = [
    (T::I16, domain::INT16, 2),
    (T::U16, domain::UINT16, 2),
    (T::I32, domain::INT32, 4),
    (T::U32, domain::UINT32, 4),
    (T::I64, domain::INT64, 8),
    (T::U64, domain::UINT64, 8),
    (T::I128, domain::INT128, 16),
    (T::U128, domain::UINT128, 16),
];

#[test]
fn every_integer_target_has_its_own_domain_and_width_whatever_the_value_arrives_as() {
    for (target, expected_domain, width) in INT_TARGETS {
        let first = term(target, None, Physical::Int(Int::I8(5)));
        assert_eq!(first.domain(), expected_domain, "{target:?}");
        assert_eq!(first.bytes().risky_ref().len(), width, "{target:?}");
        // 5 at every width is one term of the target.
        for value in every_width(5) {
            assert_eq!(
                int_bytes(target, value),
                first.bytes().risky_ref().clone(),
                "{value:?} as {target:?}"
            );
        }
    }
}

/// The JavaScript host hands each BigInt over at the narrowest width that
/// holds it, so one column sees many widths. They all widen to the
/// column's target and compare there.
#[test]
fn narrowest_width_bigints_compare_in_one_column() {
    let as_i32 = |i: Int| term(T::I32, None, Physical::Int(i));
    let (hundred, two_hundred, three_hundred) = (
        as_i32(Int::I8(100)),
        as_i32(Int::U8(200)),
        as_i32(Int::I16(300)),
    );
    for t in [&hundred, &two_hundred, &three_hundred] {
        assert_eq!(t.domain(), domain::INT32);
    }
    assert!(hundred.bytes().risky_ref() < two_hundred.bytes().risky_ref());
    assert!(two_hundred.bytes().risky_ref() < three_hundred.bytes().risky_ref());
}

#[test]
fn an_integer_outside_the_target_is_refused_not_truncated() {
    let refused = |target, i| {
        assert_eq!(
            order(target, None, Physical::Int(i)).err(),
            Some(NormalizeError::OutOfRange),
            "{i:?} as {target:?}"
        );
    };
    refused(T::I32, Int::I64(i64::from(i32::MAX) + 1));
    refused(T::I32, Int::I64(i64::from(i32::MIN) - 1));
    refused(T::I32, Int::U32(u32::MAX));
    refused(T::U32, Int::I8(-1));
    refused(T::U16, Int::U32(65_536));
    refused(T::I16, Int::U16(32_768));
    refused(T::I64, Int::U64(u64::MAX));
    refused(T::I128, Int::U128(u128::MAX));
    refused(T::U128, Int::I128(-1));
    // The edges themselves fit.
    for (target, i) in [
        (T::I32, Int::I64(i32::MAX.into())),
        (T::I32, Int::I64(i32::MIN.into())),
        (T::U16, Int::U32(65_535)),
        (T::I16, Int::I128(-32_768)),
        (T::U128, Int::U128(u128::MAX)),
        (T::I128, Int::I128(i128::MIN)),
    ] {
        assert!(
            order(target, None, Physical::Int(i)).is_ok(),
            "{i:?} as {target:?}"
        );
    }
}

#[test]
fn integers_are_big_endian_with_the_sign_bit_flipped() {
    assert_eq!(int_bytes(T::I16, Int::I16(-1)), [0x7f, 0xff]);
    assert_eq!(int_bytes(T::I16, Int::I16(0)), [0x80, 0x00]);
    assert_eq!(int_bytes(T::I16, Int::I16(i16::MIN)), [0x00, 0x00]);
    assert_eq!(int_bytes(T::I16, Int::I16(i16::MAX)), [0xff, 0xff]);
    assert_eq!(int_bytes(T::U16, Int::U16(0)), [0x00, 0x00]);
    assert_eq!(int_bytes(T::U16, Int::U16(255)), [0x00, 0xff]);
    // An 8-bit value goes into a wider target at the target's width.
    assert_eq!(int_bytes(T::I16, Int::I8(-1)), [0x7f, 0xff]);
    assert_eq!(int_bytes(T::U16, Int::U8(255)), [0x00, 0xff]);
    assert_eq!(int_bytes(T::I32, Int::I32(-2)), [0x7f, 0xff, 0xff, 0xfe]);
    assert_eq!(int_bytes(T::I32, Int::I8(-2)), [0x7f, 0xff, 0xff, 0xfe]);
    assert_eq!(int_bytes(T::U32, Int::U32(1)), [0, 0, 0, 1]);
    assert_eq!(int_bytes(T::I64, Int::I64(i64::MIN)), [0; 8]);
    let mut max = [0xff; 16];
    max[0] = 0x7f;
    assert_eq!(int_bytes(T::U128, Int::U128(u128::MAX)), [0xff; 16]);
    assert_eq!(int_bytes(T::I128, Int::I128(i128::MAX)), [0xff; 16]);
    assert_eq!(int_bytes(T::I128, Int::I128(-1)), max);
}

#[test]
fn a_float_is_its_equality_bytes_and_an_f32_widens_exactly() {
    let f64_bytes = |f: f64| bytes(T::F64, None, Physical::Float(Float::F64(f)));
    let f32_bytes = |f: f32| bytes(T::F64, None, Physical::Float(Float::F32(f)));
    assert_eq!(
        term(T::F64, None, Physical::Float(Float::F32(1.5))).domain(),
        domain::FLOAT64
    );
    for f in [0.0, -0.0, 1.5, -2.25, f64::NAN, f64::INFINITY, f64::MIN] {
        assert_eq!(
            f64_bytes(f),
            normalize(None, Physical::Float(Float::F64(f)))
                .expect("float")
                .bytes
                .risky_ref()
                .clone()
        );
    }
    assert_eq!(f64_bytes(-0.0), f64_bytes(0.0));
    assert_eq!(f64_bytes(f64::NAN), f64_bytes(-f64::NAN));
    for f in [0.0f32, -0.0, 1.5, -1.5, f32::INFINITY, f32::MIN_POSITIVE] {
        assert_eq!(f32_bytes(f), f64_bytes(f64::from(f)), "{f}");
    }
    assert_eq!(f32_bytes(f32::NAN), f64_bytes(f64::NAN));
}

#[test]
fn logical_types_order_by_their_equality_bytes() {
    let cases = [
        (T::Date, Logical::Date, Int::I32(19_000), domain::DATE, 4),
        (
            T::Timestamp,
            Logical::Timestamp(TimeUnit::Nanos),
            Int::I64(1_700_000_000_123_456_789),
            domain::TIMESTAMP,
            12,
        ),
        (
            T::Decimal,
            Logical::Decimal { scale: 2 },
            Int::I64(150),
            domain::DECIMAL,
            14,
        ),
    ];
    for (target, ty, value, expected_domain, width) in cases {
        let ordered = term(target, Some(ty), Physical::Int(value));
        let matched = normalize(Some(ty), Physical::Int(value)).expect("term");
        assert_eq!(ordered.domain(), expected_domain);
        assert_eq!(ordered.bytes().risky_ref().len(), width);
        assert_eq!(ordered.bytes().risky_ref(), matched.bytes.risky_ref());
    }
    let id = [9u8; 16];
    let uuid = term(T::Uuid, Some(Logical::Uuid), Physical::Bytes(&id));
    assert_eq!(uuid.domain(), domain::UUID);
    assert_eq!(uuid.bytes().risky_ref(), &id);
    let raw = term(T::Bytes, None, Physical::Bytes(b"abc"));
    assert_eq!(raw.domain(), domain::BYTES);
    assert_eq!(raw.bytes().risky_ref(), b"\x01abc");
    // A timestamp's unit is folded: the same instant in millis is one term.
    assert_eq!(
        bytes(
            T::Timestamp,
            Some(Logical::Timestamp(TimeUnit::Millis)),
            Physical::Int(Int::I64(1_700_000_000_123))
        ),
        bytes(
            T::Timestamp,
            Some(Logical::Timestamp(TimeUnit::Micros)),
            Physical::Int(Int::I64(1_700_000_000_123_000))
        )
    );
}

#[test]
fn text_folds_accents_and_case_but_equality_does_not() {
    let ordered = term(T::Text, None, Physical::Text("École"));
    assert_eq!(ordered.domain(), domain::TEXT);
    assert_eq!(ordered.bytes().risky_ref(), b"\x01ecole");
    assert_eq!(bytes(T::Text, None, Physical::Text("ecole")), b"\x01ecole");
    assert_ne!(
        normalize(None, Physical::Text("École"))
            .expect("text")
            .bytes
            .risky_ref(),
        normalize(None, Physical::Text("ecole"))
            .expect("text")
            .bytes
            .risky_ref()
    );
    assert_eq!(
        order(T::Text, None, Physical::Text("\u{378}")).expect_err("refused"),
        NormalizeError::UnassignedCodePoint
    );
}

/// The stored format of a text or bytes term, with literal bytes: the
/// marker, then the value. This is what both scheme crates fed their
/// encryptors before the marker moved here, so a term made from these
/// bytes is byte for byte the term they stored.
#[test]
fn text_and_bytes_start_with_the_marker_so_no_plaintext_is_empty() {
    assert_eq!(VARIABLE_WIDTH_MARKER, 0x01);
    assert_eq!(bytes(T::Text, None, Physical::Text("")), [0x01]);
    assert_eq!(bytes(T::Bytes, None, Physical::Bytes(&[])), [0x01]);
    assert_eq!(bytes(T::Text, None, Physical::Text("a")), [0x01, b'a']);
    assert_eq!(
        bytes(T::Bytes, None, Physical::Bytes(&[0xAB])),
        [0x01, 0xAB]
    );
    assert_eq!(
        text("").expect("empty text encodes").risky_ref(),
        &[VARIABLE_WIDTH_MARKER]
    );
    // The marker is constant, so it keeps the order; and the empty value
    // sorts first, as it did.
    assert!(bytes(T::Text, None, Physical::Text("")) < bytes(T::Text, None, Physical::Text("a")));
    assert!(
        bytes(T::Bytes, None, Physical::Bytes(&[])) < bytes(T::Bytes, None, Physical::Bytes(&[0]))
    );
    // Fixed-width targets go in unchanged: no marker.
    assert_eq!(int_bytes(T::U16, Int::U16(1)), [0, 1]);
    // And the width table has no zero width, so a fixed-width target
    // cannot be empty either (the conformance test encodes one value of
    // every target and checks).
    for target in OrderTarget::ALL {
        if let Some(width) = target.width() {
            assert!(width >= 1, "{target:?}");
        }
    }
}

#[test]
fn scalars_with_no_order_are_refused_with_the_reason() {
    for target in OrderTarget::ALL {
        for v in [Physical::Null, Physical::Bool(true), Physical::Bool(false)] {
            assert_eq!(
                order(*target, None, v).expect_err("refused"),
                NormalizeError::NoDomain,
                "{target:?}"
            );
        }
        assert_eq!(
            order(*target, Some(Logical::Undefined), Physical::Null).expect_err("refused"),
            NormalizeError::NoDomain
        );
    }
    let unknown = Logical::from_wire(200, 1).expect("unknown");
    assert_eq!(
        order(T::I16, Some(unknown), Physical::Int(Int::I8(1))).expect_err("refused"),
        NormalizeError::NoDomain
    );
    // Not valid for the logical type: refused before the target is looked at.
    assert_eq!(
        order(T::Uuid, Some(Logical::Uuid), Physical::Bytes(&[0; 3])).expect_err("refused"),
        NormalizeError::Invalid
    );
    assert_eq!(
        order(T::Date, Some(Logical::Date), Physical::Text("2024-01-01")).expect_err("refused"),
        NormalizeError::Invalid
    );
    assert_eq!(
        order(
            T::Decimal,
            Some(Logical::Decimal { scale: 29 }),
            Physical::Int(Int::I8(1))
        )
        .expect_err("refused"),
        NormalizeError::Invalid
    );
    assert_eq!(
        order(T::I16, Some(Logical::Undefined), Physical::Int(Int::I8(1))).expect_err("refused"),
        NormalizeError::Invalid
    );
}

/// A target takes only its own kind. An integer is not a float, a date or
/// a decimal: converting one would be a guess at what it means.
#[test]
fn a_value_of_another_kind_than_the_target_is_a_mismatch() {
    let day = (Some(Logical::Date), Physical::Int(Int::I32(1)));
    let one = (None, Physical::Int(Int::I32(1)));
    for (target, (ty, v)) in [
        (T::I32, (None, Physical::Text("1"))),
        (T::I32, (None, Physical::Float(Float::F64(1.0)))),
        (T::I32, day),
        (T::F64, one),
        (T::Date, one),
        (T::Decimal, one),
        (T::Timestamp, day),
        (T::Text, (None, Physical::Bytes(b"a"))),
        (T::Bytes, (None, Physical::Text("a"))),
        (T::Uuid, (None, Physical::Bytes(&[0; 16]))),
        (T::Bytes, (Some(Logical::Uuid), Physical::Bytes(&[0; 16]))),
    ] {
        assert_eq!(
            order(target, ty, v).expect_err("refused"),
            NormalizeError::Mismatch,
            "{ty:?} {v:?} as {target:?}"
        );
    }
}

#[test]
fn every_domain_is_distinct_and_listed_once() {
    let mut all = domain::ALL.to_vec();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), domain::ALL.len());
    assert_eq!(domain::ALL.len(), 15);
    // One target per domain, in the same order.
    let by_target: Vec<_> = OrderTarget::ALL.iter().map(|t| t.domain()).collect();
    assert_eq!(by_target, domain::ALL);
    // No order domain is an equality domain.
    for d in domain::ALL {
        assert!(!vitaminc_normalize::domain::ALL.contains(d), "{d}");
        assert!(d.starts_with("vitaminc/ore/value/"), "{d}");
    }
}

#[test]
fn the_order_normalizer_is_order_at_its_target() {
    let by_sink = Order(T::I32)
        .normalize(None, Physical::Int(Int::I16(-3)))
        .expect("term");
    let direct = order(T::I32, None, Physical::Int(Int::I16(-3))).expect("term");
    assert_eq!(by_sink.domain(), domain::INT32);
    assert_eq!(by_sink.bytes().risky_ref(), direct.bytes().risky_ref());
}

#[quickcheck]
fn integer_byte_order_is_value_order(a: i64, b: i64) -> bool {
    use std::cmp::Ordering;
    let ordered = |t: OrderTarget, x: Int, y: Int, expected: Ordering| {
        (int_bytes(t, x), int_bytes(t, y), expected)
    };
    let wide = |v: i64| i128::from(v) * 3;
    // One row per target: the two encodings, and how the values compare.
    let rows = [
        ordered(
            T::I16,
            Int::I16(a as i16),
            Int::I16(b as i16),
            (a as i16).cmp(&(b as i16)),
        ),
        ordered(
            T::I32,
            Int::I32(a as i32),
            Int::I32(b as i32),
            (a as i32).cmp(&(b as i32)),
        ),
        ordered(T::I64, Int::I64(a), Int::I64(b), a.cmp(&b)),
        ordered(
            T::I128,
            Int::I128(wide(a)),
            Int::I128(wide(b)),
            wide(a).cmp(&wide(b)),
        ),
        ordered(
            T::U16,
            Int::U16(a as u16),
            Int::U16(b as u16),
            (a as u16).cmp(&(b as u16)),
        ),
        ordered(
            T::U32,
            Int::U32(a as u32),
            Int::U32(b as u32),
            (a as u32).cmp(&(b as u32)),
        ),
        ordered(
            T::U64,
            Int::U64(a as u64),
            Int::U64(b as u64),
            (a as u64).cmp(&(b as u64)),
        ),
        ordered(
            T::U128,
            Int::U128(a as u128),
            Int::U128(b as u128),
            (a as u128).cmp(&(b as u128)),
        ),
    ];
    rows.iter().all(|(x, y, expected)| x.cmp(y) == *expected)
}

/// A value converted to a wider target orders as the value: an `i8` and a
/// `u64` compare in an `i128` column as the numbers do.
#[quickcheck]
fn values_of_any_width_order_as_numbers_in_a_wide_target(a: i8, b: u64) -> bool {
    let (x, y) = (
        int_bytes(T::I128, Int::I8(a)),
        int_bytes(T::I128, Int::U64(b)),
    );
    x.cmp(&y) == i128::from(a).cmp(&i128::from(b))
}

/// The whole 8-bit range, signed and unsigned, orders as the numbers in
/// the narrowest target, `I16`: there is no 8-bit target, so this is the
/// space an 8-bit column lands in.
#[quickcheck]
fn every_8_bit_value_orders_as_a_number_in_an_i16_target(a: i8, b: u8) -> bool {
    let (x, y) = (int_bytes(T::I16, Int::I8(a)), int_bytes(T::I16, Int::U8(b)));
    x.cmp(&y) == i16::from(a).cmp(&i16::from(b))
        && int_bytes(T::I16, Int::U8(b)) == int_bytes(T::I16, Int::I16(i16::from(b)))
}

#[quickcheck]
fn float_byte_order_is_value_order(a: f64, b: f64) -> bool {
    if a.is_nan() || b.is_nan() {
        return true;
    }
    let f64_bytes = |f: f64| bytes(T::F64, None, Physical::Float(Float::F64(f)));
    f64_bytes(a).cmp(&f64_bytes(b)) == a.partial_cmp(&b).expect("not NaN")
}

#[quickcheck]
fn every_nan_is_one_term_above_every_number(payload: u32, x: f32) -> bool {
    let f32_bytes = |f: f32| bytes(T::F64, None, Physical::Float(Float::F32(f)));
    // Any NaN bit pattern: exponent all ones, a non-zero mantissa.
    let nan = f32::from_bits(payload | 0x7f80_0000 | (u32::from(payload & 0x7f_ffff == 0)));
    let x = if x.is_nan() { 0.0 } else { x };
    f32_bytes(nan) == f32_bytes(f32::NAN) && f32_bytes(nan) > f32_bytes(x)
}

/// The order index takes date and timestamp bytes from the equality
/// encoders, so check that their byte order is the value order.
#[quickcheck]
fn date_and_timestamp_byte_order_is_value_order(a: i32, b: i32, x: i64, y: i64) -> bool {
    // Inside the day range `Logical::Date` admits.
    let (a, b) = (a % 95_000_000, b % 95_000_000);
    let date = |d: i32| bytes(T::Date, Some(Logical::Date), Physical::Int(Int::I32(d)));
    let nanos = |n: i64| {
        bytes(
            T::Timestamp,
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            Physical::Int(Int::I64(n)),
        )
    };
    date(a).cmp(&date(b)) == a.cmp(&b)
        // Truncated to microseconds: values in one microsecond tie.
        && nanos(x).cmp(&nanos(y)) == x.div_euclid(1_000).cmp(&y.div_euclid(1_000))
}

/// The integer and float encodings are the ones `orderable-bytes` 0.2.0
/// (frozen) produces, byte for byte.
mod oracle {
    use super::*;
    use orderable_bytes::OrderableBytes;

    /// Every width at once, compared as two lists rather than a chain of
    /// `&&`, so a mismatch in any width fails the property.
    #[quickcheck]
    fn integers_match_orderable_bytes(v: i128, w: u128) -> bool {
        let ours = [
            int_bytes(T::I16, Int::I16(v as i16)),
            int_bytes(T::I32, Int::I32(v as i32)),
            int_bytes(T::I64, Int::I64(v as i64)),
            int_bytes(T::I128, Int::I128(v)),
            int_bytes(T::U16, Int::U16(w as u16)),
            int_bytes(T::U32, Int::U32(w as u32)),
            int_bytes(T::U64, Int::U64(w as u64)),
            int_bytes(T::U128, Int::U128(w)),
        ];
        let frozen = [
            (v as i16).to_orderable_bytes().to_vec(),
            (v as i32).to_orderable_bytes().to_vec(),
            (v as i64).to_orderable_bytes().to_vec(),
            v.to_orderable_bytes().to_vec(),
            (w as u16).to_orderable_bytes().to_vec(),
            (w as u32).to_orderable_bytes().to_vec(),
            (w as u64).to_orderable_bytes().to_vec(),
            w.to_orderable_bytes().to_vec(),
        ];
        ours == frozen
    }

    /// For every number: `orderable-bytes` folds the zero sign but keeps
    /// NaN payloads, which this crate folds, so NaN is compared separately.
    #[quickcheck]
    fn floats_match_orderable_bytes(a: f32, b: f64) -> bool {
        let (a, b) = (
            if a.is_nan() { 1.5 } else { a },
            if b.is_nan() { 1.5 } else { b },
        );
        bytes(T::F64, None, Physical::Float(Float::F32(a))) == f64::from(a).to_orderable_bytes()
            && bytes(T::F64, None, Physical::Float(Float::F64(b))) == b.to_orderable_bytes()
    }

    #[test]
    fn the_one_nan_is_orderable_bytes_quiet_nan() {
        assert_eq!(
            bytes(T::F64, None, Physical::Float(Float::F64(f64::NAN))),
            f64::NAN.to_orderable_bytes()
        );
    }
}
