use super::*;
use quickcheck_macros::quickcheck;
use vitaminc_aead::TimeUnit;
use vitaminc_normalize::normalize;

fn term(ty: Option<Logical>, v: Physical<'_>) -> OrderPlaintext {
    order(ty, v).expect("valid test value")
}

fn bytes(ty: Option<Logical>, v: Physical<'_>) -> Vec<u8> {
    term(ty, v).bytes().risky_ref().clone()
}

#[test]
fn every_integer_width_has_its_own_domain_and_width() {
    let cases: [(Int, &str, usize); 10] = [
        (Int::I8(5), domain::INT8, 1),
        (Int::U8(5), domain::UINT8, 1),
        (Int::I16(5), domain::INT16, 2),
        (Int::U16(5), domain::UINT16, 2),
        (Int::I32(5), domain::INT32, 4),
        (Int::U32(5), domain::UINT32, 4),
        (Int::I64(5), domain::INT64, 8),
        (Int::U64(5), domain::UINT64, 8),
        (Int::I128(5), domain::INT128, 16),
        (Int::U128(5), domain::UINT128, 16),
    ];
    for (value, expected_domain, width) in cases {
        let n = term(None, Physical::Int(value));
        assert_eq!(n.domain(), expected_domain, "{value:?}");
        assert_eq!(n.bytes().risky_ref().len(), width, "{value:?}");
    }
}

#[test]
fn integers_are_big_endian_with_the_sign_bit_flipped() {
    assert_eq!(bytes(None, Physical::Int(Int::I8(-1))), [0x7f]);
    assert_eq!(bytes(None, Physical::Int(Int::I8(0))), [0x80]);
    assert_eq!(bytes(None, Physical::Int(Int::I8(i8::MIN))), [0x00]);
    assert_eq!(bytes(None, Physical::Int(Int::I8(i8::MAX))), [0xff]);
    assert_eq!(bytes(None, Physical::Int(Int::U8(0))), [0x00]);
    assert_eq!(bytes(None, Physical::Int(Int::U8(255))), [0xff]);
    assert_eq!(
        bytes(None, Physical::Int(Int::I32(-2))),
        [0x7f, 0xff, 0xff, 0xfe]
    );
    assert_eq!(bytes(None, Physical::Int(Int::U32(1))), [0, 0, 0, 1]);
    assert_eq!(bytes(None, Physical::Int(Int::I64(i64::MIN))), [0; 8]);
    let mut max = [0xff; 16];
    max[0] = 0x7f;
    assert_eq!(bytes(None, Physical::Int(Int::U128(u128::MAX))), [0xff; 16]);
    assert_eq!(bytes(None, Physical::Int(Int::I128(i128::MAX))), [0xff; 16]);
    assert_eq!(bytes(None, Physical::Int(Int::I128(-1))), max);
}

#[test]
fn floats_fold_zero_signs_and_nans_at_their_own_width() {
    let f32_bytes = |f: f32| bytes(None, Physical::Float(Float::F32(f)));
    let f64_bytes = |f: f64| bytes(None, Physical::Float(Float::F64(f)));
    assert_eq!(
        term(None, Physical::Float(Float::F32(1.5))).domain(),
        domain::FLOAT32
    );
    assert_eq!(
        term(None, Physical::Float(Float::F64(1.5))).domain(),
        domain::FLOAT64
    );
    assert_eq!(f32_bytes(0.0), [0x80, 0, 0, 0]);
    assert_eq!(f32_bytes(-0.0), f32_bytes(0.0));
    assert_eq!(f32_bytes(1.5), [0xbf, 0xc0, 0, 0]);
    assert_eq!(f32_bytes(-1.5), [0x40, 0x3f, 0xff, 0xff]);
    assert_eq!(f32_bytes(f32::NAN), f32_bytes(-f32::NAN));
    assert_eq!(
        f32_bytes(f32::from_bits(0x7f80_0001)),
        f32_bytes(f32::from_bits(0xffc0_1234))
    );
    assert_eq!(f32_bytes(f32::NAN), [0xff, 0xc0, 0, 0]);
    // Infinities are not NaN and keep their sign.
    assert_eq!(f32_bytes(f32::INFINITY), [0xff, 0x80, 0, 0]);
    assert_eq!(f32_bytes(f32::NEG_INFINITY), [0x00, 0x7f, 0xff, 0xff]);
    // Subnormals are ordinary values: above zero, below the smallest normal.
    assert!(f32_bytes(f32::from_bits(1)) > f32_bytes(0.0));
    assert!(f32_bytes(f32::from_bits(1)) < f32_bytes(f32::MIN_POSITIVE));
    // An f64 orders by the bytes it is matched by.
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
    assert_eq!(f64_bytes(f64::NAN), f64_bytes(-f64::NAN));
}

#[test]
fn logical_types_order_by_their_equality_bytes() {
    let cases = [
        (Logical::Date, Int::I32(19_000), domain::DATE, 4),
        (
            Logical::Timestamp(TimeUnit::Nanos),
            Int::I64(1_700_000_000_123_456_789),
            domain::TIMESTAMP,
            12,
        ),
        (
            Logical::Decimal { scale: 2 },
            Int::I64(150),
            domain::DECIMAL,
            14,
        ),
    ];
    for (ty, value, expected_domain, width) in cases {
        let ordered = term(Some(ty), Physical::Int(value));
        let matched = normalize(Some(ty), Physical::Int(value)).expect("term");
        assert_eq!(ordered.domain(), expected_domain);
        assert_eq!(ordered.bytes().risky_ref().len(), width);
        assert_eq!(ordered.bytes().risky_ref(), matched.bytes.risky_ref());
    }
    let id = [9u8; 16];
    let uuid = term(Some(Logical::Uuid), Physical::Bytes(&id));
    assert_eq!(uuid.domain(), domain::UUID);
    assert_eq!(uuid.bytes().risky_ref(), &id);
    let raw = term(None, Physical::Bytes(b"abc"));
    assert_eq!(raw.domain(), domain::BYTES);
    assert_eq!(raw.bytes().risky_ref(), b"abc");
    // A timestamp's unit is folded: the same instant in millis is one term.
    assert_eq!(
        bytes(
            Some(Logical::Timestamp(TimeUnit::Millis)),
            Physical::Int(Int::I64(1_700_000_000_123))
        ),
        bytes(
            Some(Logical::Timestamp(TimeUnit::Micros)),
            Physical::Int(Int::I64(1_700_000_000_123_000))
        )
    );
}

#[test]
fn text_folds_accents_and_case_but_equality_does_not() {
    let ordered = term(None, Physical::Text("École"));
    assert_eq!(ordered.domain(), domain::TEXT);
    assert_eq!(ordered.bytes().risky_ref(), b"ecole");
    assert_eq!(bytes(None, Physical::Text("ecole")), b"ecole");
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
        order(None, Physical::Text("\u{378}")).expect_err("refused"),
        NormalizeError::UnassignedCodePoint
    );
}

#[test]
fn scalars_with_no_order_are_refused_with_the_reason() {
    for v in [Physical::Null, Physical::Bool(true), Physical::Bool(false)] {
        assert_eq!(
            order(None, v).expect_err("refused"),
            NormalizeError::NoDomain
        );
        assert_eq!(domain_of(None, &v), None);
    }
    assert_eq!(
        order(Some(Logical::Undefined), Physical::Null).expect_err("refused"),
        NormalizeError::NoDomain
    );
    let unknown = Logical::from_wire(200, 1).expect("unknown");
    assert_eq!(
        order(Some(unknown), Physical::Int(Int::I8(1))).expect_err("refused"),
        NormalizeError::NoDomain
    );
    // Not valid for the logical type: refused before the domain is looked up.
    assert_eq!(
        order(Some(Logical::Uuid), Physical::Bytes(&[0; 3])).expect_err("refused"),
        NormalizeError::Invalid
    );
    assert_eq!(
        order(Some(Logical::Date), Physical::Text("2024-01-01")).expect_err("refused"),
        NormalizeError::Invalid
    );
    assert_eq!(
        order(
            Some(Logical::Decimal { scale: 29 }),
            Physical::Int(Int::I8(1))
        )
        .expect_err("refused"),
        NormalizeError::Invalid
    );
    assert_eq!(
        order(Some(Logical::Undefined), Physical::Int(Int::I8(1))).expect_err("refused"),
        NormalizeError::Invalid
    );
}

#[test]
fn every_domain_is_distinct_and_listed_once() {
    let mut all = domain::ALL.to_vec();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), domain::ALL.len());
    assert_eq!(domain::ALL.len(), 18);
    // No order domain is an equality domain.
    for d in domain::ALL {
        assert!(!vitaminc_normalize::domain::ALL.contains(d), "{d}");
        assert!(d.starts_with("vitaminc/ore/value/"), "{d}");
    }
}

#[test]
fn the_order_normalizer_is_order() {
    let by_sink = Order
        .normalize(None, Physical::Int(Int::I16(-3)))
        .expect("term");
    let direct = order(None, Physical::Int(Int::I16(-3))).expect("term");
    assert_eq!(by_sink.domain(), direct.domain());
    assert_eq!(by_sink.bytes().risky_ref(), direct.bytes().risky_ref());
}

#[quickcheck]
fn integer_byte_order_is_value_order(a: i64, b: i64) -> bool {
    use std::cmp::Ordering;
    let ordered = |x: Int, y: Int, expected: Ordering| {
        (
            bytes(None, Physical::Int(x)),
            bytes(None, Physical::Int(y)),
            expected,
        )
    };
    let wide = |v: i64| i128::from(v) * 3;
    // One row per width: the two encodings, and how the values compare.
    let rows = [
        ordered(
            Int::I8(a as i8),
            Int::I8(b as i8),
            (a as i8).cmp(&(b as i8)),
        ),
        ordered(
            Int::I16(a as i16),
            Int::I16(b as i16),
            (a as i16).cmp(&(b as i16)),
        ),
        ordered(
            Int::I32(a as i32),
            Int::I32(b as i32),
            (a as i32).cmp(&(b as i32)),
        ),
        ordered(Int::I64(a), Int::I64(b), a.cmp(&b)),
        ordered(
            Int::I128(wide(a)),
            Int::I128(wide(b)),
            wide(a).cmp(&wide(b)),
        ),
        ordered(
            Int::U8(a as u8),
            Int::U8(b as u8),
            (a as u8).cmp(&(b as u8)),
        ),
        ordered(
            Int::U16(a as u16),
            Int::U16(b as u16),
            (a as u16).cmp(&(b as u16)),
        ),
        ordered(
            Int::U32(a as u32),
            Int::U32(b as u32),
            (a as u32).cmp(&(b as u32)),
        ),
        ordered(
            Int::U64(a as u64),
            Int::U64(b as u64),
            (a as u64).cmp(&(b as u64)),
        ),
        ordered(
            Int::U128(a as u128),
            Int::U128(b as u128),
            (a as u128).cmp(&(b as u128)),
        ),
    ];
    rows.iter().all(|(x, y, expected)| x.cmp(y) == *expected)
}

#[quickcheck]
fn float_byte_order_is_value_order(a: f32, b: f32) -> bool {
    if a.is_nan() || b.is_nan() {
        return true;
    }
    let f32_bytes = |f: f32| bytes(None, Physical::Float(Float::F32(f)));
    let f64_bytes = |f: f64| bytes(None, Physical::Float(Float::F64(f)));
    let expected = a.partial_cmp(&b).expect("not NaN");
    f32_bytes(a).cmp(&f32_bytes(b)) == expected
        && f64_bytes(f64::from(a)).cmp(&f64_bytes(f64::from(b))) == expected
}

#[quickcheck]
fn every_nan_is_one_term_above_every_number(payload: u32, x: f32) -> bool {
    let f32_bytes = |f: f32| bytes(None, Physical::Float(Float::F32(f)));
    // Any NaN bit pattern: exponent all ones, a non-zero mantissa.
    let nan = f32::from_bits(payload | 0x7f80_0000 | (u32::from(payload & 0x7f_ffff == 0)));
    let x = if x.is_nan() { 0.0 } else { x };
    f32_bytes(nan) == f32_bytes(f32::NAN) && f32_bytes(nan) > f32_bytes(x)
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
        let int = |i: Int| bytes(None, Physical::Int(i));
        let ours = [
            int(Int::I8(v as i8)),
            int(Int::I16(v as i16)),
            int(Int::I32(v as i32)),
            int(Int::I64(v as i64)),
            int(Int::I128(v)),
            int(Int::U8(w as u8)),
            int(Int::U16(w as u16)),
            int(Int::U32(w as u32)),
            int(Int::U64(w as u64)),
            int(Int::U128(w)),
        ];
        let frozen = [
            (v as i8).to_orderable_bytes().to_vec(),
            (v as i16).to_orderable_bytes().to_vec(),
            (v as i32).to_orderable_bytes().to_vec(),
            (v as i64).to_orderable_bytes().to_vec(),
            v.to_orderable_bytes().to_vec(),
            (w as u8).to_orderable_bytes().to_vec(),
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
        bytes(None, Physical::Float(Float::F32(a))) == a.to_orderable_bytes()
            && bytes(None, Physical::Float(Float::F64(b))) == b.to_orderable_bytes()
    }

    #[test]
    fn the_one_nan_is_orderable_bytes_quiet_nan() {
        assert_eq!(
            bytes(None, Physical::Float(Float::F32(f32::NAN))),
            f32::NAN.to_orderable_bytes()
        );
        assert_eq!(
            bytes(None, Physical::Float(Float::F64(f64::NAN))),
            f64::NAN.to_orderable_bytes()
        );
    }
}
