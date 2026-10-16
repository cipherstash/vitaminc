//! The conformance test ADR 0002 asks for: every kind of the data model
//! has an order target or is a named exception, values equal under the
//! data model give equal terms under both the equality and the order
//! index, and the scheme trait behaves as its contract says, through
//! mocks.

mod common;

use std::cmp::Ordering;

use common::{key, Down, Fixed, Mock, MockTerm, WrongKeyLength};
use quickcheck_macros::quickcheck;
use vitaminc_aead::plaintext::kinds::id::LAST_KNOWN;
use vitaminc_aead::{Float, Int, Logical, Physical, TimeUnit};
use vitaminc_normalize::{domain as equality, normalize};
use vitaminc_ore::{
    domain, order, Context, IntoContext, NormalizeError, OrderEncrypt, OrderError, OrderKeyInit,
    OrderTarget, Raw,
};
use vitaminc_protected::{Controlled, Protected};

use OrderTarget as T;

/// A target and a pair of values in order, as that target, with its
/// domain and width.
struct Orderable<'a> {
    target: OrderTarget,
    ty: Option<Logical>,
    below: Physical<'a>,
    above: Physical<'a>,
    domain: &'static str,
    width: Option<usize>,
}

fn inventory() -> Vec<Orderable<'static>> {
    use Physical::{Bytes, Float as F, Int as I, Text};
    let plain = |target, below, above, domain, width| Orderable {
        target,
        ty: None,
        below,
        above,
        domain,
        width,
    };
    let typed = |target, ty, below, above, domain, width| Orderable {
        target,
        ty: Some(ty),
        below,
        above,
        domain,
        width,
    };
    vec![
        plain(T::I8, I(Int::I8(-1)), I(Int::U8(1)), domain::INT8, Some(1)),
        plain(
            T::U8,
            I(Int::I8(0)),
            I(Int::U8(255)),
            domain::UINT8,
            Some(1),
        ),
        plain(
            T::I16,
            I(Int::I16(i16::MIN)),
            I(Int::I16(i16::MAX)),
            domain::INT16,
            Some(2),
        ),
        plain(
            T::U16,
            I(Int::U16(0)),
            I(Int::U16(u16::MAX)),
            domain::UINT16,
            Some(2),
        ),
        plain(
            T::I32,
            I(Int::I32(i32::MIN)),
            I(Int::I32(i32::MAX)),
            domain::INT32,
            Some(4),
        ),
        plain(
            T::U32,
            I(Int::U32(0)),
            I(Int::U32(u32::MAX)),
            domain::UINT32,
            Some(4),
        ),
        plain(
            T::I64,
            I(Int::I64(i64::MIN)),
            I(Int::I64(i64::MAX)),
            domain::INT64,
            Some(8),
        ),
        plain(
            T::U64,
            I(Int::U64(0)),
            I(Int::U64(u64::MAX)),
            domain::UINT64,
            Some(8),
        ),
        plain(
            T::I128,
            I(Int::I128(i128::MIN)),
            I(Int::I128(i128::MAX)),
            domain::INT128,
            Some(16),
        ),
        plain(
            T::U128,
            I(Int::U128(0)),
            I(Int::U128(u128::MAX)),
            domain::UINT128,
            Some(16),
        ),
        plain(
            T::F64,
            F(Float::F32(f32::NEG_INFINITY)),
            F(Float::F64(f64::INFINITY)),
            domain::FLOAT64,
            Some(8),
        ),
        plain(T::Text, Text("apple"), Text("Banana"), domain::TEXT, None),
        plain(
            T::Bytes,
            Bytes(&[0, 0, 0]),
            Bytes(&[255]),
            domain::BYTES,
            None,
        ),
        typed(
            T::Date,
            Logical::Date,
            I(Int::I32(-96_465_292)),
            I(Int::I32(95_026_236)),
            domain::DATE,
            Some(4),
        ),
        typed(
            T::Timestamp,
            Logical::Timestamp(TimeUnit::Nanos),
            I(Int::I64(-1)),
            I(Int::I64(0)),
            domain::TIMESTAMP,
            Some(12),
        ),
        typed(
            T::Decimal,
            Logical::Decimal { scale: 2 },
            I(Int::I64(-150)),
            I(Int::I64(150)),
            domain::DECIMAL,
            Some(14),
        ),
        typed(
            T::Uuid,
            Logical::Uuid,
            Bytes(&[0; 16]),
            Bytes(&[1; 16]),
            domain::UUID,
            Some(16),
        ),
    ]
}

#[test]
fn every_kind_has_an_order_target_or_is_a_named_exception() {
    let kinds = inventory();
    // One row per target, every target used.
    let targets: Vec<_> = kinds.iter().map(|k| k.target).collect();
    assert_eq!(targets.len(), OrderTarget::ALL.len());
    for target in OrderTarget::ALL {
        assert!(targets.contains(target), "{target:?} has no row");
    }
    assert_eq!(domain::ALL.len(), 17);
    let scheme = Mock::new(key());
    for kind in &kinds {
        let (below, above) = (
            order(kind.target, kind.ty, kind.below).expect("term"),
            order(kind.target, kind.ty, kind.above).expect("term"),
        );
        assert_eq!(below.domain(), kind.domain);
        assert_eq!(below.width(), kind.width, "{}", kind.domain);
        if let Some(width) = kind.width {
            assert_eq!(below.bytes().risky_ref().len(), width, "{}", kind.domain);
        }
        let column = scheme.column(kind.target, ());
        let (x, y) = (
            column.encrypt_term(&below).expect("mock"),
            column.encrypt_term(&above).expect("mock"),
        );
        assert_eq!(x.cmp(&y), Ordering::Less, "{}", kind.domain);
    }
    // The exceptions: no order term under any target, and the walk skips
    // them.
    for target in OrderTarget::ALL {
        for v in [Physical::Null, Physical::Bool(false), Physical::Bool(true)] {
            assert_eq!(
                order(*target, None, v).err(),
                Some(NormalizeError::NoDomain)
            );
        }
        assert_eq!(
            order(*target, Some(Logical::Undefined), Physical::Null).err(),
            Some(NormalizeError::NoDomain)
        );
    }
    // Keep the inventory explicit: a new logical type must add a row above
    // or a named exception here, not inherit a wildcard.
    assert_eq!(
        LAST_KNOWN, 5,
        "a logical type was added: give it an order target or an exception"
    );
}

/// Values equal under the data model give equal terms under both indexes.
#[test]
fn equality_and_order_agree_on_what_is_equal() {
    let same = |target, ty: Option<Logical>, a: Physical<'_>, b: Physical<'_>| {
        let (ea, eb) = (normalize(ty, a).expect("eq"), normalize(ty, b).expect("eq"));
        let (oa, ob) = (
            order(target, ty, a).expect("ord"),
            order(target, ty, b).expect("ord"),
        );
        assert_eq!(ea.domain, eb.domain);
        assert_eq!(
            ea.bytes.risky_ref(),
            eb.bytes.risky_ref(),
            "{:?} {:?}",
            ea.domain,
            ty
        );
        assert_eq!(oa.domain(), ob.domain());
        assert_eq!(
            oa.bytes().risky_ref(),
            ob.bytes().risky_ref(),
            "{} {:?}",
            oa.domain(),
            ty
        );
    };
    // An integer is the same number at every width, under both.
    same(
        T::I64,
        None,
        Physical::Int(Int::I8(5)),
        Physical::Int(Int::U64(5)),
    );
    same(
        T::I32,
        None,
        Physical::Int(Int::I16(-300)),
        Physical::Int(Int::I128(-300)),
    );
    // A timestamp is the same instant whatever its unit.
    let (ms, us) = (
        normalize(
            Some(Logical::Timestamp(TimeUnit::Millis)),
            Physical::Int(Int::I64(1_700_000_000_123)),
        )
        .expect("eq"),
        order(
            T::Timestamp,
            Some(Logical::Timestamp(TimeUnit::Micros)),
            Physical::Int(Int::I64(1_700_000_000_123_000)),
        )
        .expect("ord"),
    );
    assert_eq!(ms.bytes.risky_ref(), us.bytes().risky_ref());
    // A decimal's scale is normalized.
    let (a, b) = (
        order(
            T::Decimal,
            Some(Logical::Decimal { scale: 2 }),
            Physical::Int(Int::I64(150)),
        )
        .expect("ord"),
        order(
            T::Decimal,
            Some(Logical::Decimal { scale: 1 }),
            Physical::Int(Int::I64(15)),
        )
        .expect("ord"),
    );
    assert_eq!(a.bytes().risky_ref(), b.bytes().risky_ref());
    // Signed zero and NaN payloads fold, and an f32 is its f64 value.
    same(
        T::F64,
        None,
        Physical::Float(Float::F64(-0.0)),
        Physical::Float(Float::F64(0.0)),
    );
    same(
        T::F64,
        None,
        Physical::Float(Float::F64(f64::NAN)),
        Physical::Float(Float::F64(-f64::NAN)),
    );
    same(
        T::F64,
        None,
        Physical::Float(Float::F32(1.5)),
        Physical::Float(Float::F64(1.5)),
    );
    // Canonically equivalent text is one term under both.
    same(
        T::Text,
        None,
        Physical::Text("e\u{301}"),
        Physical::Text("\u{e9}"),
    );
    // Where the two indexes differ, on purpose: an order term folds
    // accents and case, an equality term does not.
    let (e_eq, big_eq) = (
        normalize(None, Physical::Text("e")).expect("eq"),
        normalize(None, Physical::Text("É")).expect("eq"),
    );
    assert_ne!(e_eq.bytes.risky_ref(), big_eq.bytes.risky_ref());
    let (e, big) = (
        order(T::Text, None, Physical::Text("e")).expect("ord"),
        order(T::Text, None, Physical::Text("É")).expect("ord"),
    );
    assert_eq!(e.bytes().risky_ref(), big.bytes().risky_ref());
    // Shared kinds share their bytes with the equality index exactly.
    for (target, ty, v) in [
        (
            T::Date,
            Some(Logical::Date),
            Physical::Int(Int::I32(19_000)),
        ),
        (
            T::Decimal,
            Some(Logical::Decimal { scale: 3 }),
            Physical::Int(Int::I64(-12_345)),
        ),
        (T::Uuid, Some(Logical::Uuid), Physical::Bytes(&[9; 16])),
        (T::Bytes, None, Physical::Bytes(b"raw")),
        (T::F64, None, Physical::Float(Float::F64(2.5))),
    ] {
        assert_eq!(
            normalize(ty, v).expect("eq").bytes.risky_ref(),
            order(target, ty, v).expect("ord").bytes().risky_ref()
        );
    }
    // And no order domain is an equality domain.
    for d in domain::ALL {
        assert!(!equality::ALL.contains(d), "{d}");
    }
}

#[test]
fn a_scheme_refuses_a_target_by_name_not_by_counting_bytes() {
    let fixed = Fixed::<4>(Mock::new(key()));
    let day = Raw(Some(Logical::Date), Physical::Int(Int::I32(1)));
    assert!(fixed.column(T::Date, ()).encrypt(day).is_ok());
    assert!(fixed.column(T::I32, ()).encrypt(1i8).is_ok());
    for (target, value, domain) in [
        (T::I8, Raw(None, Physical::Int(Int::I8(1))), domain::INT8),
        (T::Text, Raw(None, Physical::Text("abcd")), domain::TEXT),
        (
            T::Bytes,
            Raw(None, Physical::Bytes(&[1, 2, 3, 4])),
            domain::BYTES,
        ),
        (
            T::I128,
            Raw(None, Physical::Int(Int::I32(1))),
            domain::INT128,
        ),
    ] {
        assert!(
            matches!(
                fixed.column(target, ()).encrypt(value),
                Err(OrderError::Unsupported { scheme: "fixed", domain: d }) if d == domain
            ),
            "{domain}"
        );
    }
}

#[test]
fn terms_compare_only_within_one_scheme_key_target_and_context() {
    let tenant = |n: u64| ("tenant", n);
    let mock = Mock::new(key());
    let under_one = mock.column(T::I8, tenant(1)).encrypt(0i8).expect("mock");
    assert_ne!(
        under_one,
        mock.column(T::I8, tenant(2)).encrypt(0i8).expect("mock")
    );
    assert_ne!(
        under_one,
        Mock::new(Protected::new([8; 32]))
            .column(T::I8, tenant(1))
            .encrypt(0i8)
            .expect("mock")
    );
    assert_ne!(
        under_one,
        Fixed::<1>(Mock::new(key()))
            .column(T::I8, tenant(1))
            .encrypt(0i8)
            .expect("fixed")
    );
    // The same bytes under another target are another term.
    let as_i8 = mock.column(T::I8, ()).encrypt(0i8).expect("mock");
    let as_u8 = mock.column(T::U8, ()).encrypt(0x80u16).expect("mock");
    assert_eq!(as_i8.bytes, as_u8.bytes);
    assert_ne!(as_i8, as_u8);
}

/// The column derives the salt from the scheme's own name, so two schemes
/// under one key and context never bind the same salt.
#[test]
fn a_columns_salt_binds_its_schemes_own_name() {
    let context = ("tenant", 1u64).into_context().encode();
    let expected = |scheme: &str| {
        Context::pae(&[
            b"vitaminc/ore/v1",
            scheme.as_bytes(),
            domain::INT8.as_bytes(),
            context.as_bytes(),
        ])
    };
    let (mock, fixed) = (Mock::new(key()), Fixed::<1>(Mock::new(key())));
    let (m, f) = (
        mock.column(T::I8, ("tenant", 1u64)),
        fixed.column(T::I8, ("tenant", 1u64)),
    );
    assert_eq!(m.salt(), &expected("mock"));
    assert_eq!(f.salt(), &expected("fixed"));
    assert_ne!(m.salt(), f.salt());
    // And the scheme binds the salt it is handed: the mocks' terms carry it.
    let term = m.encrypt(1i8).expect("mock");
    assert!(term.salt.starts_with(expected("mock").as_bytes()));
}

#[test]
fn the_column_refuses_before_the_scheme_and_passes_the_schemes_failure_through() {
    let mock = Mock::new(key());
    let column = mock.column(T::Text, ());
    for v in [Physical::Null, Physical::Bool(true)] {
        assert!(matches!(
            column.encrypt(Raw(None, v)),
            Err(OrderError::Term(NormalizeError::NoDomain))
        ));
    }
    assert!(matches!(
        column.encrypt("\u{378}"),
        Err(OrderError::Term(NormalizeError::UnassignedCodePoint))
    ));
    assert!(matches!(
        column.encrypt(7u32),
        Err(OrderError::Term(NormalizeError::Mismatch))
    ));
    assert!(matches!(
        mock.column(T::U8, ()).encrypt(300u16),
        Err(OrderError::Term(NormalizeError::OutOfRange))
    ));
    assert!(matches!(
        mock.column(T::Uuid, ())
            .encrypt(Raw(Some(Logical::Uuid), Physical::Bytes(&[0; 3]))),
        Err(OrderError::Term(NormalizeError::Invalid))
    ));
    let failed = Down.column(T::I8, ()).encrypt(1i8).expect_err("down");
    assert!(matches!(failed, OrderError::Backend(_)));
    assert_eq!(
        failed.to_string(),
        "the order scheme failed: the backend is down"
    );
}

#[test]
fn a_container_or_a_failing_source_has_no_single_term() {
    use vitaminc_aead::plaintext::SourceError;
    use vitaminc_aead::Sink;
    use vitaminc_ore::Encrypt;

    /// A source whose getter throws.
    struct Throws;
    impl Encrypt for Throws {
        fn visit<S: Sink>(self, _: S) -> Result<S::Ok, S::Error> {
            Err(<S::Error as vitaminc_aead::plaintext::Error>::source(
                SourceError::msg("getter threw"),
            ))
        }
    }
    /// A value that hands its contents on as a passthrough.
    struct Passed;
    impl Encrypt for Passed {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            sink.passthrough("public")
        }
    }

    let mock = Mock::new(key());
    let column = mock.column(T::U16, ());
    assert!(matches!(
        column.encrypt(vec![1u16, 2]),
        Err(OrderError::NotScalar)
    ));
    assert!(matches!(
        column.encrypt(std::collections::BTreeMap::from([("k", 1u16)])),
        Err(OrderError::NotScalar)
    ));
    assert!(matches!(column.encrypt(Passed), Err(OrderError::NotScalar)));
    let failed = column.encrypt(Throws).expect_err("source failed");
    assert!(matches!(failed, OrderError::Source(_)));
    assert_eq!(
        failed.to_string(),
        "the value could not be read: getter threw"
    );
}

/// A plaintext from a walk goes into the column of its own target only.
#[test]
fn a_column_takes_a_collected_term_of_its_own_target_only() {
    let mock = Mock::new(key());
    let p = order(T::I32, None, Physical::Int(Int::I8(3))).expect("term");
    assert_eq!(
        mock.column(T::I32, "c")
            .encrypt_term(&p)
            .expect("same target"),
        mock.column(T::I32, "c").encrypt(3i8).expect("mock")
    );
    assert!(matches!(
        mock.column(T::I64, "c").encrypt_term(&p),
        Err(OrderError::Term(NormalizeError::Mismatch))
    ));
}

#[test]
fn a_scheme_is_keyed_like_a_prf() {
    let from_bytes = Mock::try_from_bytes(Protected::new(vec![7; 32])).expect("32 bytes");
    let term = |scheme: &Mock| scheme.column(T::I8, ()).encrypt(1i8).expect("mock");
    assert_eq!(term(&from_bytes), term(&Mock::new(key())));
    let short = Mock::try_from_bytes(Protected::new(vec![7; 16]))
        .err()
        .expect("refused");
    assert!(matches!(short, WrongKeyLength(16)));
}

/// Callers hold chrono, rust_decimal and uuid values, not `Raw`; each
/// encrypts into the column of its type as the typed scalar it stands for.
#[test]
fn typed_values_encrypt_into_the_column_of_their_type() {
    use chrono::{NaiveDate, TimeZone, Utc};
    use rust_decimal::Decimal;
    let mock = Mock::new(key());
    let typed = |target, ty: Logical, v: Physical<'_>| {
        mock.column(target, ())
            .encrypt(Raw(Some(ty), v))
            .expect("typed")
    };
    // 2022-01-08 is day 19_000 after 1970-01-01.
    let dates = mock.column(T::Date, ());
    let day = NaiveDate::from_ymd_opt(2022, 1, 8).expect("date");
    let date = dates.encrypt(day).expect("date");
    assert_eq!(
        date,
        typed(T::Date, Logical::Date, Physical::Int(Int::I32(19_000)))
    );
    assert!(dates.encrypt(day.pred_opt().expect("date")).expect("date") < date);
    let at = Utc
        .timestamp_opt(1_700_000_000, 123_456_789)
        .single()
        .expect("instant");
    assert_eq!(
        mock.column(T::Timestamp, ())
            .encrypt(at)
            .expect("timestamp"),
        typed(
            T::Timestamp,
            Logical::Timestamp(TimeUnit::Micros),
            Physical::Int(Int::I64(1_700_000_000_123_456))
        )
    );
    let decimals = mock.column(T::Decimal, ());
    assert_eq!(
        decimals.encrypt(Decimal::new(150, 2)).expect("decimal"),
        decimals.encrypt(Decimal::new(15, 1)).expect("decimal")
    );
    let id = uuid::Uuid::from_bytes([9; 16]);
    assert_eq!(
        mock.column(T::Uuid, ()).encrypt(id).expect("uuid"),
        typed(T::Uuid, Logical::Uuid, Physical::Bytes(&[9; 16]))
    );
    // A date is not the integer it is stored as.
    assert!(matches!(
        mock.column(T::I32, ()).encrypt(day),
        Err(OrderError::Term(NormalizeError::Mismatch))
    ));
}

#[quickcheck]
fn order_through_a_column_is_value_order(a: i32, b: i16, text_a: String, text_b: String) -> bool {
    let mock = Mock::new(key());
    let ints = mock.column(T::I64, "col");
    let int_order = ints
        .encrypt(a)
        .expect("mock")
        .cmp(&ints.encrypt(b).expect("mock"))
        == i64::from(a).cmp(&i64::from(b));
    // Bytes compare as bytes; text ties where it folds together, so only
    // bytes are checked for order here.
    let bytes = mock.column(T::Bytes, "col");
    let under = |s: &str| {
        bytes
            .encrypt(Raw(None, Physical::Bytes(s.as_bytes())))
            .expect("mock")
    };
    let byte_order =
        under(&text_a).cmp(&under(&text_b)) == text_a.as_bytes().cmp(text_b.as_bytes());
    int_order && byte_order
}

#[test]
fn a_mock_term_is_the_plaintext_bytes() {
    // So the tests above are about the plaintext layer, not the mock.
    let term: MockTerm = Mock::new(key())
        .column(T::U8, ())
        .encrypt(9u16)
        .expect("mock");
    assert_eq!(term.as_ref(), &[9]);
}
