//! The conformance test ADR 0002 asks for: every kind of the data model
//! has an order term or is a named exception, values equal under the data
//! model give equal terms under both the equality and the order index,
//! and the scheme trait behaves as its contract says, through mocks.

mod common;

use std::cmp::Ordering;

use common::{key, Down, Fixed, Mock, MockTerm, WrongKeyLength};
use quickcheck_macros::quickcheck;
use vitaminc_aead::plaintext::kinds::id::LAST_KNOWN;
use vitaminc_aead::{Float, Int, Logical, Physical, TimeUnit};
use vitaminc_normalize::{domain as equality, normalize};
use vitaminc_ore::{
    domain, order, IntoContext, NormalizeError, OrderError, OrderKeyInit, OrderScheme, Raw,
};
use vitaminc_protected::{Controlled, Protected};

/// A kind that orders: a pair in order, its domain, and its width.
struct Orderable<'a> {
    ty: Option<Logical>,
    below: Physical<'a>,
    above: Physical<'a>,
    domain: &'static str,
    width: Option<usize>,
}

fn inventory() -> Vec<Orderable<'static>> {
    use Physical::{Bytes, Float as F, Int as I, Text};
    let plain = |below, above, domain, width| Orderable {
        ty: None,
        below,
        above,
        domain,
        width,
    };
    let typed = |ty, below, above, domain, width| Orderable {
        ty: Some(ty),
        below,
        above,
        domain,
        width,
    };
    vec![
        plain(I(Int::I8(-1)), I(Int::I8(1)), domain::INT8, Some(1)),
        plain(I(Int::U8(0)), I(Int::U8(255)), domain::UINT8, Some(1)),
        plain(
            I(Int::I16(i16::MIN)),
            I(Int::I16(i16::MAX)),
            domain::INT16,
            Some(2),
        ),
        plain(
            I(Int::U16(0)),
            I(Int::U16(u16::MAX)),
            domain::UINT16,
            Some(2),
        ),
        plain(
            I(Int::I32(i32::MIN)),
            I(Int::I32(i32::MAX)),
            domain::INT32,
            Some(4),
        ),
        plain(
            I(Int::U32(0)),
            I(Int::U32(u32::MAX)),
            domain::UINT32,
            Some(4),
        ),
        plain(
            I(Int::I64(i64::MIN)),
            I(Int::I64(i64::MAX)),
            domain::INT64,
            Some(8),
        ),
        plain(
            I(Int::U64(0)),
            I(Int::U64(u64::MAX)),
            domain::UINT64,
            Some(8),
        ),
        plain(
            I(Int::I128(i128::MIN)),
            I(Int::I128(i128::MAX)),
            domain::INT128,
            Some(16),
        ),
        plain(
            I(Int::U128(0)),
            I(Int::U128(u128::MAX)),
            domain::UINT128,
            Some(16),
        ),
        plain(
            F(Float::F32(f32::NEG_INFINITY)),
            F(Float::F32(f32::NAN)),
            domain::FLOAT32,
            Some(4),
        ),
        plain(
            F(Float::F64(-1.0)),
            F(Float::F64(f64::INFINITY)),
            domain::FLOAT64,
            Some(8),
        ),
        plain(Text("apple"), Text("Banana"), domain::TEXT, None),
        plain(Bytes(&[0, 0, 0]), Bytes(&[255]), domain::BYTES, None),
        typed(
            Logical::Date,
            I(Int::I32(-96_465_292)),
            I(Int::I32(95_026_236)),
            domain::DATE,
            Some(4),
        ),
        typed(
            Logical::Timestamp(TimeUnit::Nanos),
            I(Int::I64(-1)),
            I(Int::I64(0)),
            domain::TIMESTAMP,
            Some(12),
        ),
        typed(
            Logical::Decimal { scale: 2 },
            I(Int::I64(-150)),
            I(Int::I64(150)),
            domain::DECIMAL,
            Some(14),
        ),
        typed(
            Logical::Uuid,
            Bytes(&[0; 16]),
            Bytes(&[1; 16]),
            domain::UUID,
            Some(16),
        ),
    ]
}

#[test]
fn every_kind_has_an_order_term_or_is_a_named_exception() {
    let kinds = inventory();
    // One domain per orderable kind, every domain used.
    let mut domains: Vec<_> = kinds.iter().map(|k| k.domain).collect();
    domains.sort_unstable();
    domains.dedup();
    assert_eq!(domains.len(), domain::ALL.len());
    assert_eq!(domain::ALL.len(), 18);
    let scheme = Mock::new(key());
    for kind in &kinds {
        let (below, above) = (
            order(kind.ty, kind.below).expect("term"),
            order(kind.ty, kind.above).expect("term"),
        );
        assert_eq!(below.domain(), kind.domain);
        assert_eq!(below.width(), kind.width, "{}", kind.domain);
        if let Some(width) = kind.width {
            assert_eq!(below.bytes().risky_ref().len(), width, "{}", kind.domain);
        }
        let (x, y) = (
            scheme
                .encrypt_plaintext(&below, &().into_context().encode())
                .expect("mock"),
            scheme
                .encrypt_plaintext(&above, &().into_context().encode())
                .expect("mock"),
        );
        assert_eq!(x.cmp(&y), Ordering::Less, "{}", kind.domain);
    }
    // The exceptions: no order term, and the walk skips them.
    for v in [Physical::Null, Physical::Bool(false), Physical::Bool(true)] {
        assert_eq!(order(None, v).err(), Some(NormalizeError::NoDomain));
    }
    assert_eq!(
        order(Some(Logical::Undefined), Physical::Null).err(),
        Some(NormalizeError::NoDomain)
    );
    // Keep the inventory explicit: a new logical type must add a row above
    // or a named exception here, not inherit a wildcard.
    assert_eq!(
        LAST_KNOWN, 5,
        "a logical type was added: give it an order term or an exception"
    );
}

/// Values equal under the data model give equal terms under both indexes.
#[test]
fn equality_and_order_agree_on_what_is_equal() {
    let same = |ty: Option<Logical>, a: Physical<'_>, b: Physical<'_>| {
        let (ea, eb) = (normalize(ty, a).expect("eq"), normalize(ty, b).expect("eq"));
        let (oa, ob) = (order(ty, a).expect("ord"), order(ty, b).expect("ord"));
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
    // A timestamp is the same instant whatever its unit.
    same(
        Some(Logical::Timestamp(TimeUnit::Millis)),
        Physical::Int(Int::I64(1_700_000_000_123)),
        Physical::Int(Int::I64(1_700_000_000_123)),
    );
    let (ms, us) = (
        normalize(
            Some(Logical::Timestamp(TimeUnit::Millis)),
            Physical::Int(Int::I64(1_700_000_000_123)),
        )
        .expect("eq"),
        order(
            Some(Logical::Timestamp(TimeUnit::Micros)),
            Physical::Int(Int::I64(1_700_000_000_123_000)),
        )
        .expect("ord"),
    );
    assert_eq!(ms.bytes.risky_ref(), us.bytes().risky_ref());
    // A decimal's scale is normalized.
    let (a, b) = (
        order(
            Some(Logical::Decimal { scale: 2 }),
            Physical::Int(Int::I64(150)),
        )
        .expect("ord"),
        order(
            Some(Logical::Decimal { scale: 1 }),
            Physical::Int(Int::I64(15)),
        )
        .expect("ord"),
    );
    assert_eq!(a.bytes().risky_ref(), b.bytes().risky_ref());
    // Signed zero and NaN payloads fold, at both widths.
    same(
        None,
        Physical::Float(Float::F64(-0.0)),
        Physical::Float(Float::F64(0.0)),
    );
    same(
        None,
        Physical::Float(Float::F64(f64::NAN)),
        Physical::Float(Float::F64(-f64::NAN)),
    );
    let (a, b) = (
        order(None, Physical::Float(Float::F32(-0.0))).expect("ord"),
        order(None, Physical::Float(Float::F32(0.0))).expect("ord"),
    );
    assert_eq!(a.bytes().risky_ref(), b.bytes().risky_ref());
    // Canonically equivalent text is one term under both.
    same(None, Physical::Text("e\u{301}"), Physical::Text("\u{e9}"));
    // Where the two indexes differ, on purpose: an order term folds
    // accents and case, an equality term does not.
    let (e_eq, big_eq) = (
        normalize(None, Physical::Text("e")).expect("eq"),
        normalize(None, Physical::Text("É")).expect("eq"),
    );
    assert_ne!(e_eq.bytes.risky_ref(), big_eq.bytes.risky_ref());
    let (e, big) = (
        order(None, Physical::Text("e")).expect("ord"),
        order(None, Physical::Text("É")).expect("ord"),
    );
    assert_eq!(e.bytes().risky_ref(), big.bytes().risky_ref());
    // Shared kinds share their bytes with the equality index exactly.
    for (ty, v) in [
        (Some(Logical::Date), Physical::Int(Int::I32(19_000))),
        (
            Some(Logical::Decimal { scale: 3 }),
            Physical::Int(Int::I64(-12_345)),
        ),
        (Some(Logical::Uuid), Physical::Bytes(&[9; 16])),
        (None, Physical::Bytes(b"raw")),
        (None, Physical::Float(Float::F64(2.5))),
    ] {
        assert_eq!(
            normalize(ty, v).expect("eq").bytes.risky_ref(),
            order(ty, v).expect("ord").bytes().risky_ref()
        );
    }
    // And no order domain is an equality domain.
    for d in domain::ALL {
        assert!(!equality::ALL.contains(d), "{d}");
    }
}

#[test]
fn a_scheme_refuses_a_domain_by_name_not_by_counting_bytes() {
    let fixed = Fixed::<4>(Mock::new(key()));
    let context = ().into_context().encode();
    let date = order(Some(Logical::Date), Physical::Int(Int::I32(1))).expect("term");
    assert!(fixed.encrypt_plaintext(&date, &context).is_ok());
    for (ty, v, domain) in [
        (None, Physical::Int(Int::I8(1)), domain::INT8),
        (None, Physical::Text("abcd"), domain::TEXT),
        (None, Physical::Bytes(&[1, 2, 3, 4]), domain::BYTES),
        (None, Physical::Int(Int::I128(1)), domain::INT128),
    ] {
        let term = order(ty, v).expect("term");
        assert!(
            matches!(
                fixed.encrypt_plaintext(&term, &context),
                Err(OrderError::Unsupported { scheme: "fixed", domain: d }) if d == domain
            ),
            "{domain}"
        );
    }
}

#[test]
fn terms_compare_only_within_one_scheme_key_domain_and_context() {
    let zero = Physical::Int(Int::I8(0));
    let tenant = |n: u64| ("tenant", n);
    let mock = Mock::new(key());
    let under_one = mock
        .encrypt_with_context(Raw(None, zero), tenant(1))
        .expect("mock");
    assert_ne!(
        under_one,
        mock.encrypt_with_context(Raw(None, zero), tenant(2))
            .expect("mock")
    );
    assert_ne!(
        under_one,
        Mock::new(Protected::new([8; 32]))
            .encrypt_with_context(Raw(None, zero), tenant(1))
            .expect("mock")
    );
    assert_ne!(
        under_one,
        Fixed::<1>(Mock::new(key()))
            .encrypt_with_context(Raw(None, zero), tenant(1))
            .expect("fixed")
    );
    // The same bytes under another domain are another term.
    let as_i8 = mock
        .encrypt(Raw(None, Physical::Int(Int::U8(0x80))))
        .expect("mock");
    let as_u8 = mock.encrypt(Raw(None, zero)).expect("mock");
    assert_eq!(as_i8.bytes, as_u8.bytes);
    assert_ne!(as_i8, as_u8);
}

#[test]
fn the_scalar_path_refuses_before_the_scheme_and_passes_the_schemes_failure_through() {
    let mock = Mock::new(key());
    for v in [Physical::Null, Physical::Bool(true)] {
        assert!(matches!(
            mock.encrypt(Raw(None, v)),
            Err(OrderError::Term(NormalizeError::NoDomain))
        ));
    }
    assert!(matches!(
        mock.encrypt(Raw(None, Physical::Text("\u{378}"))),
        Err(OrderError::Term(NormalizeError::UnassignedCodePoint))
    ));
    assert!(matches!(
        mock.encrypt(Raw(Some(Logical::Uuid), Physical::Bytes(&[0; 3]))),
        Err(OrderError::Term(NormalizeError::Invalid))
    ));
    let failed = Down
        .encrypt(Raw(None, Physical::Int(Int::I8(1))))
        .expect_err("down");
    assert!(matches!(failed, OrderError::Backend(_)));
    assert_eq!(
        failed.to_string(),
        "the order scheme failed: the backend is down"
    );
}

#[test]
fn a_scheme_is_keyed_like_a_prf() {
    let from_bytes = Mock::try_from_bytes(Protected::new(vec![7; 32])).expect("32 bytes");
    let term = |scheme: &Mock| {
        scheme
            .encrypt(Raw(None, Physical::Int(Int::I8(1))))
            .expect("mock")
    };
    assert_eq!(term(&from_bytes), term(&Mock::new(key())));
    let short = Mock::try_from_bytes(Protected::new(vec![7; 16]))
        .err()
        .expect("refused");
    assert!(matches!(short, WrongKeyLength(16)));
}

#[quickcheck]
fn order_through_a_scheme_is_value_order(a: i32, b: i32, text_a: String, text_b: String) -> bool {
    let mock = Mock::new(key());
    let under = |v: Physical<'_>| {
        mock.encrypt_with_context(Raw(None, v), "col")
            .expect("mock")
    };
    let ints =
        under(Physical::Int(Int::I32(a))).cmp(&under(Physical::Int(Int::I32(b)))) == a.cmp(&b);
    // Bytes compare as bytes; text ties where it folds together, so only
    // bytes are checked for order here.
    let bytes = under(Physical::Bytes(text_a.as_bytes()))
        .cmp(&under(Physical::Bytes(text_b.as_bytes())))
        == text_a.as_bytes().cmp(text_b.as_bytes());
    ints && bytes
}

#[test]
fn a_mock_term_is_the_plaintext_bytes() {
    // So the tests above are about the plaintext layer, not the mock.
    let term: MockTerm = Mock::new(key())
        .encrypt(Raw(None, Physical::Int(Int::U8(9))))
        .expect("mock");
    assert_eq!(term.as_ref(), &[9]);
}
