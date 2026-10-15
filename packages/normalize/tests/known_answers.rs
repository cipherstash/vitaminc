//! Every term this crate produces, checked against today's `canonical`
//! encoders in `vitaminc-aead-value` byte for byte, and the terms sink
//! beside encryption.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, Utc};
use futures_executor::block_on;
use vitaminc_aead::plaintext::kinds::chrono as conv;
use vitaminc_aead::seal::{AsyncCipher, Cipher};
use vitaminc_aead::{
    Context, EncryptError, Float, Int, Logical, Physical, Plaintext, Sink, TimeUnit,
};
use vitaminc_aead_value::canonical::equality_input;
use vitaminc_aead_value::Value;
use vitaminc_normalize::{
    domain, encrypt_with_terms, encrypt_with_terms_async, normalize, plan_with_terms,
    NormalizeError, Step, Term,
};
use vitaminc_protected::{Controlled, Protected};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The new term for a scalar must be the old term for the equivalent
/// `Value`, domain and bytes.
#[track_caller]
fn same(ty: Option<Logical>, v: Physical<'_>, value: Value) {
    let new = normalize(ty, v).expect("normalizes");
    let old = equality_input(&value).expect("has a term");
    assert_eq!(new.domain, old.domain);
    assert_eq!(
        hex(new.bytes.risky_ref()),
        hex(old.bytes.risky_ref()),
        "{}",
        old.domain
    );
}

#[test]
fn every_integer_width_matches_todays_term() {
    for n in [0i128, 1, 5, -7, 127, -128, 255, 65_535, -32_768] {
        if let Ok(v) = i8::try_from(n) {
            same(None, Physical::Int(Int::I8(v)), Value::Int8(v));
        }
        if let Ok(v) = u8::try_from(n) {
            same(None, Physical::Int(Int::U8(v)), Value::UInt8(v));
        }
        if let Ok(v) = i16::try_from(n) {
            same(None, Physical::Int(Int::I16(v)), Value::Int16(v));
        }
        if let Ok(v) = u16::try_from(n) {
            same(None, Physical::Int(Int::U16(v)), Value::UInt16(v));
        }
        if let Ok(v) = i32::try_from(n) {
            same(None, Physical::Int(Int::I32(v)), Value::Int32(v));
        }
        if let Ok(v) = u32::try_from(n) {
            same(None, Physical::Int(Int::U32(v)), Value::UInt32(v));
        }
        if let Ok(v) = i64::try_from(n) {
            same(None, Physical::Int(Int::I64(v)), Value::Int64(v));
        }
        if let Ok(v) = u64::try_from(n) {
            same(None, Physical::Int(Int::U64(v)), Value::UInt64(v));
        }
        same(None, Physical::Int(Int::I128(n)), Value::Int128(n));
        if let Ok(v) = u128::try_from(n) {
            same(None, Physical::Int(Int::U128(v)), Value::UInt128(v));
        }
    }
    for v in [i128::MIN, i128::MAX] {
        same(None, Physical::Int(Int::I128(v)), Value::Int128(v));
    }
    for v in [i8::MIN, i8::MAX] {
        same(None, Physical::Int(Int::I8(v)), Value::Int8(v));
    }
    for v in [i16::MIN, i16::MAX] {
        same(None, Physical::Int(Int::I16(v)), Value::Int16(v));
    }
    for v in [i32::MIN, i32::MAX] {
        same(None, Physical::Int(Int::I32(v)), Value::Int32(v));
    }
    for v in [i64::MIN, i64::MAX] {
        same(None, Physical::Int(Int::I64(v)), Value::Int64(v));
    }
    same(None, Physical::Int(Int::U8(u8::MAX)), Value::UInt8(u8::MAX));
    same(
        None,
        Physical::Int(Int::U16(u16::MAX)),
        Value::UInt16(u16::MAX),
    );
    same(
        None,
        Physical::Int(Int::U32(u32::MAX)),
        Value::UInt32(u32::MAX),
    );
    same(
        None,
        Physical::Int(Int::U64(u64::MAX)),
        Value::UInt64(u64::MAX),
    );
    same(
        None,
        Physical::Int(Int::U128(u128::MAX)),
        Value::UInt128(u128::MAX),
    );
}

#[test]
fn both_float_widths_match_todays_term() {
    for v in [
        0.0f32,
        -0.0,
        1.5,
        -1.5,
        0.1,
        f32::MAX,
        f32::MIN_POSITIVE,
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::NAN,
        f32::from_bits(0xff80_0001),
        f32::from_bits(1),
    ] {
        same(None, Physical::Float(Float::F32(v)), Value::Float32(v));
    }
    for v in [
        0.0f64,
        -0.0,
        1.5,
        0.1,
        f64::MAX,
        f64::MIN_POSITIVE,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        f64::from_bits(0xfff0_0000_0000_0001),
    ] {
        same(None, Physical::Float(Float::F64(v)), Value::Float64(v));
    }
}

#[test]
fn text_and_bytes_match_todays_term() {
    for s in ["", "Ada", "e\u{301}", "\u{344}", "a\0b", "日本語"] {
        same(None, Physical::Text(s), Value::String(s.into()));
    }
    for b in [&[][..], &[0], &[1, 2, 3], &[0xff; 40]] {
        same(
            None,
            Physical::Bytes(b),
            Value::Bytes(Protected::new(b.to_vec())),
        );
    }
    assert_eq!(
        normalize(None, Physical::Text("\u{378}")).expect_err("unassigned"),
        NormalizeError::UnassignedCodePoint
    );
}

#[test]
fn dates_match_todays_term() {
    for date in [
        NaiveDate::MIN,
        NaiveDate::from_ymd_opt(1, 1, 1).expect("date"),
        NaiveDate::from_ymd_opt(1969, 12, 31).expect("date"),
        NaiveDate::from_ymd_opt(1970, 1, 1).expect("date"),
        NaiveDate::from_ymd_opt(2024, 2, 29).expect("date"),
        NaiveDate::MAX,
    ] {
        same(
            Some(Logical::Date),
            Physical::Int(Int::I32(conv::date_days(date))),
            Value::Date(date),
        );
    }
}

#[test]
fn timestamps_in_every_unit_match_todays_term() {
    for (seconds, nanos) in [
        (0, 0),
        (-1, 123_456_789),
        (59, 999_999_999),
        (1_700_000_000, 123_456_789),
        (-62_000_000_000, 5_000),
    ] {
        let ts = DateTime::<Utc>::from_timestamp(seconds, nanos).expect("timestamp");
        let nanos = conv::timestamp_nanos(ts).expect("not a leap second");
        same(
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            Physical::Int(Int::I128(nanos)),
            Value::Timestamp(ts),
        );
        // Coarser units truncate the same way, so they match the old term
        // of the instant at that precision.
        for (unit, per) in [
            (TimeUnit::Micros, 1_000i128),
            (TimeUnit::Millis, 1_000_000),
            (TimeUnit::Seconds, 1_000_000_000),
        ] {
            let count = nanos.div_euclid(per);
            let truncated = DateTime::<Utc>::from_timestamp(
                (count * per).div_euclid(1_000_000_000) as i64,
                ((count * per).rem_euclid(1_000_000_000)) as u32,
            )
            .expect("timestamp");
            same(
                Some(Logical::Timestamp(unit)),
                Physical::Int(Int::I64(i64::try_from(count).expect("fits"))),
                Value::Timestamp(truncated),
            );
        }
    }
    for ts in [DateTime::<Utc>::MIN_UTC, DateTime::<Utc>::MAX_UTC] {
        let nanos = conv::timestamp_nanos(ts).expect("not a leap second");
        same(
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            Physical::Int(Int::I128(nanos)),
            Value::Timestamp(ts),
        );
    }
}

#[test]
fn decimals_match_todays_term() {
    for s in [
        "0",
        "0.0",
        "-0.00",
        "1",
        "1.0",
        "1.50",
        "1.5",
        "-1.5",
        "0.001",
        "123456789.987654321",
        "79228162514264337593543950335",
        "-79228162514264337593543950335",
        "0.0000000000000000000000000001",
    ] {
        let d: rust_decimal::Decimal = s.parse().expect("decimal");
        same(
            Some(Logical::Decimal {
                scale: d.scale() as u8,
            }),
            Physical::Int(Int::I128(d.mantissa())),
            Value::Decimal(d),
        );
    }
}

#[test]
fn a_uuid_has_a_domain_of_its_own() {
    let id = uuid::Uuid::from_bytes([
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
        0xf0,
    ]);
    let n = normalize(Some(Logical::Uuid), Physical::Bytes(id.as_bytes())).expect("uuid");
    assert_eq!(n.domain, "vitaminc/prf/value/uuid/v1");
    assert_eq!(hex(n.bytes.risky_ref()), "123456789abcdef0123456789abcdef0");
    let plain = normalize(None, Physical::Bytes(id.as_bytes())).expect("bytes");
    assert_eq!(hex(plain.bytes.risky_ref()), hex(n.bytes.risky_ref()));
    assert_ne!(plain.domain, n.domain);
    // The uuid source carries its logical type, so the two never meet.
    let mut terms = Vec::new();
    let (_, ()) = id
        .visit(vitaminc_aead::Tee(
            vitaminc_aead::EncryptSink::<()>::root(()),
            vitaminc_normalize::Terms::new(&mut terms),
        ))
        .expect("walks");
    assert_eq!(terms[0].normalized.domain, domain::UUID);
}

#[test]
fn a_date_never_matches_its_day_count_and_widths_agree() {
    let date = NaiveDate::from_ymd_opt(2024, 2, 29).expect("date");
    let days = conv::date_days(date);
    let as_date = normalize(Some(Logical::Date), Physical::Int(Int::I32(days))).expect("date");
    let as_int = normalize(None, Physical::Int(Int::I32(days))).expect("int");
    assert_ne!(as_date.domain, as_int.domain);
    assert_ne!(as_date.bytes.risky_ref(), as_int.bytes.risky_ref());
    let narrow = normalize(None, Physical::Int(Int::I8(34))).expect("i8");
    let wide = normalize(None, Physical::Int(Int::U64(34))).expect("u64");
    assert_eq!(narrow.domain, wide.domain);
    assert_eq!(narrow.bytes.risky_ref(), wide.bytes.risky_ref());
}

// The terms sink beside encryption.

#[derive(Debug, Clone, PartialEq, Eq)]
struct Leaf {
    aad: Vec<u8>,
    plaintext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refused;

/// Seals in the clear and counts calls, so a test can see when the cipher
/// first runs.
#[derive(Default)]
struct Counting {
    calls: AtomicUsize,
}

impl Cipher for Counting {
    type Leaf = Leaf;
    type Error = Refused;

    fn seal(&self, plaintext: Protected<Vec<u8>>, aad: &Context<'_>) -> Result<Leaf, Refused> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Leaf {
            aad: aad.as_bytes().to_vec(),
            plaintext: plaintext.risky_unwrap(),
        })
    }

    fn open(&self, leaf: Leaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Refused> {
        if leaf.aad != aad.as_bytes() {
            return Err(Refused);
        }
        Ok(Protected::new(leaf.plaintext))
    }
}

fn user() -> BTreeMap<&'static str, Vec<Option<u32>>> {
    let mut m = BTreeMap::new();
    m.insert("ages", vec![Some(36), None, Some(41)]);
    m.insert("empty", vec![]);
    m
}

fn paths(terms: &[Term]) -> Vec<Vec<Step>> {
    terms.iter().map(|t| t.path.clone()).collect()
}

#[test]
fn plan_with_terms_has_every_term_without_a_cipher() {
    let (planned, terms) = plan_with_terms::<_, Refused, _>(user(), "ctx").expect("plans");
    assert_eq!(
        paths(&terms),
        [
            vec![Step::Key("ages".into()), Step::Index(0)],
            vec![Step::Key("ages".into()), Step::Index(2)],
        ]
    );
    assert_eq!(terms[0].normalized.domain, domain::INTEGER);
    assert_eq!(
        terms[1].normalized.bytes.risky_ref(),
        normalize(None, Physical::Int(Int::U32(41)))
            .expect("int")
            .bytes
            .risky_ref()
    );
    // The plan is the same one `encrypt` would seal.
    let sealed = vitaminc_aead::seal::seal_all(&Counting::default(), planned).expect("seals");
    assert!(matches!(sealed, vitaminc_aead::CipherText::Map(_)));
}

#[test]
fn encrypt_with_terms_seals_the_same_leaves_and_returns_the_terms() {
    let cipher = Counting::default();
    let (sealed, terms) = encrypt_with_terms(user(), &cipher, "ctx").expect("encrypts");
    assert_eq!(terms.len(), 2);
    // Three elements, one empty marker.
    assert_eq!(cipher.calls.load(Ordering::SeqCst), 4);
    let back: BTreeMap<String, Vec<Option<u32>>> =
        vitaminc_aead::decrypt(&cipher, sealed, "ctx").expect("decrypts");
    assert_eq!(back["ages"], [Some(36), None, Some(41)]);
}

#[test]
fn scalars_without_a_domain_and_passthroughs_get_no_term() {
    struct Doc;
    impl Plaintext for Doc {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            use vitaminc_aead::MapSink;
            let mut map = sink.map(Some(5))?;
            true.visit(map.entry("active")?)?;
            None::<u32>.visit(map.entry("missing")?)?;
            map.entry("tenant")?.passthrough("acme")?;
            vitaminc_aead::Raw(Some(Logical::Undefined), Physical::Null)
                .visit(map.entry("undefined")?)?;
            "Ada".visit(map.entry("name")?)?;
            map.end()
        }
    }
    let (_, terms) = plan_with_terms::<_, Refused, _>(Doc, "ctx").expect("plans");
    assert_eq!(paths(&terms), [vec![Step::Key("name".into())]]);
    assert_eq!(terms[0].normalized.domain, domain::TEXT);
}

/// A logical type this build does not know means something to the client
/// that sent it, so it is refused rather than encrypted with no term.
#[test]
fn an_unknown_logical_type_stops_the_walk() {
    let newer = vitaminc_aead::Raw(
        Some(Logical::from_wire(200, 0).expect("unknown")),
        Physical::Int(Int::I32(1)),
    );
    let err = plan_with_terms::<_, Refused, _>(vec![newer], "ctx")
        .err()
        .expect("refused");
    match err {
        EncryptError::Source(source) => assert_eq!(
            source.inner().downcast_ref::<NormalizeError>().copied(),
            Some(NormalizeError::NoDomain)
        ),
        other => panic!("{other:?}"),
    }
}

/// Nested paths are the container's path plus the step, at every depth.
#[test]
fn paths_follow_the_nesting() {
    let mut inner = BTreeMap::new();
    inner.insert("k", vec![vec![1u8, 2]]);
    let mut outer = BTreeMap::new();
    outer.insert("m", vec![inner]);
    let (_, terms) = plan_with_terms::<_, Refused, _>(outer, "ctx").expect("plans");
    assert_eq!(
        paths(&terms),
        [vec![
            Step::Key("m".into()),
            Step::Index(0),
            Step::Key("k".into()),
            Step::Index(0),
        ]]
    );
    assert_eq!(terms[0].normalized.domain, domain::BYTES);
}

#[test]
fn an_unassigned_code_point_stops_the_walk_with_the_normalize_error() {
    let err = plan_with_terms::<_, Refused, _>("\u{378}", "ctx")
        .err()
        .expect("refused");
    match err {
        EncryptError::Source(source) => {
            assert_eq!(
                source.inner().downcast_ref::<NormalizeError>().copied(),
                Some(NormalizeError::UnassignedCodePoint)
            );
        }
        other => panic!("{other:?}"),
    }
}

/// Seals through an await, and checks that the source's walk had finished
/// before the first one.
struct Remote {
    walked: &'static AtomicBool,
}

impl AsyncCipher for Remote {
    type Leaf = Leaf;
    type Error = Refused;

    async fn seal(
        &self,
        plaintext: Protected<Vec<u8>>,
        aad: Context<'static>,
    ) -> Result<Leaf, Refused> {
        assert!(
            self.walked.load(Ordering::SeqCst),
            "sealed before the walk ended"
        );
        Counting::default().seal(plaintext, &aad)
    }

    async fn open(&self, leaf: Leaf, aad: Context<'static>) -> Result<Protected<Vec<u8>>, Refused> {
        Counting::default().open(leaf, &aad)
    }
}

#[test]
fn encrypt_with_terms_async_has_every_term_before_its_first_await() {
    static WALKED: AtomicBool = AtomicBool::new(false);
    struct Source;
    impl Plaintext for Source {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let out = vec![1u32, 2].visit(sink);
            WALKED.store(true, Ordering::SeqCst);
            out
        }
    }
    let remote = Remote { walked: &WALKED };
    let future = encrypt_with_terms_async(Source, &remote, "ctx");
    // The walk ran, and the terms exist, before the future is polled.
    assert!(WALKED.load(Ordering::SeqCst));
    fn assert_send<T: Send>(t: T) -> T {
        t
    }
    let (sealed, terms) = block_on(assert_send(future)).expect("encrypts");
    assert_eq!(paths(&terms), [vec![Step::Index(0)], vec![Step::Index(1)]]);
    let back: Vec<u32> =
        block_on(vitaminc_aead::decrypt_async(&remote, sealed, "ctx")).expect("decrypts");
    assert_eq!(back, [1, 2]);
}
