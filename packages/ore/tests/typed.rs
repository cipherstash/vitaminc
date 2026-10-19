//! The chained API under a target named when the program is compiled:
//! what the compiler lets through always encrypts, every chain lands in
//! the space it spells out, and a term carries its target.

mod common;

use std::cmp::Ordering;

use common::{key, BackendDown, Down, Fixed, Mock, MockTerm};
use vitaminc_aead::{Bytes, Int, Logical, Physical};
use vitaminc_ore::target::{self, StaticTarget};
use vitaminc_ore::{
    order, FitsIn, IntoContext, NormalizeError, OrderEncrypt, OrderError, OrderKeyInit,
    OrderScheme, OrderSpace, OrderTarget, OrderTerm, Raw, Supports,
};
use vitaminc_protected::Controlled;

use OrderTarget as T;

/// The plaintext bytes a term encrypts, which the mock keeps as they are.
fn bytes<Tg: vitaminc_ore::Target>(term: &OrderTerm<MockTerm, Tg>) -> &[u8] {
    &term.raw().bytes
}

// The borrows exercise the `&V` rows of the table, on purpose.
#[allow(clippy::needless_borrows_for_generic_args)]
#[test]
fn a_space_under_a_marker_takes_what_always_fits_and_checks_the_rest() {
    let mock = Mock::new(key());
    let quantity = mock.target(target::I32).context(("orders", "quantity"));
    // Narrower integers of either sign fit; so do references to them.
    let (a, b, c, d) = (
        quantity.encrypt(-3i8).expect("fits"),
        quantity.encrypt(42i16).expect("fits"),
        quantity.encrypt(&300i32).expect("fits"),
        quantity.encrypt(u16::MAX).expect("fits"),
    );
    assert_eq!(quantity.compare(&a, &b), Some(Ordering::Less));
    assert_eq!(quantity.compare(&b, &c), Some(Ordering::Less));
    assert_eq!(quantity.compare(&c, &d), Some(Ordering::Less));
    assert_eq!(a.target(), T::I32);
    // Every term is the one the target's encoding gives.
    assert_eq!(
        bytes(&b),
        order(T::I32, None, Physical::Int(Int::I16(42)))
            .expect("term")
            .bytes()
            .risky_ref()
    );
    // A wider type is checked while the program runs, and compares with
    // the fitting ones.
    let checked = quantity.encrypt_checked(43i64).expect("in range");
    assert_eq!(quantity.compare(&b, &checked), Some(Ordering::Less));
    assert!(matches!(
        quantity.encrypt_checked(1i64 << 40),
        Err(OrderError::Term(NormalizeError::OutOfRange))
    ));
    assert!(matches!(
        quantity.encrypt_checked("42"),
        Err(OrderError::Term(NormalizeError::Mismatch))
    ));
}

/// Every row of the `FitsIn` table, at the extremes of its type, encrypts
/// without being refused: the one promise `encrypt` makes.
#[allow(clippy::needless_borrows_for_generic_args)]
#[test]
fn every_fits_in_row_encrypts_at_its_extremes() {
    let mock = Mock::new(key());
    fn row<Tg: StaticTarget, V: FitsIn<Tg> + Copy>(space: &OrderSpace<'_, Mock, Tg>, values: &[V])
    where
        Mock: Supports<Tg>,
    {
        for v in values {
            let term = space.encrypt(*v).expect("the mock cannot fail");
            assert_eq!(term.target(), Tg::TARGET);
            assert_eq!(
                bytes(&term).len(),
                Tg::TARGET.width().unwrap_or(bytes(&term).len())
            );
        }
    }
    let i8s = [i8::MIN, 0, i8::MAX];
    let i16s = [i16::MIN, 0, i16::MAX];
    let u16s = [0, u16::MAX];
    let i32s = [i32::MIN, 0, i32::MAX];
    let u32s = [0, u32::MAX];
    let i64s = [i64::MIN, 0, i64::MAX];
    let u64s = [0, u64::MAX];
    let i128s = [i128::MIN, 0, i128::MAX];
    let u128s = [0, u128::MAX];

    let s = mock.target(target::I8);
    row(&s, &i8s);
    let s = mock.target(target::I16);
    row(&s, &i8s);
    row(&s, &i16s);
    let s = mock.target(target::U16);
    row(&s, &u16s);
    let s = mock.target(target::I32);
    row(&s, &i8s);
    row(&s, &i16s);
    row(&s, &i32s);
    row(&s, &u16s);
    let s = mock.target(target::U32);
    row(&s, &u16s);
    row(&s, &u32s);
    let s = mock.target(target::I64);
    row(&s, &i8s);
    row(&s, &i16s);
    row(&s, &i32s);
    row(&s, &i64s);
    row(&s, &u16s);
    row(&s, &u32s);
    let s = mock.target(target::U64);
    row(&s, &u16s);
    row(&s, &u32s);
    row(&s, &u64s);
    let s = mock.target(target::I128);
    row(&s, &i8s);
    row(&s, &i16s);
    row(&s, &i32s);
    row(&s, &i64s);
    row(&s, &i128s);
    row(&s, &u16s);
    row(&s, &u32s);
    row(&s, &u64s);
    let s = mock.target(target::U128);
    row(&s, &u16s);
    row(&s, &u32s);
    row(&s, &u64s);
    row(&s, &u128s);
    let s = mock.target(target::F64);
    row(
        &s,
        &[f32::MIN, f32::NAN, f32::INFINITY, f32::MIN_POSITIVE, 0.0],
    );
    row(
        &s,
        &[f64::MIN, f64::NAN, f64::INFINITY, f64::MIN_POSITIVE, 0.0],
    );
    let s = mock.target(target::Bytes);
    row(&s, &[&b""[..], &[0xff; 3][..]]);
    row(&s, &[[0u8; 0]]);
    row(&s, &[Bytes(b"raw")]);
    s.encrypt(vec![1u8, 2]).expect("bytes");
    s.encrypt(&vec![1u8, 2]).expect("bytes");
    s.encrypt(&[1u8, 2]).expect("bytes");
    // The typed values at their own extremes.
    use chrono::{NaiveDate, NaiveDateTime};
    let s = mock.target(target::Date);
    row(&s, &[NaiveDate::MIN, NaiveDate::MAX]);
    s.encrypt(&NaiveDate::MAX).expect("date");
    let s = mock.target(target::Timestamp);
    for instant in [NaiveDateTime::MIN, NaiveDateTime::MAX] {
        let ts = vitaminc_aead::Timestamp::new(instant.and_utc()).expect("not a leap second");
        s.encrypt(&ts).expect("timestamp");
        s.encrypt(ts).expect("timestamp");
    }
    let s = mock.target(target::Decimal);
    row(
        &s,
        &[rust_decimal::Decimal::MIN, rust_decimal::Decimal::MAX],
    );
    row(&s, &[rust_decimal::Decimal::new(1, 28)]);
    let s = mock.target(target::Uuid);
    row(&s, &[uuid::Uuid::nil(), uuid::Uuid::max()]);
}

/// A chain that names no target uses the type's own, and one that names
/// no context uses the empty one: each lands in the same space as the
/// chain that spells both out.
#[test]
fn every_chain_lands_in_the_space_it_spells_out() {
    let mock = Mock::new(key());
    let spelt = mock.target(target::I64).context(("t", 7u64));
    assert_eq!(
        mock.context(("t", 7u64)).encrypt(42i64).expect("mock"),
        spelt.encrypt(42i64).expect("mock")
    );
    assert_eq!(
        mock.encrypt(42i64).expect("mock"),
        mock.target(target::I64)
            .context(())
            .encrypt(42i64)
            .expect("mock")
    );
    assert_eq!(
        mock.encrypt(42i64).expect("mock"),
        mock.target(target::I64).encrypt(42i64).expect("mock")
    );
    // The two orders of the chain are one space.
    assert_eq!(
        mock.context(("t", 7u64)).target(target::I64).salt(),
        spelt.salt()
    );
    // The default context is the empty one, in the salt.
    let empty = ().into_context().encode();
    assert_eq!(
        mock.target(target::I64).salt(),
        mock.target(target::I64).context(()).salt()
    );
    assert!(mock
        .target(target::I64)
        .salt()
        .as_bytes()
        .ends_with(empty.as_bytes()));
    // An f32 is an F64, text is Text, bytes are Bytes.
    assert_eq!(mock.encrypt(1.5f32).expect("mock").target(), T::F64);
    assert_eq!(mock.encrypt_checked("abc").expect("mock").target(), T::Text);
    assert_eq!(mock.encrypt(vec![1u8]).expect("mock").target(), T::Bytes);
    assert_eq!(mock.encrypt(&b"raw"[..]).expect("mock").target(), T::Bytes);
    // The checked chains land in the same space as the fitting ones.
    assert_eq!(
        mock.encrypt_checked(42i64).expect("mock"),
        mock.encrypt(42i64).expect("mock")
    );
    assert_eq!(
        mock.context("c").encrypt_checked(42i64).expect("mock"),
        mock.context("c").encrypt(42i64).expect("mock")
    );
    // A value that can be refused has a checked chain only.
    assert!(matches!(
        mock.encrypt_checked("\u{378}"),
        Err(OrderError::Term(NormalizeError::UnassignedCodePoint))
    ));
}

/// The typed values callers hold encrypt, without a check, into the
/// space of their type, as the typed scalar they stand for.
#[test]
fn typed_values_fit_the_space_of_their_type() {
    use chrono::{NaiveDate, TimeZone, Utc};
    use rust_decimal::Decimal;
    let mock = Mock::new(key());
    let typed = |target, ty: Logical, v: Physical<'_>| {
        mock.target(target)
            .encrypt_checked(Raw(Some(ty), v))
            .expect("typed")
            .into_raw()
    };
    // 2022-01-08 is day 19_000 after 1970-01-01.
    let day = NaiveDate::from_ymd_opt(2022, 1, 8).expect("date");
    assert_eq!(
        mock.encrypt(day).expect("date").into_raw(),
        typed(T::Date, Logical::Date, Physical::Int(Int::I32(19_000)))
    );
    let at = Utc
        .timestamp_opt(1_700_000_000, 123_456_789)
        .single()
        .expect("instant");
    let ts = vitaminc_aead::Timestamp::new(at).expect("not a leap second");
    assert_eq!(
        mock.encrypt(ts).expect("timestamp").into_raw(),
        typed(
            T::Timestamp,
            Logical::Timestamp(vitaminc_aead::TimeUnit::Micros),
            Physical::Int(Int::I64(1_700_000_000_123_456))
        )
    );
    // A `DateTime<Utc>` may be a leap second, so it is checked.
    assert_eq!(
        mock.encrypt_checked(at).expect("timestamp").into_raw(),
        mock.target(target::Timestamp)
            .encrypt_checked(at)
            .expect("timestamp")
            .into_raw()
    );
    assert_eq!(
        mock.encrypt(Decimal::new(150, 2)).expect("decimal"),
        mock.encrypt(Decimal::new(15, 1)).expect("decimal")
    );
    let id = uuid::Uuid::from_bytes([9; 16]);
    assert_eq!(
        mock.encrypt(id).expect("uuid").into_raw(),
        typed(T::Uuid, Logical::Uuid, Physical::Bytes(&[9; 16]))
    );
}

/// A term under an `OrderTarget` carries its target, so two of different
/// targets, or a term of another target than the space's, have no order.
#[test]
fn a_term_under_a_runtime_target_compares_only_with_its_own() {
    let mock = Mock::new(key());
    let (i32s, i64s) = (mock.target(T::I32), mock.target(T::I64));
    let (a, b) = (
        i32s.encrypt_checked(1i32).expect("mock"),
        i64s.encrypt_checked(2i32).expect("mock"),
    );
    assert_eq!(a.target(), T::I32);
    assert_eq!(b.target(), T::I64);
    assert_eq!(i32s.compare(&a, &b), None);
    assert_eq!(i64s.compare(&a, &b), None);
    assert_eq!(i64s.compare(&a, &a), None);
    let c = i32s.encrypt_checked(2i32).expect("mock");
    assert_eq!(i32s.compare(&a, &c), Some(Ordering::Less));
    // Both terms must be the space's, not either: a term of this space's
    // raw bytes labelled as another target's is refused on the label
    // alone, from either side, though the scheme would order the bytes.
    let mislabelled = i64s.term(a.raw().clone());
    assert_eq!(
        Mock::compare(a.raw(), mislabelled.raw()),
        Some(Ordering::Equal)
    );
    assert_eq!(i32s.compare(&a, &mislabelled), None);
    assert_eq!(i32s.compare(&mislabelled, &a), None);
    // A raw term read back is labelled as the space's, and compares.
    let read_back = i32s.term(a.raw().clone());
    assert_eq!(read_back, a);
    assert_eq!(i32s.compare(&read_back, &c), Some(Ordering::Less));
    assert_eq!(read_back.as_bytes(), a.as_ref());
}

/// A space under another context is another space; under the same
/// context it is the same one.
#[test]
fn a_space_under_another_context_is_another_space() {
    let mock = Mock::new(key());
    let a = mock.target(target::I32).context("a");
    let again = a.context("a");
    let b = a.context("b");
    assert_eq!(a.salt(), again.salt());
    assert_ne!(a.salt(), b.salt());
    assert_eq!(a.target(), T::I32);
    let (x, y) = (
        a.encrypt(1i32).expect("mock"),
        b.encrypt(1i32).expect("mock"),
    );
    assert_ne!(x, y);
    assert_eq!(a.compare(&x, &y), None, "the mock can tell");
}

/// A target chosen while the program runs is refused by the scheme it is
/// opened on; one named when it is compiled was checked then.
#[test]
fn a_runtime_target_the_scheme_does_not_take_is_refused_before_the_value() {
    let fixed = Fixed::<4>(Mock::new(key()));
    assert!(fixed.target(target::I32).encrypt(1i8).is_ok());
    assert!(fixed
        .target(target::Date)
        .encrypt(chrono::NaiveDate::MAX)
        .is_ok());
    assert!(<Fixed<4> as Supports<OrderTarget>>::supports(T::I32));
    assert!(!<Fixed<4> as Supports<OrderTarget>>::supports(T::Text));
    // Refused by target, whatever the value: a mismatched value is not
    // looked at.
    assert!(matches!(
        fixed.target(T::Text).encrypt_checked(7u32),
        Err(OrderError::Unsupported { scheme: "fixed", domain }) if domain == vitaminc_ore::domain::TEXT
    ));
    let p = order(T::I64, None, Physical::Int(Int::I8(1))).expect("term");
    assert!(matches!(
        fixed.target(T::I64).encrypt_term(&p),
        Err(OrderError::Unsupported { .. })
    ));
}

/// The scheme's own failure is the one error `encrypt` has, and it comes
/// back as the scheme's type, not wrapped.
#[test]
fn a_fitting_value_fails_only_as_the_scheme_fails() {
    assert!(matches!(
        Down.target(target::I8).encrypt(1i8),
        Err(BackendDown)
    ));
    assert!(matches!(Down.encrypt(1i64), Err(BackendDown)));
    assert!(matches!(Down.context("c").encrypt(1i64), Err(BackendDown)));
}

#[test]
#[allow(deprecated)]
fn the_deprecated_column_is_a_target_then_a_context() {
    let mock = Mock::new(key());
    let column: vitaminc_ore::OrderColumn<'_, Mock> = mock.column(T::I32, "c");
    let space = mock.target(T::I32).context("c");
    assert_eq!(column.salt(), space.salt());
    assert_eq!(
        column.encrypt_checked(1i32).expect("mock"),
        space.encrypt_checked(1i32).expect("mock")
    );
}

/// A space and a context show what is not secret and mask the scheme,
/// which holds the key; a term shows its target and the scheme's term.
#[test]
fn spaces_contexts_and_terms_debug_without_the_key() {
    let mock = Mock::new(key());
    let context = mock.context(("orders", "total"));
    let shown = format!("{context:?}");
    assert!(shown.contains(r#"scheme: "***""#), "{shown}");
    assert!(!shown.contains("***\", context: \"***"), "{shown}");
    let space = context.target(target::I32);
    let shown = format!("{space:?}");
    assert!(
        shown.ends_with(r#"OrderSpace<'_, typed::common::Mock, vitaminc_ore::target::I32> { scheme: "***", target: I32, salt: "***" }"#),
        "{shown}"
    );
    let term = space.encrypt(1i32).expect("mock");
    let shown = format!("{term:?}");
    assert!(shown.starts_with("OrderTerm { raw: MockTerm {"), "{shown}");
    assert!(shown.ends_with("target: I32 }"), "{shown}");
}
