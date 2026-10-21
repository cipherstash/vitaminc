//! Spaces that place nulls first or last: every null is the space's
//! sentinel and sorts at its end, the target's maximum is refused, the
//! space is its own space, and a query of a null answers `IS NULL` and
//! bounds a range.

mod common;

use std::cmp::Ordering;

use common::{key, Fixed, Mock};
use vitaminc_aead::{Int, Logical, Physical};
use vitaminc_ore::target::{self, I32};
use vitaminc_ore::{
    domain, order, order_with_nulls, NormalizeError, NullOrder, OrderEncrypt, OrderError,
    OrderKeyInit, OrderTarget, Raw,
};

use OrderTarget as T;

const NULL: Raw<'static> = Raw(None, Physical::Null);

#[test]
fn a_null_sorts_below_every_value_under_nulls_first_and_above_under_nulls_last() {
    let mock = Mock::new(key());
    for (nulls, end) in [
        (NullOrder::First, Ordering::Less),
        (NullOrder::Last, Ordering::Greater),
    ] {
        let ages = mock.context("users.age").target(I32).nulls(nulls);
        assert_eq!(ages.null_order(), Some(nulls), "the space keeps its policy");
        let null = ages.encrypt_null().expect("mock");
        for value in [i32::MIN, -1, 0, 1, i32::MAX - 1] {
            let term = ages.encrypt_checked(value).expect("not the maximum");
            assert_eq!(
                ages.compare(&null, &term),
                Some(end),
                "{nulls:?}: a null is at its end of the space, {value}"
            );
        }
        // A typed null, a plain null and the space's own null are one term.
        let typed = ages.encrypt_checked(None::<i32>).expect("a typed null");
        let narrower = ages.encrypt_checked(None::<i16>).expect("a typed null");
        let plain = ages.encrypt_checked(NULL).expect("a plain null");
        for other in [&typed, &narrower, &plain] {
            assert_eq!(
                ages.compare(&null, other),
                Some(Ordering::Equal),
                "{nulls:?}: every null is the sentinel"
            );
        }
        assert_eq!(typed.nulls(), Some(nulls), "a term carries its policy");
    }
}

#[test]
fn a_space_that_places_nulls_refuses_the_targets_maximum() {
    let mock = Mock::new(key());
    for nulls in [NullOrder::First, NullOrder::Last] {
        let ages = mock.target(I32).nulls(nulls);
        assert!(
            matches!(
                ages.encrypt_checked(i32::MAX),
                Err(OrderError::Term(NormalizeError::Reserved))
            ),
            "{nulls:?}: the maximum is the nulls' code"
        );
        assert!(
            matches!(
                ages.encrypt_checked(i64::from(i32::MAX)),
                Err(OrderError::Term(NormalizeError::Reserved))
            ),
            "{nulls:?}: the maximum at a wider width is refused the same way"
        );
        let ids = mock.target(target::Uuid).nulls(nulls);
        assert!(
            matches!(
                ids.encrypt_checked(Raw(Some(Logical::Uuid), Physical::Bytes(&[0xFF; 16]))),
                Err(OrderError::Term(NormalizeError::Reserved))
            ),
            "{nulls:?}: the maximum uuid is the nulls' code"
        );
        // A float target gives nothing up.
        let scores = mock.target(target::F64).nulls(nulls);
        assert!(scores.encrypt_checked(f64::INFINITY).is_ok());
        assert!(scores.encrypt_checked(f64::NAN).is_ok());
    }
    // The plain space still takes the maximum.
    assert!(mock.target(I32).encrypt(i32::MAX).is_ok());
}

#[test]
fn a_space_without_a_policy_gives_a_null_no_term_as_before() {
    let mock = Mock::new(key());
    let ages = mock.target(I32);
    assert_eq!(ages.null_order(), None);
    for refused in [
        ages.encrypt_checked(None::<i32>).err(),
        ages.encrypt_checked(NULL).err(),
    ] {
        assert!(
            matches!(refused, Some(OrderError::Term(NormalizeError::NoDomain))),
            "a plain space refuses a null"
        );
    }
    assert!(matches!(
        ages.encrypt_query_checked(None::<i32>),
        Err(OrderError::Term(NormalizeError::NoDomain))
    ));
    // An undefined is not a null, whatever the policy.
    let undefined = Raw(Some(Logical::Undefined), Physical::Null);
    assert!(matches!(
        ages.nulls(NullOrder::Last).encrypt_checked(undefined),
        Err(OrderError::Term(NormalizeError::NoDomain))
    ));
}

#[test]
fn a_space_that_places_nulls_is_its_own_space() {
    let mock = Mock::new(key());
    let plain = mock.target(I32).context("users.age");
    let first = plain.nulls(NullOrder::First);
    let last = plain.nulls(NullOrder::Last);
    assert_eq!(plain.domain(), domain::INT32);
    assert_eq!(first.domain(), domain::INT32_NULLS_FIRST);
    assert_eq!(last.domain(), domain::INT32_NULLS_LAST);
    // The salt binds the label, so the three spaces share no salt.
    assert_ne!(plain.salt(), first.salt(), "nulls-first has its own salt");
    assert_ne!(plain.salt(), last.salt(), "nulls-last has its own salt");
    assert_ne!(first.salt(), last.salt(), "the two policies differ");
    // Under nulls-last a value's plaintext is the plain space's bytes, so
    // only the salt keeps the terms apart.
    let in_plain = plain.encrypt(36i32).expect("mock");
    let in_last = last.encrypt_checked(36i32).expect("mock");
    assert_eq!(in_plain.raw().bytes(), in_last.raw().bytes());
    assert_ne!(
        in_plain.raw().salt(),
        in_last.raw().salt(),
        "a nulls-last term is not a plain-space term"
    );
    // A new context keeps the policy.
    let elsewhere = last.context("other");
    assert_eq!(elsewhere.domain(), domain::INT32_NULLS_LAST);
    assert_ne!(elsewhere.salt(), last.salt());
    // The same space, made twice, is the same space.
    assert_eq!(
        last.salt(),
        mock.context("users.age")
            .target(I32)
            .nulls(NullOrder::Last)
            .salt()
    );
}

#[test]
fn a_space_takes_a_collected_term_of_its_own_policy_only() {
    let mock = Mock::new(key());
    let last = mock
        .target(T::I32)
        .nulls(NullOrder::Last)
        .expect("fixed width");
    let placed =
        order_with_nulls(T::I32, NullOrder::Last, None, Physical::Int(Int::I8(3))).expect("term");
    assert!(last.encrypt_term(&placed).is_ok());
    for other in [
        order(T::I32, None, Physical::Int(Int::I8(3))).expect("term"),
        order_with_nulls(T::I32, NullOrder::First, None, Physical::Int(Int::I8(3))).expect("term"),
    ] {
        assert!(
            matches!(
                last.encrypt_term(&other),
                Err(OrderError::Term(NormalizeError::Mismatch))
            ),
            "{}: a term of another space is refused",
            other.domain()
        );
    }
}

/// Both policies of a marker target are one Rust type, `Nulls<I32>`, so
/// a term of one reaches the other's comparison; it carries its policy,
/// and the two compare as `None`.
#[test]
fn a_marker_space_tells_its_two_policies_apart() {
    let mock = Mock::new(key());
    let plain = mock.context("users.age").target(I32);
    let (first, last) = (plain.nulls(NullOrder::First), plain.nulls(NullOrder::Last));
    let (a, b) = (
        first.encrypt_checked(1i32).expect("mock"),
        last.encrypt_checked(1i32).expect("mock"),
    );
    assert_eq!(a.nulls(), Some(NullOrder::First));
    assert_eq!(b.nulls(), Some(NullOrder::Last));
    assert_eq!(first.compare(&a, &a), Some(Ordering::Equal));
    assert_eq!(first.compare(&a, &b), None, "two policies do not compare");
    assert_eq!(last.compare(&a, &b), None, "two policies do not compare");
    let query = last.null_query().expect("mock");
    assert_eq!(query.nulls(), Some(NullOrder::Last));
    assert_eq!(
        first.compare_query(&query, &a),
        None,
        "a query of one policy does not compare with a term of the other"
    );
    assert_eq!(
        last.compare_query(&query, &a),
        None,
        "nor in the space the query came from"
    );
    assert_eq!(
        last.compare_query(&query, &b),
        Some(Ordering::Greater),
        "a nulls-last null sorts above a value of its own space"
    );
}

#[test]
fn a_runtime_space_places_nulls_on_a_fixed_width_target_only() {
    let mock = Mock::new(key());
    for nulls in [NullOrder::First, NullOrder::Last] {
        for target in [T::Text, T::Bytes] {
            assert_eq!(
                mock.target(target).nulls(nulls).err(),
                Some(NormalizeError::NoDomain),
                "{target:?} takes no null policy"
            );
        }
    }
    let first = mock
        .target(T::I32)
        .nulls(NullOrder::First)
        .expect("fixed width");
    let last = mock
        .target(T::I32)
        .nulls(NullOrder::Last)
        .expect("fixed width");
    let (a, b) = (
        first.encrypt_checked(1i8).expect("mock"),
        last.encrypt_checked(1i8).expect("mock"),
    );
    // A runtime term carries its policy, so terms of the two policies
    // compare as `None`, not as noise.
    assert_eq!(first.compare(&a, &a), Some(Ordering::Equal));
    assert_eq!(first.compare(&a, &b), None, "two policies do not compare");
    assert_eq!(last.compare(&b, &a), None, "two policies do not compare");
}

#[test]
fn a_scheme_takes_a_policy_space_exactly_when_it_takes_the_target() {
    let fixed = Fixed::<4>(Mock::new(key()));
    let ages = fixed
        .target(T::I32)
        .nulls(NullOrder::Last)
        .expect("fixed width");
    assert!(
        ages.encrypt_null().is_ok(),
        "four bytes is the scheme's width"
    );
    let wide = fixed
        .target(T::I64)
        .nulls(NullOrder::Last)
        .expect("fixed width");
    assert!(
        matches!(
            wide.encrypt_checked(NULL),
            Err(OrderError::Unsupported { scheme: "fixed", domain: d }) if d == domain::INT64_NULLS_LAST
        ),
        "the refusal names the policy's label"
    );
    // The null's own term and query are refused the same way, before the
    // scheme is handed a plaintext of a width it does not take.
    assert!(
        matches!(
            wide.encrypt_null(),
            Err(OrderError::Unsupported { scheme: "fixed", domain: d }) if d == domain::INT64_NULLS_LAST
        ),
        "the null's term is refused for a target the scheme does not take"
    );
    assert!(
        matches!(
            wide.null_query(),
            Err(OrderError::Unsupported { scheme: "fixed", domain: d }) if d == domain::INT64_NULLS_LAST
        ),
        "the null's query is refused for a target the scheme does not take"
    );
    assert!(
        ages.null_query().is_ok(),
        "four bytes is the scheme's width"
    );
}

/// `IS NULL` is equality with the null's query; a range in a space that
/// places nulls is bounded by it, because a SQL comparison never matches
/// a null.
#[test]
fn a_query_of_a_null_finds_the_nulls_and_bounds_a_range() {
    let mock = Mock::new(key());
    let ages = mock
        .context("users.age")
        .target(I32)
        .nulls(NullOrder::First);
    let rows = [
        ages.encrypt_checked(None::<i32>).expect("mock"),
        ages.encrypt_checked(3i32).expect("mock"),
        ages.encrypt_checked(12i32).expect("mock"),
        ages.encrypt_null().expect("mock"),
    ];
    let is_null = ages.null_query().expect("mock");
    let typed = ages.encrypt_query_checked(None::<i32>).expect("mock");
    let plain = ages.encrypt_query_checked(NULL).expect("mock");
    assert_eq!(is_null, typed, "a typed null's query is the null's query");
    assert_eq!(is_null, plain, "a plain null's query is the null's query");
    assert_eq!(
        is_null.nulls(),
        Some(NullOrder::First),
        "a query carries its space's policy"
    );
    assert_eq!(is_null.target(), T::I32);
    let nulls: Vec<_> = rows
        .iter()
        .map(|row| ages.compare_query(&is_null, row) == Some(Ordering::Equal))
        .collect();
    assert_eq!(nulls, [true, false, false, true], "IS NULL finds the nulls");
    // `age < 10` under nulls-first: above the sentinel and below 10.
    let ten = ages.encrypt_query_checked(10i32).expect("mock");
    let below_ten: Vec<_> = rows
        .iter()
        .map(|row| {
            ages.compare_query(&is_null, row) == Some(Ordering::Less)
                && ages.compare_query(&ten, row) == Some(Ordering::Greater)
        })
        .collect();
    assert_eq!(
        below_ten,
        [false, true, false, false],
        "age < 10 skips the nulls"
    );
}
