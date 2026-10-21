//! Conformance checks a scheme crate runs against its real scheme, behind
//! the `test-support` feature.
//!
//! This crate tests the [`OrderScheme`](crate::OrderScheme) contract through mocks, which
//! proves the trait and the spaces, not any scheme. A scheme crate calls
//! [`conformance`] with two instances of its scheme under different keys
//! and [`static_target`] for every marker it implements, from its own
//! tests, and the checks here fail on the mistakes a scheme can make:
//! a term that does not depend on the key or the salt (the empty text
//! and bytes terms once did not), an order the scheme does not keep, a
//! target refused at runtime that a marker impl vouches for. Every
//! fixed-width target is also checked in a nulls-first and a nulls-last
//! space, so a scheme meets an all-zero and an all-ones plaintext, the
//! two sentinels.
//!
//! ```
//! # use vitaminc_ore::{Context, OrderPlaintext, OrderScheme};
//! # use vitaminc_protected::{Controlled, Protected};
//! # /// A toy: the key byte, the salt's length and the salt, then the
//! # /// plaintext. Terms compare when their key and salt agree.
//! # struct Keyed(u8);
//! # impl OrderScheme for Keyed {
//! #     const NAME: &'static str = "keyed";
//! #     type Term = Vec<u8>;
//! #     type Error = core::convert::Infallible;
//! #     type Space = Protected<Vec<u8>>;
//! #     fn open(&self, _: vitaminc_ore::OrderTarget, salt: &Context<'_>) -> Result<Self::Space, Self::Error> {
//! #         Ok(Protected::new(salt.as_bytes().to_vec()))
//! #     }
//! #     fn encrypt_plaintext(&self, salt: &Self::Space, p: &OrderPlaintext) -> Result<Vec<u8>, Self::Error> {
//! #         let salt = salt.risky_ref();
//! #         let mut t = vec![self.0];
//! #         t.extend_from_slice(&(salt.len() as u32).to_be_bytes());
//! #         t.extend_from_slice(salt);
//! #         t.extend_from_slice(p.bytes().risky_ref());
//! #         Ok(t)
//! #     }
//! #     fn compare(a: &Vec<u8>, b: &Vec<u8>) -> Option<core::cmp::Ordering> {
//! #         let header = |t: &[u8]| {
//! #             let len = u32::from_be_bytes(t.get(1..5)?.try_into().ok()?) as usize;
//! #             Some(5 + len)
//! #         };
//! #         let (ha, hb) = (header(a)?, header(b)?);
//! #         (a.get(..ha)? == b.get(..hb)?).then(|| a[ha..].cmp(&b[hb..]))
//! #     }
//! # }
//! # vitaminc_ore::supports_every_target!(Keyed);
//! use vitaminc_ore::target::I32;
//! use vitaminc_ore::test_support;
//!
//! // In the scheme crate's tests, with two keys that differ.
//! test_support::conformance(&Keyed(1), &Keyed(2));
//! test_support::static_target::<Keyed, I32>();
//! ```

use core::cmp::Ordering;

use vitaminc_aead::{Float, Int, Logical, Physical, TimeUnit};

use crate::target::{Nulls, StaticTarget};
use crate::{
    order, order_with_nulls, NullOrder, OrderEncrypt, OrderQuery, OrderSpace, OrderTarget, Supports,
};

/// A target and two values in order as it, with the empty value where
/// the target has one.
#[derive(Clone, Copy)]
struct Row {
    target: OrderTarget,
    ty: Option<Logical>,
    below: Physical<'static>,
    above: Physical<'static>,
    empty: Option<Physical<'static>>,
}

fn rows() -> Vec<Row> {
    use OrderTarget as T;
    use Physical::{Bytes, Float as F, Int as I, Text};
    let plain = |target, below, above| Row {
        target,
        ty: None,
        below,
        above,
        empty: None,
    };
    let typed = |target, ty, below, above| Row {
        target,
        ty: Some(ty),
        below,
        above,
        empty: None,
    };
    vec![
        plain(T::I16, I(Int::I16(i16::MIN)), I(Int::I16(i16::MAX))),
        plain(T::U16, I(Int::U16(0)), I(Int::U16(u16::MAX))),
        plain(T::I32, I(Int::I32(i32::MIN)), I(Int::I32(i32::MAX))),
        plain(T::U32, I(Int::U32(0)), I(Int::U32(u32::MAX))),
        plain(T::I64, I(Int::I64(i64::MIN)), I(Int::I64(i64::MAX))),
        plain(T::U64, I(Int::U64(0)), I(Int::U64(u64::MAX))),
        plain(T::I128, I(Int::I128(i128::MIN)), I(Int::I128(i128::MAX))),
        plain(T::U128, I(Int::U128(0)), I(Int::U128(u128::MAX))),
        plain(
            T::F64,
            F(Float::F64(f64::NEG_INFINITY)),
            F(Float::F64(f64::INFINITY)),
        ),
        Row {
            target: T::Text,
            ty: None,
            below: Text("apple"),
            above: Text("Banana"),
            empty: Some(Text("")),
        },
        Row {
            target: T::Bytes,
            ty: None,
            below: Bytes(&[0]),
            above: Bytes(&[255]),
            empty: Some(Bytes(&[])),
        },
        typed(
            T::Date,
            Logical::Date,
            I(Int::I32(-96_465_292)),
            I(Int::I32(95_026_236)),
        ),
        typed(
            T::Timestamp,
            Logical::Timestamp(TimeUnit::Nanos),
            I(Int::I64(-1)),
            I(Int::I64(0)),
        ),
        typed(
            T::Decimal,
            Logical::Decimal { scale: 2 },
            I(Int::I64(-150)),
            I(Int::I64(150)),
        ),
        typed(T::Uuid, Logical::Uuid, Bytes(&[0; 16]), Bytes(&[1; 16])),
    ]
}

/// Check a scheme against its contract, for every target it takes.
/// `a` and `b` are the scheme under two keys that differ. From outside
/// the scheme, one key passed twice looks the same as a scheme that
/// ignores its key, so the checks under another key name both causes.
///
/// For every target [`Supports::supports`] admits, with the inventory of
/// values this crate keeps, including an empty string and an empty byte
/// string:
///
/// - the terms of two values in order compare in that order, and two
///   terms of one value compare equal;
/// - no term is empty;
/// - a term made under another context, or another key, never compares
///   equal to the term of the same value in this space. A term that
///   depends on nothing (the empty terms both scheme crates once made)
///   compares equal to itself under every key, and fails this. This is
///   the check that holds for a randomised scheme too, whose terms carry
///   a nonce. It rests on the [`OrderScheme::compare`](crate::OrderScheme::compare)
///   contract that cross-space noise is in the direction and never in
///   equality: `Some(Equal)` only up to the scheme's collision bound,
///   or `None`. A scheme that answers `Equal` across spaces by chance
///   breaks that contract, not this check;
/// - a term made under another context, or another key, is other bytes.
///   For a deterministic scheme that is a second proof the term depends
///   on the salt and the key; for a randomised scheme every term is
///   other bytes anyway, and only the comparison above tells.
///
/// Then, for every fixed-width target, in a nulls-first and a nulls-last
/// space:
///
/// - the null's term (the all-zero or the all-ones plaintext) sorts below
///   or above a value's, and two of them compare equal;
/// - the null's term depends on the key and the salt, by the same checks
///   as above;
/// - a value's term in the space never compares equal to its term in the
///   plain space of the same target, so the salt binds the null policy.
///   Under nulls-last a value's plaintext is the same bytes in both, so
///   only the salt tells them apart.
///
/// What this cannot see is the structure of a term: a randomised scheme
/// that keeps its nonce but drops its blocks for one plaintext still
/// needs a test of its own that pins its stored format with literal
/// bytes, as the scheme crates have.
///
/// # Panics
///
/// On the first check the scheme fails, naming the target.
pub fn conformance<S: Supports<OrderTarget>>(a: &S, b: &S) {
    for row in rows().iter().filter(|row| S::supports(row.target)) {
        let name = row.target.domain();
        let space = a.target(row.target).context("conformance");
        let other_context = a.target(row.target).context("other");
        let other_key = b.target(row.target).context("conformance");
        let term = |space: &OrderSpace<'_, S>, v: Physical<'_>| {
            let plaintext = order(row.target, row.ty, v).expect("the inventory encodes");
            space
                .encrypt_term(&plaintext)
                .unwrap_or_else(|e| panic!("{name}: the scheme refused a term of its target: {e}"))
        };
        let (below, above, again) = (
            term(&space, row.below),
            term(&space, row.above),
            term(&space, row.below),
        );
        assert_eq!(
            space.compare(&below, &above),
            Some(Ordering::Less),
            "{name}: the terms of two values in order do not compare in that order"
        );
        assert_eq!(
            space.compare(&above, &below),
            Some(Ordering::Greater),
            "{name}: the comparison is not antisymmetric"
        );
        assert_eq!(
            space.compare(&below, &again),
            Some(Ordering::Equal),
            "{name}: two terms of one value do not compare equal"
        );
        let mut values = vec![row.below, row.above];
        if let Some(empty) = row.empty {
            values.push(empty);
        }
        for v in values {
            let own = term(&space, v);
            assert!(
                !own.as_bytes().is_empty(),
                "{name}: a term is empty, so it depends on nothing"
            );
            let (under_other_context, under_other_key) =
                (term(&other_context, v), term(&other_key, v));
            // Terms of two spaces are never meant to compare, so the
            // scheme may answer `None` or a wrong direction; what it must
            // not do is find them equal, which `OrderScheme::compare`
            // reserves for one value in one space, up to the scheme's
            // collision bound. Only a term that ignores the salt or the
            // key, or has no keyed block at all, compares equal here.
            assert_ne!(
                S::compare(own.raw(), under_other_context.raw()),
                Some(Ordering::Equal),
                "{name}: a term compares equal to one under another context, so it does not depend on the salt"
            );
            assert_ne!(
                S::compare(own.raw(), under_other_key.raw()),
                Some(Ordering::Equal),
                "{name}: a term compares equal to one under another key, so it does not depend on the key, or `a` and `b` hold one key"
            );
            assert_ne!(
                own.as_bytes(),
                under_other_context.as_bytes(),
                "{name}: a term is the same under another context, so it does not depend on the salt"
            );
            assert_ne!(
                own.as_bytes(),
                under_other_key.as_bytes(),
                "{name}: a term is the same under another key, so it does not depend on the key, or `a` and `b` hold one key"
            );
        }
    }
    for (row, nulls) in placed_rows::<S>() {
        let name = row
            .target
            .domain_with_nulls(nulls)
            .expect("a fixed-width row");
        let plain = a.target(row.target).context("conformance");
        let [space, other_context, other_key] = placed_spaces(a, b, row.target, nulls);
        let null = |space: &OrderSpace<'_, S, Nulls<OrderTarget>>| {
            space
                .encrypt_null()
                .unwrap_or_else(|e| panic!("{name}: the scheme refused a null's term: {e}"))
        };
        let value =
            order_with_nulls(row.target, nulls, row.ty, row.below).expect("the inventory encodes");
        let below = space
            .encrypt_term(&value)
            .unwrap_or_else(|e| panic!("{name}: the scheme refused a term of its target: {e}"));
        let (own, again) = (null(&space), null(&space));
        assert_eq!(
            space.compare(&below, &own),
            Some(end(nulls)),
            "{name}: a null does not sort at its end of the space"
        );
        assert_eq!(
            space.compare(&own, &again),
            Some(Ordering::Equal),
            "{name}: two nulls' terms do not compare equal"
        );
        assert!(
            !own.as_bytes().is_empty(),
            "{name}: a null's term is empty, so it depends on nothing"
        );
        let (under_other_context, under_other_key) = (null(&other_context), null(&other_key));
        assert_ne!(
            S::compare(own.raw(), under_other_context.raw()),
            Some(Ordering::Equal),
            "{name}: a null's term compares equal to one under another context, so it does not depend on the salt"
        );
        assert_ne!(
            S::compare(own.raw(), under_other_key.raw()),
            Some(Ordering::Equal),
            "{name}: a null's term compares equal to one under another key, so it does not depend on the key, or `a` and `b` hold one key"
        );
        assert_ne!(
            own.as_bytes(),
            under_other_context.as_bytes(),
            "{name}: a null's term is the same under another context, so it does not depend on the salt"
        );
        assert_ne!(
            own.as_bytes(),
            under_other_key.as_bytes(),
            "{name}: a null's term is the same under another key, so it does not depend on the key, or `a` and `b` hold one key"
        );
        let in_plain = plain
            .encrypt_term(&order(row.target, row.ty, row.below).expect("the inventory encodes"))
            .unwrap_or_else(|e| panic!("{name}: the scheme refused a term of its target: {e}"));
        assert_ne!(
            S::compare(below.raw(), in_plain.raw()),
            Some(Ordering::Equal),
            "{name}: a term compares equal to the plain space's, so the salt does not bind the null policy"
        );
    }
}

/// Every fixed-width row the scheme takes, under each null policy.
fn placed_rows<S: Supports<OrderTarget>>() -> Vec<(Row, NullOrder)> {
    rows()
        .into_iter()
        .filter(|row| S::supports(row.target) && row.target.width().is_some())
        .flat_map(|row| [NullOrder::First, NullOrder::Last].map(|nulls| (row, nulls)))
        .collect()
}

/// The space that places nulls as `nulls` says, the same under another
/// context, and the same under the other key.
fn placed_spaces<'s, S: Supports<OrderTarget>>(
    a: &'s S,
    b: &'s S,
    target: OrderTarget,
    nulls: NullOrder,
) -> [OrderSpace<'s, S, Nulls<OrderTarget>>; 3] {
    let placed = |scheme: &'s S, context: &str| {
        scheme
            .target(target)
            .context(context)
            .nulls(nulls)
            .expect("a fixed-width target places nulls")
    };
    [
        placed(a, "conformance"),
        placed(a, "other"),
        placed(b, "conformance"),
    ]
}

/// How a value's term compares with the null's under `nulls`.
fn end(nulls: NullOrder) -> Ordering {
    match nulls {
        NullOrder::First => Ordering::Greater,
        NullOrder::Last => Ordering::Less,
    }
}

/// Check a scheme's query side against its contract, for every target it
/// takes. `a` and `b` are the scheme under two keys that differ, as for
/// [`conformance`], which this does not repeat.
///
/// For every target [`Supports::supports`] admits:
///
/// - the query of a value compares against the terms of the values on
///   either side of it in their order, and against a term of the same
///   value as `Equal`;
/// - no query is empty;
/// - a query made under another context, or another key, never compares
///   equal to the term of the same value in this space, and this space's
///   query never compares equal to the term of the same value under
///   another context or key, by the same argument as for terms.
///
/// # Panics
///
/// On the first check the scheme fails, naming the target.
pub fn query_conformance<S: OrderQuery + Supports<OrderTarget>>(a: &S, b: &S) {
    for row in rows().iter().filter(|row| S::supports(row.target)) {
        let name = row.target.domain();
        let space = a.target(row.target).context("conformance");
        let other_context = a.target(row.target).context("other");
        let other_key = b.target(row.target).context("conformance");
        let plaintext =
            |v: Physical<'_>| order(row.target, row.ty, v).expect("the inventory encodes");
        let term = |space: &OrderSpace<'_, S>, v: Physical<'_>| {
            space
                .encrypt_term(&plaintext(v))
                .unwrap_or_else(|e| panic!("{name}: the scheme refused a term of its target: {e}"))
        };
        let query = |space: &OrderSpace<'_, S>, v: Physical<'_>| {
            space
                .encrypt_query_term(&plaintext(v))
                .unwrap_or_else(|e| panic!("{name}: the scheme refused a query of its target: {e}"))
        };
        let (below, above) = (term(&space, row.below), term(&space, row.above));
        let (query_below, query_above) = (query(&space, row.below), query(&space, row.above));
        assert_eq!(
            space.compare_query(&query_below, &above),
            Some(Ordering::Less),
            "{name}: the query of a lower value does not compare below the term of a higher"
        );
        assert_eq!(
            space.compare_query(&query_above, &below),
            Some(Ordering::Greater),
            "{name}: the query of a higher value does not compare above the term of a lower"
        );
        assert_eq!(
            space.compare_query(&query_below, &below),
            Some(Ordering::Equal),
            "{name}: the query of a value does not compare equal to its term"
        );
        let mut values = vec![row.below, row.above];
        if let Some(empty) = row.empty {
            values.push(empty);
        }
        for v in values {
            let own = term(&space, v);
            let own_query = query(&space, v);
            assert!(
                !own_query.as_bytes().is_empty(),
                "{name}: a query is empty, so it depends on nothing"
            );
            assert_ne!(
                S::compare_query(query(&other_context, v).raw(), own.raw()),
                Some(Ordering::Equal),
                "{name}: a query under another context compares equal to the term, so it does not depend on the salt"
            );
            assert_ne!(
                S::compare_query(query(&other_key, v).raw(), own.raw()),
                Some(Ordering::Equal),
                "{name}: a query under another key compares equal to the term, so it does not depend on the key"
            );
            assert_ne!(
                S::compare_query(own_query.raw(), term(&other_context, v).raw()),
                Some(Ordering::Equal),
                "{name}: a query compares equal to the term under another context, so it does not depend on the salt"
            );
            assert_ne!(
                S::compare_query(own_query.raw(), term(&other_key, v).raw()),
                Some(Ordering::Equal),
                "{name}: a query compares equal to the term under another key, so it does not depend on the key"
            );
        }
    }
    for (row, nulls) in placed_rows::<S>() {
        let name = row
            .target
            .domain_with_nulls(nulls)
            .expect("a fixed-width row");
        let [space, other_context, other_key] = placed_spaces(a, b, row.target, nulls);
        let value =
            order_with_nulls(row.target, nulls, row.ty, row.below).expect("the inventory encodes");
        let below = space
            .encrypt_term(&value)
            .unwrap_or_else(|e| panic!("{name}: the scheme refused a term of its target: {e}"));
        let null = space
            .encrypt_null()
            .unwrap_or_else(|e| panic!("{name}: the scheme refused a null's term: {e}"));
        let query = |space: &OrderSpace<'_, S, Nulls<OrderTarget>>| {
            space
                .null_query()
                .unwrap_or_else(|e| panic!("{name}: the scheme refused a null's query: {e}"))
        };
        let own = query(&space);
        assert_eq!(
            space.compare_query(&own, &null),
            Some(Ordering::Equal),
            "{name}: the null's query does not compare equal to a null's term"
        );
        assert_eq!(
            space.compare_query(&own, &below),
            Some(end(nulls).reverse()),
            "{name}: the null's query does not sort at its end of the space"
        );
        assert!(
            !own.as_bytes().is_empty(),
            "{name}: a null's query is empty, so it depends on nothing"
        );
        assert_ne!(
            S::compare_query(query(&other_context).raw(), null.raw()),
            Some(Ordering::Equal),
            "{name}: a null's query under another context compares equal to the term, so it does not depend on the salt"
        );
        assert_ne!(
            S::compare_query(query(&other_key).raw(), null.raw()),
            Some(Ordering::Equal),
            "{name}: a null's query under another key compares equal to the term, so it does not depend on the key"
        );
    }
}

/// Check that a marker the scheme implements [`Supports`] for is one its
/// runtime answer admits, so a space under the marker never hands the
/// scheme a target it would refuse. Call it once per marker impl.
///
/// # Panics
///
/// If `Supports::<OrderTarget>::supports` refuses the marker's target.
pub fn static_target<S: Supports<T> + Supports<OrderTarget>, T: StaticTarget>() {
    assert!(
        <S as Supports<OrderTarget>>::supports(T::TARGET),
        "{} implements Supports<{:?}> but refuses it at runtime",
        S::NAME,
        T::TARGET
    );
}
