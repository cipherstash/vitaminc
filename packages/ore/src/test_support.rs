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
//! target refused at runtime that a marker impl vouches for.
//!
//! ```
//! # use vitaminc_ore::{Context, OrderPlaintext, OrderScheme};
//! # use vitaminc_protected::Controlled;
//! # /// A toy: the key byte, the salt's length and the salt, then the
//! # /// plaintext. Terms compare when their key and salt agree.
//! # struct Keyed(u8);
//! # impl OrderScheme for Keyed {
//! #     const NAME: &'static str = "keyed";
//! #     type Term = Vec<u8>;
//! #     type Error = core::convert::Infallible;
//! #     type Space = Context<'static>;
//! #     fn open(&self, _: vitaminc_ore::OrderTarget, salt: &Context<'_>) -> Result<Context<'static>, Self::Error> {
//! #         Ok(salt.clone().into_owned())
//! #     }
//! #     fn encrypt_plaintext(&self, salt: &Context<'static>, p: &OrderPlaintext) -> Result<Vec<u8>, Self::Error> {
//! #         let mut t = vec![self.0];
//! #         t.extend_from_slice(&(salt.as_bytes().len() as u32).to_be_bytes());
//! #         t.extend_from_slice(salt.as_bytes());
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

use crate::target::StaticTarget;
use crate::{order, OrderEncrypt, OrderSpace, OrderTarget, Supports};

/// A target and two values in order as it, with the empty value where
/// the target has one.
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
        plain(T::I8, I(Int::I8(-1)), I(Int::I8(1))),
        plain(T::U8, I(Int::U8(0)), I(Int::U8(255))),
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
