//! The order terms of a whole value as one target: one per orderable
//! scalar with its path, from the same walk as encryption and equality
//! terms, refusing what they refuse and what does not fit the target.

use std::collections::BTreeMap;

use vitaminc_aead::plaintext::render;
use vitaminc_aead::{
    Encrypt, EncryptError, EncryptSink, Int, Logical, Physical, Raw, Tee, Unencryptable,
};
use vitaminc_normalize::{terms, Terms, TermsError};
use vitaminc_ore::{domain, order, order_terms, NormalizeError, Order, OrderTarget, Term};
use vitaminc_protected::Controlled;

fn paths<T>(terms: &[Term<T>]) -> Vec<String> {
    terms.iter().map(|t| render(&t.path)).collect()
}

/// A record of integers at several widths, nested, with a null and a
/// boolean among them: one order column's worth of values.
struct Record;

impl Encrypt for Record {
    fn visit<S: vitaminc_aead::Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        use vitaminc_aead::{MapSink, SeqSink, Sink};
        let mut map = sink.map(Some(5))?;
        map.entry("low")?.scalar(None, Physical::Int(Int::I8(-3)))?;
        map.entry("age")?.scalar(None, Physical::Int(Int::U8(36)))?;
        map.entry("ok")?.scalar(None, Physical::Bool(true))?;
        map.entry("gone")?.scalar(None, Physical::Null)?;
        let mut more = map.entry("more")?.seq(Some(2))?;
        more.element()?.scalar(None, Physical::Int(Int::I16(300)))?;
        more.element()?
            .scalar(None, Physical::Int(Int::U64(70_000)))?;
        more.end()?;
        map.end()
    }
}

#[test]
fn one_term_per_orderable_scalar_with_its_path_as_the_target() {
    let found = order_terms(OrderTarget::I32, Record).expect("terms");
    assert_eq!(
        paths(&found),
        [".low", ".age", ".more[0]", ".more[1]"],
        "a null and a boolean have no term and do not stop the walk"
    );
    // Every width becomes the target's, so the terms compare.
    assert!(found.iter().all(|t| t.normalized.domain() == domain::INT32));
    let values = [-3i32, 36, 300, 70_000];
    for (t, v) in found.iter().zip(values) {
        assert_eq!(
            t.normalized.bytes().risky_ref(),
            order(OrderTarget::I32, None, Physical::Int(Int::I32(v)))
                .expect("term")
                .bytes()
                .risky_ref()
        );
    }
}

#[test]
fn a_value_outside_the_target_stops_the_walk_at_its_path() {
    let err = order_terms(OrderTarget::I16, Record).expect_err("refused");
    let term = err.term().expect("refused by the normalizer");
    assert_eq!(term.error(), NormalizeError::OutOfRange);
    assert_eq!(render(term.path()), ".more[1]");

    let mut doc = BTreeMap::new();
    doc.insert("n", Raw(None, Physical::Int(Int::I8(1))));
    doc.insert("s", Raw(None, Physical::Text("one")));
    let err = order_terms(OrderTarget::I32, doc).expect_err("refused");
    let term = err.term().expect("refused by the normalizer");
    assert_eq!(term.error(), NormalizeError::Mismatch);
    assert_eq!(render(term.path()), ".s");
}

#[test]
fn order_and_equality_terms_come_from_one_walk() {
    let (mut equality, mut ordered) = (Vec::new(), Vec::new());
    Record
        .visit(Tee(
            Terms::<TermsError>::new(&mut equality),
            Terms::by(Order::new(OrderTarget::I64), &mut ordered),
        ))
        .expect("walk");
    // The null has an equality term, and no order term in a space that
    // does not place nulls; the boolean has neither.
    assert_eq!(
        paths(&equality),
        [".low", ".age", ".gone", ".more[0]", ".more[1]"],
        "every scalar but the boolean has an equality term"
    );
    assert_eq!(
        paths(&ordered),
        [".low", ".age", ".more[0]", ".more[1]"],
        "a space with no null policy gives the null no order term"
    );
    assert!(equality
        .iter()
        .all(|t| t.normalized.domain.starts_with("vitaminc/prf/")));
    assert!(ordered
        .iter()
        .all(|t| t.normalized.domain() == domain::INT64));
}

#[test]
fn order_terms_beside_encryption_see_the_same_walk() {
    let mut ordered = Vec::new();
    let (planned, ()) = Record
        .visit(Tee(
            EncryptSink::root("users/v1"),
            Terms::<EncryptError<core::convert::Infallible>, Order>::by(
                Order::new(OrderTarget::I32),
                &mut ordered,
            ),
        ))
        .expect("plans");
    assert_eq!(paths(&ordered), [".low", ".age", ".more[0]", ".more[1]"]);
    drop(planned);
}

#[test]
fn a_logical_type_with_no_order_domain_stops_the_walk() {
    let mut doc = BTreeMap::new();
    doc.insert(
        "x",
        Raw(Logical::from_wire(200, 1), Physical::Int(Int::I8(1))),
    );
    let err = order_terms(OrderTarget::I16, doc).expect_err("refused");
    let term = err.term().expect("refused by the normalizer");
    assert_eq!(term.error(), NormalizeError::NoDomain);
    assert_eq!(render(term.path()), ".x");
}

#[test]
fn order_terms_refuse_what_equality_terms_refuse_at_the_same_path() {
    let mut doc = BTreeMap::new();
    doc.insert("x", "\u{378}");
    let err = order_terms(OrderTarget::Text, doc.clone()).expect_err("refused");
    let term = err.term().expect("refused by the normalizer");
    assert_eq!(term.error(), NormalizeError::UnassignedCodePoint);
    assert_eq!(render(term.path()), ".x");
    // Each refusal names the index it was building, and neither names the
    // field or its value.
    assert_eq!(term.index(), "order");
    assert_eq!(
        err.to_string(),
        "no order term: text contains a code point unassigned in Unicode 16"
    );
    let equality = terms(doc).expect_err("refused");
    assert_eq!(equality.term().expect("refused").index(), "equality");
    assert_eq!(
        equality.to_string(),
        "no equality term: text contains a code point unassigned in Unicode 16"
    );

    // A value encryption refuses is refused for its shape, before the
    // normalizer sees it.
    let mut doc = BTreeMap::new();
    doc.insert("id", Raw(Some(Logical::Uuid), Physical::Bytes(&[0; 3])));
    let err = order_terms(OrderTarget::Uuid, doc).expect_err("refused");
    assert!(err.term().is_none());
    let refusal = err.refusal().expect("refused for its shape");
    assert_eq!(refusal.reason(), Unencryptable::InvalidValue);
    assert_eq!(render(refusal.path()), ".id");
}
