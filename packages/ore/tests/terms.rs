//! The order terms of a whole value: one per orderable scalar with its
//! path, from the same walk as encryption and equality terms, refusing
//! what they refuse.

use std::collections::BTreeMap;

use vitaminc_aead::plaintext::render;
use vitaminc_aead::{
    Encrypt, EncryptError, EncryptSink, Int, Logical, Physical, Raw, Tee, Unencryptable,
};
use vitaminc_normalize::{terms, Terms, TermsError};
use vitaminc_ore::{domain, order, order_terms, NormalizeError, Order, Term};
use vitaminc_protected::Controlled;

fn paths<T>(terms: &[Term<T>]) -> Vec<String> {
    terms.iter().map(|t| render(&t.path)).collect()
}

/// A record with every kind of scalar in it, nested.
struct Record;

impl Encrypt for Record {
    fn visit<S: vitaminc_aead::Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        use vitaminc_aead::{MapSink, SeqSink, Sink};
        let mut map = sink.map(Some(5))?;
        "Ada".visit(map.entry("name")?)?;
        map.entry("age")?.scalar(None, Physical::Int(Int::U8(36)))?;
        map.entry("ok")?.scalar(None, Physical::Bool(true))?;
        map.entry("gone")?.scalar(None, Physical::Null)?;
        let mut tags = map.entry("tags")?.seq(Some(2))?;
        "Été".visit(tags.element()?)?;
        tags.element()?
            .scalar(Some(Logical::Date), Physical::Int(Int::I32(19_000)))?;
        tags.end()?;
        map.end()
    }
}

#[test]
fn one_term_per_orderable_scalar_with_its_path() {
    let found = order_terms(Record).expect("terms");
    assert_eq!(
        paths(&found),
        [".name", ".age", ".tags[0]", ".tags[1]"],
        "a null and a boolean have no term and do not stop the walk"
    );
    let domains: Vec<_> = found.iter().map(|t| t.normalized.domain()).collect();
    assert_eq!(
        domains,
        [domain::TEXT, domain::UINT8, domain::TEXT, domain::DATE]
    );
    // The terms are `order`'s: folded text, the natural width.
    assert_eq!(found[0].normalized.bytes().risky_ref(), b"ada");
    assert_eq!(found[1].normalized.bytes().risky_ref(), &[36]);
    assert_eq!(found[2].normalized.bytes().risky_ref(), b"ete");
    assert_eq!(
        found[3].normalized.bytes().risky_ref(),
        order(Some(Logical::Date), Physical::Int(Int::I32(19_000)))
            .expect("term")
            .bytes()
            .risky_ref()
    );
}

#[test]
fn order_and_equality_terms_come_from_one_walk() {
    let (mut equality, mut ordered) = (Vec::new(), Vec::new());
    Record
        .visit(Tee(
            Terms::<TermsError>::new(&mut equality),
            Terms::by(Order, &mut ordered),
        ))
        .expect("walk");
    assert_eq!(paths(&equality), paths(&ordered));
    assert_eq!(equality.len(), 4);
    // Same scalar, different terms: NFC against folded, one domain family
    // against the other.
    assert_eq!(equality[2].normalized.bytes.risky_ref(), "Été".as_bytes());
    assert_eq!(ordered[2].normalized.bytes().risky_ref(), b"ete");
    assert!(equality
        .iter()
        .all(|t| t.normalized.domain.starts_with("vitaminc/prf/")));
    assert!(ordered
        .iter()
        .all(|t| t.normalized.domain().starts_with("vitaminc/ore/")));
}

#[test]
fn order_terms_beside_encryption_see_the_same_walk() {
    let mut ordered = Vec::new();
    let (planned, ()) = Record
        .visit(Tee(
            EncryptSink::root("users/v1"),
            Terms::<EncryptError<core::convert::Infallible>, Order>::by(Order, &mut ordered),
        ))
        .expect("plans");
    assert_eq!(paths(&ordered), [".name", ".age", ".tags[0]", ".tags[1]"]);
    drop(planned);
}

#[test]
fn a_logical_type_with_no_order_domain_stops_the_walk() {
    let mut doc = BTreeMap::new();
    doc.insert(
        "x",
        Raw(Logical::from_wire(200, 1), Physical::Int(Int::I8(1))),
    );
    let err = order_terms(doc).expect_err("refused");
    let term = err.term().expect("refused by the normalizer");
    assert_eq!(term.error(), NormalizeError::NoDomain);
    assert_eq!(render(term.path()), ".x");
}

#[test]
fn order_terms_refuse_what_equality_terms_refuse_at_the_same_path() {
    let mut doc = BTreeMap::new();
    doc.insert("x", "\u{378}");
    let err = order_terms(doc.clone()).expect_err("refused");
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
    let err = order_terms(doc).expect_err("refused");
    assert!(err.term().is_none());
    let refusal = err.refusal().expect("refused for its shape");
    assert_eq!(refusal.reason(), Unencryptable::InvalidValue);
    assert_eq!(render(refusal.path()), ".id");
}
