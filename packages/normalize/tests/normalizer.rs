//! `Terms` under a normalizer of the caller's own: the walk is the same,
//! the terms are the normalizer's, and the skip-or-stop rule for a scalar
//! with no term is applied to what the normalizer returns.

use std::collections::BTreeMap;

use vitaminc_aead::plaintext::render;
use vitaminc_aead::{Encrypt, Int, Logical, Physical, Raw, Tee};
use vitaminc_normalize::{
    terms, terms_by, Equality, Normalize, NormalizeError, Normalized, Terms, TermsError,
};
use vitaminc_protected::{Controlled, Protected};

/// Every int is one byte under a domain of its own; nothing else has a
/// term.
#[derive(Clone, Copy)]
struct LowByte;

impl Normalize for LowByte {
    type Term = Normalized;

    const INDEX: &'static str = "low byte";

    fn normalize(
        &self,
        ty: Option<Logical>,
        value: Physical<'_>,
    ) -> Result<Normalized, NormalizeError> {
        match (ty, value) {
            (None, Physical::Int(i)) => Ok(Normalized {
                domain: "test/low-byte/v1",
                bytes: Protected::new(vec![i.to_i128().unwrap_or(0) as u8]),
            }),
            _ => Err(NormalizeError::NoDomain),
        }
    }
}

fn doc() -> BTreeMap<&'static str, Raw<'static>> {
    let mut doc = BTreeMap::new();
    doc.insert("a", Raw(None, Physical::Int(Int::I32(0x1_02))));
    doc.insert("b", Raw(None, Physical::Text("text")));
    doc.insert("c", Raw(None, Physical::Null));
    doc
}

#[test]
fn the_terms_are_the_normalizers_and_the_walk_is_the_same() {
    let found = terms_by(LowByte, doc()).expect("terms");
    assert_eq!(found.len(), 1, "text and null have no term under LowByte");
    assert_eq!(render(&found[0].path), ".a");
    assert_eq!(found[0].normalized.domain, "test/low-byte/v1");
    assert_eq!(found[0].normalized.bytes.risky_ref(), &[0x02]);
    // `terms` is `terms_by(Equality, ..)`.
    let equality = terms(doc()).expect("terms");
    let by_name = terms_by(Equality, doc()).expect("terms");
    assert_eq!(equality.len(), 2);
    assert_eq!(equality.len(), by_name.len());
    assert_eq!(
        equality[1].normalized.bytes.risky_ref(),
        by_name[1].normalized.bytes.risky_ref()
    );
}

#[test]
fn a_logical_type_the_normalizer_refuses_stops_the_walk() {
    let mut doc = BTreeMap::new();
    doc.insert("d", Raw(Some(Logical::Date), Physical::Int(Int::I32(1))));
    let err = terms_by(LowByte, doc).expect_err("refused");
    let term = err.term().expect("refused by the normalizer");
    assert_eq!(term.error(), NormalizeError::NoDomain);
    assert_eq!(render(term.path()), ".d");
    // The refusal names the normalizer's index, not equality.
    assert_eq!(term.index(), "low byte");
    assert_eq!(
        err.to_string(),
        "no low byte term: no domain for this kind of value"
    );
}

#[test]
fn two_normalizers_share_one_walk() {
    let (mut equality, mut low) = (Vec::new(), Vec::new());
    doc()
        .visit(Tee(
            Terms::<TermsError>::new(&mut equality),
            Terms::by(LowByte, &mut low),
        ))
        .expect("walk");
    assert_eq!(
        equality.iter().map(|t| render(&t.path)).collect::<Vec<_>>(),
        [".a", ".b"]
    );
    assert_eq!(
        low.iter().map(|t| render(&t.path)).collect::<Vec<_>>(),
        [".a"]
    );
}

/// A fixed-width `None` reaches the sink as a typed null. It is indexed
/// as a plain null, which has no term, so an absent field gains no term
/// and does not stop the walk (cipherstash/vitaminc#493).
#[test]
fn a_fixed_width_none_has_no_term_and_does_not_stop_the_walk() {
    let mut doc = BTreeMap::new();
    doc.insert("gone", None::<i32>);
    doc.insert("here", Some(5i32));
    let found = terms(doc).expect("a typed null does not stop the walk");
    assert_eq!(
        found.iter().map(|t| render(&t.path)).collect::<Vec<_>>(),
        [".here"],
        "only the present field has a term"
    );
    let by_name = terms_by(LowByte, BTreeMap::from([("gone", None::<i32>)]))
        .expect("a typed null does not stop a normalizer of the caller's own");
    assert!(by_name.is_empty(), "a typed null has no term under LowByte");
}
