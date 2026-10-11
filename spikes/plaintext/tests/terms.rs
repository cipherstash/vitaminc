//! Encrypt and derive equality terms from one walk.

// Some borrows are on purpose: they exercise the `&Value` source.
#![allow(clippy::needless_borrows_for_generic_args)]

mod common;

use common::{sample, ts, Recorder};
use vitaminc_aead::Encrypt;
use vitaminc_aead_value::canonical::equality_input;
use vitaminc_aead_value::Value;
use vitaminc_plaintext_spike::{encrypt_with_terms, to_frame, Frame, PathSeg};
use vitaminc_protected::{Controlled, Protected};

fn key(k: &str) -> PathSeg {
    PathSeg::Key(k.into())
}

#[test]
fn one_walk_gives_the_ciphertext_and_a_term_per_leaf() {
    let value = sample();
    let (ct, terms) = encrypt_with_terms(&value, Recorder, ("users", 7u64)).unwrap();

    // The ciphertext is unchanged by riding along.
    assert_eq!(ct, sample().encrypt_with_aad(Recorder, ("users", 7u64)).unwrap());

    // Bool, null and passthrough have no terms, so they're absent.
    let paths: Vec<_> = terms.iter().map(|t| t.path.clone()).collect();
    assert_eq!(
        paths,
        vec![
            vec![key("name")],
            vec![key("age")],
            vec![key("scores"), PathSeg::Index(0)],
            vec![key("scores"), PathSeg::Index(1)],
            vec![key("joined")],
            vec![key("blob")],
            vec![key("seen")],
        ]
    );

    let leaves = [
        Value::String("Ada".into()),
        Value::UInt32(34),
        Value::Int8(-1),
        Value::Float64(2.5),
        Value::Date(chrono::NaiveDate::from_ymd_opt(2024, 2, 29).unwrap()),
        Value::Bytes(Protected::new(vec![1, 2, 3])),
        Value::Timestamp(ts()),
    ];
    for (term, leaf) in terms.iter().zip(&leaves) {
        let expected = equality_input(leaf).unwrap();
        let actual = term.input.as_ref().unwrap();
        assert_eq!(actual.domain, expected.domain);
        assert_eq!(actual.bytes.risky_ref(), expected.bytes.risky_ref());
    }
}

#[test]
fn a_go_frame_gives_the_same_terms_without_a_value() {
    let bytes = to_frame(&sample()).unwrap();
    let frame = Frame::parse(bytes.risky_ref()).unwrap();
    let (_, from_frame) = encrypt_with_terms(frame, Recorder, ()).unwrap();
    let (_, from_value) = encrypt_with_terms(&sample(), Recorder, ()).unwrap();
    assert_eq!(from_frame.len(), from_value.len());
    for (a, b) in from_frame.iter().zip(&from_value) {
        assert_eq!(a.path, b.path);
        let (a, b) = (a.input.as_ref().unwrap(), b.input.as_ref().unwrap());
        assert_eq!(a.bytes.risky_ref(), b.bytes.risky_ref());
    }
}

#[test]
fn a_scalar_column_is_one_term() {
    let (_, terms) = encrypt_with_terms(34u32, Recorder, ()).unwrap();
    assert_eq!(terms.len(), 1);
    assert!(terms[0].path.is_empty());
}

#[test]
fn a_term_error_is_reported_not_dropped() {
    // U+0378 is unassigned in Unicode 16: encryption succeeds, the term fails.
    let (_, terms) = encrypt_with_terms("\u{378}", Recorder, ()).unwrap();
    assert_eq!(terms.len(), 1);
    assert!(terms[0].input.is_err());
}
