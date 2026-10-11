//! Equality terms from the data model, against `canonical::equality_input`.

mod common;

use common::{decode, sample, ts, valid};
use vitaminc_aead_value::canonical::equality_input;
use vitaminc_aead_value::Value;
use vitaminc_encrypt::{Aes256Cipher, Key};
use vitaminc_plaintext_spike::{decrypt_into, encrypt_with_terms, Frame, FrameWriter, PathSeg};
use vitaminc_protected::{Controlled, Protected};

fn cipher() -> Aes256Cipher {
    Aes256Cipher::new(&Key::from([7u8; 32])).unwrap()
}

fn key(k: &str) -> PathSeg {
    PathSeg::Key(k.into())
}

#[test]
fn a_scalar_term_matches_canonical_for_every_vector() {
    let cipher = cipher();
    for v in valid() {
        let value = decode(&v.bytes);
        let (_, terms) = encrypt_with_terms(Frame::parse(&v.bytes).unwrap(), &cipher, ()).expect(&v.name);
        match (equality_input(&value), terms.first()) {
            (Ok(expected), Some(term)) => {
                let actual = term.input.as_ref().expect(&v.name);
                assert!(term.path.is_empty(), "{}", v.name);
                assert_eq!(actual.domain, expected.domain, "{}", v.name);
                assert_eq!(actual.bytes.risky_ref(), expected.bytes.risky_ref(), "{}", v.name);
            }
            // No term: null, undefined, bool, containers.
            (Err(_), None) => {}
            // Containers hold terms for their leaves; the sample checks those.
            (Err(_), Some(_)) if matches!(value, Value::Array(_) | Value::Object(_)) => {}
            (e, a) => panic!("{}: {e:?} vs {a:?}", v.name),
        }
    }
}

#[test]
fn one_walk_gives_the_ciphertext_and_a_term_per_leaf() {
    let cipher = cipher();
    let bytes = common::encode(sample());
    let (ct, terms) = encrypt_with_terms(Frame::parse(&bytes).unwrap(), &cipher, ("users", 7u64)).unwrap();

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

    // And the ciphertext from the same walk decrypts to the original frame.
    let mut out = Vec::new();
    decrypt_into(&cipher, ct, ("users", 7u64), FrameWriter::new(&mut out)).unwrap();
    assert_eq!(out, bytes);
}

#[test]
fn integer_terms_share_a_domain_across_widths() {
    let cipher = cipher();
    let a = encrypt_with_terms(34u32, &cipher, ()).unwrap().1.remove(0).input.unwrap();
    let b = encrypt_with_terms(34i8, &cipher, ()).unwrap().1.remove(0).input.unwrap();
    assert_eq!(a.domain, b.domain);
    assert_eq!(a.bytes.risky_ref(), b.bytes.risky_ref());
}

#[test]
fn a_term_error_is_reported_not_dropped() {
    // U+0378 is unassigned in Unicode 16: encryption succeeds, the term fails.
    let (_, terms) = encrypt_with_terms("\u{378}", &cipher(), ()).unwrap();
    assert_eq!(terms.len(), 1);
    assert!(terms[0].input.is_err());
}
