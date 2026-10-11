//! The spike's sinks against today's `Value`-based code, without crypto.

// Some borrows are on purpose: they exercise the `&Value` source.
#![allow(clippy::needless_borrows_for_generic_args)]

mod common;

use std::collections::BTreeMap;

use common::{decode, encode, malformed, valid, Recorder};
use vitaminc_aead::Encrypt;
use vitaminc_aead_value::canonical::equality_input;
use vitaminc_aead_value::transport::{decode_value, Reader};
use vitaminc_aead_value::Value;
use vitaminc_plaintext_spike::{to_frame, to_value, Bytes, EqualityTerm, Frame, Plaintext, Tagged};
use vitaminc_protected::Controlled;

const AAD: (&str, u64) = ("users", 7);

#[test]
fn every_source_encrypts_like_value_does() {
    for v in valid() {
        let expected = decode(&v.bytes).encrypt_with_aad(Recorder, AAD).expect(&v.name);
        let frame = Frame::parse(&v.bytes).expect(&v.name);
        let value = decode(&v.bytes);
        assert_eq!(Tagged(frame).encrypt_with_aad(Recorder, AAD).expect(&v.name), expected, "frame: {}", v.name);
        assert_eq!(Tagged(&value).encrypt_with_aad(Recorder, AAD).expect(&v.name), expected, "&Value: {}", v.name);
        assert_eq!(Tagged(to_value(frame)).encrypt_with_aad(Recorder, AAD).expect(&v.name), expected, "built: {}", v.name);
    }
}

#[test]
fn rust_types_encrypt_like_the_matching_value() {
    fn same<P: Plaintext>(p: P, value: Value) {
        assert_eq!(
            Tagged(p).encrypt_with_aad(Recorder, AAD).unwrap(),
            value.encrypt_with_aad(Recorder, AAD).unwrap()
        );
    }
    same(34u32, Value::UInt32(34));
    same(-1i8, Value::Int8(-1));
    same(u128::MAX, Value::UInt128(u128::MAX));
    same(2.5f64, Value::Float64(2.5));
    same("Ada", Value::String("Ada".into()));
    same(Bytes(&[1, 2, 3]), Value::Bytes(vitaminc_protected::Protected::new(vec![1, 2, 3])));
    same(None::<u32>, Value::Null);
    same(vec![1u32, 2], Value::Array(vec![Value::UInt32(1), Value::UInt32(2)]));
    same(
        BTreeMap::from([("a".to_string(), true), ("b".to_string(), false)]),
        Value::Object(vec![("a".into(), Value::Bool(true)), ("b".into(), Value::Bool(false))]),
    );
}

#[test]
fn same_number_different_width_gives_different_leaves() {
    // Today's behaviour, now explicit: the tag keeps the width.
    let go = Tagged(34u32).encrypt_with_aad(Recorder, AAD).unwrap();
    let js = Tagged(34i8).encrypt_with_aad(Recorder, AAD).unwrap();
    assert_ne!(go, js);
    match (go, js) {
        (common::Rec::Leaf { plaintext: a, .. }, common::Rec::Leaf { plaintext: b, .. }) => {
            assert_eq!(a, [0x06, 0x22, 0, 0, 0]);
            assert_eq!(b, [0x0C, 0x22]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn frames_round_trip_through_every_sink() {
    for v in valid() {
        let frame = Frame::parse(&v.bytes).expect(&v.name);
        assert_eq!(to_frame(frame).unwrap().risky_ref(), &v.bytes[..], "frame: {}", v.name);
        assert_eq!(to_frame(&decode(&v.bytes)).unwrap().risky_ref(), &v.bytes[..], "value: {}", v.name);
        assert_eq!(encode(to_value(frame)), v.bytes, "built: {}", v.name);
    }
}

#[test]
fn frame_parse_rejects_the_malformed_corpus() {
    for v in malformed() {
        assert!(decode_value(&mut Reader::new(&v.bytes)).is_err(), "decoder: {}", v.name);
        assert!(Frame::parse(&v.bytes).is_err(), "frame: {}", v.name);
    }
}

#[test]
fn frame_parse_agrees_with_the_decoder_on_mutated_input() {
    // xorshift, fixed seed: deterministic.
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let seeds: Vec<Vec<u8>> = valid().into_iter().map(|v| v.bytes).collect();
    let mut checked = 0;
    for _ in 0..20_000 {
        let mut bytes = seeds[next() as usize % seeds.len()].clone();
        match next() % 4 {
            0 if !bytes.is_empty() => {
                let i = next() as usize % bytes.len();
                bytes[i] = next() as u8;
            }
            1 if !bytes.is_empty() => bytes.truncate(next() as usize % bytes.len()),
            2 => bytes.push(next() as u8),
            _ if !bytes.is_empty() => {
                let i = next() as usize % bytes.len();
                bytes[i] ^= 1 << (next() % 8);
            }
            _ => {}
        }
        let decoder = decode_value(&mut Reader::new(&bytes)).is_ok();
        assert_eq!(Frame::parse(&bytes).is_ok(), decoder, "{bytes:02x?}");
        checked += 1;
    }
    assert_eq!(checked, 20_000);
}

#[test]
fn equality_input_matches_canonical_for_every_vector() {
    for v in valid() {
        let expected = equality_input(&decode(&v.bytes));
        let actual = Frame::parse(&v.bytes).unwrap().visit(EqualityTerm);
        match (expected, actual) {
            (Ok(e), Ok(a)) => {
                assert_eq!(e.domain, a.domain, "{}", v.name);
                assert_eq!(e.bytes.risky_ref(), a.bytes.risky_ref(), "{}", v.name);
            }
            (Err(e), Err(a)) => assert_eq!(e, a, "{}", v.name),
            (e, a) => panic!("{}: {e:?} vs {a:?}", v.name),
        }
    }
}

#[test]
fn integer_terms_share_a_domain_across_widths() {
    let a = 34u32.visit(EqualityTerm).unwrap();
    let b = 34i8.visit(EqualityTerm).unwrap();
    assert_eq!(a.domain, b.domain);
    assert_eq!(a.bytes.risky_ref(), b.bytes.risky_ref());
    // But signedness matters for negatives, which bytes alone can't show.
    let neg = (-1i32).visit(EqualityTerm).unwrap();
    let max = u32::MAX.visit(EqualityTerm).unwrap();
    assert_ne!(neg.bytes.risky_ref(), max.bytes.risky_ref());
}
