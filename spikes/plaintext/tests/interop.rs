//! No `Encrypt`, no `Decrypt`, no `Value`. Checked against today's code
//! with real AES-256-GCM.

mod common;

use common::{representable, sample};
use vitaminc_aead::{CipherText, LocalCipherText};
use vitaminc_aead_value::transport::{self, Reader};
use vitaminc_encrypt::{Aes256Cipher, AesCipherText, Key};
use vitaminc_plaintext_spike::hosts::go_guest::{spike as guest, today, GuestError};
use vitaminc_plaintext_spike::model::visit_seq;
use vitaminc_plaintext_spike::sources::Failing;
use vitaminc_plaintext_spike::{
    codec, decrypt_as, encrypt, to_frame, Bytes, DecodeError, DecryptError, EncryptError, Plaintext, SeqSink, Sink,
};
use vitaminc_protected::Controlled;

const AAD: &[u8] = b"\x01\x00\x00\x00spike";

fn cipher() -> Aes256Cipher {
    Aes256Cipher::new(&Key::from([7u8; 32])).unwrap()
}

#[test]
fn the_guest_interoperates_with_today_both_ways() {
    let cipher = cipher();
    for v in representable() {
        let new_ct = guest::encrypt(&cipher, AAD, &v.bytes).expect(&v.name);
        let old_ct = today::encrypt(&cipher, AAD, &v.bytes).expect(&v.name);
        assert_eq!(today::decrypt(&cipher, AAD, &new_ct).expect(&v.name), v.bytes, "new to old: {}", v.name);
        assert_eq!(guest::decrypt(&cipher, AAD, &old_ct).expect(&v.name).risky_ref(), &v.bytes[..], "old to new: {}", v.name);
        assert_eq!(guest::decrypt(&cipher, AAD, &new_ct).expect(&v.name).risky_ref(), &v.bytes[..], "new to new: {}", v.name);
    }
}

#[test]
fn ciphertext_codec_is_byte_identical_to_transport() {
    let cipher = cipher();
    for v in representable() {
        let bytes = today::encrypt(&cipher, AAD, &v.bytes).unwrap();
        let node = codec::decode::<LocalCipherText>(&bytes).expect(&v.name);
        let mut again = Vec::new();
        codec::encode(&node, &mut again).unwrap();
        assert_eq!(again, bytes, "{}", v.name);
        // And today's decoder reads what ours writes.
        let ct: AesCipherText = transport::decode_ciphertext_boxed(&mut Reader::new(&again)).expect(&v.name);
        let mut out = Vec::new();
        transport::encode_ciphertext_boxed(ct, &mut out).unwrap();
        assert_eq!(out, bytes, "{}", v.name);
    }
}

#[test]
fn wrong_aad_is_an_auth_failure() {
    let cipher = cipher();
    for v in representable() {
        let ct = guest::encrypt(&cipher, AAD, &v.bytes).unwrap();
        let wrong = guest::decrypt(&cipher, b"\x01\x00\x00\x00other", &ct);
        // A passthrough-only value authenticates nothing, by design.
        if wrong.is_ok() {
            assert!(v.bytes.first() == Some(&0xF2), "{} decrypted under the wrong AAD", v.name);
        } else {
            assert_eq!(wrong.err(), Some(GuestError::Auth), "{}", v.name);
        }
    }
    let ct = guest::encrypt(&cipher, AAD, &common::encode(sample())).unwrap();
    assert_eq!(guest::decrypt(&cipher, b"other", &ct).err(), Some(GuestError::Auth));
}

#[test]
fn the_scalar_example_from_the_trace() {
    let cipher = cipher();
    let leaf_len = |ct: CipherText<LocalCipherText, _>| match ct {
        CipherText::Single(leaf) => leaf.as_ref().len(),
        _ => panic!("expected a single leaf"),
    };
    // Go's uint32(34): 1 + 12 + 5 + 16. JS's 34n (Int8): 1 + 12 + 2 + 16.
    assert_eq!(leaf_len(encrypt(34u32, &cipher, ()).unwrap()), 34);
    assert_eq!(leaf_len(encrypt(34i8, &cipher, ()).unwrap()), 31);
}

#[test]
fn rust_values_need_no_value_in_either_direction() {
    let cipher = cipher();
    let ct = encrypt(34u32, &cipher, ()).unwrap();
    assert_eq!(decrypt_as::<u32, _, _>(&cipher, ct, ()).unwrap(), 34);

    let names = vec!["Ada", "Grace"];
    let ct = encrypt(names, &cipher, ("users", 1u64)).unwrap();
    assert_eq!(
        decrypt_as::<Vec<String>, _, _>(&cipher, ct, ("users", 1u64)).unwrap(),
        vec!["Ada".to_string(), "Grace".to_string()]
    );

    let nested = vec![vec![1u32, 2], vec![], vec![3]];
    let ct = encrypt(nested, &cipher, ()).unwrap();
    assert_eq!(decrypt_as::<Vec<Vec<u32>>, _, _>(&cipher, ct, ()).unwrap(), vec![vec![1, 2], vec![], vec![3]]);
}

#[test]
fn a_typed_decrypt_refuses_the_wrong_kind() {
    let cipher = cipher();
    let ct = encrypt(34u32, &cipher, ()).unwrap();
    assert!(matches!(
        decrypt_as::<String, _, _>(&cipher, ct, ()),
        Err(DecryptError::Sink(DecodeError::Expected("string")))
    ));
}

#[test]
fn rust_types_decrypt_in_todays_guest() {
    // A Rust source sealed on the new path reads back in today's guest as
    // the frame the same source writes. So Rust and Go callers interoperate.
    let cipher = cipher();
    let ct = encrypt(Pair(Some(2.5), Bytes(&[1, 2])), &cipher, ()).unwrap();
    let mut out = Vec::new();
    codec::encode(&ct, &mut out).unwrap();
    // `()` encodes as empty AAD.
    let frame = today::decrypt(&cipher, b"", &out).unwrap();
    assert_eq!(&frame, to_frame(Pair(Some(2.5), Bytes(&[1, 2]))).unwrap().risky_ref());
}

/// A two-element heterogeneous sequence.
struct Pair(Option<f64>, Bytes<'static>);

impl Plaintext for Pair {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut seq = sink.seq(Some(2))?;
        self.0.visit(seq.element()?)?;
        self.1.visit(seq.element()?)?;
        seq.end()
    }
}

#[test]
fn a_failing_source_stops_the_walk_with_its_own_error() {
    let cipher = cipher();
    match encrypt(Failing(34u32), &cipher, ()) {
        Err(EncryptError::Source(e)) => assert_eq!(e.to_string(), "getter threw"),
        other => panic!("{other:?}"),
    }
    assert!(to_frame(Failing(34u32)).is_err());
}

#[test]
fn unknown_lengths_are_patched_in() {
    struct Unsized(Vec<u32>);
    impl Plaintext for Unsized {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            visit_seq(sink, None, self.0)
        }
    }
    let unsized_frame = to_frame(Unsized(vec![1, 2, 3])).unwrap();
    let sized_frame = to_frame(vec![1u32, 2, 3]).unwrap();
    assert_eq!(unsized_frame.risky_ref(), sized_frame.risky_ref());
}

#[test]
fn an_all_passthrough_sequence_is_refused() {
    struct Pass;
    impl Plaintext for Pass {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            sink.passthrough("public")
        }
    }
    let cipher = cipher();
    assert!(matches!(encrypt(vec![Pass], &cipher, ()), Err(EncryptError::Shape(_))));
}
