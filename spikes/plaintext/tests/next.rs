//! Stage 2: no `Encrypt`, no `Decrypt`, no `Value`. Checked against
//! today's code with real AES-256-GCM.

// Some borrows are on purpose: they exercise the `&Value` source.
#![allow(clippy::needless_borrows_for_generic_args)]

mod common;

use common::{sample, valid};
use vitaminc_aead::LocalCipherText;
use vitaminc_aead_value::transport::{self, Reader};
use vitaminc_encrypt::{Aes256Cipher, AesCipherText, Key};
use vitaminc_plaintext_spike::hosts::go_guest::{next as guest, today, GuestError};
use vitaminc_plaintext_spike::next::model::{SeqSink, Sink};
use vitaminc_plaintext_spike::next::sources::{Bytes, Failing};
use vitaminc_plaintext_spike::next::{
    codec, decrypt_as, decrypt_into, encrypt, encrypt_with_terms, to_frame, DecodeError, DecryptError, EncryptError,
    Plaintext,
};
use vitaminc_plaintext_spike::Frame;
use vitaminc_protected::Controlled;

const AAD: &[u8] = b"\x01\x00\x00\x00spike";

fn cipher() -> Aes256Cipher {
    Aes256Cipher::new(&Key::from([7u8; 32])).unwrap()
}

#[test]
fn stage_two_guest_interoperates_with_today_both_ways() {
    let cipher = cipher();
    for v in valid() {
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
    for v in valid() {
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
    let ct = guest::encrypt(&cipher, AAD, &common::encode(sample())).unwrap();
    assert_eq!(guest::decrypt(&cipher, b"other", &ct).err(), Some(GuestError::Auth));
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
            vitaminc_plaintext_spike::next::model::visit_seq(sink, None, self.0)
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

#[test]
fn one_tee_gives_ciphertext_and_terms_like_stage_one() {
    let cipher = cipher();
    let bytes = common::encode(sample());
    let frame = Frame::parse(&bytes).unwrap();
    let (ct, terms) = encrypt_with_terms(frame, &cipher, ("users", 7u64)).unwrap();
    let (_, stage1) = vitaminc_plaintext_spike::encrypt_with_terms(&sample(), common::Recorder, ()).unwrap();

    assert_eq!(terms.len(), stage1.len());
    for (a, b) in terms.iter().zip(&stage1) {
        assert_eq!(a.path, b.path);
        assert_eq!(
            a.input.as_ref().unwrap().bytes.risky_ref(),
            b.input.as_ref().unwrap().bytes.risky_ref()
        );
    }

    // And the ciphertext from the same walk decrypts to the original frame.
    let mut out = Vec::new();
    decrypt_into(
        &cipher,
        ct,
        ("users", 7u64),
        vitaminc_plaintext_spike::next::frame_writer::FrameWriter::new(&mut out),
    )
    .unwrap();
    assert_eq!(out, bytes);
}
