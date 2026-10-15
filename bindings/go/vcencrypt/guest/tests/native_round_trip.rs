//! Native (host-target) exercise of the full guest pipeline:
//! frame parse → encrypt → transport-encode → transport-decode → decrypt
//! into a frame writer. This is the same code path `vc_encrypt` /
//! `vc_decrypt` drive inside the wasm module, minus the linear-memory ABI.

use vitaminc_aead::{
    decrypt_to_frame, encrypt, to_frame, Context, DecryptError, Frame, MapSink, Node, Plaintext,
    SeqSink, Sink,
};
use vitaminc_aead_frame::transport as codec;
use vitaminc_encrypt::{Aes256Cipher, Key, LocalCipherText};
use vitaminc_protected::Controlled;

fn cipher() -> Aes256Cipher {
    Aes256Cipher::new(&Key::from([7u8; 32])).unwrap()
}

/// A record mixing passthrough fields, a nested object and an array of
/// floats, as a host would send it.
#[derive(Clone)]
struct Sample;

impl Plaintext for Sample {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut map = sink.map(Some(4))?;
        // Non-secret fields travelling in the clear alongside the sealed ones.
        map.entry("id")?.passthrough(7i64)?;
        map.entry("created_at")?.passthrough("2026-07-25")?;
        {
            let mut user = map.entry("user")?.map(Some(4))?;
            "ada@example.com".visit(user.entry("email")?)?;
            42i64.visit(user.entry("logins")?)?;
            (-3i32).visit(user.entry("visits")?)?;
            8080u32.visit(user.entry("port")?)?;
            user.end()?;
        }
        {
            let mut readings = map.entry("readings")?.seq(Some(3))?;
            1.25f64.visit(readings.element()?)?;
            (-0.0f64).visit(readings.element()?)?;
            0.5f32.visit(readings.element()?)?;
            readings.end()?;
        }
        map.end()
    }
}

fn frame_bytes() -> Vec<u8> {
    to_frame(Sample).unwrap().risky_unwrap()
}

/// Encrypt a frame as `vc_encrypt` does: parse, encrypt in place, encode.
fn encrypt_frame(cipher: &Aes256Cipher, frame: &[u8], aad: &[u8]) -> Vec<u8> {
    let frame = Frame::parse(frame).unwrap();
    let node = encrypt(frame, cipher, Context::from_encoded(aad)).unwrap();
    let mut out = Vec::new();
    codec::encode_ciphertext(&node, &mut out).unwrap();
    out
}

/// Decrypt as `vc_decrypt` does: decode, then open into a wiped frame.
fn decrypt_frame(
    cipher: &Aes256Cipher,
    ct: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, DecryptError<vitaminc_aead::frame::FrameWriteError, vitaminc_aead::Unspecified>>
{
    let node: Node<LocalCipherText> = codec::decode_ciphertext(ct).unwrap();
    Ok(decrypt_to_frame(cipher, node, Context::from_encoded(aad))?.risky_unwrap())
}

#[test]
fn transport_pipeline_round_trips_byte_for_byte() {
    let cipher = cipher();
    let aad = b"pipeline-test";
    let ct = encrypt_frame(&cipher, &frame_bytes(), aad);
    let decrypted = decrypt_frame(&cipher, &ct, aad).unwrap();
    assert_eq!(decrypted, frame_bytes());
}

#[test]
fn aad_mismatch_fails_at_the_cipher() {
    let cipher = cipher();
    let ct = encrypt_frame(&cipher, &frame_bytes(), b"right");
    assert!(matches!(
        decrypt_frame(&cipher, &ct, b"wrong"),
        Err(DecryptError::Cipher(_))
    ));
}

#[test]
fn a_frame_sealed_as_an_element_opens_as_a_batch_element() {
    // `vc_encrypt_element` seals under the sequence-element derivation, so
    // its ciphertext is what a batch encrypt of `[value]` holds at index 0.
    let cipher = cipher();
    let aad = Context::from_encoded(b"rows".as_slice());
    let frame = frame_bytes();

    let alone = encrypt(
        Frame::parse(&frame).unwrap(),
        &cipher,
        aad.for_sequence_element(),
    )
    .unwrap();
    let batch = encrypt(vec![Frame::parse(&frame).unwrap()], &cipher, aad.clone()).unwrap();
    let vitaminc_aead::CipherText::Sequence(mut items) = batch else {
        panic!("a sequence seals as a sequence");
    };
    let from_batch = items.remove(0);

    for node in [alone, from_batch] {
        let out = decrypt_to_frame(&cipher, node, aad.for_sequence_element()).unwrap();
        assert_eq!(out.risky_unwrap(), frame);
    }
}
