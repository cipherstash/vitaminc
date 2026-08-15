//! Native (host-target) exercise of the full guest pipeline:
//! transport-decode → encrypt → transport-encode → transport-decode →
//! decrypt → transport-encode. This is the same code path `vc_encrypt` /
//! `vc_decrypt` drive inside the wasm module, minus the linear-memory ABI.

use vitaminc_aead::{Aad, Encrypt};
use vitaminc_aead_value::transport::{self as codec, Reader};
use vitaminc_aead_value::FfiValue;
use vitaminc_encrypt::{Aes256Cipher, AesCipherText, Key};

fn cipher() -> Aes256Cipher {
    Aes256Cipher::new(&Key::from([7u8; 32])).unwrap()
}

fn passthrough(v: FfiValue) -> FfiValue {
    FfiValue::Passthrough(Box::new(v))
}

fn sample() -> FfiValue {
    FfiValue::Object(vec![
        // Non-secret fields travelling in the clear alongside the sealed ones.
        ("id".into(), passthrough(FfiValue::Int64(7))),
        (
            "created_at".into(),
            passthrough(FfiValue::String("2026-07-25".into())),
        ),
        (
            "user".into(),
            FfiValue::Object(vec![
                ("email".into(), FfiValue::String("ada@example.com".into())),
                ("logins".into(), FfiValue::Int64(42)),
                ("visits".into(), FfiValue::Int32(-3)),
                ("port".into(), FfiValue::UInt32(8080)),
            ]),
        ),
        (
            "readings".into(),
            FfiValue::Array(vec![
                FfiValue::Float64(1.25),
                FfiValue::Float64(-0.0),
                FfiValue::Float32(0.5),
            ]),
        ),
    ])
}

fn encoded(value: FfiValue) -> Vec<u8> {
    let mut out = Vec::new();
    codec::encode_value(value, &mut out).unwrap();
    out
}

#[test]
fn transport_pipeline_round_trips() {
    let cipher = cipher();
    let aad = b"pipeline-test";

    // Encrypt side, as vc_encrypt does it.
    let value = codec::decode_value(&mut Reader::new(&encoded(sample()))).unwrap();
    let ct = value
        .encrypt_with_aad(&cipher, Aad::from_slice(aad))
        .unwrap();
    let mut ct_bytes = Vec::new();
    codec::encode_ciphertext_boxed(ct, &mut ct_bytes).unwrap();

    // Decrypt side, as vc_decrypt does it.
    let ct: AesCipherText = codec::decode_ciphertext_boxed(&mut Reader::new(&ct_bytes)).unwrap();
    let decrypted: FfiValue = cipher.decrypt_with_aad(ct, Aad::from_slice(aad)).unwrap();

    assert_eq!(encoded(decrypted), encoded(sample()));
}

#[test]
fn aad_mismatch_fails() {
    let cipher = cipher();
    let ct = sample()
        .encrypt_with_aad(&cipher, Aad::from_slice(b"right"))
        .unwrap();
    let mut ct_bytes = Vec::new();
    codec::encode_ciphertext_boxed(ct, &mut ct_bytes).unwrap();

    let ct: AesCipherText = codec::decode_ciphertext_boxed(&mut Reader::new(&ct_bytes)).unwrap();
    assert!(cipher
        .decrypt_with_aad::<FfiValue, _>(ct, Aad::from_slice(b"wrong"))
        .is_err());
}
