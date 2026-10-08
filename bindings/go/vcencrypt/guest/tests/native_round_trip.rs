//! Native (host-target) exercise of the full guest pipeline:
//! transport-decode → encrypt → transport-encode → transport-decode →
//! decrypt → transport-encode. This is the same code path `vc_encrypt` /
//! `vc_decrypt` drive inside the wasm module, minus the linear-memory ABI.

use vitaminc_aead::{Context, Encrypt};
use vitaminc_aead_value::transport::{self as codec, Reader};
use vitaminc_aead_value::Value;
use vitaminc_encrypt::{Aes256Cipher, AesCipherText, Key};

fn cipher() -> Aes256Cipher {
    Aes256Cipher::new(&Key::from([7u8; 32])).unwrap()
}

fn passthrough(v: Value) -> Value {
    Value::Passthrough(Box::new(v))
}

fn sample() -> Value {
    Value::Object(vec![
        // Non-secret fields travelling in the clear alongside the sealed ones.
        ("id".into(), passthrough(Value::Int64(7))),
        (
            "created_at".into(),
            passthrough(Value::String("2026-07-25".into())),
        ),
        (
            "user".into(),
            Value::Object(vec![
                ("email".into(), Value::String("ada@example.com".into())),
                ("logins".into(), Value::Int64(42)),
                ("visits".into(), Value::Int32(-3)),
                ("port".into(), Value::UInt32(8080)),
            ]),
        ),
        (
            "readings".into(),
            Value::Array(vec![
                Value::Float64(1.25),
                Value::Float64(-0.0),
                Value::Float32(0.5),
            ]),
        ),
    ])
}

fn encoded(value: Value) -> Vec<u8> {
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
        .encrypt_with_aad(&cipher, Context::from_encoded(aad))
        .unwrap();
    let mut ct_bytes = Vec::new();
    codec::encode_ciphertext_boxed(ct, &mut ct_bytes).unwrap();

    // Decrypt side, as vc_decrypt does it.
    let ct: AesCipherText = codec::decode_ciphertext_boxed(&mut Reader::new(&ct_bytes)).unwrap();
    let decrypted: Value = cipher
        .decrypt_with_aad(ct, Context::from_encoded(aad))
        .unwrap();

    assert_eq!(encoded(decrypted), encoded(sample()));
}

#[test]
fn aad_mismatch_fails() {
    let cipher = cipher();
    let ct = sample()
        .encrypt_with_aad(&cipher, Context::from_encoded(b"right"))
        .unwrap();
    let mut ct_bytes = Vec::new();
    codec::encode_ciphertext_boxed(ct, &mut ct_bytes).unwrap();

    let ct: AesCipherText = codec::decode_ciphertext_boxed(&mut Reader::new(&ct_bytes)).unwrap();
    assert!(cipher
        .decrypt_with_aad::<Value, _>(ct, Context::from_encoded(b"wrong"))
        .is_err());
}
