//! Native (host-target) exercise of the full guest pipeline:
//! transport-decode → encrypt → transport-encode → transport-decode →
//! decrypt → transport-encode. This is the same code path `vc_encrypt` /
//! `vc_decrypt` drive inside the wasm module, minus the linear-memory ABI.

use vitaminc_aead::{Aad, Encrypt};
use vitaminc_aead_value::transport::{self as codec, Reader};
use vitaminc_aead_value::FfiValue;
use vitaminc_encrypt::{Aes256Cipher, AesCipherText, Key};
use vitaminc_protected::Protected;

fn cipher() -> Aes256Cipher {
    Aes256Cipher::new(&Key::from([7u8; 32])).unwrap()
}

fn sample() -> FfiValue {
    FfiValue::Object(vec![
        (
            "user".into(),
            FfiValue::Object(vec![
                (
                    "email".into(),
                    FfiValue::String(Protected::new(b"ada@example.com".to_vec())),
                ),
                ("logins".into(), FfiValue::Int(42)),
            ]),
        ),
        (
            "readings".into(),
            FfiValue::Array(vec![FfiValue::Number(1.25), FfiValue::Number(-0.0)]),
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
    codec::encode_ciphertext(&ct, &mut ct_bytes).unwrap();

    // Decrypt side, as vc_decrypt does it.
    let ct: AesCipherText = codec::decode_ciphertext(&mut Reader::new(&ct_bytes)).unwrap();
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
    codec::encode_ciphertext(&ct, &mut ct_bytes).unwrap();

    let ct: AesCipherText = codec::decode_ciphertext(&mut Reader::new(&ct_bytes)).unwrap();
    assert!(cipher
        .decrypt_with_aad::<FfiValue, _>(ct, Aad::from_slice(b"wrong"))
        .is_err());
}
