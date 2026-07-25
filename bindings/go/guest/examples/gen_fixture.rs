//! Generates the cross-language test fixture consumed by the Go module's
//! `TestCrossLanguageFixture`: a value tree encrypted by **native** Rust
//! (aws-lc-rs backend) that Go must decrypt through the wasm guest
//! (RustCrypto backend) — proving key format, ciphertext transport,
//! sealed-leaf tags, and AAD handling all line up across languages *and*
//! across crypto backends.
//!
//! Run from `bindings/go/guest`:
//!
//! ```sh
//! cargo run --example gen_fixture
//! ```
//!
//! Regenerate only when the transport encoding or the fixture value
//! changes; the output is committed at `bindings/go/testdata/`.
//!
//! Layout (all lengths u32 LE):
//! `"VCGO1" ++ key[32] ++ len(aad) ++ aad ++ len(ct) ++ ct ++ len(val) ++ val`
//! where `ct` and `val` use the transport codec.

use std::fs;

use vitaminc_aead::{Aad, Encrypt};
use vitaminc_aead_value::FfiValue;
use vitaminc_encrypt::{Aes256Cipher, Key};
use vitaminc_protected::Protected;
use vitaminc_wasi_guest::codec;

const AAD: &[u8] = b"vitaminc/go-spike/fixture";

fn string(s: &str) -> FfiValue {
    FfiValue::String(Protected::new(s.as_bytes().to_vec()))
}

fn fixture_value() -> FfiValue {
    FfiValue::Object(vec![
        ("name".into(), string("Ada Lovelace")),
        ("age".into(), FfiValue::Int(36)),
        ("score".into(), FfiValue::Number(1.5)),
        ("active".into(), FfiValue::Bool(true)),
        ("nickname".into(), FfiValue::Null),
        ("big".into(), FfiValue::Int(i64::MIN)),
        (
            "tags".into(),
            FfiValue::Array(vec![
                string("math"),
                string("engines"),
                FfiValue::Bool(false),
            ]),
        ),
        (
            "blob".into(),
            FfiValue::Bytes(Protected::new(vec![0xDE, 0xAD, 0xBE, 0xEF])),
        ),
    ])
}

fn push_chunk(out: &mut Vec<u8>, chunk: &[u8]) {
    out.extend_from_slice(&u32::try_from(chunk.len()).unwrap().to_le_bytes());
    out.extend_from_slice(chunk);
}

fn main() {
    // Fixed key: this is test data, not a secret.
    let key_bytes: [u8; 32] = std::array::from_fn(|i| i as u8);
    let cipher = Aes256Cipher::new(&Key::from(key_bytes)).unwrap();

    let ct = fixture_value()
        .encrypt_with_aad(&cipher, Aad::from_slice(AAD))
        .unwrap();
    let mut ct_bytes = Vec::new();
    codec::encode_ciphertext(&ct, &mut ct_bytes).unwrap();

    let mut val_bytes = Vec::new();
    codec::encode_value(fixture_value(), &mut val_bytes).unwrap();

    let mut out = Vec::new();
    out.extend_from_slice(b"VCGO1");
    out.extend_from_slice(&key_bytes);
    push_chunk(&mut out, AAD);
    push_chunk(&mut out, &ct_bytes);
    push_chunk(&mut out, &val_bytes);

    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/cross_lang.bin");
    fs::create_dir_all(concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata")).unwrap();
    fs::write(path, &out).unwrap();
    println!("wrote {path} ({} bytes)", out.len());
}
