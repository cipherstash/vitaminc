//! Generates the cross-language test fixture consumed by the Go module's
//! `TestCrossLanguageFixture`: a value tree encrypted by **native** Rust
//! (aws-lc-rs backend) that Go must decrypt through the wasm guest
//! (RustCrypto backend) — proving key format, ciphertext transport,
//! sealed-leaf tags, and AAD handling all line up across languages *and*
//! across crypto backends.
//!
//! Run from `bindings/go/vcencrypt/guest`:
//!
//! ```sh
//! cargo run --example gen_fixture
//! ```
//!
//! Regenerate only when the transport encoding or the fixture value
//! changes; the output is committed at `bindings/go/vcencrypt/testdata/`.
//!
//! Layout (all lengths u32 LE):
//! `"VCGO1" ++ key[32] ++ len(aad) ++ aad ++ len(ct) ++ ct ++ len(val) ++ val`
//! where `ct` and `val` use the transport codec.

use std::fs;

use vitaminc_aead::{Aad, Encrypt};
use vitaminc_aead_value::transport as codec;
use vitaminc_aead_value::FfiValue;
use vitaminc_encrypt::{Aes256Cipher, Key};
use vitaminc_protected::Protected;

const AAD: &[u8] = b"vitaminc/go-spike/fixture";

fn string(s: &str) -> FfiValue {
    FfiValue::String(Protected::new(s.as_bytes().to_vec()))
}

fn passthrough(v: FfiValue) -> FfiValue {
    FfiValue::Passthrough(Box::new(v))
}

fn fixture_value() -> FfiValue {
    FfiValue::Object(vec![
        // Passthrough fields: non-secret, travel in the clear. Go must read
        // these back WITHOUT the key path proving decryption.
        ("id".into(), passthrough(FfiValue::Int64(42))),
        (
            "created_at".into(),
            passthrough(string("2026-07-25T00:00:00Z")),
        ),
        ("name".into(), string("Ada Lovelace")),
        ("age".into(), FfiValue::Int64(36)),
        ("score".into(), FfiValue::Float64(1.5)),
        ("active".into(), FfiValue::Bool(true)),
        ("nickname".into(), FfiValue::Null),
        ("big".into(), FfiValue::Int64(i64::MIN)),
        // Above i64::MAX: exercises the UINT64 tag cross-language.
        ("huge".into(), FfiValue::UInt64(u64::MAX)),
        // The 32-bit numeric family, at edge values: exercises the INT32 /
        // UINT32 / FLOAT32 tags (and Go's exact-width decode) cross-language.
        ("rank".into(), FfiValue::Int32(i32::MIN)),
        ("port".into(), FfiValue::UInt32(u32::MAX)),
        ("ratio".into(), FfiValue::Float32(0.5)),
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
    // Re-home the Box passthrough payload type to FfiValue value-nodes for the wire.
    codec::encode_ciphertext_boxed(ct, &mut ct_bytes).unwrap();

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
