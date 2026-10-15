//! Generates the cross-language test fixture consumed by the Go module's
//! `TestCrossLanguageFixture`: a value encrypted by **native** Rust
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
//! `cross_lang_pre_adr0001.bin` beside it is the same value and key as the
//! pre-ADR 0001 `Value` path sealed them, and is never regenerated: it pins
//! that rows written before the model change still decrypt.
//!
//! Layout (all lengths u32 LE):
//! `"VCGO1" ++ key[32] ++ len(aad) ++ aad ++ len(ct) ++ ct ++ len(val) ++ val`
//! where `ct` uses the ciphertext transport and `val` is one frame.

use std::fs;

use vitaminc_aead::{encrypt, to_frame, Context, MapSink, Plaintext, SeqSink, Sink};
use vitaminc_aead_value::transport as codec;
use vitaminc_encrypt::{Aes256Cipher, Key};
use vitaminc_protected::{Controlled, Protected};

const AAD: &[u8] = b"vitaminc/go-spike/fixture";

/// The fixture value, as a source. Hand-written rather than derived so the
/// `tags` array can mix strings and a boolean, as a host value does.
#[derive(Clone)]
struct Fixture;

impl Plaintext for Fixture {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut map = sink.map(Some(14))?;
        // Passthrough fields: non-secret, travel in the clear. Go must read
        // these back WITHOUT the key path proving decryption.
        map.entry("id")?.passthrough(42i64)?;
        map.entry("created_at")?
            .passthrough("2026-07-25T00:00:00Z")?;
        "Ada Lovelace".visit(map.entry("name")?)?;
        36i64.visit(map.entry("age")?)?;
        1.5f64.visit(map.entry("score")?)?;
        true.visit(map.entry("active")?)?;
        None::<&str>.visit(map.entry("nickname")?)?;
        i64::MIN.visit(map.entry("big")?)?;
        // Above i64::MAX: exercises the UINT64 tag cross-language.
        u64::MAX.visit(map.entry("huge")?)?;
        // The 32-bit numeric family, at edge values: exercises the INT32 /
        // UINT32 / FLOAT32 tags (and Go's exact-width decode) cross-language.
        i32::MIN.visit(map.entry("rank")?)?;
        u32::MAX.visit(map.entry("port")?)?;
        0.5f32.visit(map.entry("ratio")?)?;
        {
            let mut tags = map.entry("tags")?.seq(Some(3))?;
            "math".visit(tags.element()?)?;
            "engines".visit(tags.element()?)?;
            false.visit(tags.element()?)?;
            tags.end()?;
        }
        Protected::new(vec![0xDEu8, 0xAD, 0xBE, 0xEF]).visit(map.entry("blob")?)?;
        map.end()
    }
}

fn push_chunk(out: &mut Vec<u8>, chunk: &[u8]) {
    out.extend_from_slice(&u32::try_from(chunk.len()).unwrap().to_le_bytes());
    out.extend_from_slice(chunk);
}

fn main() {
    // Fixed key: this is test data, not a secret.
    let key_bytes: [u8; 32] = std::array::from_fn(|i| i as u8);
    let cipher = Aes256Cipher::new(&Key::from(key_bytes)).unwrap();

    let node = encrypt(Fixture, &cipher, Context::from_encoded(AAD)).unwrap();
    let mut ct_bytes = Vec::new();
    codec::encode_ciphertext(&node, &mut ct_bytes).unwrap();

    let val_bytes = to_frame(Fixture).unwrap().risky_unwrap();

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
