//! End-to-end tests for `ContextTag` against the real AES-256-GCM cipher.
//!
//! The `vitaminc-aead` unit tests prove that `ContextTag` binds the right AAD bytes at encrypt
//! time using a mock cipher. These tests close the loop with a concrete AEAD: a value sealed
//! through `ContextTag` must decrypt only when the same context is supplied — via the
//! `ContextTag::context(..).decrypt[_with_aad]` helper or the lower-level
//! `ContextTag::aad` / `ContextTag::aad_with` builders — and must fail otherwise.

use vitaminc_aead::{ContextTag, Encrypt};
use vitaminc_encrypt::{Aes256Cipher, Key};

fn cipher() -> Aes256Cipher {
    Aes256Cipher::new(&Key::from([42u8; 32])).expect("failed to create cipher")
}

#[test]
fn roundtrip_with_context_tag() {
    let cipher = cipher();

    let ciphertext = ContextTag::new("secret message", "user:42")
        .encrypt(&cipher)
        .expect("encryption failed");

    let plaintext: String = cipher
        .decrypt_with_aad(ciphertext, ContextTag::aad("user:42"))
        .expect("decryption failed");

    assert_eq!(plaintext, "secret message");
}

#[test]
fn roundtrip_with_context_tag_and_extra_aad() {
    let cipher = cipher();

    let ciphertext = ContextTag::new("secret", "table:users")
        .encrypt_with_aad(&cipher, "row:99")
        .expect("encryption failed");

    let plaintext: String = cipher
        .decrypt_with_aad(ciphertext, ContextTag::aad_with("row:99", "table:users"))
        .expect("decryption failed");

    assert_eq!(plaintext, "secret");
}

#[test]
fn decrypt_fails_with_wrong_context() {
    let cipher = cipher();

    let ciphertext = ContextTag::new("secret", "user:42")
        .encrypt(&cipher)
        .expect("encryption failed");

    let result: Result<String, _> = cipher.decrypt_with_aad(ciphertext, ContextTag::aad("user:99"));
    assert!(result.is_err(), "wrong context must not decrypt");
}

#[test]
fn decrypt_fails_when_context_omitted() {
    let cipher = cipher();

    let ciphertext = ContextTag::new("secret", "user:42")
        .encrypt(&cipher)
        .expect("encryption failed");

    // Decrypting with no AAD at all must fail — the tag was authenticated.
    let result: Result<String, _> = cipher.decrypt(ciphertext);
    assert!(result.is_err(), "omitting the context must not decrypt");
}

#[test]
fn roundtrip_with_refined_context() {
    let cipher = cipher();

    let ciphertext = ContextTag::new("secret", "table:users")
        .refine("column:email")
        .encrypt(&cipher)
        .expect("encryption failed");

    // The refined tag is the nested tuple ("table:users", "column:email").
    let plaintext: String = cipher
        .decrypt_with_aad(ciphertext, ContextTag::aad(("table:users", "column:email")))
        .expect("decryption failed");

    assert_eq!(plaintext, "secret");
}

#[test]
fn refined_context_fails_with_unrefined_aad() {
    let cipher = cipher();

    let ciphertext = ContextTag::new("secret", "table:users")
        .refine("column:email")
        .encrypt(&cipher)
        .expect("encryption failed");

    // Supplying only the outer tag must not authenticate.
    let result: Result<String, _> =
        cipher.decrypt_with_aad(ciphertext, ContextTag::aad("table:users"));
    assert!(result.is_err());
}

#[test]
fn context_tag_binds_owned_and_integer_tags() {
    let cipher = cipher();

    let ciphertext = ContextTag::new("secret", 7u64)
        .encrypt_with_aad(&cipher, String::from("session"))
        .expect("encryption failed");

    let plaintext: String = cipher
        .decrypt_with_aad(
            ciphertext,
            ContextTag::aad_with(String::from("session"), 7u64),
        )
        .expect("decryption failed");

    assert_eq!(plaintext, "secret");
}

// --- The `ContextTag::context(..).decrypt[_with_aad]` helper (symmetric with the
// --- encrypt side, driving a `Decipher` from `cipher.decipher(ciphertext)`). ---

#[test]
fn context_helper_roundtrip() {
    let cipher = cipher();

    let ciphertext = ContextTag::new("secret message", "user:42")
        .encrypt(&cipher)
        .expect("encryption failed");

    let plaintext: String = ContextTag::context("user:42")
        .decrypt(cipher.decipher(ciphertext))
        .expect("decryption failed");

    assert_eq!(plaintext, "secret message");
}

#[test]
fn context_helper_roundtrip_with_extra_aad() {
    let cipher = cipher();

    let ciphertext = ContextTag::new("secret", "table:users")
        .encrypt_with_aad(&cipher, "row:99")
        .expect("encryption failed");

    let plaintext: String = ContextTag::context("table:users")
        .decrypt_with_aad(cipher.decipher(ciphertext), "row:99")
        .expect("decryption failed");

    assert_eq!(plaintext, "secret");
}

#[test]
fn context_helper_refine_rebuilds_nested_tag() {
    let cipher = cipher();

    let ciphertext = ContextTag::new("secret", "table:users")
        .refine("column:email")
        .encrypt(&cipher)
        .expect("encryption failed");

    // The decrypt context is built with the SAME refine chain — no hand-written
    // nested tuple to get wrong.
    let plaintext: String = ContextTag::context("table:users")
        .refine("column:email")
        .decrypt(cipher.decipher(ciphertext))
        .expect("decryption failed");

    assert_eq!(plaintext, "secret");
}

#[test]
fn context_helper_wrong_tag_fails() {
    let cipher = cipher();

    let ciphertext = ContextTag::new("secret", "user:42")
        .encrypt(&cipher)
        .expect("encryption failed");

    let result: Result<String, _> =
        ContextTag::context("user:99").decrypt(cipher.decipher(ciphertext));
    assert!(result.is_err(), "wrong context must not decrypt");
}

#[test]
fn context_helper_roundtrips_composite_value() {
    let cipher = cipher();

    // A composite inner type (Vec): the (extra, tag) AAD must be distributed to every
    // element identically on encrypt and decrypt for this to round-trip.
    let items = vec![String::from("a"), String::from("b"), String::from("c")];
    let ciphertext = ContextTag::new(items.clone(), "table:users")
        .refine("column:tags")
        .encrypt_with_aad(&cipher, "row:99")
        .expect("encryption failed");

    let plaintext: Vec<String> = ContextTag::context("table:users")
        .refine("column:tags")
        .decrypt_with_aad(cipher.decipher(ciphertext), "row:99")
        .expect("decryption failed");

    assert_eq!(plaintext, items);
}

// --- Negative / coverage tests: the extra AAD, the chained-refine nesting, the
// --- `aad_with` arg order, composite values, and non-string tags must each be
// --- authenticated — a wrong/partial context must fail to decrypt. ---

#[test]
fn decrypt_fails_with_wrong_extra_aad() {
    let cipher = cipher();

    let ciphertext = ContextTag::new("secret", "table:users")
        .encrypt_with_aad(&cipher, "row:99")
        .expect("encryption failed");

    // Correct tag but wrong *extra* AAD: the extra is authenticated too, so this
    // must fail. Guards against the fold ever dropping `extra_aad`.
    let result: Result<String, _> =
        ContextTag::context("table:users").decrypt_with_aad(cipher.decipher(ciphertext), "row:00");
    assert!(result.is_err(), "wrong extra AAD must not decrypt");
}

#[test]
fn context_helper_double_refine_roundtrips() {
    let cipher = cipher();

    // Two refines => left-nested tag (("a", "b"), "c"). Pins that the e2e decrypt
    // path reconstructs the same nesting (the unit tests only assert the bytes).
    let ciphertext = ContextTag::new("secret", "a")
        .refine("b")
        .refine("c")
        .encrypt(&cipher)
        .expect("encryption failed");

    let plaintext: String = ContextTag::context("a")
        .refine("b")
        .refine("c")
        .decrypt(cipher.decipher(ciphertext))
        .expect("decryption failed");

    assert_eq!(plaintext, "secret");
}

#[test]
fn aad_with_swapped_args_fails_to_decrypt() {
    let cipher = cipher();

    // Sealed as (extra="row:99", tag="table:users").
    let ciphertext = ContextTag::new("secret", "table:users")
        .encrypt_with_aad(&cipher, "row:99")
        .expect("encryption failed");

    // `aad_with(extra, tag)` — swapping the two same-typed args silently builds the
    // wrong AAD. This pins that the documented footgun actually fails to decrypt
    // (i.e. the order genuinely matters at the byte level).
    let result: Result<String, _> =
        cipher.decrypt_with_aad(ciphertext, ContextTag::aad_with("table:users", "row:99"));
    assert!(result.is_err(), "swapped aad_with args must not decrypt");
}

#[test]
fn composite_value_fails_with_wrong_context() {
    let cipher = cipher();

    // Multi-element value: every element is bound to the context. A wrong tag must
    // fail — guards against per-element AAD threading silently dropping on any element.
    let items = vec![String::from("a"), String::from("b"), String::from("c")];
    let ciphertext = ContextTag::new(items, "table:users")
        .encrypt_with_aad(&cipher, "row:99")
        .expect("encryption failed");

    let result: Result<Vec<String>, _> =
        ContextTag::context("table:WRONG").decrypt_with_aad(cipher.decipher(ciphertext), "row:99");
    assert!(
        result.is_err(),
        "wrong context must not decrypt a composite value"
    );
}

#[test]
fn integer_tag_fails_with_wrong_context() {
    let cipher = cipher();

    // Wrong-context coverage for a non-string (`u64`) tag.
    let ciphertext = ContextTag::new("secret", 7u64)
        .encrypt(&cipher)
        .expect("encryption failed");

    let result: Result<String, _> = ContextTag::context(8u64).decrypt(cipher.decipher(ciphertext));
    assert!(result.is_err(), "wrong integer context must not decrypt");
}
