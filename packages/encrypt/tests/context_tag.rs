//! End-to-end tests for `ContextTag` against the real AES-256-GCM cipher.
//!
//! The `vitaminc-aead` unit tests prove that `ContextTag` binds the right AAD bytes at encrypt
//! time using a mock cipher. These tests close the loop with a concrete AEAD: a value sealed
//! through `ContextTag` must decrypt only when the same context is supplied via
//! `ContextTag::aad` / `ContextTag::aad_with`, and must fail otherwise.

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
        .decrypt_with_aad(ciphertext, ContextTag::aad_with("table:users", "row:99"))
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
        .decrypt_with_aad(ciphertext, ContextTag::aad_with(7u64, String::from("session")))
        .expect("decryption failed");

    assert_eq!(plaintext, "secret");
}
