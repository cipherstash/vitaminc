//! Fixtures shared by the integration-test binaries.

use vitaminc_encrypt::{Aes256Cipher, Key};

/// The one AES-256-GCM cipher every integration test drives, under a fixed
/// key so every test shares the same key material — anything encrypted by
/// one helper can be decrypted by another. Ciphertext itself is never
/// stable: each call draws a fresh random nonce.
pub fn cipher() -> Aes256Cipher {
    Aes256Cipher::new(&Key::from([42u8; 32])).expect("failed to create cipher")
}
