#![deny(clippy::unwrap_used, clippy::todo, unsafe_code, unused_imports)]
#![doc = include_str!("../README.md")]
mod backend;
mod cipher;
#[cfg(feature = "hlist")]
mod cipher_static;
mod key;

pub use cipher::{Aes256Cipher, AesCipherText};
pub use key::Key;

// Re-exports
pub use vitaminc_aead::{Aad, Cipher, Encrypt, IntoAad, LocalCipherText, Nonce, Unspecified};

/// Encrypt the given plaintext using the provided key.
/// Any type that implements the [`Encrypt`] trait can be used.
///
/// # Return type
///
/// The return type is the encrypted form of the plaintext, which is determined by the
/// `Encrypt` trait implementation for the type of `plaintext`.
///
/// # Errors
///
/// If the encryption fails, an [`Unspecified`] error is returned.
/// Specific errors may reveal information about the failure, such as key length issues or nonce generation problems
/// which can lead to security vulnerabilities so they are not detailed here.
///
/// # Example
///
/// ```rust
/// # mod vitaminc { pub mod encrypt { pub use vitaminc_encrypt::*; } pub mod aead { pub use vitaminc_aead::*; } }
/// use vitaminc::encrypt::Key;
/// use vitaminc::aead::Encrypt;
/// let key = Key::from([0u8; 32]);
/// let encrypted = vitaminc::encrypt::encrypt(&key, "message").unwrap();
/// ```
///
pub fn encrypt<T>(key: &Key, plaintext: T) -> Result<AesCipherText, Unspecified>
where
    T: Encrypt,
{
    Aes256Cipher::new(key).and_then(|cipher| plaintext.encrypt(&cipher))
}
