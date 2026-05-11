#![deny(clippy::unwrap_used, clippy::todo, unsafe_code, unused_imports)]
#![doc = include_str!("../README.md")]
mod backend;
mod cipher;
mod key;

pub use cipher::Aes256Cipher;
pub use key::{EncryptedKey, Key};

// Re-exports
pub use vitaminc_aead::{
    Aad, Cipher, Decrypt, Encrypt, IntoAad, LocalCipherText, Nonce, Unspecified,
};

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
/// See also [`decrypt`].
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
pub fn encrypt<'a, T>(key: &Key, plaintext: T) -> Result<T::Encrypted, Unspecified>
where
    T: Encrypt<'a>,
{
    Aes256Cipher::new(key).and_then(|cipher| plaintext.encrypt(&cipher))
}

/// Encrypt the given plaintext using the provided key and additional authenticated data (AAD).
///
/// # Additional Authenticated Data (AAD)
///
/// AAD is optional data that is authenticated but not encrypted.
/// Decrypting the ciphertext requires the same AAD to be provided.
///
/// Any type that implements the [`IntoAad`] trait can be used to provide AAD.
///
/// See also [`decrypt_with_aad`] and [`vitaminc_aead::Aad`].
///
/// # Example
///
/// ```rust
/// # mod vitaminc { pub mod encrypt { pub use vitaminc_encrypt::*; } pub mod aead { pub use vitaminc_aead::*; } }
/// use vitaminc::encrypt::Key;
/// use vitaminc::aead::Encrypt;
/// let key = Key::from([0u8; 32]);
/// let encrypted = vitaminc::encrypt::encrypt_with_aad(&key, "message", "additional-data").unwrap();
/// ```
///
pub fn encrypt_with_aad<'a, T, A>(
    key: &Key,
    plaintext: T,
    aad: A,
) -> Result<T::Encrypted, Unspecified>
where
    T: Encrypt<'a>,
    A: IntoAad<'a>,
{
    Aes256Cipher::new(key).and_then(|cipher| plaintext.encrypt_with_aad(&cipher, aad))
}

/// Decrypt the given ciphertext using the provided key.
/// Any type that implements the [`Decrypt`] trait can be used so long as the value was encrypted with the same key.
///
/// # CipherText type
///
/// The type of `ciphertext` must match the `Encrypted` type defined in the [`Decrypt`] trait implementation for `T`.
///
/// # Example
///
/// ```rust
/// # mod vitaminc { pub mod encrypt { pub use vitaminc_encrypt::*; } pub mod aead { pub use vitaminc_aead::*; } }
/// use vitaminc::encrypt::Key;
/// use vitaminc::aead::Decrypt;
/// let key = Key::from([0u8; 32]);
/// let ciphertext = vitaminc::encrypt::encrypt(&key, "message").unwrap();
/// let decrypted: String = vitaminc::encrypt::decrypt(&key, ciphertext).unwrap();
/// assert_eq!(decrypted, "message");
/// ```
pub fn decrypt<T>(key: &Key, ciphertext: T::Encrypted) -> Result<T, Unspecified>
where
    T: Decrypt,
{
    Aes256Cipher::new(key).and_then(|cipher| T::decrypt(ciphertext, &cipher))
}

/// Decrypt the given ciphertext using the provided key and additional authenticated data (AAD).
/// This is the reversed operation of [`encrypt_with_aad`].
///
/// See also [`encrypt_with_aad`] and [`vitaminc_aead::Aad`].
///
/// # Example
///
/// ```rust
/// # mod vitaminc { pub mod encrypt { pub use vitaminc_encrypt::*; } pub mod aead { pub use vitaminc_aead::*; } }
/// use vitaminc::encrypt::Key;
/// use vitaminc::aead::Decrypt;
/// let key = Key::from([0u8; 32]);
/// let ciphertext = vitaminc::encrypt::encrypt_with_aad(&key, "message", "additional-data").unwrap();
/// let decrypted: String = vitaminc::encrypt::decrypt_with_aad(&key, ciphertext, "additional-data").unwrap();
/// assert_eq!(decrypted, "message");
/// ```
///
/// ## Incorrect AAD will fail
///
/// If the AAD does not match the one used during encryption, decryption will fail with an [`Unspecified`] error.
///
/// ```rust
/// # mod vitaminc { pub mod encrypt { pub use vitaminc_encrypt::*; } pub mod aead { pub use vitaminc_aead::*; } }
/// # use vitaminc::encrypt::Key;
/// # use vitaminc::aead::Decrypt;
/// # let key = Key::from([0u8; 32]);
/// let ciphertext = vitaminc::encrypt::encrypt_with_aad(&key, "message", "additional-data").unwrap();
/// let result = vitaminc::encrypt::decrypt_with_aad::<String, _>(&key, ciphertext, "wrong-data");
/// assert!(result.is_err());
/// ```
///
pub fn decrypt_with_aad<'a, T, A>(
    key: &Key,
    ciphertext: T::Encrypted,
    aad: A,
) -> Result<T, Unspecified>
where
    T: Decrypt,
    A: IntoAad<'a>,
{
    Aes256Cipher::new(key).and_then(|cipher| T::decrypt_with_aad(ciphertext, &cipher, aad))
}
