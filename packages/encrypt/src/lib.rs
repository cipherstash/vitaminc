#![deny(clippy::unwrap_used, clippy::todo, unsafe_code, unused_imports)]
mod cipher;
mod key;

pub use cipher::Aes256Cipher;
pub use key::{EncryptedKey, Key};

// Re-exports
pub use vitaminc_aead::{Aad, Cipher, Decrypt, Encrypt, IntoAad, LocalCipherText, Nonce, Unspecified};

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
/// If the encryption fails, an `Unspecified` error is returned.
/// Specific errors may reveal information about the failure, such as key length issues or nonce generation problems
/// which can lead to security vulnerabilities so they are not detailed here.
///
/// See also [`decrypt`].
pub fn encrypt<T>(key: &Key, plaintext: T) -> Result<T::Encrypted, Unspecified>
where
    T: Encrypt,
{
    let cipher = Aes256Cipher::new();
    plaintext.encrypt(key, &cipher)
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
pub fn encrypt_with_aad<'a, T, A>(
    key: &Key,
    plaintext: T,
    aad: A,
) -> Result<T::Encrypted, Unspecified>
where
    T: Encrypt,
    A: IntoAad<'a>,
{
    let cipher = Aes256Cipher::new();
    plaintext.encrypt_with_aad(key, &cipher, aad)
}

/// Decrypt the given ciphertext using the provided key.
/// Any type that implements the [`Decrypt`] trait can be used.
///
/// # CipherText type
///
/// The type of `ciphertext` must match the `Encrypted` type defined in the [`Decrypt`] trait implementation for `T`.
///
pub fn decrypt<T>(key: &Key, ciphertext: T::Encrypted) -> Result<T, Unspecified>
where
    T: Decrypt,
{
    let cipher = Aes256Cipher::new();
    T::decrypt(ciphertext, key, &cipher)
}

/// Decrypt the given ciphertext using the provided key and additional authenticated data (AAD).
/// This is the reversed operation of [`encrypt_with_aad`].
///
/// See also [`encrypt_with_aad`] and [`vitaminc_aead::Aad`].
pub fn decrypt_with_aad<'a, T, A>(
    key: &Key,
    ciphertext: T::Encrypted,
    aad: A,
) -> Result<T, Unspecified>
where
    T: Decrypt,
    A: IntoAad<'a>,
{
    let cipher = Aes256Cipher::new();
    T::decrypt_with_aad(ciphertext, key, &cipher, aad)
}
