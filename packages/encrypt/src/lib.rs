#![deny(clippy::unwrap_used, clippy::todo, unsafe_code, unused_imports)]
#![doc = include_str!("../README.md")]
mod backend;
mod cipher;
#[cfg(feature = "hlist")]
mod cipher_static;
mod key;

pub use cipher::{Aes256Cipher, OpensVersion1};
pub use key::Key;

// Re-exports
/// The sink-based cipher trait [`Aes256Cipher`] implements, and the entry
/// points that drive it.
pub use vitaminc_aead::seal::Cipher;
/// The derives for the data model: `Plaintext` for values going in, and the
/// sink-based `Decrypt` for typed values coming out. Inlined so the derives'
/// `#[aead(...)]` reference renders here too.
#[doc(inline)]
pub use vitaminc_aead::typed::Decrypt;
#[allow(deprecated)]
pub use vitaminc_aead::Aad;
#[doc(inline)]
pub use vitaminc_aead::Plaintext;
pub use vitaminc_aead::{
    decrypt, decrypt_into, encrypt, CipherText, DecodeError, DecryptError, EncryptError, Node,
};
pub use vitaminc_aead::{Context, IntoAad, IntoContext, LocalCipherText, Nonce, Unspecified};

/// The ciphertext tree [`Aes256Cipher`] produces: one sealed leaf per
/// scalar, with the shape of the value around them.
pub type AesCipherText = Node<LocalCipherText>;

/// Encrypt `plaintext` under `key` with no associated data.
///
/// Any type that implements [`Plaintext`] can be encrypted. This builds a
/// one-shot [`Aes256Cipher`]; to encrypt many values, or with associated
/// data, construct the cipher once and call [`encrypt`] with it.
///
/// # Errors
///
/// [`Unspecified`] if the cipher cannot be constructed or refuses a leaf,
/// and the other [`EncryptError`] cases if the value cannot be encrypted as
/// given (a container with nothing sealed, say).
///
/// # Example
///
/// ```rust
/// # mod vitaminc { pub mod encrypt { pub use vitaminc_encrypt::*; } }
/// use vitaminc::encrypt::Key;
/// let key = Key::from([0u8; 32]);
/// let encrypted = vitaminc::encrypt::encrypt_with_key(&key, "message").unwrap();
/// ```
pub fn encrypt_with_key<T>(
    key: &Key,
    plaintext: T,
) -> Result<AesCipherText, EncryptError<Unspecified>>
where
    T: Plaintext,
{
    let cipher = Aes256Cipher::new(key).map_err(EncryptError::Cipher)?;
    encrypt(plaintext, &cipher, ())
}

/// Decrypt `ciphertext` under `key` with no associated data into `T`.
///
/// The counterpart of [`encrypt_with_key`]. `T` is any type that
/// implements the sink-based [`Decrypt`]; to decrypt many values, or with
/// associated data, construct an [`Aes256Cipher`] once and call
/// [`decrypt`] with it.
///
/// # Errors
///
/// [`DecryptError::Cipher`] for a wrong key or a tampered leaf, and the
/// other [`DecryptError`] cases when the ciphertext does not have the shape
/// `T` expects.
pub fn decrypt_with_key<T>(
    key: &Key,
    ciphertext: AesCipherText,
) -> Result<T, DecryptError<DecodeError, Unspecified>>
where
    T: Decrypt,
{
    let cipher = Aes256Cipher::new(key).map_err(DecryptError::Cipher)?;
    decrypt(&cipher, ciphertext, ())
}
