//! RustCrypto `aes-gcm` backend for AES-256-GCM.

use aes_gcm::aead::{AeadInPlace, KeyInit, Tag};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use vitaminc_aead::Unspecified;

pub(crate) struct CipherKey(Aes256Gcm);

impl CipherKey {
    pub(crate) fn new(key_bytes: &[u8; 32]) -> Result<Self, Unspecified> {
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        Ok(Self(Aes256Gcm::new(key)))
    }

    /// Encrypts `in_out` in place and appends the authentication tag.
    pub(crate) fn seal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        in_out: &mut Vec<u8>,
    ) -> Result<(), Unspecified> {
        let nonce: &[u8; super::NONCE_LEN] = nonce.try_into().map_err(|_| Unspecified)?;
        let nonce = Nonce::from_slice(nonce);
        self.0
            .encrypt_in_place(nonce, aad, in_out)
            .map_err(|_| Unspecified)
    }

    /// Decrypts `in_out` (ciphertext || tag) in place. Returns the plaintext
    /// length — `in_out[..len]` is the plaintext after the call. The tag bytes
    /// at the tail are left untouched.
    pub(crate) fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<usize, Unspecified> {
        let plaintext_len = in_out
            .len()
            .checked_sub(super::TAG_LEN)
            .ok_or(Unspecified)?;
        let nonce: &[u8; super::NONCE_LEN] = nonce.try_into().map_err(|_| Unspecified)?;
        let nonce = Nonce::from_slice(nonce);
        let (ciphertext, tag_bytes) = in_out.split_at_mut(plaintext_len);
        let tag = Tag::<Aes256Gcm>::from_slice(tag_bytes);
        self.0
            .decrypt_in_place_detached(nonce, aad, ciphertext, tag)
            .map_err(|_| Unspecified)?;
        Ok(plaintext_len)
    }
}
