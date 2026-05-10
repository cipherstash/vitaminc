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

    /// Encrypts `in_out` in place and appends the 16-byte tag.
    pub(crate) fn seal_in_place_append_tag(
        &self,
        nonce: &[u8; super::NONCE_LEN],
        aad: &[u8],
        in_out: &mut Vec<u8>,
    ) -> Result<(), Unspecified> {
        let nonce = Nonce::from_slice(nonce);
        let tag = self
            .0
            .encrypt_in_place_detached(nonce, aad, in_out)
            .map_err(|_| Unspecified)?;
        in_out.extend_from_slice(tag.as_slice());
        Ok(())
    }

    /// Decrypts `in_out` (ciphertext || tag) in place. Returns the plaintext
    /// length — `in_out[..len]` is the plaintext after the call. The tag bytes
    /// at the tail are not zeroed but are not part of the returned length.
    pub(crate) fn open_in_place(
        &self,
        nonce: &[u8; super::NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<usize, Unspecified> {
        if in_out.len() < super::TAG_LEN {
            return Err(Unspecified);
        }
        let plaintext_len = in_out.len() - super::TAG_LEN;
        let (ciphertext, tag_bytes) = in_out.split_at_mut(plaintext_len);
        let tag = Tag::<Aes256Gcm>::clone_from_slice(tag_bytes);
        let nonce = Nonce::from_slice(nonce);
        self.0
            .decrypt_in_place_detached(nonce, aad, ciphertext, &tag)
            .map_err(|_| Unspecified)?;
        Ok(plaintext_len)
    }
}
