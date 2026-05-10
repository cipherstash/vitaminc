//! `aws-lc-rs` backend for AES-256-GCM.

use aws_lc_rs::aead::{Aad as LcAad, LessSafeKey, Nonce as LcNonce, UnboundKey, AES_256_GCM};
use vitaminc_aead::Unspecified;

pub(crate) struct CipherKey(LessSafeKey);

impl CipherKey {
    pub(crate) fn new(key_bytes: &[u8; 32]) -> Result<Self, Unspecified> {
        let unbound = UnboundKey::new(&AES_256_GCM, key_bytes.as_ref()).map_err(|_| Unspecified)?;
        Ok(Self(LessSafeKey::new(unbound)))
    }

    /// Encrypts `in_out` in place and appends the 16-byte tag.
    pub(crate) fn seal_in_place_append_tag(
        &self,
        nonce: &[u8; super::NONCE_LEN],
        aad: &[u8],
        in_out: &mut Vec<u8>,
    ) -> Result<(), Unspecified> {
        let nonce = LcNonce::try_assume_unique_for_key(nonce.as_ref()).map_err(|_| Unspecified)?;
        self.0
            .seal_in_place_append_tag(nonce, LcAad::from(aad), in_out)
            .map_err(|_| Unspecified)?;
        Ok(())
    }

    /// Decrypts `in_out` (which contains ciphertext || tag) in place. Returns
    /// the plaintext length — `in_out[..len]` is the plaintext after the call.
    pub(crate) fn open_in_place(
        &self,
        nonce: &[u8; super::NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<usize, Unspecified> {
        let nonce = LcNonce::assume_unique_for_key(*nonce);
        self.0
            .open_in_place(nonce, LcAad::from(aad), in_out)
            .map(|plaintext| plaintext.len())
            .map_err(|_| Unspecified)
    }
}
