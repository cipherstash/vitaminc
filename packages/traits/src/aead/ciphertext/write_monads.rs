use bytes::BytesMut;
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;
use crate::Nonce;
use super::{CipherText, TAG_SIZE};


// TODO: Add an optional header
// TODO: We may want to make TAG_SIZE fixed at 16-bytes
pub struct CipherTextBuilder();

impl CipherTextBuilder {
    pub fn new() -> Self {
        Self()
    }

    pub fn append_nonce<const N: usize>(self, nonce: Nonce<N>) -> NonceWritten<N> {
        NonceWritten(nonce)
    }
}



// TODO: Use a Protected<Vec<u8>>
pub struct NonceWritten<const N: usize>(Nonce<N>);

impl<const N: usize> NonceWritten<N> {
    pub fn append_target_plaintext(self, plaintext: Protected<Vec<u8>>) -> PlaintextWritten<N> {
        PlaintextWritten::new(self.0, plaintext)
    }
}

pub struct PlaintextWritten<const N: usize>(Nonce<N>, Protected<Vec<u8>>);

impl<const N: usize> PlaintextWritten<N> {
    fn new(nonce: Nonce<N>, plaintext: Protected<Vec<u8>>) -> Self {
        Self(nonce, plaintext)
    }
    /*fn new(nonce: Nonce<N>, plaintext: Protected<Vec<u8>>) -> Self {
        let inner = plaintext
            .map(|data| {
                let mut bytes = Vec::with_capacity(N + data.len() + TAG_SIZE);
                bytes.extend(nonce.into_inner());
                bytes.extend(data);
                bytes
            });
            
        Self(inner)
    }*/

    pub fn accepts_ciphertext_and_tag(self, f: impl FnOnce(Vec<u8>) -> Vec<u8>) -> EncryptedWithTag<N> {
        EncryptedWithTag::new(self.0, self.1.map(f))
    }
}

pub struct EncryptedWithTag<const N: usize> {
    nonce: Nonce<N>,
    bytes: Protected<Vec<u8>>,
}

impl<const N: usize> EncryptedWithTag<N> {
    fn new(nonce: Nonce<N>, bytes: Protected<Vec<u8>>) -> Self {
        Self { bytes, nonce }
    }

    pub fn build(self) -> CipherText {
        // The value has been encrypted, so we can unwrap it
        let inner = self.bytes.risky_unwrap();
        let mut bytes = BytesMut::with_capacity(N + inner.len());
        bytes.extend(self.nonce.into_inner());
        bytes.extend(inner.into_iter());
        CipherText(bytes.freeze())
    }
}