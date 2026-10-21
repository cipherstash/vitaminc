use super::LocalCipherText;
use crate::Nonce;
use bytes::BytesMut;
use vitaminc_protected::{Controlled, Protected};

#[derive(Default)]
pub struct CipherTextBuilder();

impl CipherTextBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn append_nonce<const N: usize>(self, nonce: Nonce<N>) -> NonceWritten<N> {
        NonceWritten(nonce)
    }
}

pub struct NonceWritten<const N: usize>(Nonce<N>);

impl<const N: usize> NonceWritten<N> {
    pub fn append_target_plaintext(
        self,
        plaintext: impl Into<Protected<Vec<u8>>>,
    ) -> PlaintextWritten<N> {
        PlaintextWritten::new(self.0, plaintext.into())
    }

    /// Append a fixed-width array plaintext, reserving `reserve` extra bytes of
    /// spare capacity in the backing buffer so an in-place AEAD seal can append
    /// its tag without reallocating. Sizing the plaintext buffer is the
    /// builder's job, so callers sealing fixed-width leaves route through here
    /// rather than hand-rolling the `Vec` assembly at the call site.
    ///
    /// The array is copied out through `risky_ref` (a borrow) so `plaintext`
    /// keeps ownership of the original and is wiped by `ZeroizeOnDrop` at end
    /// of scope — a `risky_unwrap` would partially-move the bare `[u8; M]` out
    /// and skip that wipe (see issue #170).
    pub fn append_target_plaintext_array<const M: usize>(
        self,
        plaintext: Protected<[u8; M]>,
        reserve: usize,
    ) -> PlaintextWritten<N> {
        let src = plaintext.risky_ref();
        let mut buf = Vec::with_capacity(M + reserve);
        buf.extend_from_slice(src);
        PlaintextWritten::new(self.0, Protected::new(buf))
    }
}

pub struct PlaintextWritten<const N: usize>(Nonce<N>, Protected<Vec<u8>>);

impl<const N: usize> PlaintextWritten<N> {
    fn new(nonce: Nonce<N>, plaintext: Protected<Vec<u8>>) -> Self {
        Self(nonce, plaintext)
    }

    /// Hands the closure the plaintext buffer, which it must overwrite in
    /// place with the ciphertext and then extend with the tag.
    ///
    /// The closure borrows the buffer, so it stays inside the `Protected`
    /// throughout. A backend that fails part way through may leave
    /// plaintext in it, and the buffer is wiped on that path too.
    pub fn accepts_ciphertext_and_tag_ok<E>(
        self,
        f: impl FnOnce(&mut Vec<u8>) -> Result<(), E>,
    ) -> EncryptedWithTag<N, E> {
        let Self(nonce, mut buf) = self;
        // On an error `buf` is dropped, and so wiped, with the closure.
        EncryptedWithTag::new(nonce, buf.risky_try_update(f).map(|()| buf))
    }
}

pub struct EncryptedWithTag<const N: usize, E> {
    nonce: Nonce<N>,
    bytes: Result<Protected<Vec<u8>>, E>,
}

impl<const N: usize, E> EncryptedWithTag<N, E> {
    fn new(nonce: Nonce<N>, bytes: Result<Protected<Vec<u8>>, E>) -> Self {
        Self { bytes, nonce }
    }

    pub fn build(self) -> Result<LocalCipherText, E> {
        // SAFETY: at this point `self.bytes` is the *ciphertext* (sealed by
        // the AEAD primitive — version || nonce || ciphertext || tag, with
        // the tag bound to AAD). It is not secret-bearing, so unwrapping the
        // `Protected` guard does not leak plaintext. The resulting
        // `LocalCipherText` is intentionally durable: it is what we return
        // to the caller.
        let inner = self.bytes?.risky_unwrap();
        let mut bytes = BytesMut::with_capacity(1 + N + inner.len());
        bytes.extend([super::WIRE_VERSION]);
        bytes.extend(self.nonce.into_inner());
        bytes.extend(inner);
        Ok(LocalCipherText(bytes.freeze()))
    }
}
