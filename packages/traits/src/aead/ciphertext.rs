use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use vitaminc_protected::{Controlled, Protected};
use super::Nonce;

const TAG_SIZE: usize = 16;

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CipherText(Bytes);

impl CipherText {
    pub fn into_inner(self) -> Bytes {
        self.0
    }

    pub fn into_reader<const N: usize>(self) -> NonceReader<N> {
        NonceReader(self.0.into())
    }
}

pub struct NonceReader<const N: usize>(Bytes);

impl <const N: usize> NonceReader<N> {
    pub fn ciphertext(&self) -> &[u8] {
        &self.0[N..]
    }

    /// We can prove that the nonce will be read no more than once
    /// but we can't prove that it will be read at all.
    pub fn read_nonce(self) -> (Nonce<N>, CiphertexAndTagReader<N>) {
        let mut buf = [0u8; N];
        buf.copy_from_slice(&self.0[..N]);
        (Nonce(buf), CiphertextAndTagReader(self.0))
    }
}

pub struct CiphertextAndTagReader<const N: usize>(Bytes);

impl <const N: usize> CiphertextAndTagReader<N> {
    pub fn ciphertext(&self) -> &[u8] {
        &self.0[N..]
    }

    pub fn read_ciphertext(self) -> (CipherText, PlaintextReader) {
        // TODO: Use a RefCell
        (CipherText(self.0), PlaintextWritten(self.0))
    }
}



// In general, the name of the next struct should describe what will happen next not the state left over after the current monoid.

// The `read_nonce` method is a side-effect. The side effect could also be a Monoid so that we can determine if that side effect has been applied.
// For example, `read_nonce` could return `NonceRead` and a `MustReadNonce` could be a monoid.
// All monoids **must** have `build` or `try_build` called. We can use `#[must_use]` to enforce this.
// This could be used for `MustWrite` perhaps we well (a bit like a RefCell).
// Because `try_build` must be called. The side effect must be consumed. `try_build` can ascertain that a condition is met.
// We could create a derive macro for Monoid on a struct.

// TODO: We can't use Bytes because it doesn't implement Zeroize
// Just use a Vec in a Protected (or a heapless Vec)
// TODO: In fact, it shouldn't be either: We should just keep the Nonce and when we get the plaintext we instatiate a Protected<Vec<u8>> of the correct size then
// along with the offset (as a const generic).
pub struct CipherTextBuilder<const NONCE_SIZE: usize>(BytesMut);

// TODO: Use a Protected<Vec<u8>>
pub struct NonceWritten<const N: usize>(BytesMut);

impl<const N: usize> NonceWritten<N> {
    pub fn ciphertext_mut(&mut self) -> Option<&mut [u8]> {
        self.0.get_mut(N..)
    }

    pub fn append_ciphertext(mut self, ciphertext: &[u8]) -> Self {
        self.0.extend_from_slice(ciphertext);
        // TODO: Return a CipherTextWritten
        self
    }

    pub fn append_ciphertext_and_tag(mut self, ciphertext: &[u8]) -> CipherText {
        self.0.extend_from_slice(ciphertext);
        self.build()
    }

    pub fn append_target_plaintext(mut self, plaintext: Protected<Vec<u8>>) -> PlaintextWritten<N> {
        self.0.extend(plaintext.risky_unwrap());
        PlaintextWritten::new(self.0)
    }

    pub fn build(self) -> CipherText {
        // TODO: Check that the ciphertext and tag have both been written
        // We can set a flag in extend/asMut trait impls
        CipherText(self.0.freeze())
    }
}

// This is a delayed builder (monoid) and will implement `try_build` to ensure that the tag is written
pub struct AcceptsCipherTextAndTag<const N: usize> {
    bytes: BytesMut,
    built: bool,
}

impl<const N: usize> AcceptsCipherTextAndTag<N> {
    pub fn try_build(self) -> Result<CipherText, ()> {
        if self.built {
            Ok(CipherText(self.bytes.freeze()))
        } else {
            Err(()) // TODO: Define an error type
        }
    }
}

pub struct PlaintextWritten<const N: usize> {
    bytes: BytesMut,
    encrypted: bool,
    tag_written: bool,
}

impl<const N: usize> PlaintextWritten<N> {
    fn new(bytes: BytesMut) -> Self {
        Self { bytes, encrypted: false, tag_written: false }
    }

    fn accepts_ciphertext(self) {}

    pub fn accepts_ciphertext_and_tag(self) -> AcceptsCipherTextAndTag<N> {
        AcceptsCipherTextAndTag { bytes: self.bytes, built: false }
    }

    pub fn try_build(self) -> Result<CipherText, ()> {
        if self.encrypted && self.tag_written {
            Ok(CipherText(self.bytes.freeze()))
        } else {
            Err(()) // TODO: Define an error type
        }
    }
}

// TODO: **Create this as a monoidic set of types
// TODO: Add an optional header
// TODO: We may want to make TAG_SIZE fixed at 16-bytes
impl<const NONCE_SIZE: usize> CipherTextBuilder<NONCE_SIZE> {
    /// Allocates a new Ciphertext with the given size.
    /// The `NONCE_SIZE` and `TAG_SIZE` are _added_ to `size` to calculate the total length of the output.
    pub fn new(size: usize) -> Self {
        Self(BytesMut::with_capacity(size + NONCE_SIZE + TAG_SIZE))
    }

    pub fn append_nonce(mut self, nonce: &Nonce<NONCE_SIZE>) -> NonceWritten<NONCE_SIZE> {
        self.0.extend_from_slice(nonce.as_ref());
        NonceWritten(self.0)
    }

    pub fn read_nonce(&self) -> Nonce<NONCE_SIZE> {
        let mut buf = [0u8; NONCE_SIZE];
        buf.copy_from_slice(&self.0[..NONCE_SIZE]);
        Nonce(buf)
    }

    pub fn append_tag(mut self, tag: &[u8]) -> Self {
        self.0.extend_from_slice(tag);
        self
    }

    pub fn append_target_plaintext(mut self, plaintext: Protected<Vec<u8>>) -> Self {
        self.0.extend(plaintext.risky_unwrap());
        self
    }

    pub fn into_plaintext(self) -> Protected<Vec<u8>> {
        Protected::new(self.0.to_vec())
    }

   

    pub fn build(self) -> CipherText {
        CipherText(self.0.freeze())
    }
}

impl<const N: usize> Extend<u8> for CipherTextBuilder<N> {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = u8>,
    {
        self.0.extend(iter);
    }
}

impl<'a, const N: usize> Extend<&'a u8> for AcceptsCipherTextAndTag<N> {
    fn extend<I: IntoIterator<Item = &'a u8>>(&mut self, iter: I) {
        self.bytes.extend(iter);
        self.built = true;
    }
}

impl<const N: usize> AsMut<[u8]> for AcceptsCipherTextAndTag<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe {
            self.built = true;
            // SAFETY: We know that the bytes are valid because we only append to the buffer
            self.bytes.get_unchecked_mut(N..)
            // FIXME: We can't know for sure if this 
        }
    }
}

pub struct NonceRead<const N: usize>(Bytes);

impl<const N: usize> AsRef<[u8]> for CipherTextBuilder<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0[N..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::Nonce;

    #[test]
    fn test_ciphertext_builder_with_append() {
        let nonce = Nonce([1u8; 12]);
        let ciphertext = CipherTextBuilder::<12>::new(10)
            .append_nonce(&nonce);
            /*.append_ciphertext(&[2u8; 10])
            .append_tag(&[3u8; 16])
            .build();

        assert_eq!(ciphertext.0.len(), 38);
        assert_eq!(&ciphertext.0[..12], &[1u8; 12]);
        assert_eq!(&ciphertext.0[12..22], &[2u8; 10]);
        assert_eq!(&ciphertext.0[22..], &[3u8; 16]);*/
    }
/*
    #[test]
    fn test_ciphertext_builder_with_extend() {
        let nonce = Nonce([1u8; 12]);
        let encrypted: Vec<u8> = vec![2u8; 10];
        let mut builder = CipherTextBuilder::<12, 16>::new(10)
            .append_nonce(&nonce);

        builder.extend(encrypted);
        let ciphertext = builder.append_tag(&[3u8; 16]).build();

        assert_eq!(ciphertext.0.len(), 38);
        assert_eq!(&ciphertext.0[..12], &[1u8; 12]);
        assert_eq!(&ciphertext.0[12..22], &[2u8; 10]);
        assert_eq!(&ciphertext.0[22..], &[3u8; 16]);
    }

    #[test]
    fn test_ciphertext_builder_with_ciphertext_mut() {
        let nonce = Nonce([1u8; 12]);
        let plaintext: Protected<Vec<u8>> = Protected::new(vec![0u8; 10]);
        let encrypted: Vec<u8> = vec![2u8; 10];
        let mut builder = CipherTextBuilder::<12, 16>::new(10)
            .append_nonce(&nonce)
            .append_target_plaintext(plaintext);

        let ciphertext = builder.ciphertext_mut().unwrap();
        ciphertext.copy_from_slice(&encrypted);
        let ciphertext = builder.append_tag(&[3u8; 16]).build();

        assert_eq!(ciphertext.0.len(), 38);
        assert_eq!(&ciphertext.0[..12], &[1u8; 12]);
        assert_eq!(&ciphertext.0[12..22], &[2u8; 10]);
        assert_eq!(&ciphertext.0[22..], &[3u8; 16]);
    }*/
}
