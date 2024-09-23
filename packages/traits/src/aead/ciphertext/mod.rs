mod write_monads;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use super::Nonce;

pub use write_monads::CipherTextBuilder;

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
    pub fn read_nonce(self) -> (Nonce<N>, CiphertextAndTagReader<N>) {
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

// TODO: **Create this as a monoidic set of types





pub struct NonceRead<const N: usize>(Bytes);



#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::Nonce;
    use vitaminc_protected::Protected;

    #[test]
    fn test_ciphertext_builder_with_plaintext_in_place() {
        let nonce = Nonce([1u8; 12]);
        let plaintext: Protected<Vec<u8>> = Protected::new(vec![0u8; 10]);
        let ciphertext = CipherTextBuilder::new()
            .append_nonce(nonce)
            .append_target_plaintext(plaintext)
            .accepts_ciphertext_and_tag(|mut ciphertext| {
                ciphertext.copy_from_slice(&[2u8; 10]);
                ciphertext.extend([3u8; 16]);
                ciphertext
            })
            .build();

        assert_eq!(ciphertext.0.len(), 38);
        assert_eq!(&ciphertext.0[..12], &[1u8; 12]);
        assert_eq!(&ciphertext.0[12..22], &[2u8; 10]);
        assert_eq!(&ciphertext.0[22..], &[3u8; 16]);
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
