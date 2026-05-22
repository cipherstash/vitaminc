use crate::backend::CipherKey;
use vitaminc_aead::{Cipher, Encrypt, IntoAad, Unspecified};
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::{Generatable, RandomError, SafeRand};

/// 256-bit key type for use with symmetric encryption algorithms like AES-256-GCM.
/// Vitaminc does not support smaller key sizes to ensure quantum security and compatibility with AWS-LC.
// SAFETY: Safe to implement Debug because the inner type is Protected, which does not leak sensitive data.
#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
pub struct Key(Protected<[u8; 32]>);

impl Key {
    pub(crate) fn cipher_key(&self) -> Result<CipherKey, Unspecified> {
        CipherKey::new(self.0.risky_ref())
    }
}

impl From<[u8; 32]> for Key {
    fn from(key: [u8; 32]) -> Self {
        Self(Protected::new(key))
    }
}

impl Generatable for Key {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        Generatable::random(rng).map(Self)
    }
}

impl Encrypt for Key {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.encrypt_bytes_array(self.0.risky_unwrap(), aad)
    }
}

// Quickcheck `Arbitrary` impls for the property tests in `cipher::test` —
// gated to non-wasm32 alongside their consumers (see comment in `cipher.rs`).
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) mod tests {
    use super::*;
    use quickcheck::Arbitrary;

    fn gen_array(g: &mut quickcheck::Gen) -> [u8; 32] {
        let mut array = [0u8; 32];
        for byte in array.iter_mut() {
            *byte = u8::arbitrary(g);
        }
        array
    }

    impl quickcheck::Arbitrary for Key {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            Key::from(gen_array(g))
        }
    }

    /// A pair of keys guaranteed to be distinct at generation time. Property
    /// tests that depend on the keys differing (e.g. wrong-key rejection) use
    /// this so they cannot be flaky on the astronomically unlikely event that
    /// two independently random keys collide.
    #[derive(Clone, Debug)]
    pub(crate) struct DifferingKeyPair(pub Key, pub Key);

    impl quickcheck::Arbitrary for DifferingKeyPair {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let raw_a = gen_array(g);
            let mut raw_b = gen_array(g);
            while raw_a == raw_b {
                raw_b = gen_array(g);
            }
            Self(Key::from(raw_a), Key::from(raw_b))
        }
    }
}
