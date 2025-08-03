use aws_lc_rs::aead::UnboundKey;
use vitaminc_aead::{Cipher, Decrypt, Encrypt, IntoAad, LocalCipherText, Unspecified};
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::{Generatable, RandomError, SafeRand};

/// 256-bit key type for use with symmetric encryption algorithms like AES-256-GCM.
/// Vitaminc does not support smaller key sizes to ensure quantum security and compatibility with AWS-LC.
// SAFETY: Safe to implement Debug because the inner type is Protected, which does not leak sensitive data.
#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
pub struct Key(Protected<[u8; 32]>);

impl Key {
    pub(crate) fn as_unbound(&self) -> Result<UnboundKey, Unspecified> {
        UnboundKey::new(&aws_lc_rs::aead::AES_256_GCM, self.0.risky_ref()).map_err(|_| Unspecified)
    }
}

impl From<[u8; 32]> for Key {
    fn from(key: [u8; 32]) -> Self {
        Self(Protected::new(key))
    }
}

// TODO: How do we support a key "with ID" (i.e. a committing key)?
// TODO: Also, cipher keys should implement Usage<Key> to ensure they are used correctly.

impl Generatable for Key {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        Generatable::random(rng).map(Self)
    }
}

pub struct EncryptedKey(LocalCipherText);

impl Encrypt for Key {
    type Encrypted = EncryptedKey;

    fn encrypt_with_aad<'a, C, A>(
        self,
        cipher: &C,
        aad: A,
    ) -> Result<Self::Encrypted, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        self.0.encrypt_with_aad(cipher, aad).map(EncryptedKey)
    }
}

impl Decrypt for Key {
    type Encrypted = EncryptedKey;

    fn decrypt_with_aad<'a, C, A>(
        encrypted: Self::Encrypted,
        cipher: &C,
        aad: A,
    ) -> Result<Self, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        Decrypt::decrypt_with_aad(encrypted.0, cipher, aad).map(Self)
    }
}

#[cfg(test)]
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
            let key = gen_array(g);
            Self(Protected::new(key))
        }
    }   

    /// A pair of keys that are guaranteed to be different when generated.
    #[derive(Clone, Debug)]
    pub(crate) struct DifferingKeyPair(pub Key, pub Key);

    #[cfg(test)]
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
