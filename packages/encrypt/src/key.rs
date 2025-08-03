use aws_lc_rs::aead::UnboundKey;
use vitaminc_aead::{Cipher, Decrypt, Encrypt, IntoAad, LocalCipherText, Unspecified};
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::{Generatable, RandomError, SafeRand};

/// 256-bit key type for use with symmetric encryption algorithms like AES-256-GCM.
/// Vitaminc does not support smaller key sizes to ensure quantum security and compatibility with AWS-LC.
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
        key: &C::Key,
        cipher: &C,
        aad: A,
    ) -> Result<Self::Encrypted, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        self.0.encrypt_with_aad(key, cipher, aad).map(EncryptedKey)
    }
}

impl Decrypt for Key {
    type Encrypted = EncryptedKey;

    fn decrypt_with_aad<'a, C, A>(
        encrypted: Self::Encrypted,
        key: &C::Key,
        cipher: &C,
        aad: A,
    ) -> Result<Self, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        Decrypt::decrypt_with_aad(encrypted.0, key, cipher, aad).map(Self)
    }
}
