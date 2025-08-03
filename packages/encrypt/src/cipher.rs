use crate::Key;
use aws_lc_rs::aead::{Aad as LcAad, LessSafeKey, Nonce as LcNonce, AES_256_GCM, NONCE_LEN};
use vitaminc_aead::{
    Cipher, CipherTextBuilder, IntoAad, LocalCipherText, NonceGenerator, RandomNonceGenerator,
    Unspecified,
};
use vitaminc_protected::Controlled;

/// Implements the AES-256-GCM cipher using the `aws-lc-rs` library.
pub struct Aes256Cipher {
    nonce_generator: RandomNonceGenerator<NONCE_LEN>,
}

impl Aes256Cipher {
    pub fn new() -> Self {
        Self {
            nonce_generator: RandomNonceGenerator::init(),
        }
    }
}

impl Default for Aes256Cipher {
    fn default() -> Self {
        Self::new()
    }
}

impl Cipher for Aes256Cipher {
    type Key = Key;

    fn encrypt_vec<'a, A>(
        &self,
        plaintext: Vec<u8>,
        key: &<Self as Cipher>::Key,
        aad: A,
    ) -> Result<LocalCipherText, Unspecified>
    where
        A: IntoAad<'a>,
    {
        let unboundkey = key.as_unbound().map_err(|_| Unspecified)?;
        let nonce = self.nonce_generator.generate()?;
        let nonce_lc =
            LcNonce::try_assume_unique_for_key(nonce.as_ref()).map_err(|_| Unspecified)?;
        let aad = aad.into_aad();
        let aad = LcAad::from(aad.as_bytes());

        CipherTextBuilder::new()
            .append_nonce(nonce)
            .append_target_plaintext(plaintext)
            .accepts_ciphertext_and_tag_ok(|mut buf| {
                LessSafeKey::new(unboundkey)
                    .seal_in_place_append_tag(nonce_lc, aad, &mut buf)
                    .map(|_| buf)
                    .map_err(|_| Unspecified)
            })
            .build()
    }

    fn encrypt_slice<'a, A>(
        &self,
        plaintext: &'a [u8],
        key: &Self::Key,
        aad: A,
    ) -> Result<LocalCipherText, Unspecified>
    where
        A: IntoAad<'a>,
        Self: 'a,
    {
        // Copy into a Vec with capacity N + tag_len
        let mut plaintext_vec = Vec::with_capacity(plaintext.len() + AES_256_GCM.tag_len());
        plaintext_vec.extend_from_slice(&plaintext);
        let result = self.encrypt_vec(plaintext_vec, key, aad);

        result
    }

    fn decrypt_vec<'a, A>(
        &self,
        ciphertext: LocalCipherText,
        key: &Self::Key,
        aad: A,
    ) -> Result<Vec<u8>, Unspecified>
    where
        A: IntoAad<'a>,
    {
        let unboundkey = key.as_unbound().map_err(|_| Unspecified)?;
        let (nonce, reader) = ciphertext.into_reader().read_nonce::<NONCE_LEN>();
        let nonce_lc = LcNonce::assume_unique_for_key(nonce.into_inner());
        let aad = aad.into_aad();
        let aad = LcAad::from(aad.as_bytes());

        reader
            .accepts_plaintext_ok(|data| {
                LessSafeKey::new(unboundkey)
                    .open_in_place(nonce_lc, aad, data)
                    .map_err(|_| Unspecified)
                    .map(|plaintext| plaintext.len())
            })
            .read()
            .map(|data| data.risky_unwrap())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    mod cipher {
        use super::*;

        mod roundtrip_bytes {
            use super::*;

            #[test]
            fn succeeds_with_no_aad() {
                let cipher = Aes256Cipher::new();
                let key = Key::from([0u8; 32]);
                let plaintext = vec![1u8; 15];
                let ciphertext = cipher
                    .encrypt_vec(plaintext.clone(), &key, ())
                    .expect("Encryption failed");

                let decrypted = cipher
                    .decrypt_vec(ciphertext, &key, ())
                    .expect("Decryption failed");

                assert_eq!(plaintext, decrypted);
            }

            #[test]
            fn succeeds_with_matching_aad() {
                let aad = "public-AAD";
                let cipher = Aes256Cipher::new();
                let key = Key::from([0u8; 32]);
                let plaintext = vec![1u8; 15];
                let ciphertext = cipher
                    .encrypt_vec(plaintext.clone(), &key, aad)
                    .expect("Encryption failed");

                let decrypted = cipher
                    .decrypt_vec(ciphertext, &key, aad)
                    .expect("Decryption failed");

                assert_eq!(plaintext, decrypted);
            }

            #[test]
            fn fails_with_missing_aad() {
                let cipher = Aes256Cipher::new();
                let key = Key::from([0u8; 32]);
                let plaintext = vec![1u8; 15];
                let ciphertext = cipher
                    .encrypt_vec(plaintext.clone(), &key, "foo")
                    .expect("Encryption failed");

                assert!(cipher.decrypt_vec(ciphertext, &key, ()).is_err());
            }

            #[test]
            fn fails_with_incorrect_key() {
                let cipher = Aes256Cipher::new();
                let plaintext = vec![1u8; 15];
                let ciphertext = cipher
                    .encrypt_vec(plaintext.clone(), &[0; 32].into(), ())
                    .expect("Encryption failed");

                assert!(cipher
                    .decrypt_vec(ciphertext, &[1; 32].into(), ())
                    .is_err());
            }
        }
    }

    mod encrypt_traits {
        use super::*;
        use vitaminc_aead::{Decrypt, Encrypt};

        #[test]
        fn roundtrip_string() {
            let cipher = Aes256Cipher::new();
            let key = Key::from([0u8; 32]);
            let ciphertext = String::from("Hello")
                .encrypt(&key, &cipher)
                .expect("Encryption failed");
            let decrypted = String::decrypt(ciphertext, &key, &cipher).expect("Decryption failed");
            assert_eq!(decrypted, "Hello");
        }
    }
}

// TODO: Add tests using the top-level Aead struct, too
// TODO: Can we use the test vectors from aws-lc?
