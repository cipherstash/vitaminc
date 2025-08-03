use aws_lc_rs::aead::{Aad as LcAad, LessSafeKey, Nonce as LcNonce, AES_256_GCM, NONCE_LEN};
use vitaminc_aead::{
    Cipher, CipherTextBuilder, IntoAad, LocalCipherText, NonceGenerator, RandomNonceGenerator, Unspecified,
};
use vitaminc_protected::Controlled;
use zeroize::Zeroize;
use crate::Key;

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

    fn encrypt_bytes<'a, A>(
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
        let nonce_lc = LcNonce::try_assume_unique_for_key(nonce.as_ref()).map_err(|_| Unspecified)?;
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

    fn encrypt_array<'a, const N: usize, A>(
        &self,
        mut plaintext: [u8; N],
        key: &Self::Key,
        aad: A,
    ) -> Result<LocalCipherText, Unspecified>
    where
        A: IntoAad<'a>,
    {
        // Copy into a Vec with capacity N + tag_len
        let mut plaintext_vec = Vec::with_capacity(N + AES_256_GCM.tag_len());
        plaintext_vec.extend_from_slice(&plaintext);
        let result = self.encrypt_bytes(plaintext_vec, key, aad);

        // Because we copied to a vec, we need to zeroize the original array
        plaintext.zeroize();
        result
    }

    fn decrypt_bytes<'a, A>(
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

    fn decrypt_array<'a, const N: usize, A>(
        &self,
        ciphertext: LocalCipherText,
        key: &Self::Key,
        aad: A,
    ) -> Result<[u8; N], Unspecified>
    where
        A: IntoAad<'a>,
    {
        let mut output = [0u8; N];
        let mut result_vec = self.decrypt_bytes(ciphertext, key, aad)?;
        let result = if result_vec.len() != N {
            Err(Unspecified)
        } else {
            output.copy_from_slice(&result_vec);
            Ok(output)
        };

        // Zeroize the result vector
        result_vec.zeroize();
        result
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
                let ciphertext = cipher.encrypt_bytes(plaintext.clone(), &key, ()).expect("Encryption failed");
                let decrypted = cipher.decrypt_bytes(ciphertext, &key, ()).expect("Decryption failed");

                assert_eq!(plaintext, decrypted);
            }

            #[test]
            fn succeeds_with_matching_aad() {
                let aad = "public-AAD";
                let cipher = Aes256Cipher::new();
                let key = Key::from([0u8; 32]);
                let plaintext = vec![1u8; 15];
                let ciphertext = cipher.encrypt_bytes(plaintext.clone(), &key, aad).expect("Encryption failed");
                let decrypted = cipher.decrypt_bytes(ciphertext, &key, aad).expect("Decryption failed");

                assert_eq!(plaintext, decrypted);
            }

            #[test]
            fn fails_with_missing_aad() {
                let cipher = Aes256Cipher::new();
                let key = Key::from([0u8; 32]);
                let plaintext = vec![1u8; 15];
                let ciphertext = cipher
                    .encrypt_bytes(plaintext.clone(), &key, "foo")
                    .expect("Encryption failed");

                assert!(cipher.decrypt_bytes(ciphertext, &key, ()).is_err());
            }

            #[test]
            fn fails_with_incorrect_key() {
                let cipher = Aes256Cipher::new();
                let plaintext = vec![1u8; 15];
                let ciphertext = cipher
                    .encrypt_bytes(plaintext.clone(), &[0; 32].into(), ())
                    .expect("Encryption failed");

                assert!(cipher
                    .decrypt_bytes(ciphertext, &[1; 32].into(), ())
                    .is_err());
            }
        }
    }

    mod roundtrip_array {
        use super::*;

        #[test]
        fn succeeds_with_no_aad() {
            let cipher = Aes256Cipher::new();
            let key = Key::from([0u8; 32]);
            let plaintext: [u8; 15] = [1; 15];
            let ciphertext = cipher.encrypt_array(plaintext, &key, ()).expect("Encryption failed");
            let decrypted = cipher.decrypt_array(ciphertext, &key, ()).expect("Decryption failed");

            assert_eq!(plaintext, decrypted);
        }

        #[test]
        fn succeeds_with_matching_aad() {
            let cipher = Aes256Cipher::new();
            let key = Key::from([0u8; 32]);
            let plaintext: [u8; 15] = [1; 15];
            let ciphertext = cipher.encrypt_array(plaintext, &key, "AAD").expect("Encryption failed");
            let decrypted = cipher.decrypt_array(ciphertext, &key, "AAD").expect("Decryption failed");

            assert_eq!(plaintext, decrypted);
        }

        #[test]
        fn fails_with_missing_aad() {
            let cipher = Aes256Cipher::new();
            let key = Key::from([0u8; 32]);
            let plaintext: [u8; 15] = [1; 15];
            let ciphertext = cipher.encrypt_array(plaintext, &key, "foo").expect("Encryption failed");
            assert!(cipher.decrypt_array::<15, _>(ciphertext, &key, ()).is_err());
        }

        #[test]
        fn fails_with_incorrect_key() {
            let cipher = Aes256Cipher::new();
            let plaintext: [u8; 15] = [1; 15];
            let ciphertext = cipher
                .encrypt_array(plaintext, &Key::from([0; 32]), ())
                .expect("Encryption failed");

            assert!(cipher
                .decrypt_array::<15, _>(ciphertext, &Key::from([1; 32]), ())
                .is_err());
        }
    }

    mod encrypt_traits {
        use super::*;
        use vitaminc_aead::{Decrypt, Encrypt};

        #[test]
        fn roundtrip_string() {
            let cipher = Aes256Cipher::new();
            let key = Key::from([0u8; 32]);
            let ciphertext = String::from("Hello").encrypt(&key, &cipher)
                .expect("Encryption failed");
            let decrypted = String::decrypt(ciphertext, &key, &cipher).expect("Decryption failed");
            assert_eq!(decrypted, "Hello");
        }
    }
}

// TODO: Add tests using the top-level Aead struct, too
// TODO: Can we use the test vectors from aws-lc?
