use aws_lc_rs::aead::{Aad as LcAad, LessSafeKey, Nonce as LcNonce, AES_256_GCM, NONCE_LEN};
use vitaminc_aead::{
    Cipher, CipherTextBuilder, IntoAad, LocalCipherText, NonceGenerator, RandomNonceGenerator,
    Unspecified,
};
use vitaminc_protected::Controlled;
use crate::Key;

/// Implements the AES-256-GCM cipher using the `aws-lc-rs` library.
pub struct Aes256Cipher {
    nonce_generator: RandomNonceGenerator<NONCE_LEN>,
    key: LessSafeKey,
}

impl Aes256Cipher {
    pub fn new(key: &Key) -> Result<Self, Unspecified> {
        key.as_unbound().map_err(|_| Unspecified).map(|unbound_key| Self {
            nonce_generator: RandomNonceGenerator::init(),
            key: LessSafeKey::new(unbound_key),
        })
    }
}

impl Cipher for Aes256Cipher {
    fn encrypt_vec<'a, A>(
        &self,
        plaintext: Vec<u8>,
        aad: A,
    ) -> Result<LocalCipherText, Unspecified>
    where
        A: IntoAad<'a>,
    {
        let nonce = self.nonce_generator.generate()?;
        let nonce_lc =
            LcNonce::try_assume_unique_for_key(nonce.as_ref()).map_err(|_| Unspecified)?;
        let aad = aad.into_aad();
        let aad = LcAad::from(aad.as_bytes());

        CipherTextBuilder::new()
            .append_nonce(nonce)
            .append_target_plaintext(plaintext)
            .accepts_ciphertext_and_tag_ok(|mut buf| {
                self.key
                    .seal_in_place_append_tag(nonce_lc, aad, &mut buf)
                    .map(|_| buf)
                    .map_err(|_| Unspecified)
            })
            .build()
    }

    fn encrypt_slice<'a, A>(
        &self,
        plaintext: &'a [u8],
        aad: A,
    ) -> Result<LocalCipherText, Unspecified>
    where
        A: IntoAad<'a>,
        Self: 'a,
    {
        // Copy into a Vec with capacity N + tag_len
        let mut plaintext_vec = Vec::with_capacity(plaintext.len() + AES_256_GCM.tag_len());
        plaintext_vec.extend_from_slice(&plaintext);
        let result = self.encrypt_vec(plaintext_vec, aad);

        result
    }

    fn decrypt_vec<'a, A>(
        &self,
        ciphertext: LocalCipherText,
        aad: A,
    ) -> Result<Vec<u8>, Unspecified>
    where
        A: IntoAad<'a>,
    {
        let (nonce, reader) = ciphertext.into_reader().read_nonce::<NONCE_LEN>();
        let nonce_lc = LcNonce::assume_unique_for_key(nonce.into_inner());
        let aad = aad.into_aad();
        let aad = LcAad::from(aad.as_bytes());

        reader
            .accepts_plaintext_ok(|data| {
                self.key
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
    use quickcheck_macros::quickcheck;
    use super::*;

    mod cipher {
        use super::*;

        mod roundtrip_bytes {
            use quickcheck::TestResult;
            use crate::key::tests::DifferingKeyPair;
            use super::*;

            #[quickcheck]
            fn succeeds_with_no_aad(key: Key, plaintext: Vec<u8>) -> bool {
                let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
                let ciphertext = cipher
                    .encrypt_vec(plaintext.clone(), ())
                    .expect("Encryption failed");

                let decrypted = cipher
                    .decrypt_vec(ciphertext, ())
                    .expect("Decryption failed");

                plaintext == decrypted
            }

            #[quickcheck]
            fn succeeds_with_matching_aad(key: Key, plaintext: Vec<u8>) -> bool {
                let aad = "public-AAD";
                let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
                let ciphertext = cipher
                    .encrypt_vec(plaintext.clone(), aad)
                    .expect("Encryption failed");

                let decrypted = cipher
                    .decrypt_vec(ciphertext, aad)
                    .expect("Decryption failed");

                plaintext == decrypted
            }

            #[quickcheck]
            fn fails_with_missing_aad(key: Key, plaintext: Vec<u8>) -> bool {
                let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
                let ciphertext = cipher
                    .encrypt_vec(plaintext.clone(), "foo-aad")
                    .expect("Encryption failed");

                cipher.decrypt_vec(ciphertext, ()).is_err()
            }

            #[quickcheck]
            fn fails_with_incorrect_key(DifferingKeyPair(key_a, key_b): DifferingKeyPair, plaintext: Vec<u8>) -> TestResult {
                let cipher_a = Aes256Cipher::new(&key_a).expect("Failed to create cipher A");
                let ciphertext = cipher_a
                    .encrypt_vec(plaintext, ())
                    .expect("Encryption failed");

                let cipher_b = Aes256Cipher::new(&key_b).expect("Failed to create cipher B");
                TestResult::from_bool(cipher_b
                    .decrypt_vec(ciphertext, ())
                    .is_err())
            }
        }
    }

    mod encrypt_traits {
        use super::*;
        use vitaminc_aead::{Decrypt, Encrypt};

        #[quickcheck]
        fn roundtrip_string(key: Key, plaintext: String) -> bool {
            let check = plaintext.clone();
            let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
            let ciphertext = plaintext
                .encrypt(&cipher)
                .expect("Encryption failed");

            let decrypted = String::decrypt(ciphertext, &cipher).expect("Decryption failed");
            decrypted == check
        }

        #[quickcheck]
        fn roundtrip_str(key: Key, plaintext: String) -> bool {
            let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
            let ciphertext = plaintext.as_str()
                .encrypt(&cipher)
                .expect("Encryption failed");
            
            let decrypted = String::decrypt(ciphertext, &cipher).expect("Decryption failed");
            decrypted == plaintext
        }
    }
}