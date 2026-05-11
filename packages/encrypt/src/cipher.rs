use crate::backend::{CipherKey, NONCE_LEN, TAG_LEN};
use crate::Key;
use vitaminc_aead::{
    Cipher, CipherTextBuilder, IntoAad, LocalCipherText, NonceGenerator, RandomNonceGenerator,
    Unspecified,
};
use vitaminc_protected::Controlled;

/// Implements AES-256-GCM. Backend is selected at compile time:
/// `aws-lc-rs` on native targets, `aes-gcm` (RustCrypto) on `wasm32`.
pub struct Aes256Cipher {
    nonce_generator: RandomNonceGenerator<NONCE_LEN>,
    key: CipherKey,
}

impl Aes256Cipher {
    pub fn new(key: &Key) -> Result<Self, Unspecified> {
        Ok(Self {
            nonce_generator: RandomNonceGenerator::init()?,
            key: key.cipher_key()?,
        })
    }
}

impl Cipher for Aes256Cipher {
    fn encrypt_vec<'a, A>(&self, plaintext: Vec<u8>, aad: A) -> Result<LocalCipherText, Unspecified>
    where
        A: IntoAad<'a>,
    {
        let nonce = self.nonce_generator.generate()?;
        let nonce_bytes: [u8; NONCE_LEN] = nonce.as_ref().try_into().map_err(|_| Unspecified)?;
        let aad = aad.into_aad();

        CipherTextBuilder::new()
            .append_nonce(nonce)
            .append_target_plaintext(plaintext)
            .accepts_ciphertext_and_tag_ok(|mut buf| {
                self.key
                    .seal(&nonce_bytes, aad.as_bytes(), &mut buf)
                    .map(|()| buf)
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
        let mut plaintext_vec = Vec::with_capacity(plaintext.len() + TAG_LEN);
        plaintext_vec.extend_from_slice(plaintext);
        self.encrypt_vec(plaintext_vec, aad)
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
        let nonce_bytes = nonce.into_inner();
        let aad = aad.into_aad();

        reader
            .accepts_plaintext_ok(|data| self.key.open(&nonce_bytes, aad.as_bytes(), data))
            .read()
            .map(|data| data.risky_unwrap())
    }
}

// quickcheck doesn't run under `wasm-pack test --node` (it shells out to
// std::thread, which isn't available on wasm32-unknown-unknown). These property
// tests already cover both backends on native via the
// `_test-rust-crypto-backend` feature; the wasm32 codegen path is gated by the
// KAT in `crate::backend::tests`.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod test {
    use super::*;
    use quickcheck_macros::quickcheck;

    mod cipher {
        use super::*;

        mod roundtrip_bytes {
            use super::*;
            use crate::key::tests::DifferingKeyPair;
            use quickcheck::TestResult;

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
            fn fails_with_incorrect_key(
                DifferingKeyPair(key_a, key_b): DifferingKeyPair,
                plaintext: Vec<u8>,
            ) -> TestResult {
                let cipher_a = Aes256Cipher::new(&key_a).expect("Failed to create cipher A");
                let ciphertext = cipher_a
                    .encrypt_vec(plaintext, ())
                    .expect("Encryption failed");

                let cipher_b = Aes256Cipher::new(&key_b).expect("Failed to create cipher B");
                TestResult::from_bool(cipher_b.decrypt_vec(ciphertext, ()).is_err())
            }
        }
    }

    mod encryptable_types {
        use super::*;
        use vitaminc_aead::{Decrypt, Encrypt};
        use vitaminc_protected::Protected;

        #[quickcheck]
        fn roundtrip_string(key: Key, plaintext: String) -> bool {
            let check = plaintext.clone();
            let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
            let ciphertext = plaintext.encrypt(&cipher).expect("Encryption failed");

            let decrypted = String::decrypt(ciphertext, &cipher).expect("Decryption failed");
            decrypted == check
        }

        #[quickcheck]
        fn roundtrip_str(key: Key, plaintext: String) -> bool {
            let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
            let ciphertext = plaintext
                .as_str()
                .encrypt(&cipher)
                .expect("Encryption failed");

            let decrypted = String::decrypt(ciphertext, &cipher).expect("Decryption failed");
            decrypted == plaintext
        }

        #[quickcheck]
        fn roundtrip_protected_string(key: Key, plaintext: Protected<String>) -> bool {
            let check = plaintext.clone();
            let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
            let ciphertext = plaintext.encrypt(&cipher).expect("Encryption failed");

            let decrypted: Protected<String> =
                Protected::decrypt(ciphertext, &cipher).expect("Decryption failed");
            decrypted.risky_unwrap() == check.risky_unwrap()
        }

        #[quickcheck]
        fn roundtrip_protected_vec(key: Key, plaintext: Protected<Vec<u8>>) -> bool {
            let check = plaintext.clone();
            let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
            let ciphertext = plaintext.encrypt(&cipher).expect("Encryption failed");

            let decrypted: Protected<Vec<u8>> =
                Protected::decrypt(ciphertext, &cipher).expect("Decryption failed");
            decrypted.risky_unwrap() == check.risky_unwrap()
        }
    }
}
