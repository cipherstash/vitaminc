use crate::backend::{CipherKey, NONCE_LEN};
use crate::Key;
use vitaminc_aead::{
    Cipher, CipherTextBuilder, Decipher, DecipherVisitor, Decrypt, Encrypt, IntoAad,
    LocalCipherText, MapAccess, MapCipher, NonceGenerator, RandomNonceGenerator, SeqAccess,
    SeqCipher, Unspecified,
};
use vitaminc_protected::Controlled;

/// The recursive ciphertext container produced by [`Aes256Cipher`].
///
/// The shape mirrors the structure of the plaintext that was encrypted: a
/// single value yields [`Single`](AesCipherText::Single), a `Vec` yields
/// [`Sequence`](AesCipherText::Sequence), a `HashMap` yields
/// [`Map`](AesCipherText::Map). Nested structures are represented recursively.
#[derive(Debug)]
pub enum AesCipherText {
    /// A single sealed value (nonce + ciphertext + tag).
    Single(LocalCipherText),
    /// A sequence of ciphertexts produced from a `Vec`-shaped plaintext.
    Sequence(Vec<AesCipherText>),
    /// A map of (cleartext key, ciphertext value) pairs produced from a
    /// `HashMap`-shaped plaintext. Keys are not encrypted.
    Map(Vec<(String, AesCipherText)>),
}

/// Implements AES-256-GCM. Backend is selected at compile time:
/// `aws-lc-rs` on native targets, `aes-gcm` (RustCrypto) on `wasm32`.
pub struct Aes256Cipher {
    nonce_generator: RandomNonceGenerator<NONCE_LEN>,
    key: CipherKey,
}

impl Aes256Cipher {
    /// Construct a new AES-256-GCM cipher bound to the given [`Key`].
    ///
    /// A fresh random nonce generator is initialised for each cipher instance.
    /// Returns an error if the platform RNG cannot be seeded or the key cannot
    /// be loaded into the backend.
    pub fn new(key: &Key) -> Result<Self, Unspecified> {
        Ok(Self {
            nonce_generator: RandomNonceGenerator::init()?,
            key: key.cipher_key()?,
        })
    }
}

impl<'c> Cipher for &'c Aes256Cipher {
    type Ok = AesCipherText;
    type Error = Unspecified;
    type SeqCipher = AesSeqCipher<'c>;
    type MapCipher = AesMapCipher<'c>;

    fn encrypt_bytes_vec<'a, A>(self, data: Vec<u8>, aad: A) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        let nonce = self.nonce_generator.generate()?;
        let nonce_bytes: [u8; NONCE_LEN] = nonce.as_ref().try_into().map_err(|_| Unspecified)?;
        let aad = aad.into_aad();

        CipherTextBuilder::new()
            .append_nonce(nonce)
            .append_target_plaintext(data)
            .accepts_ciphertext_and_tag_ok(|mut buf| {
                self.key
                    .seal(&nonce_bytes, aad.as_bytes(), &mut buf)
                    .map(|()| buf)
            })
            .build()
            .map(AesCipherText::Single)
    }

    fn encrypt_seq(self, size_hint: Option<usize>) -> Self::SeqCipher {
        AesSeqCipher {
            cipher: self,
            items: Vec::with_capacity(size_hint.unwrap_or(0)),
        }
    }

    fn encrypt_map(self) -> Self::MapCipher {
        AesMapCipher {
            cipher: self,
            entries: Vec::new(),
            current_key: None,
        }
    }

    // Tracked: https://github.com/cipherstash/vitaminc/issues/172
    // fn encrypt_none(self) -> Result<Self::Ok, Self::Error> { }
    // fn passthrough<T: 'static>(self, data: T) -> Result<Self::Ok, Self::Error> { }
}

/// [`SeqCipher`] driver for [`Aes256Cipher`]. Encrypts each element under its
/// own fresh nonce and accumulates the results into an
/// [`AesCipherText::Sequence`].
pub struct AesSeqCipher<'c> {
    cipher: &'c Aes256Cipher,
    items: Vec<AesCipherText>,
}

impl<'c> SeqCipher for AesSeqCipher<'c> {
    type Ok = AesCipherText;
    type Error = Unspecified;

    fn encrypt_next<'a, T, A>(mut self, data: T, aad: A) -> Result<Self, Self::Error>
    where
        T: Encrypt,
        A: IntoAad<'a>,
    {
        let encrypted = data.encrypt_with_aad(self.cipher, aad)?;
        self.items.push(encrypted);
        Ok(self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(AesCipherText::Sequence(self.items))
    }
}

/// [`MapCipher`] driver for [`Aes256Cipher`]. Keys are stored in the clear;
/// values are encrypted under their own fresh nonce and accumulated into an
/// [`AesCipherText::Map`].
pub struct AesMapCipher<'c> {
    cipher: &'c Aes256Cipher,
    entries: Vec<(String, AesCipherText)>,
    current_key: Option<String>,
}

impl<'c> MapCipher for AesMapCipher<'c> {
    type Ok = AesCipherText;
    type Error = Unspecified;

    fn encrypt_key(mut self, key: &'static str) -> Result<Self, Self::Error> {
        self.current_key = Some(key.to_string());
        Ok(self)
    }

    fn encrypt_value<'a, U, A>(mut self, value: U, aad: A) -> Result<Self, Self::Error>
    where
        U: Encrypt,
        A: IntoAad<'a>,
    {
        let key = self.current_key.take().ok_or(Unspecified)?;
        let encrypted = value.encrypt_with_aad(self.cipher, aad)?;
        self.entries.push((key, encrypted));
        Ok(self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(AesCipherText::Map(self.entries))
    }
}

impl Aes256Cipher {
    /// Decrypt an [`AesCipherText`] into `T` with no associated data.
    /// `T` is inferred from the call site.
    pub fn decrypt<'c, T: Decrypt<'c> + 'c>(
        &'c self,
        ciphertext: AesCipherText,
    ) -> Result<T, Unspecified> {
        self.decrypt_with_aad(ciphertext, ())
    }

    /// Decrypt an [`AesCipherText`] into `T` using the supplied associated data.
    /// Returns [`Unspecified`] if the AAD does not match the value used at
    /// encryption time, or if the structural shape of the ciphertext does not
    /// match what `T` expects.
    pub fn decrypt_with_aad<'c, 'a, T, A>(
        &'c self,
        ciphertext: AesCipherText,
        aad: A,
    ) -> Result<T, Unspecified>
    where
        T: Decrypt<'c> + 'c,
        A: IntoAad<'a>,
    {
        let aad = aad.into_aad();
        T::decrypt(AesDecipher {
            cipher: self,
            ciphertext,
            aad: aad.as_bytes().to_vec(),
        })
    }
}

struct AesDecipher<'c> {
    cipher: &'c Aes256Cipher,
    ciphertext: AesCipherText,
    aad: Vec<u8>,
}

impl AesDecipher<'_> {
    fn decrypt_local_ciphertext(
        cipher: &Aes256Cipher,
        ct: LocalCipherText,
        aad: &[u8],
    ) -> Result<Vec<u8>, Unspecified> {
        let (nonce, reader) = ct.into_reader().read_nonce::<NONCE_LEN>();
        let nonce_bytes = nonce.into_inner();

        reader
            .accepts_plaintext_ok(|data| cipher.key.open(&nonce_bytes, aad, data))
            .read()
            .map(|data| data.risky_unwrap())
    }
}

impl<'c> Decipher<'c> for AesDecipher<'c> {
    type Ok<T>
        = Result<T, Unspecified>
    where
        T: Send + 'c;
    type Error = Unspecified;

    fn map_ok<T, U, F>(ok: Self::Ok<T>, f: F) -> Self::Ok<U>
    where
        T: Send + 'c,
        U: Send + 'c,
        F: FnOnce(T) -> U,
    {
        ok.map(f)
    }

    fn decrypt_bytes<V: DecipherVisitor<'c> + Send + 'c>(self, visitor: V) -> Self::Ok<V::Value> {
        match self.ciphertext {
            AesCipherText::Single(ct) => {
                let bytes = Self::decrypt_local_ciphertext(self.cipher, ct, &self.aad)?;
                visitor.visit_bytes_vec(bytes)
            }
            _ => Err(Unspecified),
        }
    }

    fn decrypt_seq<V: DecipherVisitor<'c> + Send + 'c>(self, visitor: V) -> Self::Ok<V::Value> {
        match self.ciphertext {
            AesCipherText::Sequence(items) => {
                let seq_access = AesSeqAccess {
                    cipher: self.cipher,
                    items: items.into_iter(),
                    aad: self.aad,
                };
                visitor.visit_seq(seq_access)
            }
            _ => Err(Unspecified),
        }
    }

    fn decrypt_map<V: DecipherVisitor<'c> + Send + 'c>(self, visitor: V) -> Self::Ok<V::Value> {
        match self.ciphertext {
            AesCipherText::Map(entries) => {
                let map_access = AesMapAccess {
                    cipher: self.cipher,
                    entries: entries.into_iter(),
                    aad: self.aad,
                };
                visitor.visit_map(map_access)
            }
            _ => Err(Unspecified),
        }
    }
}

struct AesSeqAccess<'c> {
    cipher: &'c Aes256Cipher,
    items: std::vec::IntoIter<AesCipherText>,
    aad: Vec<u8>,
}

impl<'c> SeqAccess<'c> for AesSeqAccess<'c> {
    type Error = Unspecified;

    fn next_element<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<T>, Self::Error> {
        let ct = match self.items.next() {
            Some(ct) => ct,
            None => return Ok(None),
        };
        let decipher = AesDecipher {
            cipher: self.cipher,
            ciphertext: ct,
            aad: self.aad.clone(),
        };
        T::decrypt(decipher).map(Some)
    }
}

struct AesMapAccess<'c> {
    cipher: &'c Aes256Cipher,
    entries: std::vec::IntoIter<(String, AesCipherText)>,
    aad: Vec<u8>,
}

impl<'c> MapAccess<'c> for AesMapAccess<'c> {
    type Error = Unspecified;

    fn next_entry<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<(String, T)>, Self::Error> {
        let (key, ct) = match self.entries.next() {
            Some(entry) => entry,
            None => return Ok(None),
        };
        let decipher = AesDecipher {
            cipher: self.cipher,
            ciphertext: ct,
            aad: self.aad.clone(),
        };
        let value = T::decrypt(decipher)?;
        Ok(Some((key, value)))
    }
}

// quickcheck doesn't run under `wasm-pack test --node` (it shells out to
// std::thread, which isn't available on wasm32-unknown-unknown). These property
// tests already cover both backends on native via the
// `_test-rust-crypto-backend` feature; the wasm32 codegen path is gated by the
// KAT in `crate::backend::tests`.
#[cfg(all(test, not(target_arch = "wasm32")))]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use quickcheck_macros::quickcheck;
    use std::collections::HashMap;
    use vitaminc_aead::Encrypt;

    #[quickcheck]
    fn roundtrip_byte_array(key: Key, plaintext: [u8; 16]) -> bool {
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = plaintext.encrypt(&cipher).expect("Encryption failed");
        let decrypted: [u8; 16] = cipher.decrypt(ciphertext).expect("Decryption failed");
        decrypted == plaintext
    }

    #[quickcheck]
    fn roundtrip_string(key: Key, plaintext: String) -> bool {
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = plaintext
            .clone()
            .encrypt(&cipher)
            .expect("Encryption failed");
        let decrypted: String = cipher.decrypt(ciphertext).expect("Decryption failed");
        decrypted == plaintext
    }

    #[quickcheck]
    fn roundtrip_str(key: Key, plaintext: String) -> bool {
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = plaintext
            .as_str()
            .encrypt(&cipher)
            .expect("Encryption failed");
        let decrypted: String = cipher.decrypt(ciphertext).expect("Decryption failed");
        decrypted == plaintext
    }

    #[quickcheck]
    fn roundtrip_u32(key: Key, plaintext: u32) -> bool {
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = plaintext.encrypt(&cipher).expect("Encryption failed");
        let decrypted: u32 = cipher.decrypt(ciphertext).expect("Decryption failed");
        decrypted == plaintext
    }

    #[quickcheck]
    fn roundtrip_vec_of_strings(key: Key, plaintext: Vec<String>) -> bool {
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = plaintext
            .clone()
            .encrypt(&cipher)
            .expect("Encryption failed");
        let decrypted: Vec<String> = cipher.decrypt(ciphertext).expect("Decryption failed");
        decrypted == plaintext
    }

    #[quickcheck]
    fn roundtrip_string_with_aad(key: Key, plaintext: String) -> bool {
        let aad = "test-aad";
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = plaintext
            .clone()
            .encrypt_with_aad(&cipher, aad)
            .expect("Encryption failed");
        let decrypted: String = cipher
            .decrypt_with_aad(ciphertext, aad)
            .expect("Decryption failed");
        decrypted == plaintext
    }

    #[quickcheck]
    fn decrypt_fails_with_wrong_aad(key: Key, plaintext: String) -> bool {
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = plaintext
            .encrypt_with_aad(&cipher, "correct-aad")
            .expect("Encryption failed");
        cipher
            .decrypt_with_aad::<String, _>(ciphertext, "wrong-aad")
            .is_err()
    }

    #[quickcheck]
    fn decrypt_fails_with_wrong_key(key_a: Key, key_b: Key, plaintext: String) -> bool {
        let cipher_a = Aes256Cipher::new(&key_a).expect("Failed to create cipher A");
        let cipher_b = Aes256Cipher::new(&key_b).expect("Failed to create cipher B");
        let ciphertext = plaintext.encrypt(&cipher_a).expect("Encryption failed");
        // Different keys will almost certainly differ; if they happen to match, decrypt succeeds which is fine
        cipher_b.decrypt::<String>(ciphertext).is_err()
    }

    #[test]
    fn roundtrip_hashmap() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");

        let mut plaintext = HashMap::new();
        plaintext.insert("name", "Alice");
        plaintext.insert("city", "Sydney");

        let ciphertext = plaintext.encrypt(&cipher).expect("Encryption failed");
        let decrypted: HashMap<String, String> =
            cipher.decrypt(ciphertext).expect("Decryption failed");

        assert_eq!(decrypted.len(), 2);
        assert_eq!(decrypted.get("name").unwrap(), "Alice");
        assert_eq!(decrypted.get("city").unwrap(), "Sydney");
    }

    #[quickcheck]
    fn roundtrip_protected_string(key: Key, plaintext: String) -> bool {
        use vitaminc_protected::{Controlled, Protected};

        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let protected = Protected::new(plaintext.clone());
        let ciphertext = protected.encrypt(&cipher).expect("Encryption failed");
        let decrypted: Protected<String> = cipher.decrypt(ciphertext).expect("Decryption failed");
        decrypted.risky_unwrap() == plaintext
    }
}
