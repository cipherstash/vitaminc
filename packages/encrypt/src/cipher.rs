use crate::backend::{CipherKey, NONCE_LEN};
use crate::Key;
use std::any::Any;
use vitaminc_aead::{
    Cipher, CipherTextBuilder, Decipher, DecipherVisitor, Decrypt, Encrypt, IntoAad,
    LocalCipherText, MapAccess, MapCipher, NonceGenerator, RandomNonceGenerator, SeqAccess,
    SeqCipher, Unspecified,
};
use vitaminc_protected::Protected;

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
    /// The authenticated absent marker produced by [`Cipher::encrypt_none`].
    /// Stores a sealed empty plaintext whose tag binds the supplied AAD.
    None(LocalCipherText),
    /// A typed value passed through unencrypted via [`Cipher::passthrough`].
    /// Not serializable to bytes — see
    /// `packages/aead/src/cipher.rs` for the API-level type bound and the
    /// runtime downcast performed by
    /// [`Decipher::decrypt_passthrough`](vitaminc_aead::Decipher::decrypt_passthrough).
    Passthrough(Box<dyn Any + Send + 'static>),
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

    fn encrypt_bytes_vec<'a, A>(
        self,
        data: Protected<Vec<u8>>,
        aad: A,
    ) -> Result<Self::Ok, Self::Error>
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

    fn encrypt_none<'a, A>(self, aad: A) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        let nonce = self.nonce_generator.generate()?;
        let nonce_bytes: [u8; NONCE_LEN] = nonce.as_ref().try_into().map_err(|_| Unspecified)?;
        let aad = aad.into_aad();

        CipherTextBuilder::new()
            .append_nonce(nonce)
            .append_target_plaintext(Vec::<u8>::new())
            .accepts_ciphertext_and_tag_ok(|mut buf| {
                self.key
                    .seal(&nonce_bytes, aad.as_bytes(), &mut buf)
                    .map(|()| buf)
            })
            .build()
            .map(AesCipherText::None)
    }

    fn passthrough<T>(self, value: T) -> Result<Self::Ok, Self::Error>
    where
        T: Any + Send + 'static,
    {
        Ok(AesCipherText::Passthrough(Box::new(value)))
    }
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

    fn passthrough_next<T>(mut self, value: T) -> Result<Self, Self::Error>
    where
        T: Any + Send + 'static,
    {
        self.items.push(AesCipherText::Passthrough(Box::new(value)));
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
    current_key: Option<&'static str>,
}

impl<'c> MapCipher for AesMapCipher<'c> {
    type Ok = AesCipherText;
    type Error = Unspecified;

    fn encrypt_key(mut self, key: &'static str) -> Result<Self, Self::Error> {
        // A key already pending means `encrypt_key` was called twice with no
        // intervening `encrypt_value` — a trait-contract violation. Fail rather
        // than silently drop the first key.
        if self.current_key.is_some() {
            return Err(Unspecified);
        }
        self.current_key = Some(key);
        Ok(self)
    }

    fn encrypt_value<'a, U, A>(mut self, value: U, aad: A) -> Result<Self, Self::Error>
    where
        U: Encrypt,
        A: IntoAad<'a>,
    {
        let key = self.current_key.take().ok_or(Unspecified)?;
        let encrypted = value.encrypt_with_aad(self.cipher, aad)?;
        self.entries.push((key.to_string(), encrypted));
        Ok(self)
    }

    fn passthrough_entry<T>(mut self, key: &'static str, value: T) -> Result<Self, Self::Error>
    where
        T: Any + Send + 'static,
    {
        // A key already pending means `encrypt_key` ran without a matching
        // `encrypt_value` — adopting it here would silently drop the pending
        // key, which is the same trait-contract violation `encrypt_key`
        // rejects.
        if self.current_key.is_some() {
            return Err(Unspecified);
        }
        self.entries
            .push((key.to_string(), AesCipherText::Passthrough(Box::new(value))));
        Ok(self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        // Finalising with a pending key would silently drop the entry.
        if self.current_key.is_some() {
            return Err(Unspecified);
        }
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
    ) -> Result<Protected<Vec<u8>>, Unspecified> {
        let (nonce, reader) = ct.into_reader().read_nonce::<NONCE_LEN>();
        let nonce_bytes = nonce.into_inner();

        reader
            .accepts_plaintext_ok(|data| cipher.key.open(&nonce_bytes, aad, data))
            .read()
    }
}

impl<'c> Decipher<'c> for AesDecipher<'c> {
    type Ok<T>
        = Result<T, Unspecified>
    where
        T: Send + 'c;

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

    fn decrypt_passthrough<T>(self) -> Self::Ok<T>
    where
        T: Any + Send + 'static,
    {
        match self.ciphertext {
            AesCipherText::Passthrough(boxed) => {
                boxed.downcast::<T>().map(|b| *b).map_err(|_| Unspecified)
            }
            _ => Err(Unspecified),
        }
    }

    fn decrypt_option<T>(self) -> Self::Ok<Option<T>>
    where
        T: Decrypt<'c> + 'c,
    {
        match self.ciphertext {
            AesCipherText::None(ct) => {
                // Verify the AAD-bound tag over the empty plaintext.
                Self::decrypt_local_ciphertext(self.cipher, ct, &self.aad)?;
                Ok(None)
            }
            // Passthrough must never be decoded as an Option payload.
            AesCipherText::Passthrough(_) => Err(Unspecified),
            other => {
                let inner = AesDecipher {
                    cipher: self.cipher,
                    ciphertext: other,
                    aad: self.aad,
                };
                T::decrypt(inner).map(Some)
            }
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
    use crate::key::tests::DifferingKeyPair;
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
    fn decrypt_fails_with_wrong_key(keys: DifferingKeyPair, plaintext: String) -> bool {
        // `DifferingKeyPair` guarantees the two keys are distinct, so this test
        // is deterministic — a key collision cannot make it spuriously fail.
        let DifferingKeyPair(key_a, key_b) = keys;
        let cipher_a = Aes256Cipher::new(&key_a).expect("Failed to create cipher A");
        let cipher_b = Aes256Cipher::new(&key_b).expect("Failed to create cipher B");
        let ciphertext = plaintext.encrypt(&cipher_a).expect("Encryption failed");
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

    #[test]
    fn roundtrip_hashmap_with_aad() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let aad = "map-context";

        let mut plaintext = HashMap::new();
        plaintext.insert("name", "Alice");
        plaintext.insert("city", "Sydney");

        let ciphertext = plaintext
            .encrypt_with_aad(&cipher, aad)
            .expect("Encryption failed");
        let decrypted: HashMap<String, String> = cipher
            .decrypt_with_aad(ciphertext, aad)
            .expect("Decryption failed");

        assert_eq!(decrypted.len(), 2);
        assert_eq!(decrypted.get("name").unwrap(), "Alice");
        assert_eq!(decrypted.get("city").unwrap(), "Sydney");
    }

    #[test]
    fn decrypt_hashmap_fails_with_wrong_aad() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");

        let mut plaintext = HashMap::new();
        plaintext.insert("name", "Alice");

        let ciphertext = plaintext
            .encrypt_with_aad(&cipher, "correct-aad")
            .expect("Encryption failed");
        assert!(cipher
            .decrypt_with_aad::<HashMap<String, String>, _>(ciphertext, "wrong-aad")
            .is_err());
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

    #[quickcheck]
    fn roundtrip_option_some_string(key: Key, plaintext: String) -> bool {
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let value = Some(plaintext.clone());
        let ciphertext = value.encrypt(&cipher).expect("Encryption failed");
        let decrypted: Option<String> = cipher.decrypt(ciphertext).expect("Decryption failed");
        decrypted == Some(plaintext)
    }

    #[test]
    fn roundtrip_option_none_string() {
        let key = Key::from([7u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let value: Option<String> = None;
        let ciphertext = value.encrypt(&cipher).expect("Encryption failed");
        let decrypted: Option<String> = cipher.decrypt(ciphertext).expect("Decryption failed");
        assert_eq!(decrypted, None);
    }

    #[quickcheck]
    fn roundtrip_option_some_with_aad(key: Key, plaintext: String) -> bool {
        let aad = "opt-aad";
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = Some(plaintext.clone())
            .encrypt_with_aad(&cipher, aad)
            .expect("Encryption failed");
        let decrypted: Option<String> = cipher
            .decrypt_with_aad(ciphertext, aad)
            .expect("Decryption failed");
        decrypted == Some(plaintext)
    }

    #[quickcheck]
    fn roundtrip_option_none_with_aad(key: Key) -> bool {
        let aad = "opt-none-aad";
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = None::<String>
            .encrypt_with_aad(&cipher, aad)
            .expect("Encryption failed");
        let decrypted: Option<String> = cipher
            .decrypt_with_aad(ciphertext, aad)
            .expect("Decryption failed");
        decrypted.is_none()
    }

    #[quickcheck]
    fn decrypt_option_none_fails_with_wrong_aad(key: Key) -> bool {
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = None::<String>
            .encrypt_with_aad(&cipher, "correct")
            .expect("Encryption failed");
        cipher
            .decrypt_with_aad::<Option<String>, _>(ciphertext, "wrong")
            .is_err()
    }

    #[test]
    fn decrypt_string_rejects_none_ciphertext() {
        // Closes the empty-plaintext masking concern: an authenticated `None`
        // marker must not be decodable as `String("")`.
        let key = Key::from([9u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = None::<String>.encrypt(&cipher).expect("Encryption failed");
        assert!(cipher.decrypt::<String>(ciphertext).is_err());
    }

    #[test]
    fn decrypt_option_rejects_passthrough_ciphertext() {
        // Type-laundering guard: a passthrough must not satisfy Option<T>.
        let key = Key::from([11u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = (&cipher).passthrough(42u32).expect("passthrough failed");
        assert!(cipher.decrypt::<Option<u32>>(ciphertext).is_err());
    }

    #[test]
    fn roundtrip_passthrough_u32() {
        let key = Key::from([1u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = (&cipher).passthrough(12345u32).expect("passthrough failed");
        let decrypted: u32 = decrypt_passthrough_via(&cipher, ciphertext).expect("decode failed");
        assert_eq!(decrypted, 12345u32);
    }

    #[test]
    fn roundtrip_passthrough_string() {
        let key = Key::from([2u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = (&cipher)
            .passthrough(String::from("version-tag"))
            .expect("passthrough failed");
        let decrypted: String =
            decrypt_passthrough_via(&cipher, ciphertext).expect("decode failed");
        assert_eq!(decrypted, "version-tag");
    }

    #[test]
    fn passthrough_type_mismatch_returns_err() {
        let key = Key::from([3u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = (&cipher).passthrough(42u32).expect("passthrough failed");
        let result: Result<String, _> = decrypt_passthrough_via(&cipher, ciphertext);
        assert!(result.is_err());
    }

    // Convenience: drive `Decipher::decrypt_passthrough` from a known
    // ciphertext. Mirrors what a derive-generated `Decrypt` impl would do
    // for a `#[encrypt(passthrough)]` field.
    fn decrypt_passthrough_via<T>(
        cipher: &Aes256Cipher,
        ciphertext: AesCipherText,
    ) -> Result<T, Unspecified>
    where
        T: Any + Send + 'static,
    {
        let decipher = AesDecipher {
            cipher,
            ciphertext,
            aad: Vec::new(),
        };
        decipher.decrypt_passthrough::<T>()
    }

    #[quickcheck]
    fn roundtrip_vec_of_option_string(key: Key, items: Vec<Option<String>>) -> bool {
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = items.clone().encrypt(&cipher).expect("Encryption failed");
        let decrypted: Vec<Option<String>> = cipher.decrypt(ciphertext).expect("Decryption failed");
        decrypted == items
    }

    // --- MapCipher state-machine contract ---
    //
    // `AesMapCipher` enforces a strict key→value pairing: every `encrypt_key`
    // must be followed by exactly one `encrypt_value` (or `passthrough_entry`
    // for the unencrypted variant) before the next key or `end`. The four
    // tests below pin down each branch where the contract can be violated.

    #[test]
    fn encrypt_key_twice_without_value_fails() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let map = (&cipher).encrypt_map().encrypt_key("first").unwrap();
        assert!(map.encrypt_key("second").is_err());
    }

    #[test]
    fn encrypt_value_without_pending_key_fails() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let map = (&cipher).encrypt_map();
        assert!(map.encrypt_value("orphan-value", ()).is_err());
    }

    #[test]
    fn passthrough_entry_with_pending_key_fails() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let map = (&cipher).encrypt_map().encrypt_key("pending").unwrap();
        // Adopting the new key here would silently drop "pending".
        assert!(map.passthrough_entry("other", 42u32).is_err());
    }

    #[test]
    fn end_with_pending_key_fails() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let map = (&cipher).encrypt_map().encrypt_key("pending").unwrap();
        assert!(map.end().is_err());
    }

    #[test]
    fn passthrough_entry_succeeds_with_no_pending_key() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        // Sanity: the new guard does not break the happy path.
        let ciphertext = (&cipher)
            .encrypt_map()
            .passthrough_entry("version", 1u32)
            .and_then(|m| m.end())
            .expect("passthrough_entry should succeed without a pending key");
        match ciphertext {
            AesCipherText::Map(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].0, "version");
                assert!(matches!(entries[0].1, AesCipherText::Passthrough(_)));
            }
            _ => panic!("expected Map ciphertext"),
        }
    }
}
