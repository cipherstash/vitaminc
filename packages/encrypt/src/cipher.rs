use crate::backend::{CipherKey, NONCE_LEN};
use crate::Key;
use std::any::Any;
use vitaminc_aead::{
    Cipher, CipherTextBuilder, CipherTree, Decrypt, IntoAad, LeafOpener, LocalCipherText,
    MapCipher, NonceGenerator, PendingLeaf, RandomNonceGenerator, SeqCipher, TreeCipher,
    TreeDecipher, TreeMap, TreeSeq, Unspecified,
};
use vitaminc_protected::Protected;

/// The recursive ciphertext container produced by [`Aes256Cipher`].
///
/// A [`CipherTree`] whose leaves are sealed [`LocalCipherText`]s. Its shape
/// mirrors the encrypted plaintext: a single value yields
/// [`Single`](CipherTree::Single), a `Vec` yields
/// [`Sequence`](CipherTree::Sequence), a `HashMap` yields
/// [`Map`](CipherTree::Map). The structural drive/walk is shared with any other
/// cipher built on [`CipherTree`]; only the per-leaf sealing differs.
pub type AesCipherText = CipherTree<LocalCipherText>;

/// Implements AES-256-GCM. Backend is selected at compile time:
/// `aws-lc-rs` on native targets, `aes-gcm` (RustCrypto) on `wasm32`.
pub struct Aes256Cipher {
    pub(crate) nonce_generator: RandomNonceGenerator<NONCE_LEN>,
    pub(crate) key: CipherKey,
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

    /// Seal a single [`PendingLeaf`] under a fresh random nonce. This is the AES
    /// per-leaf step the generic [`TreeCipher`] codec leaves to the cipher.
    fn seal_leaf(&self, leaf: PendingLeaf) -> Result<LocalCipherText, Unspecified> {
        let nonce = self.nonce_generator.generate()?;
        // Copy the nonce bytes out without consuming the nonce (it is still
        // appended to the ciphertext below) and without a fallible slice
        // conversion — `Nonce<NONCE_LEN>` already wraps `[u8; NONCE_LEN]`.
        let nonce_bytes = *nonce.as_array();

        CipherTextBuilder::new()
            .append_nonce(nonce)
            .append_target_plaintext(leaf.plaintext)
            .accepts_ciphertext_and_tag_ok(|mut buf| {
                self.key
                    .seal(&nonce_bytes, &leaf.aad, &mut buf)
                    .map(|()| buf)
            })
            .build()
    }

    /// Seal every leaf of a pending tree, preserving structure. AES seals
    /// eagerly leaf-by-leaf; a batching cipher would instead size a key request
    /// with [`CipherTree::leaf_count`] and pull keys here. Leaves are sealed in
    /// [`CipherTree::for_each_leaf`] order (see the `vitaminc_aead::tree`
    /// module's "Leaf ordering contract").
    fn seal_tree(&self, tree: CipherTree<PendingLeaf>) -> Result<AesCipherText, Unspecified> {
        tree.try_map_leaves(&mut |leaf| self.seal_leaf(leaf))
    }
}

/// The per-leaf opening step for [`Aes256Cipher`]: decrypt a leaf with the
/// cipher's key and the nonce stored in the leaf. A `Copy` lookup wrapper so the
/// generic [`TreeDecipher`] can thread it through every leaf of the structure.
#[derive(Clone, Copy)]
pub struct AesOpener<'c>(&'c Aes256Cipher);

impl LeafOpener for AesOpener<'_> {
    type Leaf = LocalCipherText;

    fn open(self, leaf: LocalCipherText, aad: &[u8]) -> Result<Protected<Vec<u8>>, Unspecified> {
        let (nonce, reader) = leaf.into_reader().read_nonce::<NONCE_LEN>()?;
        let nonce_bytes = nonce.into_inner();
        reader
            .accepts_plaintext_ok(|data| self.0.key.open(&nonce_bytes, aad, data))
            .read()
    }
}

/// A [`Decipher`](vitaminc_aead::Decipher) over an [`AesCipherText`], produced by
/// [`Aes256Cipher::decipher`]. The structural walk is shared via [`TreeDecipher`];
/// [`AesOpener`] supplies the per-leaf decryption.
pub type AesDecipher<'c> = TreeDecipher<AesOpener<'c>>;

/// `&Aes256Cipher` is the [`Cipher`] so values can be encrypted ergonomically as
/// `value.encrypt(&cipher)`. The structural traversal is delegated to the generic
/// [`TreeCipher`] codec (which only *collects* leaves); this impl adds the AES
/// seal step, sealing the collected tree before handing it back. A coherence
/// blanket impl is impossible (it would conflict with every direct `Cipher`
/// impl), so a future backend repeats this thin collect-then-seal shape.
impl<'c> Cipher for &'c Aes256Cipher {
    type Ok = AesCipherText;
    type Error = Unspecified;
    type SeqCipher = AesSeq<'c>;
    type MapCipher = AesMap<'c>;

    fn encrypt_bytes_vec<'a, A>(
        self,
        data: Protected<Vec<u8>>,
        aad: A,
    ) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        self.seal_tree(TreeCipher.encrypt_bytes_vec(data, aad)?)
    }

    fn encrypt_seq(self, size_hint: Option<usize>) -> Self::SeqCipher {
        AesSeq {
            inner: TreeCipher.encrypt_seq(size_hint),
            cipher: self,
        }
    }

    fn encrypt_map(self) -> Self::MapCipher {
        AesMap {
            inner: TreeCipher.encrypt_map(),
            cipher: self,
        }
    }

    fn encrypt_none<'a, A>(self, aad: A) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        self.seal_tree(TreeCipher.encrypt_none(aad)?)
    }

    fn passthrough<T>(self, value: T) -> Result<Self::Ok, Self::Error>
    where
        T: Any + Send + 'static,
    {
        self.seal_tree(TreeCipher.passthrough(value)?)
    }
}

/// [`SeqCipher`] for `&Aes256Cipher`: accumulates a pending tree via the generic
/// [`TreeSeq`], then seals the whole sequence in one pass at [`end`](SeqCipher::end).
pub struct AesSeq<'c> {
    inner: TreeSeq,
    cipher: &'c Aes256Cipher,
}

impl SeqCipher for AesSeq<'_> {
    type Ok = AesCipherText;
    type Error = Unspecified;

    fn encrypt_next<'a, T, A>(mut self, data: T, aad: A) -> Result<Self, Self::Error>
    where
        T: vitaminc_aead::Encrypt,
        A: IntoAad<'a>,
    {
        self.inner = self.inner.encrypt_next(data, aad)?;
        Ok(self)
    }

    fn passthrough_next<T>(mut self, value: T) -> Result<Self, Self::Error>
    where
        T: Any + Send + 'static,
    {
        self.inner = self.inner.passthrough_next(value)?;
        Ok(self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.cipher.seal_tree(self.inner.end()?)
    }
}

/// [`MapCipher`] for `&Aes256Cipher`: accumulates a pending tree via the generic
/// [`TreeMap`] (which enforces the key→value contract), then seals at
/// [`end`](MapCipher::end).
pub struct AesMap<'c> {
    inner: TreeMap,
    cipher: &'c Aes256Cipher,
}

impl MapCipher for AesMap<'_> {
    type Ok = AesCipherText;
    type Error = Unspecified;

    fn encrypt_key(mut self, key: &'static str) -> Result<Self, Self::Error> {
        self.inner = self.inner.encrypt_key(key)?;
        Ok(self)
    }

    fn encrypt_value<'a, T, A>(mut self, value: T, aad: A) -> Result<Self, Self::Error>
    where
        T: vitaminc_aead::Encrypt,
        A: IntoAad<'a>,
    {
        self.inner = self.inner.encrypt_value(value, aad)?;
        Ok(self)
    }

    fn passthrough_entry<T>(mut self, key: &'static str, value: T) -> Result<Self, Self::Error>
    where
        T: Any + Send + 'static,
    {
        self.inner = self.inner.passthrough_entry(key, value)?;
        Ok(self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.cipher.seal_tree(self.inner.end()?)
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
        // AAD is threaded through the `Decrypt`/`Decipher` call chain (mirroring how
        // `Encrypt::encrypt_with_aad` threads it on the encrypt side), not baked into the
        // decipher up front.
        T::decrypt_with_aad(self.decipher(ciphertext), aad)
    }

    /// Construct a [`Decipher`](vitaminc_aead::Decipher) over `ciphertext` bound
    /// to this cipher.
    ///
    /// This is the decrypt-side counterpart to passing `&cipher` (a [`Cipher`])
    /// on the encrypt side: it hands callers a concrete decipher they can drive
    /// directly via [`Decrypt::decrypt_with_aad`], which is what generic
    /// decrypt-side helpers (e.g. `ContextTag`) build on. The ergonomic
    /// [`decrypt`](Aes256Cipher::decrypt) /
    /// [`decrypt_with_aad`](Aes256Cipher::decrypt_with_aad) methods are thin
    /// wrappers around it. The structural walk lives in [`TreeDecipher`];
    /// [`AesOpener`] supplies the per-leaf decryption.
    pub fn decipher(&self, ciphertext: AesCipherText) -> AesDecipher<'_> {
        TreeDecipher::new(AesOpener(self), ciphertext)
    }
}

// quickcheck doesn't run under `wasm-pack test --node` (it shells out to
// std::thread, which isn't available on wasm32-unknown-unknown). These property
// tests already cover both backends on native via the
// `_test-rust-crypto-backend` feature; the wasm32 codegen path is gated by the
// KAT in `crate::backend::tests`.
//
// Written as two stacked `cfg` attributes rather than `cfg(all(test, …))` so
// cargo-mutants sees the literal `cfg(test)` and skips this whole test module —
// it doesn't look for `test` nested inside `all(...)`, and the `#[quickcheck]`
// fns aren't `#[test]` at the syntax level, so it would otherwise mutate them
// (e.g. replace a property body with `true`, which trivially "survives").
// Stacked `cfg` attributes are AND-ed, so this compiles identically.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use crate::key::tests::DifferingKeyPair;
    use quickcheck_macros::quickcheck;
    use std::collections::HashMap;
    use vitaminc_aead::{Decipher, Encrypt, MapCipher, SeqCipher};

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
    fn decrypt_seq_fails_with_wrong_aad(key: Key, plaintext: Vec<String>) -> bool {
        // The Sequence path re-supplies the same AAD to every element, so a wrong
        // AAD must fail the per-element authentication rather than silently
        // decrypting. An empty sequence has no element tags to reject — the
        // container shape itself is not AEAD-authenticated on either side — so
        // skip it.
        if plaintext.is_empty() {
            return true;
        }
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = plaintext
            .encrypt_with_aad(&cipher, "correct-aad")
            .expect("Encryption failed");
        cipher
            .decrypt_with_aad::<Vec<String>, _>(ciphertext, "wrong-aad")
            .is_err()
    }

    #[quickcheck]
    fn roundtrip_vec_with_aad(key: Key, plaintext: Vec<String>) -> bool {
        // Positive counterpart to `decrypt_seq_fails_with_wrong_aad`: every element
        // must authenticate when the *correct* AAD is re-supplied per element by
        // `AesSeqAccess::next_element`. Exercises the borrowed-AAD seq path across
        // arbitrary element counts (the empty vec has no element tags and trivially
        // roundtrips). A wrong-AAD-fails test alone can't catch a regression where
        // the per-element AAD is dropped or mis-borrowed so even the correct AAD
        // fails — only this positive multi-element roundtrip does.
        let aad = "seq-aad";
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = plaintext
            .clone()
            .encrypt_with_aad(&cipher, aad)
            .expect("Encryption failed");
        let decrypted: Vec<String> = cipher
            .decrypt_with_aad(ciphertext, aad)
            .expect("Decryption failed");
        decrypted == plaintext
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
    fn roundtrip_equatable_string(key: Key, plaintext: String) -> bool {
        use vitaminc_protected::{Controlled, Equatable, Protected};

        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let value: Equatable<Protected<String>> = Equatable::new(plaintext.clone());
        let ciphertext = value.encrypt(&cipher).expect("Encryption failed");
        let decrypted: Equatable<Protected<String>> =
            cipher.decrypt(ciphertext).expect("Decryption failed");
        decrypted.risky_unwrap() == plaintext
    }

    #[quickcheck]
    fn roundtrip_equatable_u32(key: Key, plaintext: u32) -> bool {
        use vitaminc_protected::{Controlled, Equatable, Protected};

        // `u32` routes through the fixed-size `encrypt_bytes_array` path, so this
        // exercises the `Equatable` wrapper over that branch — not just the
        // byte-vec path covered by `roundtrip_equatable_string`.
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let value: Equatable<Protected<u32>> = Equatable::new(plaintext);
        let ciphertext = value.encrypt(&cipher).expect("Encryption failed");
        let decrypted: Equatable<Protected<u32>> =
            cipher.decrypt(ciphertext).expect("Decryption failed");
        decrypted.risky_unwrap() == plaintext
    }

    #[quickcheck]
    fn roundtrip_equatable_with_aad(key: Key, plaintext: String) -> bool {
        use vitaminc_protected::{Controlled, Equatable, Protected};

        // Positive correct-AAD roundtrip *through* the `Equatable` layer — the
        // wrong-AAD test only proves rejection, never that the right AAD recovers
        // the value. Also asserts the rebuilt wrapper's own constant-time
        // `PartialEq` (the reason `Decrypt` reconstructs `Equatable` via
        // `init_from_inner` rather than handing back a bare `Protected`).
        let aad = "equatable-aad";
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let value: Equatable<Protected<String>> = Equatable::new(plaintext.clone());
        let ciphertext = value
            .encrypt_with_aad(&cipher, aad)
            .expect("Encryption failed");
        let decrypted: Equatable<Protected<String>> = cipher
            .decrypt_with_aad(ciphertext, aad)
            .expect("Decryption failed");
        let expected: Equatable<Protected<String>> = Equatable::new(plaintext.clone());
        decrypted == expected && decrypted.risky_unwrap() == plaintext
    }

    #[quickcheck]
    fn decrypt_equatable_fails_with_wrong_aad(key: Key, plaintext: String) -> bool {
        use vitaminc_protected::{Equatable, Protected};

        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let value: Equatable<Protected<String>> = Equatable::new(plaintext);
        let ciphertext = value
            .encrypt_with_aad(&cipher, "correct-aad")
            .expect("Encryption failed");
        cipher
            .decrypt_with_aad::<Equatable<Protected<String>>, _>(ciphertext, "wrong-aad")
            .is_err()
    }

    #[quickcheck]
    fn decrypt_equatable_fails_with_wrong_key(keys: DifferingKeyPair, plaintext: String) -> bool {
        use vitaminc_protected::{Equatable, Protected};

        // Completes the tamper matrix with the key axis (sibling `String` path has
        // both wrong-AAD and wrong-key). `DifferingKeyPair` guarantees the two keys
        // are distinct, so a key collision cannot make this spuriously pass.
        let DifferingKeyPair(key_a, key_b) = keys;
        let cipher_a = Aes256Cipher::new(&key_a).expect("Failed to create cipher A");
        let cipher_b = Aes256Cipher::new(&key_b).expect("Failed to create cipher B");
        let value: Equatable<Protected<String>> = Equatable::new(plaintext);
        let ciphertext = value.encrypt(&cipher_a).expect("Encryption failed");
        cipher_b
            .decrypt::<Equatable<Protected<String>>>(ciphertext)
            .is_err()
    }

    #[quickcheck]
    fn equatable_ciphertext_is_wrapper_agnostic(key: Key, plaintext: String) -> bool {
        use vitaminc_protected::{Controlled, Equatable, Protected};

        // `Equatable` adds nothing to the ciphertext, so the two are interchangeable:
        // a value sealed as `Equatable<Protected<String>>` decrypts cleanly as the
        // bare inner `Protected<String>`, and a bare `String` ciphertext reads back
        // through the `Equatable` layer. Pins the wrapper-agnostic invariant — a
        // future change that tagged the wrapper into the ciphertext would break this.
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");

        let eq_ciphertext = Equatable::<Protected<String>>::new(plaintext.clone())
            .encrypt(&cipher)
            .expect("Encryption failed");
        let as_protected: Protected<String> = cipher
            .decrypt(eq_ciphertext)
            .expect("decrypt as Protected failed");

        let bare_ciphertext = plaintext
            .clone()
            .encrypt(&cipher)
            .expect("Encryption failed");
        let as_equatable: Equatable<Protected<String>> = cipher
            .decrypt(bare_ciphertext)
            .expect("decrypt as Equatable failed");

        as_protected.risky_unwrap() == plaintext && as_equatable.risky_unwrap() == plaintext
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
        cipher.decipher(ciphertext).decrypt_passthrough::<T>()
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

    // --- Nonce uniqueness (fundamental AEAD property) ---

    #[quickcheck]
    fn nonce_is_unique_across_encryptions(key: Key, plaintext: String) -> bool {
        // Two encryptions of the same plaintext under the same cipher must
        // produce different ciphertexts — each `encrypt_*` call draws a fresh
        // nonce. The plaintext is incidental (the nonce is drawn independently),
        // but running this as a property samples a fresh nonce pair per case,
        // exercising many more of the generator's outputs than a single fixed
        // run would. Catches a future RNG / nonce-reuse regression before it
        // becomes a catastrophic AEAD failure.
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ct1 = plaintext
            .clone()
            .encrypt(&cipher)
            .expect("Encryption failed");
        let ct2 = plaintext.encrypt(&cipher).expect("Encryption failed");
        match (ct1, ct2) {
            (AesCipherText::Single(a), AesCipherText::Single(b)) => a.as_ref() != b.as_ref(),
            _ => panic!("expected Single ciphertexts"),
        }
    }

    // --- Variant-rejection catch-alls (FC.1 cluster) ---
    //
    // Each `decrypt_*` method accepts exactly one `AesCipherText` variant and
    // routes every other variant to `Err(Unspecified)`. These are the
    // structural type-laundering guards the design relies on. The four tests
    // below pin every catch-all sub-path (the `None`/`Passthrough` cases
    // already pinned individually above are re-asserted here for completeness).
    // `AesCipherText` is not `Clone`, so each rejected variant is rebuilt fresh.

    fn single_ct(cipher: &Aes256Cipher) -> AesCipherText {
        "single".to_string().encrypt(cipher).expect("encrypt")
    }
    fn sequence_ct(cipher: &Aes256Cipher) -> AesCipherText {
        vec!["a".to_string(), "b".to_string()]
            .encrypt(cipher)
            .expect("encrypt")
    }
    fn map_ct(cipher: &Aes256Cipher) -> AesCipherText {
        let mut m = HashMap::new();
        m.insert("k", "v");
        m.encrypt(cipher).expect("encrypt")
    }
    fn none_ct(cipher: &Aes256Cipher) -> AesCipherText {
        None::<String>.encrypt(cipher).expect("encrypt")
    }
    fn passthrough_ct(cipher: &Aes256Cipher) -> AesCipherText {
        cipher.passthrough(7u32).expect("passthrough")
    }

    #[test]
    fn decrypt_bytes_rejects_non_single_variants() {
        let cipher = Aes256Cipher::new(&Key::from([20u8; 32])).expect("Failed to create cipher");
        // `decrypt_bytes` (driving e.g. `String`) accepts only `Single`.
        assert!(
            cipher.decrypt::<String>(sequence_ct(&cipher)).is_err(),
            "Sequence"
        );
        assert!(cipher.decrypt::<String>(map_ct(&cipher)).is_err(), "Map");
        assert!(cipher.decrypt::<String>(none_ct(&cipher)).is_err(), "None");
        assert!(
            cipher.decrypt::<String>(passthrough_ct(&cipher)).is_err(),
            "Passthrough"
        );
    }

    #[test]
    fn decrypt_seq_rejects_non_sequence_variants() {
        let cipher = Aes256Cipher::new(&Key::from([21u8; 32])).expect("Failed to create cipher");
        // `decrypt_seq` (driving `Vec<T>`) accepts only `Sequence`.
        assert!(
            cipher.decrypt::<Vec<String>>(single_ct(&cipher)).is_err(),
            "Single"
        );
        assert!(
            cipher.decrypt::<Vec<String>>(map_ct(&cipher)).is_err(),
            "Map"
        );
        assert!(
            cipher.decrypt::<Vec<String>>(none_ct(&cipher)).is_err(),
            "None"
        );
        assert!(
            cipher
                .decrypt::<Vec<String>>(passthrough_ct(&cipher))
                .is_err(),
            "Passthrough"
        );
    }

    #[test]
    fn decrypt_map_rejects_non_map_variants() {
        let cipher = Aes256Cipher::new(&Key::from([22u8; 32])).expect("Failed to create cipher");
        // `decrypt_map` (driving `HashMap<String, T>`) accepts only `Map`.
        assert!(
            cipher
                .decrypt::<HashMap<String, String>>(single_ct(&cipher))
                .is_err(),
            "Single"
        );
        assert!(
            cipher
                .decrypt::<HashMap<String, String>>(sequence_ct(&cipher))
                .is_err(),
            "Sequence"
        );
        assert!(
            cipher
                .decrypt::<HashMap<String, String>>(none_ct(&cipher))
                .is_err(),
            "None"
        );
        assert!(
            cipher
                .decrypt::<HashMap<String, String>>(passthrough_ct(&cipher))
                .is_err(),
            "Passthrough"
        );
    }

    #[test]
    fn decrypt_passthrough_rejects_non_passthrough_variants() {
        let cipher = Aes256Cipher::new(&Key::from([23u8; 32])).expect("Failed to create cipher");
        // `decrypt_passthrough` accepts only `Passthrough`.
        assert!(
            decrypt_passthrough_via::<u32>(&cipher, single_ct(&cipher)).is_err(),
            "Single"
        );
        assert!(
            decrypt_passthrough_via::<u32>(&cipher, sequence_ct(&cipher)).is_err(),
            "Sequence"
        );
        assert!(
            decrypt_passthrough_via::<u32>(&cipher, map_ct(&cipher)).is_err(),
            "Map"
        );
        assert!(
            decrypt_passthrough_via::<u32>(&cipher, none_ct(&cipher)).is_err(),
            "None"
        );
    }

    // --- Option<T> type variation: exercise the `other`-arm sub-paths ---
    //
    // `roundtrip_option_some_string` only lands the `Single` sub-path with a
    // `String` leaf. These cover a non-String `Single` leaf (u32), the
    // `Sequence` sub-path (Vec), the `Map` sub-path (HashMap), and the
    // `Protected`-rewrap path.

    #[quickcheck]
    fn roundtrip_option_some_u32(key: Key, value: u32) -> bool {
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ct = Some(value).encrypt(&cipher).expect("Encryption failed");
        cipher
            .decrypt::<Option<u32>>(ct)
            .expect("Decryption failed")
            == Some(value)
    }

    #[quickcheck]
    fn roundtrip_option_some_vec_of_strings(items: Vec<String>) -> bool {
        let cipher = Aes256Cipher::new(&Key::from([31u8; 32])).expect("Failed to create cipher");
        let ct = Some(items.clone())
            .encrypt(&cipher)
            .expect("Encryption failed");
        cipher
            .decrypt::<Option<Vec<String>>>(ct)
            .expect("Decryption failed")
            == Some(items)
    }

    #[test]
    fn roundtrip_option_some_hashmap() {
        let cipher = Aes256Cipher::new(&Key::from([32u8; 32])).expect("Failed to create cipher");
        let mut m = HashMap::new();
        m.insert("name", "Alice");
        let ct = Some(m).encrypt(&cipher).expect("Encryption failed");
        let decoded: Option<HashMap<String, String>> =
            cipher.decrypt(ct).expect("Decryption failed");
        assert_eq!(
            decoded.unwrap().get("name").map(String::as_str),
            Some("Alice")
        );
    }

    #[quickcheck]
    fn roundtrip_option_some_protected_string(plaintext: String) -> bool {
        use vitaminc_protected::{Controlled, Protected};
        let cipher = Aes256Cipher::new(&Key::from([33u8; 32])).expect("Failed to create cipher");
        let ct = Some(Protected::new(plaintext.clone()))
            .encrypt(&cipher)
            .expect("Encryption failed");
        let decoded: Option<Protected<String>> = cipher.decrypt(ct).expect("Decryption failed");
        decoded.map(Controlled::risky_unwrap) == Some(plaintext)
    }

    #[quickcheck]
    fn decrypt_option_some_fails_with_wrong_aad(plaintext: String) -> bool {
        // Wrong-AAD rejection threaded through the `Option` type itself (not just
        // the inner leaf).
        let cipher = Aes256Cipher::new(&Key::from([34u8; 32])).expect("Failed to create cipher");
        let ct = Some(plaintext)
            .encrypt_with_aad(&cipher, "correct")
            .expect("Encryption failed");
        cipher
            .decrypt_with_aad::<Option<String>, _>(ct, "wrong")
            .is_err()
    }

    #[test]
    fn nested_option_shape_is_caller_decided() {
        // `Some(Some(x))` seals to the same `Single(_)` as `Some(x)`; the
        // call-site type decides the decoded shape. Pins the documented
        // serde-style property so an accidental future "fix" can't close the
        // recursion door. See the note on `decrypt_option`.
        let cipher = Aes256Cipher::new(&Key::from([35u8; 32])).expect("Failed to create cipher");
        let outer: Option<Option<String>> = Some(Some("x".into()));
        let ct = outer.encrypt(&cipher).expect("Encryption failed");
        let decoded: Option<String> = cipher.decrypt(ct).expect("Decryption failed");
        assert_eq!(decoded, Some("x".into()));
    }

    // --- Mixed encrypted / passthrough entries + Any-TypeId ---

    #[test]
    fn seq_cipher_accepts_mixed_encrypt_next_and_passthrough_next() {
        let cipher = Aes256Cipher::new(&Key::from([40u8; 32])).expect("Failed to create cipher");
        let ct = (&cipher)
            .encrypt_seq(Some(3))
            .encrypt_next("first", ())
            .unwrap()
            .passthrough_next(99u32)
            .unwrap()
            .encrypt_next("third", ())
            .unwrap()
            .end()
            .unwrap();
        match ct {
            AesCipherText::Sequence(items) => {
                assert_eq!(items.len(), 3);
                assert!(matches!(items[0], AesCipherText::Single(_)));
                assert!(matches!(items[1], AesCipherText::Passthrough(_)));
                assert!(matches!(items[2], AesCipherText::Single(_)));
            }
            _ => panic!("expected Sequence"),
        }
    }

    #[test]
    fn map_with_mixed_entries_cannot_decode_as_uniform_hashmap() {
        // A passthrough value in a map cannot satisfy a uniform `HashMap<_, T>`
        // decode: `T`'s bytes visitor hits the FC.1 catch-all on the
        // Passthrough variant, failing the whole decode.
        let cipher = Aes256Cipher::new(&Key::from([41u8; 32])).expect("Failed to create cipher");
        let ct = (&cipher)
            .encrypt_map()
            .encrypt_key("name")
            .unwrap()
            .encrypt_value("Alice".to_string(), ())
            .unwrap()
            .passthrough_entry("schema_version", 1u32)
            .unwrap()
            .end()
            .unwrap();
        assert!(cipher.decrypt::<HashMap<String, String>>(ct).is_err());
    }

    #[test]
    fn roundtrip_hashmap_of_option_values() {
        // The companion happy case: mixed Some/None values decode correctly iff
        // the decode type explicitly accepts the variation (`Option<T>`).
        let cipher = Aes256Cipher::new(&Key::from([42u8; 32])).expect("Failed to create cipher");
        let mut m: HashMap<&'static str, Option<String>> = HashMap::new();
        m.insert("present", Some("Alice".to_string()));
        m.insert("absent", None);
        let ct = m.encrypt(&cipher).expect("Encryption failed");
        let decoded: HashMap<String, Option<String>> =
            cipher.decrypt(ct).expect("Decryption failed");
        assert_eq!(decoded.get("present"), Some(&Some("Alice".to_string())));
        assert_eq!(decoded.get("absent"), Some(&None));
    }

    #[test]
    fn passthrough_option_is_distinct_type_from_inner() {
        // `Any`/`TypeId` pin: `Option<u32>` and `u32` are distinct types even
        // when the value is `Some(n)`. A passthrough sealed as `Option<u32>`
        // must only downcast back to `Option<u32>`.
        let cipher = Aes256Cipher::new(&Key::from([43u8; 32])).expect("Failed to create cipher");
        let ct = cipher.passthrough(Some(42u32)).expect("passthrough failed");
        let decoded: Option<u32> =
            decrypt_passthrough_via(&cipher, ct).expect("decode as Option<u32> should succeed");
        assert_eq!(decoded, Some(42u32));

        let ct2 = cipher.passthrough(Some(42u32)).expect("passthrough failed");
        assert!(
            decrypt_passthrough_via::<u32>(&cipher, ct2).is_err(),
            "Option<u32> passthrough must not downcast to u32"
        );
    }

    #[quickcheck]
    fn decrypt_byte_array_ciphertext_as_vec_u8(key: Key, bytes: [u8; 16]) -> bool {
        // `Decrypt for Vec<u8>` reads the bytes pipeline (`Single`), not a
        // `Sequence`. There is no `Encrypt for Vec<u8>` (no `Encrypt for u8`),
        // so a `[u8; N]` ciphertext is the canonical `Single` producer
        // decodable as `Vec<u8>`. Pins the otherwise-unexercised impl across
        // arbitrary byte payloads.
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ct = bytes.encrypt(&cipher).expect("Encryption failed");
        let decoded: Vec<u8> = cipher.decrypt(ct).expect("Decryption failed");
        decoded == bytes.to_vec()
    }
}
