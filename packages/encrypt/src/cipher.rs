use crate::backend::{CipherKey, NONCE_LEN, TAG_LEN};
use crate::Key;
use std::any::Any;
use std::borrow::Cow;
use std::collections::HashSet;
use vitaminc_aead::{
    Aad, Cipher, CipherText, CipherTextBuilder, Decipher, DecipherVisitor, Decrypt, Encrypt,
    IntoAad, LocalCipherText, MapAccess, MapCipher, NonceGenerator, RandomNonceGenerator,
    SeqAccess, SeqCipher, Unspecified, WIRE_VERSION,
};
use vitaminc_protected::{Controlled, Protected};

/// The passthrough payload type used by [`Aes256Cipher`]: type-erased boxed
/// values, downcast back to a concrete type at decrypt time via
/// [`AesDecipher::decrypt_passthrough_as`].
pub type BoxedPassthrough = Box<dyn Any + Send + 'static>;

/// The recursive ciphertext container produced by [`Aes256Cipher`] — the
/// shared [`CipherText`] tree instantiated with [`LocalCipherText`] leaves
/// and [`BoxedPassthrough`] passthrough values.
///
/// The shape mirrors the structure of the plaintext that was encrypted: a
/// single value yields [`Single`](CipherText::Single), while non-empty
/// `Vec`s and `HashMap`s yield [`Sequence`](CipherText::Sequence) and
/// [`Map`](CipherText::Map). Empty composites use the authenticated marker
/// variants [`EmptySequence`](CipherText::EmptySequence) and
/// [`EmptyMap`](CipherText::EmptyMap). Nested structures are represented
/// recursively.
pub type AesCipherText = CipherText<LocalCipherText, BoxedPassthrough>;

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

    fn seal_empty_marker<'a, A>(&self, aad: A) -> Result<LocalCipherText, Unspecified>
    where
        A: IntoAad<'a>,
    {
        seal_leaf(self, Protected::new(Vec::new()), aad)
    }
}

/// Seal one leaf: `version(1) ‖ nonce ‖ ciphertext ‖ tag`, with the wire
/// version bound into the AAD via `Aad::for_leaf`.
///
/// This is THE leaf seal path — the dynamic [`Cipher`] impl and the static
/// hlist cipher (`cipher_static.rs`) both go through it, so a wire-format
/// change lands in every path at once instead of drifting between copies.
/// The one exception is [`Cipher::encrypt_bytes_array`], which duplicates
/// the derivation to keep its no-realloc fixed-width fast path; its output
/// bytes are pinned equal to this path by test.
pub(crate) fn seal_leaf<'a, A>(
    cipher: &Aes256Cipher,
    data: Protected<Vec<u8>>,
    aad: A,
) -> Result<LocalCipherText, Unspecified>
where
    A: IntoAad<'a>,
{
    let nonce = cipher.nonce_generator.generate()?;
    let nonce_bytes: [u8; NONCE_LEN] = nonce.as_ref().try_into().map_err(|_| Unspecified)?;
    // Outermost derivation: bind the wire version the builder prefixes to
    // the stored leaf — see `Aad::for_leaf`.
    let aad = aad.into_aad().for_leaf(WIRE_VERSION);

    CipherTextBuilder::new()
        .append_nonce(nonce)
        .append_target_plaintext(data)
        .accepts_ciphertext_and_tag_ok(|mut buf| {
            cipher
                .key
                .seal(&nonce_bytes, aad.as_bytes(), &mut buf)
                .map(|()| buf)
        })
        .build()
}

/// Open one leaf sealed by [`seal_leaf`] (or the equivalent array fast
/// path): checks the wire version before parsing, then verifies with the
/// same `Aad::for_leaf` derivation. Shared by the dynamic decipher and the
/// static hlist path for the same anti-drift reason as [`seal_leaf`].
pub(crate) fn open_leaf<'a, A>(
    cipher: &Aes256Cipher,
    ct: LocalCipherText,
    aad: A,
) -> Result<Protected<Vec<u8>>, Unspecified>
where
    A: IntoAad<'a>,
{
    // `read_version` rejects unknown wire versions before any parsing; the
    // version is *also* bound under the tag (`for_leaf`, mirroring the seal
    // side), so a relabeled byte that parses still fails.
    let (nonce, reader) = ct.into_reader().read_version()?.read_nonce::<NONCE_LEN>()?;
    let nonce_bytes = nonce.into_inner();
    let aad = aad.into_aad().for_leaf(WIRE_VERSION);

    reader
        .accepts_plaintext_ok(|data| cipher.key.open(&nonce_bytes, aad.as_bytes(), data))
        .read()
}

impl<'c> Cipher for &'c Aes256Cipher {
    type Ok = AesCipherText;
    type Error = Unspecified;
    type Passthrough = BoxedPassthrough;
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
        seal_leaf(self, data, aad).map(AesCipherText::Single)
    }

    fn encrypt_bytes_array<'a, const N: usize, A>(
        self,
        data: Protected<[u8; N]>,
        aad: A,
    ) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        // Override the trait default (which does a plain `to_vec`, sized
        // exactly `N`, forcing the in-place seal to reallocate when it appends
        // the tag). `append_target_plaintext_array` pre-sizes the buffer to
        // `N + TAG_LEN` so the seal appends the tag into spare capacity and the
        // ciphertext is produced with a single heap allocation. Output bytes
        // are identical to the default path.
        let nonce = self.nonce_generator.generate()?;
        let nonce_bytes: [u8; NONCE_LEN] = nonce.as_ref().try_into().map_err(|_| Unspecified)?;
        // Outermost derivation: bind the wire version — see `Aad::for_leaf`.
        let aad = aad.into_aad().for_leaf(WIRE_VERSION);

        CipherTextBuilder::new()
            .append_nonce(nonce)
            .append_target_plaintext_array(data, TAG_LEN)
            .accepts_ciphertext_and_tag_ok(|mut buf| {
                self.key
                    .seal(&nonce_bytes, aad.as_bytes(), &mut buf)
                    .map(|()| buf)
            })
            .build()
            .map(AesCipherText::Single)
    }

    fn encrypt_seq<'a, A>(self, size_hint: Option<usize>, aad: A) -> Self::SeqCipher
    where
        A: IntoAad<'a>,
    {
        let aad = aad.into_aad().into_owned();
        AesSeqCipher {
            cipher: self,
            items: Vec::with_capacity(size_hint.unwrap_or(0)),
            // Both derived once here, then borrowed per element — cheaper
            // than the per-element clone the old AAD-per-call shape required.
            element_aad: aad.for_sequence_element(),
            aad,
            encrypted: false,
        }
    }

    fn encrypt_map<'a, A>(self, aad: A) -> Self::MapCipher
    where
        A: IntoAad<'a>,
    {
        AesMapCipher {
            cipher: self,
            entries: Vec::new(),
            seen_keys: HashSet::new(),
            current_key: None,
            aad: aad.into_aad().into_owned(),
            encrypted: false,
        }
    }

    fn encrypt_none<'a, A>(self, aad: A) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        // Domain-separated so a `Single` leaf sealed under the bare AAD can
        // never be re-tagged as an authenticated absence (and vice versa).
        self.seal_empty_marker(aad.into_aad().for_none())
            .map(AesCipherText::None)
    }

    fn passthrough(self, value: Self::Passthrough) -> Result<Self::Ok, Self::Error> {
        Ok(AesCipherText::Passthrough(value))
    }

    fn passthrough_boxed(
        self,
        value: Box<dyn Any + Send + 'static>,
    ) -> Result<Self::Ok, Self::Error> {
        // This cipher's passthrough type *is* `Box<dyn Any + Send>` (see
        // `BoxedPassthrough`), so the type-erased box is already the
        // passthrough payload — store it directly.
        self.passthrough(value)
    }
}

/// [`SeqCipher`] driver for [`Aes256Cipher`]. Encrypts each element under its
/// own fresh nonce and accumulates the results into an
/// [`AesCipherText::Sequence`].
pub struct AesSeqCipher<'c> {
    cipher: &'c Aes256Cipher,
    items: Vec<AesCipherText>,
    /// The AAD fixed at [`Cipher::encrypt_seq`]; the empty marker is sealed
    /// against its `for_empty_sequence` derivation.
    aad: Aad<'static>,
    /// [`Aad::for_sequence_element`] of `aad`, derived once and applied to
    /// every element. The labelled derivation is what authenticates the
    /// container shape: a leaf sealed in element position can never verify
    /// as a top-level `Single` (or vice versa) — see
    /// [`Aad::for_sequence_element`].
    element_aad: Aad<'static>,
    /// Whether at least one item was appended through the authenticated
    /// [`encrypt_next`](SeqCipher::encrypt_next) path. Passthrough items
    /// authenticate nothing, so a sequence with items but no encrypted ones
    /// would otherwise carry no AEAD tag at all — see [`end`](SeqCipher::end).
    encrypted: bool,
}

impl<'c> SeqCipher for AesSeqCipher<'c> {
    type Ok = AesCipherText;
    type Error = Unspecified;
    type Passthrough = BoxedPassthrough;

    fn encrypt_next<T>(mut self, data: T) -> Result<Self, Self::Error>
    where
        T: Encrypt,
    {
        // Borrow the stored derived AAD — no allocation per element.
        let encrypted =
            data.encrypt_with_aad(self.cipher, Aad::from_slice(self.element_aad.as_bytes()))?;
        // A nested `Encrypt` impl may route through the passthrough channel
        // (e.g. `FfiValue::Passthrough`), producing an unauthenticated node
        // despite arriving via this method. Only a genuinely sealed node may
        // satisfy `end`'s all-passthrough rejection, otherwise a container of
        // only passthrough elements would encrypt Ok yet carry no AEAD tag
        // (and `decrypt_seq` would refuse it forever).
        self.encrypted |= !matches!(encrypted, AesCipherText::Passthrough(_));
        self.items.push(encrypted);
        Ok(self)
    }

    fn passthrough_next(mut self, value: Self::Passthrough) -> Result<Self, Self::Error> {
        self.items.push(AesCipherText::Passthrough(value));
        Ok(self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        if self.items.is_empty() {
            self.cipher
                .seal_empty_marker(self.aad.for_empty_sequence())
                .map(AesCipherText::EmptySequence)
        } else if !self.encrypted {
            // Every item is a passthrough: nothing in the container
            // authenticates the AAD (or, when the sequence is a map value,
            // its entry key). Such a container would decrypt under any AAD,
            // so refuse to produce it — all-passthrough data has no business
            // going through a cipher.
            Err(Unspecified)
        } else {
            Ok(AesCipherText::Sequence(self.items))
        }
    }
}

/// [`MapCipher`] driver for [`Aes256Cipher`]. Keys are stored in the clear;
/// values are encrypted under their own fresh nonce and accumulated into an
/// [`AesCipherText::Map`]. Each value is sealed against
/// [`Aad::for_map_entry`] of the caller's AAD and its key, so swapping or
/// renaming keys in a stored ciphertext fails decryption (passthrough
/// entries excepted — they are unauthenticated by design).
///
/// Duplicate keys are rejected at encrypt time: `encrypt_key` and
/// `passthrough_entry` fail on a key that is already present, mirroring
/// `decrypt_map`'s outright rejection of duplicates (a verified duplicate
/// would otherwise let an attacker splice a stale value for one field into
/// a current ciphertext). Failing at seal time keeps the contract symmetric
/// for every encoder — a duplicate-keyed source (e.g. a hand-built
/// `FfiValue::Object`) errors immediately instead of producing a ciphertext
/// that can never be read back.
pub struct AesMapCipher<'c> {
    cipher: &'c Aes256Cipher,
    entries: Vec<(String, AesCipherText)>,
    /// Every key committed so far — duplicate rejection must stay O(1) per
    /// key because map keys can arrive from an untrusted host across the FFI
    /// boundary, where a linear scan per key is a quadratic-work lever
    /// (`decrypt_map` uses the same structure for the same reason).
    seen_keys: HashSet<String>,
    current_key: Option<Cow<'static, str>>,
    /// The AAD fixed at [`Cipher::encrypt_map`]. Each entry's value is sealed
    /// against `for_map_entry` of this; the empty marker against
    /// `for_empty_map` of it.
    aad: Aad<'static>,
    /// Whether at least one entry was appended through the authenticated
    /// [`encrypt_value`](MapCipher::encrypt_value) path — see
    /// [`AesSeqCipher::encrypted`] and [`end`](MapCipher::end).
    encrypted: bool,
}

impl<'c> MapCipher for AesMapCipher<'c> {
    type Ok = AesCipherText;
    type Error = Unspecified;
    type Passthrough = BoxedPassthrough;

    fn encrypt_key<K>(mut self, key: K) -> Result<Self, Self::Error>
    where
        K: Into<Cow<'static, str>>,
    {
        // A key already pending means `encrypt_key` was called twice with no
        // intervening `encrypt_value` — a trait-contract violation. Fail rather
        // than silently drop the first key.
        if self.current_key.is_some() {
            return Err(Unspecified);
        }
        let key = key.into();
        // Reject duplicates at seal time: `decrypt_map` rejects them outright,
        // so accepting one here would produce a permanently unreadable
        // ciphertext with no error until read time.
        if !self.seen_keys.insert(key.as_ref().to_owned()) {
            return Err(Unspecified);
        }
        self.current_key = Some(key);
        Ok(self)
    }

    fn encrypt_value<U>(mut self, value: U) -> Result<Self, Self::Error>
    where
        U: Encrypt,
    {
        let key = self.current_key.take().ok_or(Unspecified)?;
        // Seal against PAE(domain, aad, key) — the trait contract that makes
        // key and value inseparable. `AesMapAccess::next_entry` derives the
        // same AAD on decrypt.
        let entry_aad = self.aad.for_map_entry(&key);
        let encrypted = value.encrypt_with_aad(self.cipher, entry_aad)?;
        // See `AesSeqCipher::encrypt_next`: a nested impl may have routed
        // through the passthrough channel, and an unauthenticated node must
        // not satisfy `end`'s all-passthrough rejection.
        self.encrypted |= !matches!(encrypted, AesCipherText::Passthrough(_));
        self.entries.push((key.into_owned(), encrypted));
        Ok(self)
    }

    fn passthrough_entry<K>(mut self, key: K, value: Self::Passthrough) -> Result<Self, Self::Error>
    where
        K: Into<Cow<'static, str>>,
    {
        // A key already pending means `encrypt_key` ran without a matching
        // `encrypt_value` — adopting it here would silently drop the pending
        // key, which is the same trait-contract violation `encrypt_key`
        // rejects.
        if self.current_key.is_some() {
            return Err(Unspecified);
        }
        let key = key.into();
        // Same duplicate rejection as `encrypt_key` — see the type docs.
        if !self.seen_keys.insert(key.as_ref().to_owned()) {
            return Err(Unspecified);
        }
        self.entries
            .push((key.into_owned(), AesCipherText::Passthrough(value)));
        Ok(self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        // Finalising with a pending key would silently drop the entry.
        if self.current_key.is_some() {
            return Err(Unspecified);
        }
        if self.entries.is_empty() {
            self.cipher
                .seal_empty_marker(self.aad.for_empty_map())
                .map(AesCipherText::EmptyMap)
        } else if !self.encrypted {
            // Every entry is a passthrough: nothing authenticates the AAD or
            // the entry keys — see `AesSeqCipher::end`.
            Err(Unspecified)
        } else {
            Ok(AesCipherText::Map(self.entries))
        }
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

    /// Construct a [`Decipher`] over `ciphertext` bound to this cipher.
    ///
    /// This is the decrypt-side counterpart to passing `&cipher` (a [`Cipher`])
    /// on the encrypt side: it hands callers a concrete [`Decipher`] they can
    /// drive directly via [`Decrypt::decrypt_with_aad`], which is what generic
    /// decrypt-side helpers (e.g. `ContextTag`) build on. The ergonomic
    /// [`decrypt`](Aes256Cipher::decrypt) /
    /// [`decrypt_with_aad`](Aes256Cipher::decrypt_with_aad) methods are thin
    /// wrappers around it.
    pub fn decipher(&self, ciphertext: AesCipherText) -> AesDecipher<'_> {
        AesDecipher {
            cipher: self,
            ciphertext,
        }
    }
}

/// A [`Decipher`] over a single [`AesCipherText`], produced by
/// [`Aes256Cipher::decipher`]. Carries the cipher and ciphertext; the AAD is
/// supplied per call by [`Decrypt::decrypt_with_aad`].
pub struct AesDecipher<'c> {
    cipher: &'c Aes256Cipher,
    ciphertext: AesCipherText,
}

impl AesDecipher<'_> {
    /// Typed convenience over [`Decipher::decrypt_passthrough`] for this
    /// cipher's [`BoxedPassthrough`] payload type: recovers the payload and
    /// downcasts it to `T`, returning [`Unspecified`] if the ciphertext is not
    /// a passthrough or the stored type does not match.
    pub fn decrypt_passthrough_as<T>(self) -> Result<T, Unspecified>
    where
        T: Any + Send + 'static,
    {
        self.decrypt_passthrough()?
            .downcast::<T>()
            .map(|b| *b)
            .map_err(|_| Unspecified)
    }

    fn decrypt_local_ciphertext(
        cipher: &Aes256Cipher,
        ct: LocalCipherText,
        aad: &[u8],
    ) -> Result<Protected<Vec<u8>>, Unspecified> {
        open_leaf(cipher, ct, Aad::from_slice(aad))
    }

    fn verify_empty_marker(
        cipher: &Aes256Cipher,
        ct: LocalCipherText,
        aad: &[u8],
    ) -> Result<(), Unspecified> {
        let plaintext = Self::decrypt_local_ciphertext(cipher, ct, aad)?;
        if plaintext.risky_ref().is_empty() {
            Ok(())
        } else {
            Err(Unspecified)
        }
    }
}

impl<'c> Decipher<'c> for AesDecipher<'c> {
    type Ok<T>
        = Result<T, Unspecified>
    where
        T: Send + 'c;

    type Passthrough = BoxedPassthrough;

    fn map_ok<T, U, F>(ok: Self::Ok<T>, f: F) -> Self::Ok<U>
    where
        T: Send + 'c,
        U: Send + 'c,
        F: FnOnce(T) -> U,
    {
        ok.map(f)
    }

    fn decrypt_bytes<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        match self.ciphertext {
            AesCipherText::Single(ct) => {
                let aad = aad.into_aad();
                let bytes = Self::decrypt_local_ciphertext(self.cipher, ct, aad.as_bytes())?;
                visitor.visit_bytes_vec(bytes)
            }
            _ => Err(Unspecified),
        }
    }

    fn decrypt_seq<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        match self.ciphertext {
            // At least one non-passthrough item is required: passthrough
            // items authenticate nothing, so an all-passthrough sequence
            // (which `AesSeqCipher::end` refuses to produce) would decrypt
            // under any AAD. Mirrors the encrypt-side rejection.
            AesCipherText::Sequence(items)
                if items
                    .iter()
                    .any(|i| !matches!(i, AesCipherText::Passthrough(_))) =>
            {
                let seq_access = AesSeqAccess {
                    cipher: self.cipher,
                    items: items.into_iter(),
                    element_aad: aad.into_aad().for_sequence_element(),
                };
                visitor.visit_seq(seq_access)
            }
            AesCipherText::EmptySequence(ct) => {
                let aad = aad.into_aad();
                Self::verify_empty_marker(self.cipher, ct, aad.for_empty_sequence().as_bytes())?;
                // Store the element derivation, exactly as the non-empty arm
                // does: the iterator is empty so it is never read today, but
                // a divergent value here would silently break a future
                // visitor that consulted it.
                let seq_access = AesSeqAccess {
                    cipher: self.cipher,
                    items: Vec::new().into_iter(),
                    element_aad: aad.for_sequence_element(),
                };
                visitor.visit_seq(seq_access)
            }
            _ => Err(Unspecified),
        }
    }

    fn decrypt_map<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        match self.ciphertext {
            // At least one non-passthrough entry required — see `decrypt_seq`.
            AesCipherText::Map(entries)
                if entries
                    .iter()
                    .any(|(_, v)| !matches!(v, AesCipherText::Passthrough(_))) =>
            {
                // Reject duplicate keys before the visitor sees any entry.
                // Two ciphertexts of the same logical record seal a given
                // key's value against the identical `for_map_entry` AAD, so
                // a stale entry appended to a current ciphertext *verifies*;
                // with a last-wins visitor that is a single-field rollback.
                // No legitimate flow produces the same key twice (a column
                // projection returns a subset of *distinct* keys), so this
                // constrains membership not at all.
                let mut seen = std::collections::HashSet::with_capacity(entries.len());
                if !entries.iter().all(|(key, _)| seen.insert(key.as_str())) {
                    return Err(Unspecified);
                }
                let map_access = AesMapAccess {
                    cipher: self.cipher,
                    entries: entries.into_iter(),
                    aad: aad.into_aad(),
                    pending: None,
                };
                visitor.visit_map(map_access)
            }
            AesCipherText::EmptyMap(ct) => {
                let aad = aad.into_aad();
                Self::verify_empty_marker(self.cipher, ct, aad.for_empty_map().as_bytes())?;
                // Raw caller AAD, not the marker derivation — see `decrypt_seq`.
                let map_access = AesMapAccess {
                    cipher: self.cipher,
                    entries: Vec::new().into_iter(),
                    aad,
                    pending: None,
                };
                visitor.visit_map(map_access)
            }
            _ => Err(Unspecified),
        }
    }

    fn decrypt_any<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        let AesDecipher { cipher, ciphertext } = self;
        match ciphertext {
            ct @ AesCipherText::Single(_) => cipher.decipher(ct).decrypt_bytes(visitor, aad),
            ct @ (AesCipherText::Sequence(_) | AesCipherText::EmptySequence(_)) => {
                cipher.decipher(ct).decrypt_seq(visitor, aad)
            }
            ct @ (AesCipherText::Map(_) | AesCipherText::EmptyMap(_)) => {
                cipher.decipher(ct).decrypt_map(visitor, aad)
            }
            AesCipherText::None(ct) => {
                // Verify the domain-separated marker (tag AND empty
                // plaintext) before reporting absence — an unauthenticated
                // `visit_none` would let an attacker forge "absent" values,
                // and a bare-AAD check would let a `Single` leaf be re-tagged
                // as one. Mirrors `decrypt_option`.
                let aad = aad.into_aad();
                Self::verify_empty_marker(cipher, ct, aad.for_none().as_bytes())?;
                visitor.visit_none()
            }
            // A self-describing visitor recovers a passthrough via
            // `visit_passthrough` (the payload is handed over type-erased);
            // visitors that do not override it inherit the default rejection.
            // The typed `decrypt_passthrough` path remains available for
            // callers that know the shape up front.
            AesCipherText::Passthrough(boxed) => visitor.visit_passthrough(boxed),
        }
    }

    fn decrypt_passthrough(self) -> Self::Ok<Self::Passthrough> {
        match self.ciphertext {
            AesCipherText::Passthrough(boxed) => Ok(boxed),
            _ => Err(Unspecified),
        }
    }

    fn decrypt_option<'a, T, A>(self, aad: A) -> Self::Ok<Option<T>>
    where
        T: Decrypt<'c> + 'c,
        A: IntoAad<'a>,
    {
        match self.ciphertext {
            AesCipherText::None(ct) => {
                // Verify the tag over the domain-separated marker AAD AND
                // that the sealed plaintext is actually empty. Without both,
                // a `Single(leaf)` sealed under the same caller AAD could be
                // re-tagged as `None(leaf)` and decrypt as Ok(None) — silent
                // authenticated data deletion.
                let aad = aad.into_aad();
                Self::verify_empty_marker(self.cipher, ct, aad.for_none().as_bytes())?;
                Ok(None)
            }
            // Passthrough must never be decoded as an Option payload.
            AesCipherText::Passthrough(_) => Err(Unspecified),
            // Any other variant is the `Some` payload: recurse into `T`. This is
            // what lets `Option<Vec<T>>`, `Option<HashMap<K, V>>`,
            // `Option<Protected<T>>` compose naturally.
            //
            // Note: there is no depth tag in the ciphertext, so the *shape* of
            // nested options is decided by `T` at the call site, not by the
            // bytes — `Some(Some(x))` and `Some(x)` seal to identical
            // `Single(_)` ciphertexts. Decoding the same ciphertext as
            // `Option<String>` yields `Some("x")` and as `Option<Option<String>>`
            // yields `Some(Some("x"))`; both succeed. This mirrors serde's
            // treatment of `Option` and is intentional — every caller fixes a
            // concrete type at the call site. See `nested_option_shape_is_caller_decided`.
            other => {
                let inner = self.cipher.decipher(other);
                T::decrypt_with_aad(inner, aad).map(Some)
            }
        }
    }
}

struct AesSeqAccess<'c> {
    cipher: &'c Aes256Cipher,
    items: std::vec::IntoIter<AesCipherText>,
    /// [`Aad::for_sequence_element`] of the caller's AAD, derived once at
    /// construction. `next_element` re-supplies it per element by *borrowing*
    /// these bytes, so there is no per-element allocation. Mirrors
    /// `AesSeqCipher::element_aad` on the encrypt side.
    element_aad: Aad<'static>,
}

impl<'c> SeqAccess<'c> for AesSeqAccess<'c> {
    type Error = Unspecified;

    fn next_element<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<T>, Self::Error> {
        let ct = match self.items.next() {
            Some(ct) => ct,
            None => return Ok(None),
        };
        let decipher = self.cipher.decipher(ct);
        // Each element was sealed against the derived element AAD; re-supply
        // it per element by *borrowing* the stored bytes. Mirrors
        // `SeqCipher::encrypt_next`.
        T::decrypt_with_aad(decipher, self.element_aad.as_bytes()).map(Some)
    }
}

struct AesMapAccess<'c, 'a> {
    cipher: &'c Aes256Cipher,
    entries: std::vec::IntoIter<(String, AesCipherText)>,
    aad: Aad<'a>,
    /// The entry handed out by `next_key` and not yet consumed by
    /// `next_value`. Holding the ciphertext here (rather than decrypting it
    /// up front) is what lets the caller choose the plaintext type *after*
    /// seeing the key — see [`MapAccess::next_key`].
    pending: Option<(String, AesCipherText)>,
}

impl<'c> MapAccess<'c> for AesMapAccess<'c, '_> {
    type Error = Unspecified;

    fn next_key(&mut self) -> Result<Option<String>, Self::Error> {
        // A still-pending entry means the caller skipped a value. Skipping is
        // refused rather than tolerated: an entry whose value is never
        // decrypted is an entry whose AAD binding is never verified, so a
        // lenient decoder here would silently accept a tampered field it
        // chose not to look at.
        if self.pending.is_some() {
            return Err(Unspecified);
        }
        match self.entries.next() {
            Some((key, ct)) => {
                self.pending = Some((key.clone(), ct));
                Ok(Some(key))
            }
            None => Ok(None),
        }
    }

    fn next_value<T: Decrypt<'c> + 'c>(&mut self) -> Result<T, Self::Error> {
        let (key, ct) = self.pending.take().ok_or(Unspecified)?;
        let decipher = self.cipher.decipher(ct);
        // Mirror `AesMapCipher::encrypt_value`: the value was sealed against
        // PAE(domain, aad, key), so a swapped or renamed key fails here.
        let entry_aad = self.aad.for_map_entry(&key);
        T::decrypt_with_aad(decipher, entry_aad)
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
    use vitaminc_aead::{Element, Encrypt};

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
        // Non-empty sequences reject a wrong AAD at an element; empty sequences
        // reject it at their authenticated, domain-separated marker.
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
        // arbitrary element counts, including the authenticated empty marker. A
        // wrong-AAD-fails test alone can't catch a regression where the correct AAD
        // fails — only this positive roundtrip does.
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
    fn roundtrip_empty_hashmap_with_aad() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let plaintext = HashMap::<String, String>::new();

        let ciphertext = plaintext
            .clone()
            .encrypt_with_aad(&cipher, "map-context")
            .expect("Encryption failed");
        let decrypted: HashMap<String, String> = cipher
            .decrypt_with_aad(ciphertext, "map-context")
            .expect("Decryption failed");

        assert_eq!(decrypted, plaintext);
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

    #[test]
    fn empty_composites_fail_with_wrong_aad() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");

        let empty_sequence = Vec::<String>::new()
            .encrypt_with_aad(&cipher, "correct-aad")
            .expect("Encryption failed");
        assert!(cipher
            .decrypt_with_aad::<Vec<String>, _>(empty_sequence, "wrong-aad")
            .is_err());

        let empty_map = HashMap::<String, String>::new()
            .encrypt_with_aad(&cipher, "correct-aad")
            .expect("Encryption failed");
        assert!(cipher
            .decrypt_with_aad::<HashMap<String, String>, _>(empty_map, "wrong-aad")
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
        let ciphertext = (&cipher)
            .passthrough(Box::new(42u32))
            .expect("passthrough failed");
        assert!(cipher.decrypt::<Option<u32>>(ciphertext).is_err());
    }

    #[test]
    fn roundtrip_passthrough_u32() {
        let key = Key::from([1u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = (&cipher)
            .passthrough(Box::new(12345u32))
            .expect("passthrough failed");
        let decrypted: u32 = decrypt_passthrough_via(&cipher, ciphertext).expect("decode failed");
        assert_eq!(decrypted, 12345u32);
    }

    #[test]
    fn roundtrip_passthrough_string() {
        let key = Key::from([2u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = (&cipher)
            .passthrough(Box::new(String::from("version-tag")))
            .expect("passthrough failed");
        let decrypted: String =
            decrypt_passthrough_via(&cipher, ciphertext).expect("decode failed");
        assert_eq!(decrypted, "version-tag");
    }

    #[test]
    fn passthrough_type_mismatch_returns_err() {
        let key = Key::from([3u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ciphertext = (&cipher)
            .passthrough(Box::new(42u32))
            .expect("passthrough failed");
        let result: Result<String, _> = decrypt_passthrough_via(&cipher, ciphertext);
        assert!(result.is_err());
    }

    // Convenience: recover a typed passthrough from a known ciphertext via
    // the decipher's `decrypt_passthrough_as` downcast helper.
    fn decrypt_passthrough_via<T>(
        cipher: &Aes256Cipher,
        ciphertext: AesCipherText,
    ) -> Result<T, Unspecified>
    where
        T: Any + Send + 'static,
    {
        cipher.decipher(ciphertext).decrypt_passthrough_as::<T>()
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
        let map = (&cipher).encrypt_map(()).encrypt_key("first").unwrap();
        assert!(map.encrypt_key("second").is_err());
    }

    #[test]
    fn encrypt_value_without_pending_key_fails() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let map = (&cipher).encrypt_map(());
        assert!(map.encrypt_value("orphan-value").is_err());
    }

    #[test]
    fn passthrough_entry_with_pending_key_fails() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let map = (&cipher).encrypt_map(()).encrypt_key("pending").unwrap();
        // Adopting the new key here would silently drop "pending".
        assert!(map.passthrough_entry("other", Box::new(42u32)).is_err());
    }

    #[test]
    fn end_with_pending_key_fails() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let map = (&cipher).encrypt_map(()).encrypt_key("pending").unwrap();
        assert!(map.end().is_err());
    }

    #[test]
    fn passthrough_entry_succeeds_with_no_pending_key() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        // Sanity: the new guard does not break the happy path. An encrypted
        // sibling is included because an all-passthrough map is rejected at
        // end() — see `all_passthrough_map_fails_to_encrypt`.
        let ciphertext = (&cipher)
            .encrypt_map(())
            .passthrough_entry("version", Box::new(1u32))
            .and_then(|m| m.encrypt_key("email"))
            .and_then(|m| m.encrypt_value("ada@example.com"))
            .and_then(|m| m.end())
            .expect("passthrough_entry should succeed without a pending key");
        match ciphertext {
            AesCipherText::Map(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].0, "version");
                assert!(matches!(entries[0].1, AesCipherText::Passthrough(_)));
            }
            _ => panic!("expected Map ciphertext"),
        }
    }

    // --- Map key authentication ---
    //
    // Each map value is sealed against `Aad::for_map_entry(aad, key)`, so key
    // and value are cryptographically inseparable: an attacker who swaps or
    // renames the cleartext keys inside a stored ciphertext cannot produce a
    // map that still decrypts.

    fn encrypted_two_entry_map(cipher: &Aes256Cipher) -> Vec<(String, AesCipherText)> {
        let mut map = HashMap::new();
        map.insert("a", 1u32);
        map.insert("b", 2u32);
        match map.encrypt(cipher).expect("Encryption failed") {
            AesCipherText::Map(entries) => entries,
            _ => panic!("expected Map ciphertext"),
        }
    }

    #[test]
    fn swapped_map_keys_fail_decryption() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let mut entries = encrypted_two_entry_map(&cipher);

        // Exchange the cleartext keys, leaving each value in place.
        let (k0, k1) = (entries[0].0.clone(), entries[1].0.clone());
        entries[0].0 = k1;
        entries[1].0 = k0;

        let result: Result<HashMap<String, u32>, _> = cipher.decrypt(AesCipherText::Map(entries));
        assert!(result.is_err());
    }

    #[test]
    fn renamed_map_key_fails_decryption() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let mut entries = encrypted_two_entry_map(&cipher);

        entries[0].0 = "evil".to_string();

        let result: Result<HashMap<String, u32>, _> = cipher.decrypt(AesCipherText::Map(entries));
        assert!(result.is_err());
    }

    #[test]
    fn renamed_map_key_with_empty_sequence_value_fails_decryption() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let mut map = HashMap::new();
        map.insert("roles".to_string(), Vec::<String>::new());

        let mut entries = match map.encrypt(&cipher).expect("Encryption failed") {
            AesCipherText::Map(entries) => entries,
            _ => panic!("expected Map ciphertext"),
        };
        entries[0].0 = "is_admin".to_string();

        let result: Result<HashMap<String, Vec<String>>, _> =
            cipher.decrypt(AesCipherText::Map(entries));
        assert!(result.is_err());
    }

    #[test]
    fn renamed_map_key_with_empty_map_value_fails_decryption() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let mut map = HashMap::new();
        map.insert("roles".to_string(), HashMap::<String, String>::new());

        let mut entries = match map.encrypt(&cipher).expect("Encryption failed") {
            AesCipherText::Map(entries) => entries,
            _ => panic!("expected Map ciphertext"),
        };
        entries[0].0 = "is_admin".to_string();

        let result: Result<HashMap<String, HashMap<String, String>>, _> =
            cipher.decrypt(AesCipherText::Map(entries));
        assert!(result.is_err());
    }

    #[test]
    fn unauthenticated_empty_composite_shapes_are_rejected() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");

        assert!(cipher
            .decrypt::<Vec<String>>(AesCipherText::Sequence(Vec::new()))
            .is_err());
        assert!(cipher
            .decrypt::<HashMap<String, String>>(AesCipherText::Map(Vec::new()))
            .is_err());
    }

    // --- Composite AAD is fixed at construction ---
    //
    // The sub-cipher captures the AAD once, so a hand-written `Encrypt` impl
    // has no second place to supply it and cannot seal the elements and the
    // container under different AAD. Before this shape, an impl that threaded
    // the real AAD to `encrypt_next` but `()` to `end` round-tripped happily
    // with data and produced an undecryptable ciphertext the first time the
    // collection was empty.

    /// A hand-written `Encrypt` impl driving the sub-cipher directly, of the
    /// kind a derive macro would generate.
    struct Tags(Vec<String>);

    impl Encrypt for Tags {
        fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
        where
            C: Cipher,
            A: IntoAad<'a>,
        {
            let len = self.0.len();
            self.0
                .into_iter()
                .try_fold(cipher.encrypt_seq(Some(len), aad), |c, item| {
                    c.encrypt_next(item)
                })?
                .end()
        }
    }

    #[test]
    fn hand_written_impl_roundtrips_empty_and_nonempty() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");

        let ct = Tags(vec!["a".into(), "b".into()])
            .encrypt_with_aad(&cipher, "user:42")
            .expect("Encryption failed");
        let out: Vec<String> = cipher
            .decrypt_with_aad(ct, "user:42")
            .expect("non-empty should decrypt");
        assert_eq!(out, vec!["a".to_string(), "b".to_string()]);

        // The case that used to break: no elements, so the marker's AAD is
        // the only thing carrying the caller's context.
        let ct = Tags(Vec::new())
            .encrypt_with_aad(&cipher, "user:42")
            .expect("Encryption failed");
        let out: Vec<String> = cipher
            .decrypt_with_aad(ct, "user:42")
            .expect("empty should decrypt under the same AAD");
        assert!(out.is_empty());

        // And it is still AAD-sensitive — the marker binds "user:42".
        let ct = Tags(Vec::new())
            .encrypt_with_aad(&cipher, "user:42")
            .expect("Encryption failed");
        assert!(cipher
            .decrypt_with_aad::<Vec<String>, _>(ct, "user:99")
            .is_err());
    }

    // --- All-passthrough composites ---
    //
    // Passthrough items authenticate nothing, so a composite containing only
    // passthrough items would carry no AEAD tag at all: it would "decrypt"
    // under any AAD, and as a map value its cleartext key could be renamed
    // undetected. Both sides refuse: `end()` won't produce such a container,
    // and the decrypt arms reject one arriving from storage.

    #[test]
    fn all_passthrough_sequence_fails_to_encrypt() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let result = (&cipher)
            .encrypt_seq(Some(1), "context")
            .passthrough_next(Box::new(1u32))
            .and_then(|s| s.end());
        assert!(result.is_err());
    }

    #[test]
    fn all_passthrough_map_fails_to_encrypt() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let result = (&cipher)
            .encrypt_map("context")
            .passthrough_entry("version", Box::new(1u32))
            .and_then(|m| m.end());
        assert!(result.is_err());
    }

    #[test]
    fn all_passthrough_composites_fail_to_decrypt() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");

        let hostile_seq = AesCipherText::Sequence(vec![AesCipherText::Passthrough(Box::new(1u32))]);
        assert!(cipher.decrypt::<Vec<String>>(hostile_seq).is_err());

        let hostile_map = AesCipherText::Map(vec![(
            "version".to_string(),
            AesCipherText::Passthrough(Box::new(1u32)),
        )]);
        assert!(cipher
            .decrypt::<HashMap<String, String>>(hostile_map)
            .is_err());
    }

    // --- None marker integrity ---
    //
    // The None marker is sealed under `Aad::for_none` and verified to contain
    // an empty plaintext, so a `Single` leaf can't be re-tagged as an
    // authenticated absence (silent data deletion), nor an absence as an
    // encrypted empty byte string.

    #[test]
    fn single_retagged_as_none_fails_to_decrypt() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let leaf = match "secret".encrypt_with_aad(&cipher, "context").unwrap() {
            AesCipherText::Single(leaf) => leaf,
            _ => panic!("expected Single ciphertext"),
        };
        let result: Result<Option<String>, _> =
            cipher.decrypt_with_aad(AesCipherText::None(leaf), "context");
        assert!(result.is_err());
    }

    #[test]
    fn empty_single_retagged_as_none_fails_to_decrypt() {
        // Even an EMPTY encrypted string can't masquerade as None: the marker
        // AAD is domain-separated, not just emptiness-checked.
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let leaf = match "".encrypt_with_aad(&cipher, "context").unwrap() {
            AesCipherText::Single(leaf) => leaf,
            _ => panic!("expected Single ciphertext"),
        };
        let result: Result<Option<String>, _> =
            cipher.decrypt_with_aad(AesCipherText::None(leaf), "context");
        assert!(result.is_err());
    }

    #[test]
    fn none_marker_still_roundtrips() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let ct = Option::<String>::None
            .encrypt_with_aad(&cipher, "context")
            .unwrap();
        let decrypted: Option<String> = cipher.decrypt_with_aad(ct, "context").unwrap();
        assert_eq!(decrypted, None);
    }

    #[test]
    fn empty_composite_markers_are_domain_separated() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");

        let sequence_marker = match Vec::<String>::new()
            .encrypt_with_aad(&cipher, "context")
            .expect("Encryption failed")
        {
            AesCipherText::EmptySequence(marker) => marker,
            _ => panic!("expected EmptySequence ciphertext"),
        };
        assert!(cipher
            .decrypt_with_aad::<HashMap<String, String>, _>(
                AesCipherText::EmptyMap(sequence_marker),
                "context",
            )
            .is_err());

        let map_marker = match HashMap::<String, String>::new()
            .encrypt_with_aad(&cipher, "context")
            .expect("Encryption failed")
        {
            AesCipherText::EmptyMap(marker) => marker,
            _ => panic!("expected EmptyMap ciphertext"),
        };
        assert!(
            cipher
                .decrypt_with_aad::<Vec<String>, _>(
                    AesCipherText::EmptySequence(map_marker),
                    "context",
                )
                .is_err()
        );
    }

    #[test]
    fn empty_composite_markers_reject_nonempty_plaintext() {
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let aad = Aad::from_slice(b"context").for_empty_sequence();
        let marker = match "not-empty"
            .encrypt_with_aad(&cipher, aad)
            .expect("Encryption failed")
        {
            AesCipherText::Single(marker) => marker,
            _ => panic!("expected Single ciphertext"),
        };

        assert!(cipher
            .decrypt_with_aad::<Vec<String>, _>(AesCipherText::EmptySequence(marker), "context",)
            .is_err());
    }

    #[test]
    fn reordered_map_entries_still_decrypt() {
        // Reordering entries WITHOUT touching the key↔value pairing is fine —
        // a map is unordered, and each value stays sealed against its own key.
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");
        let mut entries = encrypted_two_entry_map(&cipher);

        entries.swap(0, 1);

        let decrypted: HashMap<String, u32> = cipher
            .decrypt(AesCipherText::Map(entries))
            .expect("reordered entries should decrypt");
        assert_eq!(decrypted.len(), 2);
    }

    #[test]
    fn runtime_string_keys_roundtrip() {
        // Keys built at runtime (the FFI case) — exercises the
        // `HashMap<String, T>` Encrypt impl and Cow-keyed `encrypt_key`.
        let key = Key::from([42u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("Failed to create cipher");

        let mut map: HashMap<String, String> = HashMap::new();
        for id in 0..3 {
            map.insert(format!("user:{id}"), format!("value-{id}"));
        }

        let ciphertext = map
            .clone()
            .encrypt_with_aad(&cipher, "context")
            .expect("Encryption failed");
        let decrypted: HashMap<String, String> = cipher
            .decrypt_with_aad(ciphertext, "context")
            .expect("Decryption failed");
        assert_eq!(decrypted, map);
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
        cipher.passthrough(Box::new(7u32)).expect("passthrough")
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
            .encrypt_seq(Some(3), ())
            .encrypt_next("first")
            .unwrap()
            .passthrough_next(Box::new(99u32))
            .unwrap()
            .encrypt_next("third")
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
            .encrypt_map(())
            .encrypt_key("name")
            .unwrap()
            .encrypt_value("Alice".to_string())
            .unwrap()
            .passthrough_entry("schema_version", Box::new(1u32))
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
        let ct = cipher
            .passthrough(Box::new(Some(42u32)))
            .expect("passthrough failed");
        let decoded: Option<u32> =
            decrypt_passthrough_via(&cipher, ct).expect("decode as Option<u32> should succeed");
        assert_eq!(decoded, Some(42u32));

        let ct2 = cipher
            .passthrough(Box::new(Some(42u32)))
            .expect("passthrough failed");
        assert!(
            decrypt_passthrough_via::<u32>(&cipher, ct2).is_err(),
            "Option<u32> passthrough must not downcast to u32"
        );
    }

    #[test]
    fn duplicate_map_keys_fail_decryption() {
        // Two ciphertexts of one logical record seal a given key's value
        // against the identical `for_map_entry` AAD, so a stale entry
        // appended to a current ciphertext verifies. Without the duplicate
        // rejection, a last-wins visitor would hand back the stale value
        // while every other field stays current — single-field rollback.
        let cipher = Aes256Cipher::new(&Key::from([50u8; 32])).expect("Failed to create cipher");
        let mut v1 = HashMap::new();
        v1.insert("balance", "100");
        v1.insert("owner", "alice");
        let mut v2 = HashMap::new();
        v2.insert("balance", "5");
        v2.insert("owner", "alice");

        let stale_balance = match v1.encrypt(&cipher).expect("encrypt v1") {
            AesCipherText::Map(entries) => entries
                .into_iter()
                .find(|(k, _)| k == "balance")
                .expect("balance entry"),
            _ => panic!("expected Map"),
        };
        let tampered = match v2.encrypt(&cipher).expect("encrypt v2") {
            AesCipherText::Map(mut entries) => {
                entries.push(stale_balance);
                AesCipherText::Map(entries)
            }
            _ => panic!("expected Map"),
        };
        assert!(cipher.decrypt::<HashMap<String, String>>(tampered).is_err());
    }

    #[test]
    fn single_rewrapped_as_sequence_fails_decryption() {
        // The container shape is authenticated through the element AAD
        // derivation: a top-level `Single` is sealed against the bare AAD,
        // a sequence element against `for_sequence_element` of it, so an
        // attacker re-nesting `{Single}` as `Sequence([Single])` cannot get
        // `["x"]` back where the app stored `"x"`.
        let cipher = Aes256Cipher::new(&Key::from([51u8; 32])).expect("Failed to create cipher");
        let single = "x".to_string().encrypt(&cipher).expect("encrypt");
        let forged = AesCipherText::Sequence(vec![single]);
        assert!(cipher.decrypt::<Vec<String>>(forged).is_err());
    }

    #[test]
    fn every_leaf_carries_the_wire_version_prefix() {
        // The version byte is the leaf format's first byte on every
        // leaf-bearing variant — Single, None, both empty markers, sequence
        // elements, and map values. `wire_version` is the keyless peek
        // migration tooling relies on.
        use vitaminc_aead::WIRE_VERSION;
        let cipher = Aes256Cipher::new(&Key::from([54u8; 32])).expect("Failed to create cipher");

        fn leaf_versions(ct: &AesCipherText) -> Vec<Option<u8>> {
            match ct {
                AesCipherText::Single(l)
                | AesCipherText::None(l)
                | AesCipherText::EmptySequence(l)
                | AesCipherText::EmptyMap(l) => vec![l.wire_version()],
                AesCipherText::Sequence(items) => items.iter().flat_map(leaf_versions).collect(),
                AesCipherText::Map(entries) => {
                    entries.iter().flat_map(|(_, v)| leaf_versions(v)).collect()
                }
                AesCipherText::Passthrough(_) => vec![],
            }
        }

        let mut map = HashMap::new();
        map.insert("k", "v");
        let cts = [
            "single".to_string().encrypt(&cipher).expect("encrypt"),
            None::<String>.encrypt(&cipher).expect("encrypt"),
            Vec::<String>::new().encrypt(&cipher).expect("encrypt"),
            HashMap::<&str, &str>::new()
                .encrypt(&cipher)
                .expect("encrypt"),
            vec!["a".to_string(), "b".to_string()]
                .encrypt(&cipher)
                .expect("encrypt"),
            map.encrypt(&cipher).expect("encrypt"),
        ];
        for ct in &cts {
            let versions = leaf_versions(ct);
            assert!(!versions.is_empty());
            assert!(versions.iter().all(|v| *v == Some(WIRE_VERSION)));
        }
    }

    #[test]
    fn relabeled_wire_version_fails_decryption() {
        // Flipping the version byte must fail — first at the parse check
        // (unknown version), and even a version a future parser accepted
        // would fail the tag, because the byte is bound into the leaf AAD
        // via `Aad::for_leaf`.
        let cipher = Aes256Cipher::new(&Key::from([55u8; 32])).expect("Failed to create cipher");
        let leaf = match "x".to_string().encrypt(&cipher).expect("encrypt") {
            AesCipherText::Single(leaf) => leaf,
            _ => panic!("expected Single"),
        };
        let mut bytes = leaf.as_ref().to_vec();
        bytes[0] ^= 0x02;
        let relabeled = AesCipherText::Single(LocalCipherText::from(bytes));
        assert!(cipher.decrypt::<String>(relabeled).is_err());
    }

    #[test]
    fn sequence_element_rehomed_to_top_level_fails_decryption() {
        // The inverse direction: an element extracted from a stored
        // sequence must not decrypt as a top-level value.
        let cipher = Aes256Cipher::new(&Key::from([52u8; 32])).expect("Failed to create cipher");
        let element = match vec!["x".to_string()].encrypt(&cipher).expect("encrypt") {
            AesCipherText::Sequence(mut items) => items.pop().expect("one element"),
            _ => panic!("expected Sequence"),
        };
        assert!(cipher.decrypt::<String>(element).is_err());
    }

    #[test]
    fn element_decrypts_a_stored_sequence_element() {
        // The DX counterpart to
        // `sequence_element_rehomed_to_top_level_fails_decryption`: a row
        // extracted from a batch-encrypted sequence decrypts under the
        // caller's own AAD when the caller states its element-ness in the
        // type — `Element` derives `for_sequence_element` internally.
        let cipher = Aes256Cipher::new(&Key::from([56u8; 32])).expect("Failed to create cipher");
        let ct = vec!["a".to_string(), "b".to_string()]
            .encrypt_with_aad(&cipher, "users")
            .expect("encrypt");
        let element = match ct {
            AesCipherText::Sequence(mut items) => items.pop().expect("two elements"),
            _ => panic!("expected Sequence"),
        };
        let row: Element<String> = cipher.decrypt_with_aad(element, "users").expect("decrypt");
        assert_eq!(row.into_inner(), "b");
    }

    #[test]
    fn element_encrypted_alone_decrypts_within_a_sequence() {
        // The reverse interchange: a row inserted alone via `Element` seals
        // exactly as batch encryption would have, so rows collected back into
        // a `Sequence` decrypt as a whole `Vec`.
        let cipher = Aes256Cipher::new(&Key::from([57u8; 32])).expect("Failed to create cipher");
        let ct1 = Element("a".to_string())
            .encrypt_with_aad(&cipher, "users")
            .expect("encrypt");
        let ct2 = Element("b".to_string())
            .encrypt_with_aad(&cipher, "users")
            .expect("encrypt");
        let collected = AesCipherText::Sequence(vec![ct1, ct2]);
        let rows: Vec<String> = cipher
            .decrypt_with_aad(collected, "users")
            .expect("decrypt");
        assert_eq!(rows, ["a", "b"]);
    }

    #[test]
    fn element_is_not_interchangeable_with_bare_values() {
        // `Element` opts a value into collection semantics; it must not weaken
        // the shape authentication for values that never opted in. Both
        // crossings fail: bare ciphertext read as `Element`, and `Element`
        // ciphertext read as a bare value.
        let cipher = Aes256Cipher::new(&Key::from([58u8; 32])).expect("Failed to create cipher");
        let bare = "x"
            .to_string()
            .encrypt_with_aad(&cipher, "users")
            .expect("encrypt");
        assert!(cipher
            .decrypt_with_aad::<Element<String>, _>(bare, "users")
            .is_err());
        let element = Element("x".to_string())
            .encrypt_with_aad(&cipher, "users")
            .expect("encrypt");
        assert!(cipher
            .decrypt_with_aad::<String, _>(element, "users")
            .is_err());
    }

    #[test]
    fn vec_of_elements_double_derives_and_does_not_interchange_with_vec() {
        // The documented footgun on `Element`: wrap the row, not the
        // collection. `Vec<Element<T>>` seals under a double element
        // derivation, so it round-trips symmetrically but fails closed
        // against `Vec<T>` — it must never decrypt as one.
        let cipher = Aes256Cipher::new(&Key::from([59u8; 32])).expect("Failed to create cipher");
        let ct = vec![Element("a".to_string())]
            .encrypt_with_aad(&cipher, "users")
            .expect("encrypt");
        assert!(cipher
            .decrypt_with_aad::<Vec<String>, _>(ct, "users")
            .is_err());

        let ct = vec![Element("a".to_string())]
            .encrypt_with_aad(&cipher, "users")
            .expect("encrypt");
        let rows: Vec<Element<String>> = cipher.decrypt_with_aad(ct, "users").expect("decrypt");
        assert_eq!(rows, [Element("a".to_string())]);
    }

    #[test]
    fn empty_sequence_marker_nested_one_level_fails_decryption() {
        // A stored top-level `EmptySequence` marker is sealed against
        // `for_empty_sequence(aad)`; nested one level it must re-verify
        // against `for_empty_sequence(for_sequence_element(aad))`, so the
        // rewrap `[[]] where [] was stored` fails.
        let cipher = Aes256Cipher::new(&Key::from([53u8; 32])).expect("Failed to create cipher");
        let marker = Vec::<String>::new().encrypt(&cipher).expect("encrypt");
        assert!(matches!(marker, AesCipherText::EmptySequence(_)));
        let forged = AesCipherText::Sequence(vec![marker]);
        assert!(cipher.decrypt::<Vec<Vec<String>>>(forged).is_err());
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
