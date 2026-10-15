//! `StaticCipher` impl for `&Aes256Cipher` — the HList-shaped output path.
//!
//! See `vitaminc_aead::hlist` for the design rationale.

use crate::Aes256Cipher;
use vitaminc_aead::hlist::{Absent, Encrypted, Entry, StaticCipher};
use vitaminc_aead::{tags, IntoAad, Unspecified};
use vitaminc_protected::{Controlled, Protected};

/// What an [`Absent`] seals: the null leaf, as `None` is everywhere else
/// (ADR 0001). No separate absence derivation is needed, because the leaf
/// itself says what it is.
const NULL_LEAF: [u8; 1] = [tags::NULL];

/// What an [`Encrypted`] seals: the caller's bytes as a tagged bytes leaf,
/// `[tags::BYTES] ++ data`, the same leaf the sink-based path seals for a
/// `Vec<u8>`. The tag is what keeps an `Encrypted` and an `Absent` apart
/// under one AAD: a raw payload of one zero byte would otherwise be the
/// null leaf, so a present field could pass as an absence and an absence
/// could open as a present value.
fn tagged_bytes(data: Protected<Vec<u8>>) -> Protected<Vec<u8>> {
    data.map(|bytes| {
        let mut leaf = Vec::with_capacity(bytes.len() + 1);
        leaf.push(tags::BYTES);
        leaf.extend_from_slice(&bytes);
        leaf
    })
}

/// The caller's bytes back out of a tagged bytes leaf. Any other leaf,
/// the null leaf of an [`Absent`] first among them, is refused.
fn untagged_bytes(leaf: Protected<Vec<u8>>) -> Result<Protected<Vec<u8>>, Unspecified> {
    if leaf.risky_ref().first() != Some(&tags::BYTES) {
        return Err(Unspecified);
    }
    Ok(leaf.map(|mut bytes| {
        bytes.remove(0);
        bytes
    }))
}

impl StaticCipher for &Aes256Cipher {
    type Error = Unspecified;

    fn encrypt_bytes<'a, A>(
        self,
        data: Protected<Vec<u8>>,
        aad: A,
    ) -> Result<Encrypted, Self::Error>
    where
        A: IntoAad<'a>,
    {
        let local = seal_into_local(self, tagged_bytes(data), aad)?;
        Ok(Encrypted::from_local(local))
    }

    fn encrypt_none<'a, A>(self, aad: A) -> Result<Absent, Self::Error>
    where
        A: IntoAad<'a>,
    {
        // The marker is a sealed null leaf under the slot's own AAD: the same
        // bytes `encrypt` seals for a `None` there, so the static and the
        // sink-based paths agree on what absence is. An `Encrypted` is a
        // tagged bytes leaf, so neither can stand in for the other:
        // `verify_absent` requires the null leaf and `open_encrypted` the
        // bytes tag.
        let local = seal_into_local(self, Protected::new(NULL_LEAF.to_vec()), aad)?;
        Ok(Absent::from_local(local))
    }
}

impl Aes256Cipher {
    /// Open an [`Encrypted`] leaf under the supplied AAD. Counterpart to
    /// [`StaticCipher::encrypt_bytes`]. Named so it cannot shadow
    /// [`Cipher::open`](vitaminc_aead::seal::Cipher::open), which takes a
    /// [`LocalCipherText`](vitaminc_aead::LocalCipherText) and a `&Context`
    /// and must resolve the same with or without the `hlist` feature.
    ///
    /// The plaintext is returned inside `Protected` to thread the chain of
    /// custody across the call boundary. The returned `Protected<Vec<u8>>`
    /// is zeroized on drop (`Protected` is `ZeroizeOnDrop`). A sealed leaf
    /// that is not a tagged bytes leaf, an [`Absent`] marker re-wrapped as
    /// an `Encrypted` first among them, is refused.
    pub fn open_encrypted<'a, A>(
        &self,
        ct: Encrypted,
        aad: A,
    ) -> Result<Protected<Vec<u8>>, Unspecified>
    where
        A: IntoAad<'a>,
    {
        untagged_bytes(open_local(self, ct.into_local(), aad)?)
    }

    /// Verify an [`Absent`] marker under the supplied AAD. Returns
    /// `Ok(())` if the tag binds `aad` **and** the sealed plaintext is the
    /// null leaf, `Err(Unspecified)` otherwise.
    pub fn verify_absent<'a, A>(&self, ct: Absent, aad: A) -> Result<(), Unspecified>
    where
        A: IntoAad<'a>,
    {
        // A conforming marker seals the null leaf; requiring that here (not
        // just a valid tag) means a key-holding writer cannot pass any other
        // sealed value off as an absence — defense in depth for the marker's
        // meaning, not just its authenticity. The `Protected` drops (and
        // zeroizes) at the end of the expression.
        let plaintext = open_local(self, ct.into_local(), aad)?;
        if plaintext.risky_ref() == &NULL_LEAF {
            Ok(())
        } else {
            Err(Unspecified)
        }
    }

    /// Open a map [`Entry`]'s encrypted value, deriving the same
    /// [`Context::for_map_entry`](vitaminc_aead::Context::for_map_entry) binding
    /// [`StaticMapBuilder::encrypt_entry`] sealed it under — so an entry
    /// whose cleartext key was renamed or swapped fails to open.
    ///
    /// [`StaticMapBuilder::encrypt_entry`]: vitaminc_aead::hlist::StaticMapBuilder::encrypt_entry
    pub fn open_encrypted_entry<'a, A>(
        &self,
        entry: Entry<Encrypted>,
        aad: A,
    ) -> Result<Protected<Vec<u8>>, Unspecified>
    where
        A: IntoAad<'a>,
    {
        let entry_aad = aad.into_aad().for_map_entry(entry.key);
        self.open_encrypted(entry.value, entry_aad)
    }

    /// Verify a map [`Entry`]'s absent marker, key-bound like
    /// [`open_encrypted_entry`](Aes256Cipher::open_encrypted_entry).
    pub fn verify_absent_entry<'a, A>(
        &self,
        entry: Entry<Absent>,
        aad: A,
    ) -> Result<(), Unspecified>
    where
        A: IntoAad<'a>,
    {
        let entry_aad = aad.into_aad().for_map_entry(entry.key);
        self.verify_absent(entry.value, entry_aad)
    }
}

// Leaf seal/open shared with the dynamic path — see `cipher::seal_leaf` /
// `cipher::open_leaf` for why a single copy matters.
use crate::cipher::{open_leaf as open_local, seal_leaf as seal_into_local};

// Split cfgs (not `all(test, …)`) so cargo-mutants recognises the test module
// and skips it — see the comment on `cipher::test`.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use crate::backend::NONCE_LEN;
    use crate::key::tests::DifferingKeyPair;
    use crate::Key;
    use quickcheck_macros::quickcheck;
    use vitaminc_aead::hlist::{Entry, HCons, HNil, Map, Passthrough, StaticCipher};
    use vitaminc_aead::seal::Cipher;
    use vitaminc_aead::{Context, LocalCipherText};

    // A worked example. In production this type alias would be generated
    // by a derive macro from the user's struct definition.
    type UserCiphertext = Map<
        HCons<
            Entry<Map<HCons<Entry<Encrypted>, HNil>>>, // preferences (nested)
            HCons<
                Entry<Absent>, // nickname: None
                HCons<
                    Entry<Passthrough<u8>>, // version (typed!)
                    HCons<
                        Entry<Encrypted>, // password_hash
                        HNil,
                    >,
                >,
            >,
        >,
    >;

    const AAD: &[u8] = b"user:42";

    #[test]
    fn static_user_roundtrip() {
        let key = Key::from([7u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("cipher init");

        let user_ct: UserCiphertext = (&cipher)
            .encrypt_map()
            .encrypt_entry(
                "password_hash",
                Protected::new(b"argon2id$hash".to_vec()),
                AAD,
            )
            .expect("encrypt pw")
            .passthrough_entry("version", 3u8)
            .none_entry("nickname", AAD)
            .expect("encrypt none")
            .nested_entry("preferences", AAD, |b, aad| {
                Ok(
                    b.encrypt_entry("theme", Protected::new(b"midnight".to_vec()), aad)?
                        .end(),
                )
            })
            .expect("encrypt prefs")
            .end();

        // Decryption is destructuring. No downcast, no shape check, no Box.
        let Map(HCons(prefs_e, HCons(nickname_e, HCons(version_e, HCons(pw_e, HNil))))) = user_ct;

        assert_eq!(pw_e.key, "password_hash");
        assert_eq!(version_e.key, "version");
        assert_eq!(nickname_e.key, "nickname");
        assert_eq!(prefs_e.key, "preferences");

        let version: u8 = version_e.value.0; // typed access, no fallibility
        let pw = String::from_utf8(
            cipher
                .open_encrypted_entry(pw_e, AAD)
                .expect("open pw")
                .risky_unwrap(),
        )
        .unwrap();
        cipher
            .verify_absent_entry(nickname_e, AAD)
            .expect("verify none");

        // The inner AAD is re-derived from the outer AAD and the entry's own
        // cleartext key — the binding `nested_entry` established at build time.
        let inner_aad = prefs_e.nested_aad(AAD);
        let Map(HCons(theme_e, HNil)) = prefs_e.value;
        let theme = String::from_utf8(
            cipher
                .open_encrypted_entry(theme_e, inner_aad)
                .expect("open theme")
                .risky_unwrap(),
        )
        .unwrap();

        assert_eq!(pw, "argon2id$hash");
        assert_eq!(version, 3u8);
        assert_eq!(theme, "midnight");
    }

    // Entry values are sealed against `Context::for_map_entry(aad, key)`, so a
    // stored entry whose cleartext key is renamed (the untrusted-input path a
    // future deserializer would expose) must fail to open — the same key-swap
    // resistance the dynamic MapCipher enforces.

    #[test]
    fn static_entry_with_renamed_key_fails_to_open() {
        let key = Key::from([9u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("cipher init");
        let map = (&cipher)
            .encrypt_map()
            .encrypt_entry("email", Protected::new(b"ada@example.com".to_vec()), AAD)
            .expect("encrypt")
            .end();
        let Map(HCons(entry, HNil)) = map;
        let renamed = Entry {
            key: "backup_email",
            value: entry.value,
        };
        assert!(cipher.open_encrypted_entry(renamed, AAD).is_err());
    }

    #[test]
    fn static_nested_entry_with_renamed_key_fails_to_open_inner() {
        // A nested map has no leaf of its own; its outer key is bound through
        // the derived inner AAD. Renaming the outer key changes `nested_aad`,
        // so every inner open fails — the same key-swap resistance leaf
        // entries get from `for_map_entry`.
        let key = Key::from([10u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("cipher init");
        let map = (&cipher)
            .encrypt_map()
            .nested_entry("preferences", AAD, |b, aad| {
                Ok(
                    b.encrypt_entry("theme", Protected::new(b"midnight".to_vec()), aad)?
                        .end(),
                )
            })
            .expect("encrypt prefs")
            .end();
        let Map(HCons(entry, HNil)) = map;
        let renamed = Entry {
            key: "billing",
            value: entry.value,
        };
        let inner_aad = renamed.nested_aad(AAD);
        let Map(HCons(theme_e, HNil)) = renamed.value;
        assert!(cipher.open_encrypted_entry(theme_e, inner_aad).is_err());
    }

    #[test]
    fn static_nested_map_spliced_from_another_record_fails_to_open_inner() {
        // Cross-record splice: a nested map built for user:99 under the same
        // key name must not open inside user:42's record — the inner AAD
        // derivation includes the *record's* AAD, not just the entry key.
        let key = Key::from([11u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("cipher init");
        let build = |aad: &'static [u8]| {
            let map = (&cipher)
                .encrypt_map()
                .nested_entry("preferences", aad, |b, inner| {
                    Ok(
                        b.encrypt_entry("theme", Protected::new(b"midnight".to_vec()), inner)?
                            .end(),
                    )
                })
                .expect("encrypt prefs")
                .end();
            let Map(HCons(entry, HNil)) = map;
            entry
        };
        let victim = build(b"user:42");
        let foreign = build(b"user:99");

        // Splice user:99's nested map under user:42's entry key.
        let spliced = Entry {
            key: victim.key,
            value: foreign.value,
        };
        let inner_aad = spliced.nested_aad(b"user:42".as_slice());
        let Map(HCons(theme_e, HNil)) = spliced.value;
        assert!(cipher.open_encrypted_entry(theme_e, inner_aad).is_err());
    }

    #[test]
    fn static_absent_entry_with_renamed_key_fails_to_verify() {
        let key = Key::from([9u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("cipher init");
        let map = (&cipher)
            .encrypt_map()
            .none_entry("nickname", AAD)
            .expect("encrypt none")
            .end();
        let Map(HCons(entry, HNil)) = map;
        let renamed = Entry {
            key: "email",
            value: entry.value,
        };
        assert!(cipher.verify_absent_entry(renamed, AAD).is_err());
    }

    #[test]
    fn static_open_fails_with_wrong_aad() {
        let key = Key::from([3u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("cipher init");
        let leaf = (&cipher)
            .encrypt_bytes(Protected::new(b"hello".to_vec()), b"right".as_slice())
            .expect("encrypt");
        assert!(cipher.open_encrypted(leaf, b"wrong".as_slice()).is_err());
    }

    #[test]
    fn static_verify_absent_fails_with_wrong_aad() {
        let key = Key::from([4u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("cipher init");
        let absent = (&cipher)
            .encrypt_none(b"right".as_slice())
            .expect("encrypt none");
        assert!(cipher.verify_absent(absent, b"wrong".as_slice()).is_err());
    }

    #[test]
    fn static_passthrough_keeps_type() {
        // No cipher needed — passthrough is just wrapping.
        let key = Key::from([5u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("cipher init");
        let p: Passthrough<(u16, &'static str)> = (&cipher).passthrough((42u16, "tag"));
        let (n, s) = p.0;
        assert_eq!(n, 42u16);
        assert_eq!(s, "tag");
    }

    fn _proof_send() {
        fn assert_send<T: Send>() {}
        assert_send::<UserCiphertext>();
    }

    // Arbitrary bytes that weren't produced by a real seal must return an
    // error, never panic — `open` and `verify_absent` are the entry points a
    // future deserializer would feed untrusted input to. Quickcheck shrinks to
    // the empty buffer if the under-length nonce guard ever regresses.

    #[quickcheck]
    fn open_rejects_arbitrary_bytes(key: Key, bytes: Vec<u8>) -> bool {
        let cipher = Aes256Cipher::new(&key).unwrap();
        let leaf = Encrypted::from_local(LocalCipherText::from(bytes));
        cipher.open_encrypted(leaf, b"aad".as_slice()).is_err()
    }

    #[quickcheck]
    fn verify_absent_rejects_arbitrary_bytes(key: Key, bytes: Vec<u8>) -> bool {
        let cipher = Aes256Cipher::new(&key).unwrap();
        let leaf = Absent::from_local(LocalCipherText::from(bytes));
        cipher.verify_absent(leaf, b"aad".as_slice()).is_err()
    }

    #[test]
    fn verify_absent_requires_the_null_leaf() {
        // Even a key-holding writer must not be able to pass another sealed
        // value off as an absence marker: verify_absent requires the sealed
        // plaintext to be the null leaf, not merely the tag to bind `aad`.
        // Every `Encrypted` is a tagged bytes leaf, so none qualifies, not
        // even the one-byte zero payload whose raw bytes are the null leaf.
        let cipher = Aes256Cipher::new(&Key::from([6u8; 32])).unwrap();
        let aad = b"aad".as_slice();
        for payload in [
            &[tags::NULL][..],
            &[][..],
            &[tags::UNDEFINED][..],
            b"payload",
        ] {
            let sealed = (&cipher)
                .encrypt_bytes(Protected::new(payload.to_vec()), aad)
                .unwrap();
            let as_absent = Absent::from_local(sealed.into_local());
            assert_eq!(
                cipher.verify_absent(as_absent, aad),
                Err(Unspecified),
                "payload: {payload:?}"
            );
        }
        // The null leaf itself, sealed through the leaf path, is one.
        let sealed = seal_into_local(&cipher, Protected::new(NULL_LEAF.to_vec()), aad).unwrap();
        assert_eq!(
            cipher.verify_absent(Absent::from_local(sealed), aad),
            Ok(())
        );
    }

    #[test]
    fn an_absence_marker_does_not_open_as_a_present_value() {
        // The other direction: an `Absent` re-wrapped as an `Encrypted`
        // authenticates, but it is the null leaf, not a bytes leaf, so a
        // caller decoding a present field never reads a zero byte from it.
        let cipher = Aes256Cipher::new(&Key::from([6u8; 32])).unwrap();
        let aad = b"aad".as_slice();
        let absent = (&cipher).encrypt_none(aad).unwrap();
        let as_encrypted = Encrypted::from_local(absent.into_local());
        assert!(matches!(
            cipher.open_encrypted(as_encrypted, aad),
            Err(Unspecified)
        ));
        // Through the map builder too.
        let map = (&cipher)
            .encrypt_map()
            .none_entry("flag", aad)
            .unwrap()
            .end();
        let Map(HCons(entry, HNil)) = map;
        let as_present = Entry {
            key: entry.key,
            value: Encrypted::from_local(entry.value.into_local()),
        };
        assert!(matches!(
            cipher.open_encrypted_entry(as_present, aad),
            Err(Unspecified)
        ));
        // And a present one-byte zero does not verify as absent.
        let map = (&cipher)
            .encrypt_map()
            .encrypt_entry("flag", Protected::new(vec![0]), aad)
            .unwrap()
            .end();
        let Map(HCons(entry, HNil)) = map;
        let as_absent = Entry {
            key: entry.key,
            value: Absent::from_local(entry.value.into_local()),
        };
        assert_eq!(cipher.verify_absent_entry(as_absent, aad), Err(Unspecified));
    }

    // An `Absent` is a sealed null leaf, which is what `encrypt` seals for
    // a `None` too, so the two paths agree on absence. An `Encrypted` is a
    // tagged bytes leaf, which is what `encrypt` seals for a `Vec<u8>`.

    #[test]
    fn absent_is_the_null_leaf_sealed_under_the_slots_aad() {
        let cipher = Aes256Cipher::new(&Key::from([2u8; 32])).unwrap();
        let aad = b"shared-aad".as_slice();
        let absent = (&cipher).encrypt_none(aad).unwrap();
        let plaintext = open_local(&cipher, absent.into_local(), aad).unwrap();
        assert_eq!(plaintext.risky_ref(), &NULL_LEAF);
        // And what the sink-based path seals for `None` verifies as absent.
        let node = vitaminc_aead::encrypt(None::<u32>, &cipher, aad).unwrap();
        let vitaminc_aead::CipherText::Single(leaf) = node else {
            panic!("a None is one leaf");
        };
        cipher
            .verify_absent(Absent::from_local(leaf), aad)
            .expect("the sink path's None is an absence");
    }

    #[test]
    fn encrypted_is_the_bytes_leaf_the_sink_path_seals() {
        let cipher = Aes256Cipher::new(&Key::from([2u8; 32])).unwrap();
        let aad = b"shared-aad".as_slice();
        let sealed = (&cipher)
            .encrypt_bytes(Protected::new(vec![0, 7]), aad)
            .unwrap();
        let plaintext = open_local(&cipher, sealed.into_local(), aad).unwrap();
        assert_eq!(plaintext.risky_ref(), &[tags::BYTES, 0, 7]);
        // So a `Vec<u8>` sealed by the sink path opens as an `Encrypted`,
        // and an `Encrypted` decrypts as a `Vec<u8>`.
        let node = vitaminc_aead::encrypt(vec![0u8, 7], &cipher, aad).unwrap();
        let vitaminc_aead::CipherText::Single(leaf) = node else {
            panic!("bytes are one leaf");
        };
        let opened = cipher
            .open_encrypted(Encrypted::from_local(leaf), aad)
            .unwrap();
        assert_eq!(opened.risky_ref(), &[0, 7]);
        let sealed = (&cipher)
            .encrypt_bytes(Protected::new(vec![0, 7]), aad)
            .unwrap();
        let node = vitaminc_aead::CipherText::Single(sealed.into_local());
        let bytes: Vec<u8> = vitaminc_aead::decrypt(&cipher, node, aad).unwrap();
        assert_eq!(bytes, [0, 7]);
    }

    #[test]
    fn encrypted_empty_does_not_validate_as_absent() {
        let cipher = Aes256Cipher::new(&Key::from([2u8; 32])).unwrap();
        let aad = b"shared-aad".as_slice();
        let encrypted_empty = (&cipher)
            .encrypt_bytes(Protected::new(Vec::new()), aad)
            .unwrap();
        let as_absent = Absent::from_local(encrypted_empty.into_local());
        assert!(cipher.verify_absent(as_absent, aad).is_err());
    }

    #[test]
    fn the_cipher_trait_open_resolves_by_method_syntax_with_hlist_on() {
        // The hlist methods are named so they never shadow `Cipher::open`:
        // with the feature on, `cipher.open(leaf, &ctx)` is still the trait
        // method, so turning the feature on is additive for every caller.
        let cipher = Aes256Cipher::new(&Key::from([2u8; 32])).unwrap();
        let ctx = Context::from_encoded(b"ctx".as_slice());
        let leaf = cipher.seal(Protected::new(vec![tags::NULL]), &ctx).unwrap();
        let opened = cipher.open(leaf, &ctx).unwrap();
        assert_eq!(opened.risky_ref(), &[tags::NULL]);
    }

    // A ciphertext sealed under one key must not open under a different key.

    #[quickcheck]
    fn open_with_wrong_key_fails(keys: DifferingKeyPair, plaintext: Vec<u8>) -> bool {
        let DifferingKeyPair(key_a, key_b) = keys;
        let cipher_a = Aes256Cipher::new(&key_a).unwrap();
        let cipher_b = Aes256Cipher::new(&key_b).unwrap();
        let aad = b"aad".as_slice();
        let ct = (&cipher_a)
            .encrypt_bytes(Protected::new(plaintext), aad)
            .unwrap();
        cipher_b.open_encrypted(ct, aad).is_err()
    }

    #[quickcheck]
    fn verify_absent_with_wrong_key_fails(keys: DifferingKeyPair) -> bool {
        let DifferingKeyPair(key_a, key_b) = keys;
        let cipher_a = Aes256Cipher::new(&key_a).unwrap();
        let cipher_b = Aes256Cipher::new(&key_b).unwrap();
        let aad = b"aad".as_slice();
        let absent = (&cipher_a).encrypt_none(aad).unwrap();
        cipher_b.verify_absent(absent, aad).is_err()
    }

    // Flipping any single byte — across the nonce, ciphertext body, or tag —
    // must fail verification. Exhaustive sweep over the whole ciphertext.

    #[test]
    fn open_fails_on_tampering_any_byte() {
        let cipher = Aes256Cipher::new(&Key::from([3u8; 32])).unwrap();
        let aad = b"aad".as_slice();
        let ct = (&cipher)
            .encrypt_bytes(Protected::new(b"hello".to_vec()), aad)
            .unwrap();
        let bytes = ct.into_local().as_ref().to_vec();
        for idx in 0..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[idx] ^= 1;
            let leaf = Encrypted::from_local(LocalCipherText::from(tampered));
            assert!(
                cipher.open_encrypted(leaf, aad).is_err(),
                "tamper at byte {idx}"
            );
        }
    }

    // AES-GCM is non-deterministic: a fresh nonce per call means two seals of
    // the same plaintext under the same (key, AAD) must differ. Running these
    // as properties samples many nonce pairs, catching an RNG regression a
    // single fixed case could miss.

    #[quickcheck]
    fn encrypt_bytes_is_nondeterministic(key: Key, plaintext: Vec<u8>) -> bool {
        let cipher = Aes256Cipher::new(&key).unwrap();
        let aad = b"aad".as_slice();
        let b1 = (&cipher)
            .encrypt_bytes(Protected::new(plaintext.clone()), aad)
            .unwrap()
            .into_local()
            .as_ref()
            .to_vec();
        let b2 = (&cipher)
            .encrypt_bytes(Protected::new(plaintext), aad)
            .unwrap()
            .into_local()
            .as_ref()
            .to_vec();
        // Distinct ciphertexts, and specifically distinct nonces (the leaf
        // layout is version(1) ‖ nonce ‖ ciphertext ‖ tag).
        b1 != b2 && b1[1..1 + NONCE_LEN] != b2[1..1 + NONCE_LEN]
    }

    #[quickcheck]
    fn encrypt_none_is_nondeterministic(key: Key) -> bool {
        let cipher = Aes256Cipher::new(&key).unwrap();
        let aad = b"aad".as_slice();
        let a1 = (&cipher).encrypt_none(aad).unwrap().into_local();
        let a2 = (&cipher).encrypt_none(aad).unwrap().into_local();
        a1.as_ref() != a2.as_ref()
    }
}
