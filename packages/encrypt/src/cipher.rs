use crate::backend::{CipherKey, NONCE_LEN};
use crate::Key;
use vitaminc_aead::seal::Cipher;
use vitaminc_aead::{
    CipherTextBuilder, Context, IntoAad, LocalCipherText, NonceGenerator, RandomNonceGenerator,
    Unspecified, WIRE_VERSION,
};
use vitaminc_protected::Protected;

/// Implements AES-256-GCM. Backend is selected at compile time:
/// `aws-lc-rs` on native targets, `aes-gcm` (RustCrypto) on `wasm32`.
///
/// This is the sink-based [`Cipher`] of ADR 0001: it seals and opens one
/// tagged leaf under the AAD the walk derived for the leaf's place in the
/// tree, and nothing else. The container logic (element and entry AAD,
/// empty markers, the nothing-sealed refusal) lives once in
/// `vitaminc_aead::EncryptSink` and the opening walk, so a value encrypted
/// from static Rust seals the same tagged leaves a host value does and
/// every ciphertext is self-describing. Drive it with
/// [`vitaminc_aead::encrypt`] and [`vitaminc_aead::decrypt`].
///
/// The nonce generator is a `RefCell`, so the cipher is `!Sync`: it is the
/// synchronous `Cipher`, used from one thread at a time, not an
/// `AsyncCipher` shared across tasks.
///
/// ```compile_fail,E0277
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<vitaminc_encrypt::Aes256Cipher>();
/// ```
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

    /// This cipher, opening wire version 1 leaves as well as current ones.
    ///
    /// Use it only to read ciphertext from the pre-ADR 0001 `Value` path:
    /// `vitaminc-aead-value` 0.5 and the Go binding built on it. Those
    /// leaves are tagged like today's, so they open to the same values.
    /// `vitaminc-encrypt` 0.5's `Encrypt` path also wrote version 1 leaves,
    /// but with raw, untagged bytes; read through this view, such a leaf
    /// can come back as a different value with no error. That is why
    /// [`Aes256Cipher`] itself, and so the typed [`decrypt`], refuses every
    /// version 1 leaf.
    ///
    /// Sealing through the view writes current leaves, exactly as the
    /// cipher does.
    ///
    /// [`decrypt`]: vitaminc_aead::decrypt
    pub fn opening_version_1(&self) -> OpensVersion1<'_> {
        OpensVersion1(self)
    }
}

/// The wire version the pre-ADR 0001 `Value` path sealed its tagged leaves
/// under. See [`Aes256Cipher::opening_version_1`].
const VALUE_PATH_WIRE_VERSION: u8 = 1;

/// An [`Aes256Cipher`] that also opens wire version 1 leaves, made by
/// [`Aes256Cipher::opening_version_1`].
pub struct OpensVersion1<'a>(&'a Aes256Cipher);

/// Seal one leaf: `version(1) ‖ nonce ‖ ciphertext ‖ tag`, with the wire
/// version bound into the AAD via `Context::for_leaf`.
///
/// This is THE leaf seal path — the [`Cipher`] impl and the static hlist
/// cipher (`cipher_static.rs`) both go through it, so a wire-format change
/// lands in every path at once instead of drifting between copies.
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
    // the stored leaf — see `Context::for_leaf`.
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

/// Open one leaf sealed by [`seal_leaf`]: checks the wire version before
/// parsing, then verifies with the same `Context::for_leaf` derivation.
/// Shared by the [`Cipher`] impl and the static hlist path for the same
/// anti-drift reason as [`seal_leaf`]. Only the current wire version opens.
pub(crate) fn open_leaf<'a, A>(
    cipher: &Aes256Cipher,
    ct: LocalCipherText,
    aad: A,
) -> Result<Protected<Vec<u8>>, Unspecified>
where
    A: IntoAad<'a>,
{
    open_leaf_in(cipher, ct, aad, &[WIRE_VERSION])
}

/// [`open_leaf`], accepting any wire version in `accepted`.
fn open_leaf_in<'a, A>(
    cipher: &Aes256Cipher,
    ct: LocalCipherText,
    aad: A,
    accepted: &[u8],
) -> Result<Protected<Vec<u8>>, Unspecified>
where
    A: IntoAad<'a>,
{
    // `read_version_in` rejects any other wire version before parsing; the
    // version read is *also* bound under the tag (`for_leaf`, mirroring the
    // seal side), so a relabeled byte that parses still fails.
    let (version, reader) = ct.into_reader().read_version_in(accepted)?;
    let (nonce, reader) = reader.read_nonce::<NONCE_LEN>()?;
    let nonce_bytes = nonce.into_inner();
    let aad = aad.into_aad().for_leaf(version);

    reader
        .accepts_plaintext_ok(|data| cipher.key.open(&nonce_bytes, aad.as_bytes(), data))
        .read()
}

impl Cipher for Aes256Cipher {
    type Leaf = LocalCipherText;
    type Error = Unspecified;

    fn seal(
        &self,
        plaintext: Protected<Vec<u8>>,
        aad: &Context<'_>,
    ) -> Result<LocalCipherText, Unspecified> {
        seal_leaf(self, plaintext, aad.clone())
    }

    fn open(
        &self,
        leaf: LocalCipherText,
        aad: &Context<'_>,
    ) -> Result<Protected<Vec<u8>>, Unspecified> {
        open_leaf(self, leaf, aad.clone())
    }
}

impl Cipher for OpensVersion1<'_> {
    type Leaf = LocalCipherText;
    type Error = Unspecified;

    fn seal(
        &self,
        plaintext: Protected<Vec<u8>>,
        aad: &Context<'_>,
    ) -> Result<LocalCipherText, Unspecified> {
        seal_leaf(self.0, plaintext, aad.clone())
    }

    fn open(
        &self,
        leaf: LocalCipherText,
        aad: &Context<'_>,
    ) -> Result<Protected<Vec<u8>>, Unspecified> {
        open_leaf_in(
            self.0,
            leaf,
            aad.clone(),
            &[VALUE_PATH_WIRE_VERSION, WIRE_VERSION],
        )
    }
}

// Split cfgs (not `all(test, …)`) so cargo-mutants recognises the test
// module and skips it. The property tests draw random keys, which the
// wasm32 test harness cannot seed.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use crate::key::tests::DifferingKeyPair;
    use quickcheck_macros::quickcheck;
    use std::collections::HashMap;
    use vitaminc_aead::{decrypt, encrypt, CipherText, DecryptError, Node};
    use vitaminc_protected::Controlled;

    fn cipher(key: &Key) -> Aes256Cipher {
        Aes256Cipher::new(key).expect("cipher")
    }

    fn leaf_of(node: Node<LocalCipherText>) -> LocalCipherText {
        match node {
            CipherText::Single(leaf) => leaf,
            other => panic!("expected a single leaf, got {other:?}"),
        }
    }

    mod leaf_paths {
        //! The sink-based `Cipher` seals the same leaf bytes as `seal_leaf`,
        //! so a leaf from either path opens through the other.
        use super::*;

        #[test]
        fn a_leaf_sealed_by_the_cipher_opens_through_open_leaf() {
            let cipher = cipher(&Key::from([3u8; 32]));
            let aad = Context::from_encoded(b"ctx".as_slice());
            let leaf = cipher
                .seal(Protected::new(b"\x04hi".to_vec()), &aad)
                .unwrap();
            let opened = open_leaf(&cipher, leaf, aad).unwrap();
            assert_eq!(opened.risky_unwrap(), b"\x04hi");
        }

        #[test]
        fn a_leaf_sealed_by_seal_leaf_opens_through_the_cipher() {
            let cipher = cipher(&Key::from([3u8; 32]));
            let aad = Context::from_encoded(b"ctx".as_slice());
            let leaf = seal_leaf(&cipher, Protected::new(b"\x04hi".to_vec()), aad.clone()).unwrap();
            let opened = Cipher::open(&cipher, leaf, &aad).unwrap();
            assert_eq!(opened.risky_unwrap(), b"\x04hi");
        }

        #[test]
        fn the_cipher_refuses_a_leaf_under_another_aad() {
            let cipher = cipher(&Key::from([3u8; 32]));
            let leaf = cipher
                .seal(
                    Protected::new(b"\x04hi".to_vec()),
                    &Context::from_encoded(b"right".as_slice()),
                )
                .unwrap();
            assert!(
                Cipher::open(&cipher, leaf, &Context::from_encoded(b"wrong".as_slice())).is_err()
            );
        }
    }

    // Round trips through the whole path, over random keys and values.

    #[quickcheck]
    fn roundtrip_string(key: Key, plaintext: String) -> bool {
        let cipher = cipher(&key);
        let ct = encrypt(plaintext.clone(), &cipher, ()).unwrap();
        let back: String = decrypt(&cipher, ct, ()).unwrap();
        back == plaintext
    }

    #[quickcheck]
    fn roundtrip_u32(key: Key, plaintext: u32) -> bool {
        let cipher = cipher(&key);
        let ct = encrypt(plaintext, &cipher, ()).unwrap();
        let back: u32 = decrypt(&cipher, ct, ()).unwrap();
        back == plaintext
    }

    #[quickcheck]
    fn roundtrip_byte_array(key: Key, plaintext: [u8; 16]) -> bool {
        let cipher = cipher(&key);
        let ct = encrypt(plaintext, &cipher, ()).unwrap();
        let back: [u8; 16] = decrypt(&cipher, ct, ()).unwrap();
        back == plaintext
    }

    #[quickcheck]
    fn roundtrip_vec_of_strings_with_aad(key: Key, plaintext: Vec<String>) -> bool {
        let cipher = cipher(&key);
        let ct = encrypt(plaintext.clone(), &cipher, "rows").unwrap();
        let back: Vec<String> = decrypt(&cipher, ct, "rows").unwrap();
        back == plaintext
    }

    #[quickcheck]
    fn roundtrip_option(key: Key, plaintext: Option<String>) -> bool {
        let cipher = cipher(&key);
        let ct = encrypt(plaintext.clone(), &cipher, "opt").unwrap();
        let back: Option<String> = decrypt(&cipher, ct, "opt").unwrap();
        back == plaintext
    }

    #[quickcheck]
    fn roundtrip_protected_string(key: Key, plaintext: String) -> bool {
        let cipher = cipher(&key);
        let ct = encrypt(Protected::new(plaintext.clone()), &cipher, ()).unwrap();
        let back: Protected<String> = decrypt(&cipher, ct, ()).unwrap();
        back.risky_unwrap() == plaintext
    }

    #[test]
    fn roundtrip_hashmap_with_aad() {
        let cipher = cipher(&Key::from([1u8; 32]));
        let mut map = HashMap::new();
        map.insert("name".to_string(), "Ada".to_string());
        map.insert("role".to_string(), "founder".to_string());
        let ct = encrypt(map.clone(), &cipher, "user:42").unwrap();
        let back: HashMap<String, String> = decrypt(&cipher, ct, "user:42").unwrap();
        assert_eq!(back, map);
    }

    #[test]
    fn roundtrip_empty_composites_with_aad() {
        let cipher = cipher(&Key::from([1u8; 32]));
        let ct = encrypt(Vec::<String>::new(), &cipher, "ctx").unwrap();
        assert!(matches!(ct, CipherText::EmptySequence(_)));
        let back: Vec<String> = decrypt(&cipher, ct, "ctx").unwrap();
        assert!(back.is_empty());
        let ct = encrypt(HashMap::<String, String>::new(), &cipher, "ctx").unwrap();
        assert!(matches!(ct, CipherText::EmptyMap(_)));
        let back: HashMap<String, String> = decrypt(&cipher, ct, "ctx").unwrap();
        assert!(back.is_empty());
    }

    // The cipher refuses what it should.

    #[quickcheck]
    fn decrypt_fails_with_wrong_aad(key: Key, plaintext: String) -> bool {
        let cipher = cipher(&key);
        let ct = encrypt(plaintext, &cipher, "right").unwrap();
        matches!(
            decrypt::<String, _, _>(&cipher, ct, "wrong"),
            Err(DecryptError::Cipher(Unspecified))
        )
    }

    #[quickcheck]
    fn decrypt_fails_with_wrong_key(keys: DifferingKeyPair, plaintext: String) -> bool {
        let DifferingKeyPair(a, b) = keys;
        let ct = encrypt(plaintext, &cipher(&a), ()).unwrap();
        decrypt::<String, _, _>(&cipher(&b), ct, ()).is_err()
    }

    #[test]
    fn empty_composites_fail_with_wrong_aad() {
        let cipher = cipher(&Key::from([2u8; 32]));
        let ct = encrypt(Vec::<String>::new(), &cipher, "right").unwrap();
        assert!(decrypt::<Vec<String>, _, _>(&cipher, ct, "wrong").is_err());
        let ct = encrypt(HashMap::<String, String>::new(), &cipher, "right").unwrap();
        assert!(decrypt::<HashMap<String, String>, _, _>(&cipher, ct, "wrong").is_err());
    }

    #[test]
    fn empty_composite_markers_are_domain_separated() {
        // The two markers seal the same empty plaintext; the AAD derivation
        // is what tells them apart, so one cannot stand in for the other.
        let cipher = cipher(&Key::from([42u8; 32]));
        let CipherText::EmptySequence(seq_marker) =
            encrypt(Vec::<String>::new(), &cipher, "ctx").unwrap()
        else {
            panic!("expected an empty-sequence marker");
        };
        assert!(decrypt::<HashMap<String, String>, _, _>(
            &cipher,
            CipherText::EmptyMap(seq_marker),
            "ctx"
        )
        .is_err());
        let CipherText::EmptyMap(map_marker) =
            encrypt(HashMap::<String, String>::new(), &cipher, "ctx").unwrap()
        else {
            panic!("expected an empty-map marker");
        };
        assert!(decrypt::<Vec<String>, _, _>(
            &cipher,
            CipherText::EmptySequence(map_marker),
            "ctx"
        )
        .is_err());
    }

    #[test]
    fn single_rewrapped_as_sequence_fails_decryption() {
        // The container shape is authenticated through the element AAD
        // derivation: a top-level leaf is sealed against the bare AAD, a
        // sequence element against `for_sequence_element` of it, so
        // re-nesting `{Single}` as `Sequence([Single])` cannot get `["x"]`
        // back where the app stored `"x"`.
        let cipher = cipher(&Key::from([51u8; 32]));
        let single = encrypt("x".to_string(), &cipher, ()).unwrap();
        let forged = CipherText::Sequence(vec![single]);
        assert!(decrypt::<Vec<String>, _, _>(&cipher, forged, ()).is_err());
    }

    #[test]
    fn sequence_element_rehomed_to_top_level_fails_decryption() {
        let cipher = cipher(&Key::from([52u8; 32]));
        let CipherText::Sequence(mut items) = encrypt(vec!["x".to_string()], &cipher, ()).unwrap()
        else {
            panic!("expected a sequence");
        };
        let element = items.pop().unwrap();
        assert!(decrypt::<String, _, _>(&cipher, element, ()).is_err());
    }

    #[test]
    fn swapped_or_renamed_map_keys_fail_decryption() {
        // Each map value is sealed against `Context::for_map_entry(aad, key)`,
        // so key and value are inseparable. Leaves are not `Clone`, so each
        // forgery starts from a fresh ciphertext.
        let cipher = cipher(&Key::from([53u8; 32]));
        let sealed = || {
            let mut map = HashMap::new();
            map.insert("a".to_string(), "1".to_string());
            map.insert("b".to_string(), "2".to_string());
            match encrypt(map, &cipher, "ctx").unwrap() {
                CipherText::Map(entries) => entries,
                other => panic!("expected a map, got {other:?}"),
            }
        };
        let open = |entries| {
            decrypt::<HashMap<String, String>, _, _>(&cipher, CipherText::Map(entries), "ctx")
        };

        let mut swapped = sealed();
        let (first, second) = (swapped[0].0.clone(), swapped[1].0.clone());
        swapped[0].0 = second;
        swapped[1].0 = first;
        assert!(open(swapped).is_err());

        let mut renamed = sealed();
        for (key, _) in &mut renamed {
            key.push('x');
        }
        assert!(open(renamed).is_err());

        // Order is not authenticated: the same entries reversed still open.
        let mut reordered = sealed();
        reordered.reverse();
        let back = open(reordered).unwrap();
        assert_eq!(back["a"], "1");
        assert_eq!(back["b"], "2");
    }

    #[test]
    fn every_leaf_carries_the_wire_version_prefix() {
        // The version byte is the leaf format's first byte on every
        // leaf-bearing node. `wire_version` is the keyless peek migration
        // tooling relies on.
        let cipher = cipher(&Key::from([54u8; 32]));
        fn versions(node: &Node<LocalCipherText>) -> Vec<Option<u8>> {
            match node {
                CipherText::Single(l)
                | CipherText::None(l)
                | CipherText::EmptySequence(l)
                | CipherText::EmptyMap(l) => vec![l.wire_version()],
                CipherText::Sequence(items) => items.iter().flat_map(versions).collect(),
                CipherText::Map(entries) => entries.iter().flat_map(|(_, v)| versions(v)).collect(),
                CipherText::Passthrough(_) => vec![],
            }
        }
        let mut map = HashMap::new();
        map.insert("k".to_string(), "v".to_string());
        let nodes = [
            encrypt("single".to_string(), &cipher, ()).unwrap(),
            encrypt(None::<String>, &cipher, ()).unwrap(),
            encrypt(Vec::<String>::new(), &cipher, ()).unwrap(),
            encrypt(HashMap::<String, String>::new(), &cipher, ()).unwrap(),
            encrypt(vec!["a".to_string(), "b".to_string()], &cipher, ()).unwrap(),
            encrypt(map, &cipher, ()).unwrap(),
        ];
        for node in &nodes {
            let found = versions(node);
            assert!(!found.is_empty());
            assert!(found.iter().all(|v| *v == Some(WIRE_VERSION)));
        }
    }

    #[test]
    fn relabeled_wire_version_fails_decryption() {
        // Flipping the version byte must fail — first at the parse check
        // (unknown version), and even a version a future parser accepted
        // would fail the tag, because the byte is bound into the leaf AAD
        // via `Context::for_leaf`.
        let cipher = cipher(&Key::from([55u8; 32]));
        let leaf = leaf_of(encrypt("x".to_string(), &cipher, ()).unwrap());
        let mut bytes = leaf.as_ref().to_vec();
        bytes[0] ^= 0x02;
        let relabeled = CipherText::Single(LocalCipherText::from(bytes));
        assert!(decrypt::<String, _, _>(&cipher, relabeled, ()).is_err());
    }

    #[test]
    fn tampering_any_byte_fails_decryption() {
        let cipher = cipher(&Key::from([56u8; 32]));
        let bytes = leaf_of(encrypt("hello".to_string(), &cipher, ()).unwrap())
            .as_ref()
            .to_vec();
        for idx in 0..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[idx] ^= 1;
            let node = CipherText::Single(LocalCipherText::from(tampered));
            assert!(
                decrypt::<String, _, _>(&cipher, node, ()).is_err(),
                "tamper at byte {idx}"
            );
        }
    }

    #[test]
    fn a_truncated_or_extended_leaf_fails_decryption() {
        // A short read or a tag cut off in storage, and a stray byte on the
        // end: every prefix of a sealed leaf and the leaf plus one byte fail
        // closed, on both backends.
        let cipher = cipher(&Key::from([58u8; 32]));
        let bytes = leaf_of(encrypt("hello".to_string(), &cipher, ()).unwrap())
            .as_ref()
            .to_vec();
        for len in 0..bytes.len() {
            let node = CipherText::Single(LocalCipherText::from(bytes[..len].to_vec()));
            assert!(
                decrypt::<String, _, _>(&cipher, node, ()).is_err(),
                "truncated to {len} bytes"
            );
        }
        let mut extended = bytes.clone();
        extended.push(0);
        let node = CipherText::Single(LocalCipherText::from(extended));
        assert!(decrypt::<String, _, _>(&cipher, node, ()).is_err());
    }

    #[test]
    fn a_wrapped_key_is_one_bytes_leaf_that_unwraps_to_the_same_key() {
        // Key wrapping: `Key::wrap` seals the key's 32 bytes as one tagged
        // bytes leaf, `[BYTES] ++ key`, and `Key::from_wrapped` reads them
        // straight back into a `Key`. This pins the wrapping wire format.
        let kek = cipher(&Key::from([59u8; 32]));
        let aad = Context::from_encoded(b"dek:1".as_slice());
        let dek = Key::from([0x5A; 32]);
        let wrapped = dek.wrap(&kek, aad.clone()).unwrap();
        let leaf = leaf_of(wrapped);
        let copy = LocalCipherText::from(leaf.as_ref().to_vec());
        let opened = Cipher::open(&kek, copy, &aad).unwrap();
        let mut expected = vec![vitaminc_aead::tags::BYTES];
        expected.extend_from_slice(&[0x5A; 32]);
        assert_eq!(opened.risky_ref(), &expected);
        let unwrapped = Key::from_wrapped(&kek, CipherText::Single(leaf), aad).unwrap();
        // It is the same key: a value sealed under it opens under the
        // original.
        let original = cipher(&Key::from([0x5A; 32]));
        let ct = encrypt("payload".to_string(), &cipher(&unwrapped), ()).unwrap();
        let back: String = decrypt(&original, ct, ()).unwrap();
        assert_eq!(back, "payload");
    }

    #[test]
    fn a_wrapped_leaf_of_the_wrong_length_or_kind_does_not_unwrap_to_a_key() {
        // A wrongly wrapped key must never come back as a usable key.
        let kek = cipher(&Key::from([60u8; 32]));
        let aad = Context::from_encoded(b"dek:1".as_slice());
        let refused = |node: Node<LocalCipherText>| {
            matches!(
                Key::from_wrapped(&kek, node, aad.clone()),
                Err(DecryptError::Sink(_))
            )
        };
        assert!(refused(encrypt([0x5Au8; 31], &kek, aad.clone()).unwrap()));
        assert!(refused(
            encrypt(vec![0x5Au8; 33], &kek, aad.clone()).unwrap()
        ));
        assert!(refused(
            encrypt(Vec::<u8>::new(), &kek, aad.clone()).unwrap()
        ));
        assert!(refused(encrypt("not a key", &kek, aad.clone()).unwrap()));
    }

    #[test]
    fn a_wrapped_key_does_not_unwrap_under_another_aad() {
        let kek = cipher(&Key::from([61u8; 32]));
        let wrapped = Key::from([0x5A; 32]).wrap(&kek, "dek:1").unwrap();
        assert!(matches!(
            Key::from_wrapped(&kek, wrapped, "dek:2"),
            Err(DecryptError::Cipher(_))
        ));
    }

    mod wire_versions {
        //! New leaves are wire version 2. Version 1 leaves come from two
        //! released writers that cannot be told apart: the `Value` path
        //! sealed tagged scalars, `vitaminc-encrypt` 0.5.1's `Encrypt` path
        //! sealed raw bytes. The cipher, and so the typed path, refuses
        //! every version 1 leaf; only `opening_version_1` reads them.
        use super::*;
        use crate::decrypt_with_key;
        use vitaminc_aead::tags;

        /// Seal a leaf as the 0.5.1 `seal_leaf` did: version 1 in front,
        /// and version 1 bound into the AAD.
        fn seal_version_1(
            cipher: &Aes256Cipher,
            plaintext: &[u8],
            aad: Context,
        ) -> LocalCipherText {
            let nonce = cipher.nonce_generator.generate().unwrap();
            let nonce_bytes: [u8; NONCE_LEN] = nonce.as_ref().try_into().unwrap();
            let mut buf = plaintext.to_vec();
            cipher
                .key
                .seal(&nonce_bytes, aad.for_leaf(1).as_bytes(), &mut buf)
                .unwrap();
            let mut leaf = vec![1];
            leaf.extend_from_slice(&nonce_bytes);
            leaf.extend(buf);
            LocalCipherText::from(leaf)
        }

        #[test]
        fn a_new_leaf_is_wire_version_2() {
            let cipher = cipher(&Key::from([62u8; 32]));
            let leaf = leaf_of(encrypt("x", &cipher, ()).unwrap());
            assert_eq!(WIRE_VERSION, 2);
            assert_eq!(leaf.wire_version(), Some(2));
            let through_view = cipher
                .opening_version_1()
                .seal(Protected::new(vec![tags::STRING]), &Context::empty())
                .unwrap();
            assert_eq!(through_view.wire_version(), Some(2));
        }

        #[test]
        fn a_0_5_1_raw_string_leaf_is_not_read_as_a_different_string() {
            // What 0.5.1's `encrypt(&key, "\nhello")` stored: raw UTF-8,
            // no tag. `\n` is `tags::STRING`, so read as tagged it would
            // come back as "hello".
            let key = Key::from([7u8; 32]);
            let cipher = cipher(&key);
            let leaf = || seal_version_1(&cipher, b"\nhello", Context::empty());
            let typed = decrypt::<String, _, _>(&cipher, CipherText::Single(leaf()), ());
            assert!(matches!(typed, Err(DecryptError::Cipher(_))), "{typed:?}");
            let one_shot = decrypt_with_key::<String>(&key, CipherText::Single(leaf()));
            assert!(
                matches!(one_shot, Err(DecryptError::Cipher(_))),
                "{one_shot:?}"
            );
        }

        #[test]
        fn a_0_5_1_raw_bytes_leaf_is_not_read_as_different_bytes() {
            let cipher = cipher(&Key::from([8u8; 32]));
            let leaf = seal_version_1(&cipher, &[tags::BYTES, 1, 2, 3], Context::empty());
            let typed = decrypt::<Vec<u8>, _, _>(&cipher, CipherText::Single(leaf), ());
            assert!(matches!(typed, Err(DecryptError::Cipher(_))), "{typed:?}");
        }

        #[test]
        fn the_cipher_refuses_a_tagged_version_1_leaf() {
            let cipher = cipher(&Key::from([63u8; 32]));
            let aad = Context::from_encoded(b"ctx".as_slice());
            let leaf = seal_version_1(&cipher, &[tags::STRING, b'h', b'i'], aad.clone());
            assert_eq!(
                Cipher::open(&cipher, leaf, &aad).map(|_| ()),
                Err(Unspecified)
            );
        }

        #[test]
        fn the_version_1_view_opens_a_tagged_version_1_leaf_and_a_current_one() {
            let cipher = cipher(&Key::from([64u8; 32]));
            let aad = Context::from_encoded(b"ctx".as_slice());
            let old = seal_version_1(&cipher, &[tags::STRING, b'h', b'i'], aad.clone());
            let view = cipher.opening_version_1();
            let back: String = decrypt(&view, CipherText::Single(old), aad.clone()).unwrap();
            assert_eq!(back, "hi");
            let current = encrypt("hi", &cipher, aad.clone()).unwrap();
            let back: String = decrypt(&view, current, aad).unwrap();
            assert_eq!(back, "hi");
        }

        #[test]
        fn the_version_1_view_still_authenticates_the_version() {
            // A current leaf relabeled as version 1 parses, but its tag
            // was made under version 2's AAD, so it fails; so does a version
            // the view does not read.
            let cipher = cipher(&Key::from([65u8; 32]));
            let aad = Context::from_encoded(b"ctx".as_slice());
            let bytes = leaf_of(encrypt("hi", &cipher, aad.clone()).unwrap())
                .as_ref()
                .to_vec();
            for version in [0, 1, 3] {
                let mut relabeled = bytes.clone();
                relabeled[0] = version;
                let opened = Cipher::open(
                    &cipher.opening_version_1(),
                    LocalCipherText::from(relabeled),
                    &aad,
                );
                assert_eq!(opened.map(|_| ()), Err(Unspecified), "version {version}");
            }
            let wrong_aad = seal_version_1(&cipher, &[tags::STRING], aad);
            let opened = Cipher::open(
                &cipher.opening_version_1(),
                wrong_aad,
                &Context::from_encoded(b"other".as_slice()),
            );
            assert_eq!(opened.map(|_| ()), Err(Unspecified));
        }
    }

    #[quickcheck]
    fn nonce_is_unique_across_encryptions(key: Key, plaintext: String) -> bool {
        // Two encryptions of the same plaintext under the same cipher must
        // produce different ciphertexts — each seal draws a fresh nonce.
        // Running this as a property samples a fresh nonce pair per case.
        let cipher = cipher(&key);
        let a = leaf_of(encrypt(plaintext.clone(), &cipher, ()).unwrap());
        let b = leaf_of(encrypt(plaintext, &cipher, ()).unwrap());
        a.as_ref() != b.as_ref() && a.as_ref()[1..1 + NONCE_LEN] != b.as_ref()[1..1 + NONCE_LEN]
    }

    #[test]
    fn a_static_scalar_seals_the_same_leaf_plaintext_a_host_value_does() {
        // A Rust `String` and a frame holding the same text open to the same
        // tagged leaf plaintext, so there is one leaf format.
        let cipher = cipher(&Key::from([57u8; 32]));
        let aad = Context::from_encoded(b"ctx".as_slice());
        let frame = vitaminc_aead::to_frame("hi").unwrap();
        let from_frame = leaf_of(
            encrypt(
                vitaminc_aead::Frame::parse(frame.risky_ref()).unwrap(),
                &cipher,
                aad.clone(),
            )
            .unwrap(),
        );
        let from_rust = leaf_of(encrypt("hi".to_string(), &cipher, aad.clone()).unwrap());
        let opened_frame = Cipher::open(&cipher, from_frame, &aad).unwrap();
        let opened_rust = Cipher::open(&cipher, from_rust, &aad).unwrap();
        assert_eq!(opened_frame.risky_ref(), opened_rust.risky_ref());
        // The sealed leaf is the tagged text: `STRING` then the bytes, with
        // no length prefix.
        assert_eq!(
            opened_rust.risky_ref(),
            &[vitaminc_aead::tags::STRING, b'h', b'i']
        );
    }
}
