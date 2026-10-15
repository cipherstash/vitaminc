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
/// ```compile_fail
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
}

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
/// anti-drift reason as [`seal_leaf`].
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
