//! `StaticCipher` impl for `&Aes256Cipher` — the HList-shaped output path.
//!
//! See `vitaminc_aead::hlist` for the design rationale.

use crate::backend::NONCE_LEN;
use crate::Aes256Cipher;
use vitaminc_aead::hlist::{Absent, Encrypted, StaticCipher};
use vitaminc_aead::{CipherTextBuilder, IntoAad, NonceGenerator, Unspecified};
use vitaminc_protected::Protected;

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
        let local = seal_into_local(self, data, aad)?;
        Ok(Encrypted::from_local(local))
    }

    fn encrypt_none<'a, A>(self, aad: A) -> Result<Absent, Self::Error>
    where
        A: IntoAad<'a>,
    {
        let local = seal_into_local(self, Protected::new(Vec::new()), absent_aad(aad))?;
        Ok(Absent::from_local(local))
    }
}

/// Domain-separate the absence marker from an empty [`Encrypted`].
///
/// Both seal an empty plaintext, so without this their `LocalCipherText` bytes
/// would be identical under the same `(key, AAD)` and an `Absent` slot could be
/// swapped for an empty `Encrypted` one (and vice versa) without tripping tag
/// verification. Prefixing a fixed label binds the "absent" role into the tag
/// (PAE-encoded via the tuple `IntoAad` impl), so the two no longer
/// cross-validate. `verify_absent` re-derives the same wrapped AAD.
fn absent_aad<'a, A: IntoAad<'a>>(aad: A) -> (&'a [u8], A) {
    (b"vitaminc:absent", aad)
}

impl Aes256Cipher {
    /// Open an [`Encrypted`] leaf under the supplied AAD. Counterpart to
    /// [`StaticCipher::encrypt_bytes`].
    ///
    /// The plaintext is returned inside `Protected` to thread the chain of
    /// custody across the call boundary, matching
    /// [`Aes256Cipher::decrypt_with_aad`]. The returned `Protected<Vec<u8>>` is
    /// zeroized on drop (`Protected` is `ZeroizeOnDrop`).
    pub fn open<'a, A>(&self, ct: Encrypted, aad: A) -> Result<Protected<Vec<u8>>, Unspecified>
    where
        A: IntoAad<'a>,
    {
        open_local(self, ct.into_local(), aad)
    }

    /// Verify an [`Absent`] marker under the supplied AAD. Returns
    /// `Ok(())` if the tag binds `aad`, `Err(Unspecified)` otherwise.
    pub fn verify_absent<'a, A>(&self, ct: Absent, aad: A) -> Result<(), Unspecified>
    where
        A: IntoAad<'a>,
    {
        // Sealed plaintext is empty by construction; we only care about the
        // tag verification. The returned `Protected<Vec<u8>>` drops at the
        // end of this expression. The AAD is wrapped to match `encrypt_none`.
        open_local(self, ct.into_local(), absent_aad(aad)).map(|_| ())
    }
}

fn seal_into_local<'a, A>(
    cipher: &Aes256Cipher,
    data: Protected<Vec<u8>>,
    aad: A,
) -> Result<vitaminc_aead::LocalCipherText, Unspecified>
where
    A: IntoAad<'a>,
{
    let nonce = cipher.nonce_generator.generate()?;
    let nonce_bytes: [u8; NONCE_LEN] = nonce.as_ref().try_into().map_err(|_| Unspecified)?;
    let aad = aad.into_aad();

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

fn open_local<'a, A>(
    cipher: &Aes256Cipher,
    ct: vitaminc_aead::LocalCipherText,
    aad: A,
) -> Result<Protected<Vec<u8>>, Unspecified>
where
    A: IntoAad<'a>,
{
    let aad = aad.into_aad();
    let (nonce, reader) = ct.into_reader().read_nonce::<NONCE_LEN>()?;
    let nonce_bytes = nonce.into_inner();

    reader
        .accepts_plaintext_ok(|data| cipher.key.open(&nonce_bytes, aad.as_bytes(), data))
        .read()
}

// Split cfgs (not `all(test, …)`) so cargo-mutants recognises the test module
// and skips it — see the comment on `cipher::test`.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use crate::key::tests::DifferingKeyPair;
    use crate::Key;
    use quickcheck_macros::quickcheck;
    use vitaminc_aead::hlist::{Entry, HCons, HNil, Map, Passthrough, StaticCipher};
    use vitaminc_aead::LocalCipherText;
    use vitaminc_protected::Controlled;

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
    const INNER_AAD: &[u8] = b"user:42/prefs";

    #[test]
    fn static_user_roundtrip() {
        let key = Key::from([7u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("cipher init");

        let prefs = (&cipher)
            .encrypt_map()
            .encrypt_entry("theme", Protected::new(b"midnight".to_vec()), INNER_AAD)
            .expect("encrypt prefs")
            .end();

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
            .nested_entry("preferences", prefs)
            .end();

        // Decryption is destructuring. No downcast, no shape check, no Box.
        let Map(HCons(prefs_e, HCons(nickname_e, HCons(version_e, HCons(pw_e, HNil))))) = user_ct;

        let pw = String::from_utf8(
            cipher
                .open(pw_e.value, AAD)
                .expect("open pw")
                .risky_unwrap(),
        )
        .unwrap();
        let version: u8 = version_e.value.0; // typed access, no fallibility
        cipher
            .verify_absent(nickname_e.value, AAD)
            .expect("verify none");

        let Map(HCons(theme_e, HNil)) = prefs_e.value;
        let theme = String::from_utf8(
            cipher
                .open(theme_e.value, INNER_AAD)
                .expect("open theme")
                .risky_unwrap(),
        )
        .unwrap();

        assert_eq!(pw, "argon2id$hash");
        assert_eq!(version, 3u8);
        assert_eq!(theme, "midnight");
        assert_eq!(pw_e.key, "password_hash");
        assert_eq!(version_e.key, "version");
        assert_eq!(nickname_e.key, "nickname");
        assert_eq!(prefs_e.key, "preferences");
    }

    #[test]
    fn static_open_fails_with_wrong_aad() {
        let key = Key::from([3u8; 32]);
        let cipher = Aes256Cipher::new(&key).expect("cipher init");
        let leaf = (&cipher)
            .encrypt_bytes(Protected::new(b"hello".to_vec()), b"right".as_slice())
            .expect("encrypt");
        assert!(cipher.open(leaf, b"wrong".as_slice()).is_err());
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
        cipher.open(leaf, b"aad".as_slice()).is_err()
    }

    #[quickcheck]
    fn verify_absent_rejects_arbitrary_bytes(key: Key, bytes: Vec<u8>) -> bool {
        let cipher = Aes256Cipher::new(&key).unwrap();
        let leaf = Absent::from_local(LocalCipherText::from(bytes));
        cipher.verify_absent(leaf, b"aad".as_slice()).is_err()
    }

    // An empty `Encrypted` and an `Absent` seal the same empty plaintext; the
    // domain separator on `encrypt_none` is what keeps their tags from
    // cross-validating under the same (key, AAD). Single representative case
    // each — the property is structural, not value-dependent.

    #[test]
    fn absent_does_not_validate_as_encrypted_empty() {
        let cipher = Aes256Cipher::new(&Key::from([2u8; 32])).unwrap();
        let aad = b"shared-aad".as_slice();
        let absent = (&cipher).encrypt_none(aad).unwrap();
        // Reinterpret the Absent's bytes as an Encrypted leaf under the same AAD.
        let as_encrypted = Encrypted::from_local(absent.into_local());
        assert!(cipher.open(as_encrypted, aad).is_err());
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
        cipher_b.open(ct, aad).is_err()
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
            assert!(cipher.open(leaf, aad).is_err(), "tamper at byte {idx}");
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
        // Distinct ciphertexts, and specifically distinct nonce prefixes.
        b1 != b2 && b1[..NONCE_LEN] != b2[..NONCE_LEN]
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
