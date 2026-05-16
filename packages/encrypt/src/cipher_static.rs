//! `StaticCipher` impl for `&Aes256Cipher` — the HList-shaped output path.
//!
//! See `vitaminc_aead::hlist` for the design rationale.

use crate::backend::NONCE_LEN;
use crate::Aes256Cipher;
use vitaminc_aead::hlist::{Absent, Encrypted, StaticCipher};
use vitaminc_aead::{CipherTextBuilder, IntoAad, NonceGenerator, Unspecified};
use vitaminc_protected::Controlled;

impl StaticCipher for &Aes256Cipher {
    type Error = Unspecified;

    fn encrypt_bytes<'a, A>(self, data: Vec<u8>, aad: A) -> Result<Encrypted, Self::Error>
    where
        A: IntoAad<'a>,
    {
        let local = seal_into_local(self, data, aad)?;
        Ok(Encrypted(local))
    }

    fn encrypt_none<'a, A>(self, aad: A) -> Result<Absent, Self::Error>
    where
        A: IntoAad<'a>,
    {
        let local = seal_into_local(self, Vec::new(), aad)?;
        Ok(Absent(local))
    }
}

impl Aes256Cipher {
    /// Open an [`Encrypted`] leaf under the supplied AAD. Counterpart to
    /// [`StaticCipher::encrypt_bytes`].
    pub fn open<'a, A>(&self, ct: Encrypted, aad: A) -> Result<Vec<u8>, Unspecified>
    where
        A: IntoAad<'a>,
    {
        open_local(self, ct.0, aad)
    }

    /// Verify an [`Absent`] marker under the supplied AAD. Returns
    /// `Ok(())` if the tag binds `aad`, `Err(Unspecified)` otherwise.
    pub fn verify_absent<'a, A>(&self, ct: Absent, aad: A) -> Result<(), Unspecified>
    where
        A: IntoAad<'a>,
    {
        // Sealed plaintext is empty by construction; we only care about the
        // tag verification.
        open_local(self, ct.0, aad).map(|pt| debug_assert!(pt.is_empty()))
    }
}

fn seal_into_local<'a, A>(
    cipher: &Aes256Cipher,
    data: Vec<u8>,
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
) -> Result<Vec<u8>, Unspecified>
where
    A: IntoAad<'a>,
{
    let aad = aad.into_aad();
    let (nonce, reader) = ct.into_reader().read_nonce::<NONCE_LEN>();
    let nonce_bytes = nonce.into_inner();

    reader
        .accepts_plaintext_ok(|data| cipher.key.open(&nonce_bytes, aad.as_bytes(), data))
        .read()
        .map(|data| data.risky_unwrap())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use crate::Key;
    use vitaminc_aead::hlist::{Entry, HCons, HNil, Map, Passthrough, StaticCipher};

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
            .encrypt_entry("theme", b"midnight".to_vec(), INNER_AAD)
            .expect("encrypt prefs")
            .end();

        let user_ct: UserCiphertext = (&cipher)
            .encrypt_map()
            .encrypt_entry("password_hash", b"argon2id$hash".to_vec(), AAD)
            .expect("encrypt pw")
            .passthrough_entry("version", 3u8)
            .none_entry("nickname", AAD)
            .expect("encrypt none")
            .nested_entry("preferences", prefs)
            .end();

        // Decryption is destructuring. No downcast, no shape check, no Box.
        let Map(HCons(prefs_e, HCons(nickname_e, HCons(version_e, HCons(pw_e, HNil))))) = user_ct;

        let pw = String::from_utf8(cipher.open(pw_e.value, AAD).expect("open pw")).unwrap();
        let version: u8 = version_e.value.0; // typed access, no fallibility
        cipher
            .verify_absent(nickname_e.value, AAD)
            .expect("verify none");

        let Map(HCons(theme_e, HNil)) = prefs_e.value;
        let theme =
            String::from_utf8(cipher.open(theme_e.value, INNER_AAD).expect("open theme")).unwrap();

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
            .encrypt_bytes(b"hello".to_vec(), b"right".as_slice())
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
}
