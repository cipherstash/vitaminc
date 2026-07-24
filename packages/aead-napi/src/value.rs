use std::borrow::Cow;

use vitaminc_aead::{
    Cipher, Decipher, DecipherVisitor, Decrypt, Encrypt, IntoAad, MapAccess, MapCipher, SeqAccess,
    SeqCipher, Unspecified,
};
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

/// Leaf type tags, prepended to every leaf plaintext **inside** the AEAD
/// envelope. The tag is what lets a dynamically typed JS value round-trip:
/// a string, a number, and a `Buffer` all seal to bytes, and the tag —
/// authenticated along with the payload — records which one to rebuild.
/// Flipping a tag requires forging the AEAD tag, so type confusion at this
/// layer is not available to an attacker holding the ciphertext.
pub(crate) mod tag {
    /// JS `null`. No payload.
    pub const NULL: u8 = 0x00;
    /// JS `undefined`. No payload.
    pub const UNDEFINED: u8 = 0x01;
    /// JS `false`. No payload — the value is the tag.
    pub const BOOL_FALSE: u8 = 0x02;
    /// JS `true`. No payload.
    pub const BOOL_TRUE: u8 = 0x03;
    /// JS number: 8 bytes, IEEE-754 bit pattern, little-endian. Raw bits
    /// (not a numeric encoding) so `NaN` payloads and `-0` survive.
    pub const NUMBER: u8 = 0x04;
    /// JS string: UTF-8 bytes.
    pub const STRING: u8 = 0x05;
    /// JS binary data (`Buffer` / `Uint8Array`): raw bytes.
    pub const BYTES: u8 = 0x06;
}

/// An owned, `Send` representation of a JavaScript value — the bridge
/// between NAPI values (which are bound to the JS thread and its `Env`) and
/// the [`Encrypt`]/[`Decrypt`] traits (whose [`Decrypt`] bound requires
/// `Send` and provides no `Env`).
///
/// JS values are converted into `NapiValue` on the JS thread (see the
/// [`FromNapiValue`](napi::bindgen_prelude::FromNapiValue) impl), after
/// which encryption and decryption can run on any thread; decrypted values
/// convert back on the JS thread. Secret-bearing leaves (strings and bytes)
/// are held in [`Protected`] so the Rust-side copies are wiped on drop —
/// the original copies in the V8 heap are owned by the JS engine and cannot
/// be wiped from here.
///
/// Structurally this is `serde_json::Value`'s role in serde: a
/// self-describing tree. Leaves seal as `[tag] ++ payload` (see [`tag`]),
/// arrays drive the cipher's sequence mode, objects its map mode, so the
/// ciphertext shape mirrors the value and [`Decrypt`] can rebuild it via
/// [`Decipher::decrypt_any`] without knowing the type in advance.
///
/// `null` and `undefined` are distinct tagged leaves rather than uses of
/// [`Cipher::encrypt_none`] — `Option` semantics can't distinguish them,
/// and JS callers can.
#[derive(Zeroize)]
pub enum NapiValue {
    /// JS `null`.
    Null,
    /// JS `undefined`.
    Undefined,
    /// JS boolean.
    Bool(bool),
    /// JS number. Round-trips by IEEE-754 bit pattern.
    Number(f64),
    /// JS string as UTF-8 bytes. Validated UTF-8 at construction; held as
    /// bytes inside [`Protected`] so the copy is wiped on drop.
    String(Protected<Vec<u8>>),
    /// JS binary data (`Buffer` / `Uint8Array` contents).
    Bytes(Protected<Vec<u8>>),
    /// JS array. Encrypts via the cipher's sequence mode.
    Array(Vec<NapiValue>),
    /// JS plain object. Encrypts via the cipher's map mode: keys travel in
    /// the clear (bound into each value's AAD — see
    /// [`Aad::for_map_entry`]); values are sealed.
    Object(Vec<(String, NapiValue)>),
}

// No `ZeroizeOnDrop` derive: it would add a `Drop` impl, and `Drop` types
// cannot be destructured — the `Encrypt` impl moves leaves out of `self`.
// The secret-bearing leaves are inside `Protected`, which wipes on drop on
// its own; container metadata (numbers, booleans, keys) can be wiped
// explicitly via `Zeroize` where callers need it.

/// Build a tagged leaf plaintext: `[tag] ++ payload`.
///
/// The bare-bytes window between `risky_ref` and the re-wrap in
/// [`Protected`] is bounded to this function, mirroring the built-in leaf
/// `Encrypt` impls (see the chain-of-custody notes in `vitaminc-aead`).
fn tagged(tag: u8, data: Protected<Vec<u8>>) -> Protected<Vec<u8>> {
    let payload = data.risky_ref();
    let mut buf = Vec::with_capacity(1 + payload.len());
    buf.push(tag);
    buf.extend_from_slice(payload);
    // `data` drops (and wipes) here; `buf` is owned by the new `Protected`.
    Protected::new(buf)
}

impl Encrypt for NapiValue {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        match self {
            NapiValue::Null => cipher.encrypt_bytes_vec(Protected::new(vec![tag::NULL]), aad),
            NapiValue::Undefined => {
                cipher.encrypt_bytes_vec(Protected::new(vec![tag::UNDEFINED]), aad)
            }
            NapiValue::Bool(b) => {
                let t = if b { tag::BOOL_TRUE } else { tag::BOOL_FALSE };
                cipher.encrypt_bytes_vec(Protected::new(vec![t]), aad)
            }
            NapiValue::Number(n) => {
                let mut buf = Vec::with_capacity(9);
                buf.push(tag::NUMBER);
                buf.extend_from_slice(&n.to_bits().to_le_bytes());
                cipher.encrypt_bytes_vec(Protected::new(buf), aad)
            }
            NapiValue::String(s) => cipher.encrypt_bytes_vec(tagged(tag::STRING, s), aad),
            NapiValue::Bytes(b) => cipher.encrypt_bytes_vec(tagged(tag::BYTES, b), aad),
            NapiValue::Array(items) => {
                // Mirror the built-in `Vec<T>` impl: every element sealed
                // against the same AAD, positions carried structurally.
                let len = items.len();
                items
                    .into_iter()
                    .try_fold(cipher.encrypt_seq(Some(len), aad), |c, item| {
                        c.encrypt_next(item)
                    })?
                    .end()
            }
            NapiValue::Object(entries) => {
                // Mirror the built-in `HashMap` impls; the cipher binds each
                // key into its value's AAD via `Aad::for_map_entry`.
                entries
                    .into_iter()
                    .try_fold(cipher.encrypt_map(aad), |c, (key, value)| {
                        c.encrypt_entry(Cow::Owned(key), value)
                    })?
                    .end()
            }
        }
    }
}

struct NapiValueVisitor;

impl<'c> DecipherVisitor<'c> for NapiValueVisitor {
    type Value = NapiValue;

    fn visit_bytes_vec(self, data: Protected<Vec<u8>>) -> Result<Self::Value, Unspecified> {
        let bytes = data.risky_ref();
        let (&t, payload) = bytes.split_first().ok_or(Unspecified)?;
        match (t, payload) {
            (tag::NULL, []) => Ok(NapiValue::Null),
            (tag::UNDEFINED, []) => Ok(NapiValue::Undefined),
            (tag::BOOL_FALSE, []) => Ok(NapiValue::Bool(false)),
            (tag::BOOL_TRUE, []) => Ok(NapiValue::Bool(true)),
            (tag::NUMBER, bits) => {
                let bits: [u8; 8] = bits.try_into().map_err(|_| Unspecified)?;
                Ok(NapiValue::Number(f64::from_bits(u64::from_le_bytes(bits))))
            }
            (tag::STRING, utf8) => {
                // Validate now so the JS conversion later is infallible.
                std::str::from_utf8(utf8).map_err(|_| Unspecified)?;
                Ok(NapiValue::String(Protected::new(utf8.to_vec())))
            }
            (tag::BYTES, raw) => Ok(NapiValue::Bytes(Protected::new(raw.to_vec()))),
            _ => Err(Unspecified),
        }
        // `data` drops (and wipes) here; leaf payloads were copied into
        // fresh `Protected` values.
    }

    fn visit_seq<A: SeqAccess<'c>>(self, mut seq: A) -> Result<Self::Value, Unspecified> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<NapiValue>().map_err(|_| Unspecified)? {
            items.push(item);
        }
        Ok(NapiValue::Array(items))
    }

    fn visit_map<A: MapAccess<'c>>(self, mut map: A) -> Result<Self::Value, Unspecified> {
        let mut entries = Vec::new();
        while let Some(entry) = map.next_entry::<NapiValue>().map_err(|_| Unspecified)? {
            entries.push(entry);
        }
        Ok(NapiValue::Object(entries))
    }

    /// A Rust-side `Option::None` sealed with `encrypt_none` maps onto JS
    /// `null` — the closest JS analog of an authenticated absent value.
    /// (JS-originated values never produce this shape: `null` and
    /// `undefined` are tagged leaves.)
    fn visit_none(self) -> Result<Self::Value, Unspecified> {
        Ok(NapiValue::Null)
    }
}

impl<'c> Decrypt<'c> for NapiValue {
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        // The value's type is recovered from the ciphertext shape (and the
        // authenticated leaf tag), not fixed by the caller.
        decipher.decrypt_any(NapiValueVisitor, aad)
    }
}

#[cfg(test)]
impl PartialEq for NapiValue {
    /// Structural equality for tests only. Variable-time — leaf comparisons
    /// use ordinary byte equality — which is why this is `cfg(test)`: use
    /// `vitaminc_protected::Equatable` where constant-time equality of
    /// secrets is required.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (NapiValue::Null, NapiValue::Null) => true,
            (NapiValue::Undefined, NapiValue::Undefined) => true,
            (NapiValue::Bool(a), NapiValue::Bool(b)) => a == b,
            (NapiValue::Number(a), NapiValue::Number(b)) => a.to_bits() == b.to_bits(),
            (NapiValue::String(a), NapiValue::String(b))
            | (NapiValue::Bytes(a), NapiValue::Bytes(b)) => a.risky_ref() == b.risky_ref(),
            (NapiValue::Array(a), NapiValue::Array(b)) => a == b,
            (NapiValue::Object(a), NapiValue::Object(b)) => a == b,
            _ => false,
        }
    }
}

#[cfg(test)]
impl std::fmt::Debug for NapiValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NapiValue::Null => f.write_str("Null"),
            NapiValue::Undefined => f.write_str("Undefined"),
            NapiValue::Bool(b) => write!(f, "Bool({b})"),
            NapiValue::Number(n) => write!(f, "Number({n})"),
            NapiValue::String(_) => f.write_str("String(<redacted>)"),
            NapiValue::Bytes(_) => f.write_str("Bytes(<redacted>)"),
            NapiValue::Array(items) => f.debug_tuple("Array").field(items).finish(),
            NapiValue::Object(entries) => f.debug_tuple("Object").field(entries).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_encrypt::{Aes256Cipher, Key};

    fn cipher() -> Aes256Cipher {
        Aes256Cipher::new(&Key::from([7u8; 32])).expect("cipher")
    }

    fn s(v: &str) -> NapiValue {
        NapiValue::String(Protected::new(v.as_bytes().to_vec()))
    }

    fn roundtrip(value: NapiValue) -> NapiValue {
        roundtrip_with_aad(value, ())
    }

    fn roundtrip_with_aad<'a, A: IntoAad<'a> + Clone>(value: NapiValue, aad: A) -> NapiValue {
        let cipher = cipher();
        let ct = value
            .encrypt_with_aad(&cipher, aad.clone())
            .expect("encrypt");
        cipher.decrypt_with_aad(ct, aad).expect("decrypt")
    }

    #[test]
    fn roundtrip_leaves() {
        assert_eq!(roundtrip(NapiValue::Null), NapiValue::Null);
        assert_eq!(roundtrip(NapiValue::Undefined), NapiValue::Undefined);
        assert_eq!(roundtrip(NapiValue::Bool(true)), NapiValue::Bool(true));
        assert_eq!(roundtrip(NapiValue::Bool(false)), NapiValue::Bool(false));
        assert_eq!(
            roundtrip(NapiValue::Number(1234.5678)),
            NapiValue::Number(1234.5678)
        );
        assert_eq!(roundtrip(s("hello world")), s("hello world"));
        assert_eq!(
            roundtrip(NapiValue::Bytes(Protected::new(vec![0, 159, 146, 150]))),
            NapiValue::Bytes(Protected::new(vec![0, 159, 146, 150]))
        );
    }

    #[test]
    fn roundtrip_number_edge_cases() {
        // Raw-bits round-trip: -0.0 and a specific NaN payload survive.
        assert_eq!(roundtrip(NapiValue::Number(-0.0)), NapiValue::Number(-0.0));
        assert_eq!(
            roundtrip(NapiValue::Number(f64::INFINITY)),
            NapiValue::Number(f64::INFINITY)
        );
        let nan = f64::from_bits(0x7ff8_dead_beef_0001);
        assert_eq!(roundtrip(NapiValue::Number(nan)), NapiValue::Number(nan));
    }

    #[test]
    fn roundtrip_nested_structure() {
        let value = NapiValue::Object(vec![
            ("name".into(), s("alice")),
            ("age".into(), NapiValue::Number(30.0)),
            ("active".into(), NapiValue::Bool(true)),
            ("nickname".into(), NapiValue::Null),
            (
                "tags".into(),
                NapiValue::Array(vec![s("a"), s("b"), NapiValue::Number(3.0)]),
            ),
            (
                "nested".into(),
                NapiValue::Object(vec![(
                    "key".into(),
                    NapiValue::Bytes(Protected::new(vec![1, 2, 3])),
                )]),
            ),
        ]);
        let expected = NapiValue::Object(vec![
            ("name".into(), s("alice")),
            ("age".into(), NapiValue::Number(30.0)),
            ("active".into(), NapiValue::Bool(true)),
            ("nickname".into(), NapiValue::Null),
            (
                "tags".into(),
                NapiValue::Array(vec![s("a"), s("b"), NapiValue::Number(3.0)]),
            ),
            (
                "nested".into(),
                NapiValue::Object(vec![(
                    "key".into(),
                    NapiValue::Bytes(Protected::new(vec![1, 2, 3])),
                )]),
            ),
        ]);
        assert_eq!(roundtrip(value), expected);
    }

    #[test]
    fn roundtrip_empty_containers() {
        assert_eq!(
            roundtrip(NapiValue::Array(vec![])),
            NapiValue::Array(vec![])
        );
        assert_eq!(
            roundtrip(NapiValue::Object(vec![])),
            NapiValue::Object(vec![])
        );
        assert_eq!(roundtrip(s("")), s(""));
        assert_eq!(
            roundtrip(NapiValue::Bytes(Protected::new(vec![]))),
            NapiValue::Bytes(Protected::new(vec![]))
        );
    }

    #[test]
    fn roundtrip_with_aad_binds() {
        let cipher = cipher();
        let ct = s("secret")
            .encrypt_with_aad(&cipher, "ctx")
            .expect("encrypt");
        // Wrong AAD must fail.
        assert!(cipher
            .decrypt_with_aad::<NapiValue, _>(ct, "other")
            .is_err());
    }

    #[test]
    fn string_and_bytes_do_not_confuse() {
        // Same payload bytes, different tags: a string never decrypts as
        // bytes did — the authenticated tag separates them.
        let cipher = cipher();
        let as_string = s("abc").encrypt(&cipher).expect("encrypt string");
        let as_bytes = NapiValue::Bytes(Protected::new(b"abc".to_vec()))
            .encrypt(&cipher)
            .expect("encrypt bytes");
        let rs: NapiValue = cipher.decrypt(as_string).expect("decrypt");
        let rb: NapiValue = cipher.decrypt(as_bytes).expect("decrypt");
        assert!(matches!(rs, NapiValue::String(_)));
        assert!(matches!(rb, NapiValue::Bytes(_)));
    }

    #[test]
    fn invalid_utf8_string_leaf_fails_decryption() {
        // A String leaf is validated on decrypt; seal invalid UTF-8 under
        // the STRING tag by constructing the tagged plaintext directly.
        let cipher = cipher();
        let ct = NapiValue::Bytes(Protected::new(vec![0xff, 0xfe]))
            .encrypt(&cipher)
            .expect("encrypt");
        // Bytes round-trips fine…
        let v: NapiValue = cipher.decrypt(ct).expect("decrypt");
        assert!(matches!(v, NapiValue::Bytes(_)));
        // …and the tag byte lives inside the AEAD envelope, so we cannot
        // flip BYTES→STRING without the key. Simulate a malicious *encryptor*
        // instead: seal `[STRING, 0xff]` as raw tagged bytes via the tagged()
        // helper and check the decrypt-side validation rejects it.
        use vitaminc_aead::Cipher as _;
        let bad = (&cipher)
            .encrypt_bytes_vec(
                Protected::new(vec![super::tag::STRING, 0xff]),
                vitaminc_aead::Aad::empty(),
            )
            .expect("encrypt raw");
        assert!(cipher.decrypt::<NapiValue>(bad).is_err());
    }

    #[test]
    fn truncated_number_leaf_fails() {
        let cipher = cipher();
        use vitaminc_aead::Cipher as _;
        let bad = (&cipher)
            .encrypt_bytes_vec(
                Protected::new(vec![super::tag::NUMBER, 1, 2, 3]),
                vitaminc_aead::Aad::empty(),
            )
            .expect("encrypt raw");
        assert!(cipher.decrypt::<NapiValue>(bad).is_err());
    }

    #[test]
    fn unknown_tag_fails() {
        let cipher = cipher();
        use vitaminc_aead::Cipher as _;
        let bad = (&cipher)
            .encrypt_bytes_vec(Protected::new(vec![0x7f]), vitaminc_aead::Aad::empty())
            .expect("encrypt raw");
        assert!(cipher.decrypt::<NapiValue>(bad).is_err());
        // Empty plaintext (no tag at all) also fails.
        let empty = (&cipher)
            .encrypt_bytes_vec(Protected::new(vec![]), vitaminc_aead::Aad::empty())
            .expect("encrypt raw");
        assert!(cipher.decrypt::<NapiValue>(empty).is_err());
    }

    #[test]
    fn rust_option_none_decrypts_as_null() {
        // A Rust `Option::None` sealed with `encrypt_none` surfaces as JS
        // `null` through the self-describing path.
        let cipher = cipher();
        let ct = Option::<String>::None.encrypt(&cipher).expect("encrypt");
        let v: NapiValue = cipher.decrypt(ct).expect("decrypt");
        assert_eq!(v, NapiValue::Null);
    }

    #[test]
    fn swapped_object_keys_fail_decryption() {
        // End-to-end check that the map key binding protects JS objects.
        use vitaminc_encrypt::AesCipherText;
        let cipher = cipher();
        let value = NapiValue::Object(vec![
            ("a".into(), NapiValue::Number(1.0)),
            ("b".into(), NapiValue::Number(2.0)),
        ]);
        let ct = value.encrypt(&cipher).expect("encrypt");
        let tampered = match ct {
            AesCipherText::Map(mut entries) => {
                let (k0, k1) = (entries[0].0.clone(), entries[1].0.clone());
                entries[0].0 = k1;
                entries[1].0 = k0;
                AesCipherText::Map(entries)
            }
            _ => panic!("expected Map"),
        };
        assert!(cipher.decrypt::<NapiValue>(tampered).is_err());
    }
}
