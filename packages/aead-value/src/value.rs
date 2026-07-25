use std::borrow::Cow;

use crate::tags;
use vitaminc_aead::{
    Cipher, Decipher, DecipherVisitor, Decrypt, Encrypt, IntoAad, MapAccess, MapCipher, SeqAccess,
    SeqCipher, Unspecified,
};
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

/// An owned, `Send`, language-neutral representation of a dynamically typed
/// host value — the bridge between FFI values (which are typically bound to
/// a host thread or environment handle) and the [`Encrypt`]/[`Decrypt`]
/// traits (whose [`Decrypt`] bound requires `Send` and provides no host
/// context).
///
/// Host values are converted into `FfiValue` on the host's thread by the
/// per-language binding crate, after which encryption and decryption can
/// run on any thread; decrypted values convert back on the host's thread.
/// Secret-bearing leaves (strings and bytes) are held in [`Protected`] so
/// the Rust-side copies are wiped on drop — copies owned by the host
/// runtime's heap cannot be wiped from here.
///
/// Structurally this is `serde_json::Value`'s role in serde: a
/// self-describing tree. Leaves seal as `[tag] ++ payload` (see [`tags`]),
/// arrays drive the cipher's sequence mode, objects its map mode, so the
/// ciphertext shape mirrors the value and [`Decrypt`] can rebuild it via
/// [`Decipher::decrypt_any`] without knowing the type in advance.
///
/// `Null` and `Undefined` are distinct tagged leaves rather than uses of
/// [`Cipher::encrypt_none`] — `Option` semantics can't distinguish them,
/// and JavaScript callers can. See the crate docs for the cross-language
/// type mapping, including how [`Number`](FfiValue::Number),
/// [`Int`](FfiValue::Int), and [`UInt`](FfiValue::UInt) divide the numeric
/// space.
///
/// The cross-language contract is the frozen tag table plus the leaf
/// encodings (see [`tags`]); this enum is merely Rust's materialization of
/// that model. Bindings in other languages implement the model, not this
/// enum.
#[derive(Zeroize)]
pub enum FfiValue {
    /// Null (JS `null`, Python `None`, Go `nil`).
    Null,
    /// JavaScript `undefined`. Languages without an analog decode this to
    /// their null value and never encode it.
    Undefined,
    /// Boolean.
    Bool(bool),
    /// Floating-point number. Round-trips by IEEE-754 bit pattern.
    Number(f64),
    /// 64-bit signed integer. Kept distinct from [`Number`](FfiValue::Number)
    /// so integer-typed languages round-trip integers as integers.
    Int(i64),
    /// 64-bit unsigned integer. Kept distinct from [`Int`](FfiValue::Int) so
    /// unsigned values above `i64::MAX` — previously unrepresentable — round
    /// trip losslessly. This closes the model's only representational hole in
    /// the integer space.
    UInt(u64),
    /// String as UTF-8 bytes. Validated UTF-8 at construction; held as
    /// bytes inside [`Protected`] so the copy is wiped on drop.
    String(Protected<Vec<u8>>),
    /// Binary data.
    Bytes(Protected<Vec<u8>>),
    /// Array. Encrypts via the cipher's sequence mode.
    Array(Vec<FfiValue>),
    /// String-keyed object/map. Encrypts via the cipher's map mode: keys
    /// travel in the clear (bound into each value's AAD — see
    /// [`Aad::for_map_entry`]); values are sealed.
    Object(Vec<(String, FfiValue)>),
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

impl Encrypt for FfiValue {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        match self {
            FfiValue::Null => cipher.encrypt_bytes_vec(Protected::new(vec![tags::NULL]), aad),
            FfiValue::Undefined => {
                cipher.encrypt_bytes_vec(Protected::new(vec![tags::UNDEFINED]), aad)
            }
            FfiValue::Bool(b) => {
                let t = if b { tags::BOOL_TRUE } else { tags::BOOL_FALSE };
                cipher.encrypt_bytes_vec(Protected::new(vec![t]), aad)
            }
            FfiValue::Number(n) => {
                let mut buf = Vec::with_capacity(9);
                buf.push(tags::NUMBER);
                buf.extend_from_slice(&n.to_bits().to_le_bytes());
                cipher.encrypt_bytes_vec(Protected::new(buf), aad)
            }
            FfiValue::Int(i) => {
                let mut buf = Vec::with_capacity(9);
                buf.push(tags::INT64);
                buf.extend_from_slice(&i.to_le_bytes());
                cipher.encrypt_bytes_vec(Protected::new(buf), aad)
            }
            FfiValue::UInt(u) => {
                let mut buf = Vec::with_capacity(9);
                buf.push(tags::UINT64);
                buf.extend_from_slice(&u.to_le_bytes());
                cipher.encrypt_bytes_vec(Protected::new(buf), aad)
            }
            FfiValue::String(s) => cipher.encrypt_bytes_vec(tagged(tags::STRING, s), aad),
            FfiValue::Bytes(b) => cipher.encrypt_bytes_vec(tagged(tags::BYTES, b), aad),
            FfiValue::Array(items) => {
                // Mirror the built-in `Vec<T>` impl: every element sealed
                // against `Aad::for_sequence_element` of the caller's AAD.
                // Element positions are carried structurally only — order is
                // NOT authenticated, and a tampered ciphertext with permuted
                // elements still decrypts. See `Aad::for_sequence_element`
                // for why the index is deliberately unbound.
                let len = items.len();
                items
                    .into_iter()
                    .try_fold(cipher.encrypt_seq(Some(len), aad), |c, item| {
                        c.encrypt_next(item)
                    })?
                    .end()
            }
            FfiValue::Object(entries) => {
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

struct FfiValueVisitor;

impl<'c> DecipherVisitor<'c> for FfiValueVisitor {
    type Value = FfiValue;

    fn visit_bytes_vec(self, data: Protected<Vec<u8>>) -> Result<Self::Value, Unspecified> {
        let bytes = data.risky_ref();
        let (&t, payload) = bytes.split_first().ok_or(Unspecified)?;
        match (t, payload) {
            (tags::NULL, []) => Ok(FfiValue::Null),
            (tags::UNDEFINED, []) => Ok(FfiValue::Undefined),
            (tags::BOOL_FALSE, []) => Ok(FfiValue::Bool(false)),
            (tags::BOOL_TRUE, []) => Ok(FfiValue::Bool(true)),
            (tags::NUMBER, bits) => {
                let bits: [u8; 8] = bits.try_into().map_err(|_| Unspecified)?;
                Ok(FfiValue::Number(f64::from_bits(u64::from_le_bytes(bits))))
            }
            (tags::INT64, bytes) => {
                let bytes: [u8; 8] = bytes.try_into().map_err(|_| Unspecified)?;
                Ok(FfiValue::Int(i64::from_le_bytes(bytes)))
            }
            (tags::UINT64, bytes) => {
                let bytes: [u8; 8] = bytes.try_into().map_err(|_| Unspecified)?;
                Ok(FfiValue::UInt(u64::from_le_bytes(bytes)))
            }
            (tags::STRING, utf8) => {
                // Validate now so host conversions later are infallible.
                std::str::from_utf8(utf8).map_err(|_| Unspecified)?;
                Ok(FfiValue::String(Protected::new(utf8.to_vec())))
            }
            (tags::BYTES, raw) => Ok(FfiValue::Bytes(Protected::new(raw.to_vec()))),
            _ => Err(Unspecified),
        }
        // `data` drops (and wipes) here; leaf payloads were copied into
        // fresh `Protected` values.
    }

    fn visit_seq<A: SeqAccess<'c>>(self, mut seq: A) -> Result<Self::Value, Unspecified> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<FfiValue>().map_err(|_| Unspecified)? {
            items.push(item);
        }
        Ok(FfiValue::Array(items))
    }

    fn visit_map<A: MapAccess<'c>>(self, mut map: A) -> Result<Self::Value, Unspecified> {
        let mut entries = Vec::new();
        while let Some(entry) = map.next_entry::<FfiValue>().map_err(|_| Unspecified)? {
            entries.push(entry);
        }
        Ok(FfiValue::Object(entries))
    }

    /// A Rust-side `Option::None` sealed with `encrypt_none` maps onto
    /// [`FfiValue::Null`] — the closest host analog of an authenticated
    /// absent value. (Host-originated values never produce this shape:
    /// `Null` and `Undefined` are tagged leaves.)
    fn visit_none(self) -> Result<Self::Value, Unspecified> {
        Ok(FfiValue::Null)
    }
}

impl<'c> Decrypt<'c> for FfiValue {
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        // The value's type is recovered from the ciphertext shape (and the
        // authenticated leaf tag), not fixed by the caller.
        decipher.decrypt_any(FfiValueVisitor, aad)
    }
}

#[cfg(test)]
impl PartialEq for FfiValue {
    /// Structural equality for tests only. Variable-time — leaf comparisons
    /// use ordinary byte equality — which is why this is `cfg(test)`: use
    /// `vitaminc_protected::Equatable` where constant-time equality of
    /// secrets is required.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (FfiValue::Null, FfiValue::Null) => true,
            (FfiValue::Undefined, FfiValue::Undefined) => true,
            (FfiValue::Bool(a), FfiValue::Bool(b)) => a == b,
            (FfiValue::Number(a), FfiValue::Number(b)) => a.to_bits() == b.to_bits(),
            (FfiValue::Int(a), FfiValue::Int(b)) => a == b,
            (FfiValue::UInt(a), FfiValue::UInt(b)) => a == b,
            (FfiValue::String(a), FfiValue::String(b))
            | (FfiValue::Bytes(a), FfiValue::Bytes(b)) => a.risky_ref() == b.risky_ref(),
            (FfiValue::Array(a), FfiValue::Array(b)) => a == b,
            (FfiValue::Object(a), FfiValue::Object(b)) => a == b,
            _ => false,
        }
    }
}

#[cfg(test)]
impl std::fmt::Debug for FfiValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FfiValue::Null => f.write_str("Null"),
            FfiValue::Undefined => f.write_str("Undefined"),
            FfiValue::Bool(b) => write!(f, "Bool({b})"),
            FfiValue::Number(n) => write!(f, "Number({n})"),
            FfiValue::Int(i) => write!(f, "Int({i})"),
            FfiValue::UInt(u) => write!(f, "UInt({u})"),
            FfiValue::String(_) => f.write_str("String(<redacted>)"),
            FfiValue::Bytes(_) => f.write_str("Bytes(<redacted>)"),
            FfiValue::Array(items) => f.debug_tuple("Array").field(items).finish(),
            FfiValue::Object(entries) => f.debug_tuple("Object").field(entries).finish(),
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

    fn s(v: &str) -> FfiValue {
        FfiValue::String(Protected::new(v.as_bytes().to_vec()))
    }

    fn roundtrip(value: FfiValue) -> FfiValue {
        roundtrip_with_aad(value, ())
    }

    fn roundtrip_with_aad<'a, A: IntoAad<'a> + Clone>(value: FfiValue, aad: A) -> FfiValue {
        let cipher = cipher();
        let ct = value
            .encrypt_with_aad(&cipher, aad.clone())
            .expect("encrypt");
        cipher.decrypt_with_aad(ct, aad).expect("decrypt")
    }

    // ---------------------------------------------------------------
    // Known-answer tests: the leaf wire format
    //
    // A capturing mock cipher records the exact plaintext bytes each leaf
    // produces. These are the cross-language conformance vectors: every
    // binding must produce and accept exactly these encodings. Changing
    // any expected byte here is a wire-format break.
    // ---------------------------------------------------------------

    mod kat {
        use super::*;
        use std::any::Any;
        use std::cell::RefCell;

        pub(super) struct CapturingCipher {
            pub plaintext: RefCell<Vec<u8>>,
        }

        pub(super) struct UnusedSeq;
        pub(super) struct UnusedMap;

        impl Cipher for &CapturingCipher {
            type Ok = ();
            type Error = Unspecified;
            type Passthrough = Box<dyn Any + Send + 'static>;
            type SeqCipher = UnusedSeq;
            type MapCipher = UnusedMap;

            fn encrypt_bytes_vec<'a, A>(
                self,
                data: Protected<Vec<u8>>,
                _aad: A,
            ) -> Result<Self::Ok, Self::Error>
            where
                A: IntoAad<'a>,
            {
                *self.plaintext.borrow_mut() = data.risky_unwrap();
                Ok(())
            }

            fn encrypt_seq<'a, A>(self, _size_hint: Option<usize>, _aad: A) -> Self::SeqCipher
            where
                A: IntoAad<'a>,
            {
                UnusedSeq
            }

            fn encrypt_map<'a, A>(self, _aad: A) -> Self::MapCipher
            where
                A: IntoAad<'a>,
            {
                UnusedMap
            }

            fn encrypt_none<'a, A>(self, _aad: A) -> Result<Self::Ok, Self::Error>
            where
                A: IntoAad<'a>,
            {
                Err(Unspecified)
            }

            fn passthrough(self, _value: Self::Passthrough) -> Result<Self::Ok, Self::Error> {
                Err(Unspecified)
            }
        }

        impl SeqCipher for UnusedSeq {
            type Ok = ();
            type Error = Unspecified;
            type Passthrough = Box<dyn Any + Send + 'static>;

            fn encrypt_next<T>(self, _data: T) -> Result<Self, Self::Error>
            where
                T: Encrypt,
            {
                Err(Unspecified)
            }

            fn passthrough_next(self, _value: Self::Passthrough) -> Result<Self, Self::Error> {
                Err(Unspecified)
            }

            fn end(self) -> Result<Self::Ok, Self::Error> {
                Err(Unspecified)
            }
        }

        impl MapCipher for UnusedMap {
            type Ok = ();
            type Error = Unspecified;
            type Passthrough = Box<dyn Any + Send + 'static>;

            fn encrypt_key<K>(self, _key: K) -> Result<Self, Self::Error>
            where
                K: Into<Cow<'static, str>>,
            {
                Err(Unspecified)
            }

            fn encrypt_value<T>(self, _value: T) -> Result<Self, Self::Error>
            where
                T: Encrypt,
            {
                Err(Unspecified)
            }

            fn passthrough_entry<K>(
                self,
                _key: K,
                _value: Self::Passthrough,
            ) -> Result<Self, Self::Error>
            where
                K: Into<Cow<'static, str>>,
            {
                Err(Unspecified)
            }

            fn end(self) -> Result<Self::Ok, Self::Error> {
                Err(Unspecified)
            }
        }
    }

    /// The exact leaf plaintext a value seals — the conformance vector.
    fn leaf_bytes(value: FfiValue) -> Vec<u8> {
        let capture = kat::CapturingCipher {
            plaintext: std::cell::RefCell::new(Vec::new()),
        };
        value.encrypt(&capture).expect("leaf encrypt");
        let bytes = capture.plaintext.borrow().clone();
        bytes
    }

    #[test]
    fn kat_null() {
        assert_eq!(leaf_bytes(FfiValue::Null), [0x00]);
    }

    #[test]
    fn kat_undefined() {
        assert_eq!(leaf_bytes(FfiValue::Undefined), [0x01]);
    }

    #[test]
    fn kat_bool() {
        assert_eq!(leaf_bytes(FfiValue::Bool(false)), [0x02]);
        assert_eq!(leaf_bytes(FfiValue::Bool(true)), [0x03]);
    }

    #[test]
    fn kat_number() {
        // 1.5 = 0x3FF8000000000000, little-endian.
        assert_eq!(
            leaf_bytes(FfiValue::Number(1.5)),
            [0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x3F]
        );
        // -0.0: sign bit only — distinct from +0.0 on the wire.
        assert_eq!(
            leaf_bytes(FfiValue::Number(-0.0)),
            [0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]
        );
    }

    #[test]
    fn kat_int64() {
        assert_eq!(
            leaf_bytes(FfiValue::Int(42)),
            [0x07, 42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        // -1: all ones (two's complement).
        assert_eq!(
            leaf_bytes(FfiValue::Int(-1)),
            [0x07, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(
            leaf_bytes(FfiValue::Int(i64::MIN)),
            [0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]
        );
    }

    #[test]
    fn kat_uint64() {
        assert_eq!(
            leaf_bytes(FfiValue::UInt(42)),
            [0x08, 42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        // u64::MAX: all ones — the value INT64 cannot represent.
        assert_eq!(
            leaf_bytes(FfiValue::UInt(u64::MAX)),
            [0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(
            leaf_bytes(FfiValue::UInt(0)),
            [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn kat_int_and_uint_never_collide() {
        // Int(-1) and UInt(u64::MAX) share payload bytes but differ by tag,
        // so they never collide on the wire.
        assert_ne!(
            leaf_bytes(FfiValue::Int(-1)),
            leaf_bytes(FfiValue::UInt(u64::MAX))
        );
    }

    #[test]
    fn kat_string() {
        assert_eq!(leaf_bytes(s("abc")), [0x05, b'a', b'b', b'c']);
        assert_eq!(leaf_bytes(s("")), [0x05]);
    }

    #[test]
    fn kat_bytes() {
        assert_eq!(
            leaf_bytes(FfiValue::Bytes(Protected::new(vec![0xDE, 0xAD]))),
            [0x06, 0xDE, 0xAD]
        );
    }

    #[test]
    fn kat_int_and_number_never_collide() {
        // Int(1) and Number(1.0) are different types AND different bytes.
        assert_ne!(
            leaf_bytes(FfiValue::Int(1)),
            leaf_bytes(FfiValue::Number(1.0))
        );
    }

    // ---------------------------------------------------------------
    // Round trips through a real cipher
    // ---------------------------------------------------------------

    #[test]
    fn roundtrip_leaves() {
        assert_eq!(roundtrip(FfiValue::Null), FfiValue::Null);
        assert_eq!(roundtrip(FfiValue::Undefined), FfiValue::Undefined);
        assert_eq!(roundtrip(FfiValue::Bool(true)), FfiValue::Bool(true));
        assert_eq!(roundtrip(FfiValue::Bool(false)), FfiValue::Bool(false));
        assert_eq!(
            roundtrip(FfiValue::Number(1234.5678)),
            FfiValue::Number(1234.5678)
        );
        assert_eq!(roundtrip(FfiValue::Int(0)), FfiValue::Int(0));
        assert_eq!(roundtrip(FfiValue::Int(i64::MAX)), FfiValue::Int(i64::MAX));
        assert_eq!(roundtrip(FfiValue::Int(i64::MIN)), FfiValue::Int(i64::MIN));
        assert_eq!(roundtrip(FfiValue::UInt(0)), FfiValue::UInt(0));
        assert_eq!(
            roundtrip(FfiValue::UInt(u64::MAX)),
            FfiValue::UInt(u64::MAX)
        );
        assert_eq!(roundtrip(s("hello world")), s("hello world"));
        assert_eq!(
            roundtrip(FfiValue::Bytes(Protected::new(vec![0, 159, 146, 150]))),
            FfiValue::Bytes(Protected::new(vec![0, 159, 146, 150]))
        );
    }

    #[test]
    fn roundtrip_preserves_int_vs_number() {
        // The decrypted variant matches the encrypted one — integers do not
        // collapse into floats or vice versa.
        assert!(matches!(roundtrip(FfiValue::Int(1)), FfiValue::Int(1)));
        assert!(matches!(
            roundtrip(FfiValue::Number(1.0)),
            FfiValue::Number(_)
        ));
        // UInt stays UInt — it does not collapse into Int or Number.
        assert!(matches!(roundtrip(FfiValue::UInt(1)), FfiValue::UInt(1)));
    }

    #[test]
    fn roundtrip_number_edge_cases() {
        // Raw-bits round-trip: -0.0 and a specific NaN payload survive.
        assert_eq!(roundtrip(FfiValue::Number(-0.0)), FfiValue::Number(-0.0));
        assert_eq!(
            roundtrip(FfiValue::Number(f64::INFINITY)),
            FfiValue::Number(f64::INFINITY)
        );
        let nan = f64::from_bits(0x7ff8_dead_beef_0001);
        assert_eq!(roundtrip(FfiValue::Number(nan)), FfiValue::Number(nan));
    }

    #[test]
    fn roundtrip_nested_structure() {
        let make = || {
            FfiValue::Object(vec![
                ("name".into(), s("alice")),
                ("age".into(), FfiValue::Int(30)),
                ("score".into(), FfiValue::Number(99.5)),
                ("active".into(), FfiValue::Bool(true)),
                ("nickname".into(), FfiValue::Null),
                (
                    "tags".into(),
                    FfiValue::Array(vec![s("a"), s("b"), FfiValue::Int(3)]),
                ),
                (
                    "nested".into(),
                    FfiValue::Object(vec![(
                        "key".into(),
                        FfiValue::Bytes(Protected::new(vec![1, 2, 3])),
                    )]),
                ),
            ])
        };
        assert_eq!(roundtrip(make()), make());
    }

    #[test]
    fn roundtrip_empty_containers() {
        assert_eq!(roundtrip(FfiValue::Array(vec![])), FfiValue::Array(vec![]));
        assert_eq!(
            roundtrip(FfiValue::Object(vec![])),
            FfiValue::Object(vec![])
        );
        assert_eq!(roundtrip(s("")), s(""));
        assert_eq!(
            roundtrip(FfiValue::Bytes(Protected::new(vec![]))),
            FfiValue::Bytes(Protected::new(vec![]))
        );
    }

    #[test]
    fn roundtrip_with_aad_binds() {
        let cipher = cipher();
        let ct = s("secret")
            .encrypt_with_aad(&cipher, "ctx")
            .expect("encrypt");
        // Wrong AAD must fail.
        assert!(cipher.decrypt_with_aad::<FfiValue, _>(ct, "other").is_err());
    }

    // ---------------------------------------------------------------
    // Tamper and malformed-leaf rejection
    // ---------------------------------------------------------------

    #[test]
    fn string_and_bytes_do_not_confuse() {
        // Same payload bytes, different tags: a string never decrypts as
        // bytes did — the authenticated tag separates them.
        let cipher = cipher();
        let as_string = s("abc").encrypt(&cipher).expect("encrypt string");
        let as_bytes = FfiValue::Bytes(Protected::new(b"abc".to_vec()))
            .encrypt(&cipher)
            .expect("encrypt bytes");
        let rs: FfiValue = cipher.decrypt(as_string).expect("decrypt");
        let rb: FfiValue = cipher.decrypt(as_bytes).expect("decrypt");
        assert!(matches!(rs, FfiValue::String(_)));
        assert!(matches!(rb, FfiValue::Bytes(_)));
    }

    #[test]
    fn invalid_utf8_string_leaf_fails_decryption() {
        // The tag byte lives inside the AEAD envelope, so BYTES→STRING
        // cannot be flipped without the key. Simulate a malicious
        // *encryptor* instead: seal `[STRING, 0xff]` directly and check the
        // decrypt-side validation rejects it.
        let cipher = cipher();
        use vitaminc_aead::Cipher as _;
        let bad = (&cipher)
            .encrypt_bytes_vec(
                Protected::new(vec![tags::STRING, 0xff]),
                vitaminc_aead::Aad::empty(),
            )
            .expect("encrypt raw");
        assert!(cipher.decrypt::<FfiValue>(bad).is_err());
    }

    #[test]
    fn truncated_fixed_width_leaves_fail() {
        let cipher = cipher();
        use vitaminc_aead::Cipher as _;
        for tag in [tags::NUMBER, tags::INT64, tags::UINT64] {
            // 3 payload bytes instead of 8.
            let bad = (&cipher)
                .encrypt_bytes_vec(
                    Protected::new(vec![tag, 1, 2, 3]),
                    vitaminc_aead::Aad::empty(),
                )
                .expect("encrypt raw");
            assert!(cipher.decrypt::<FfiValue>(bad).is_err());
            // 9 payload bytes instead of 8.
            let mut long = vec![tag];
            long.extend_from_slice(&[0u8; 9]);
            let bad = (&cipher)
                .encrypt_bytes_vec(Protected::new(long), vitaminc_aead::Aad::empty())
                .expect("encrypt raw");
            assert!(cipher.decrypt::<FfiValue>(bad).is_err());
        }
    }

    #[test]
    fn payload_after_payloadless_tag_fails() {
        // NULL/UNDEFINED/BOOL_* carry no payload; trailing bytes are
        // malformed, not ignored.
        let cipher = cipher();
        use vitaminc_aead::Cipher as _;
        for tag in [
            tags::NULL,
            tags::UNDEFINED,
            tags::BOOL_FALSE,
            tags::BOOL_TRUE,
        ] {
            let bad = (&cipher)
                .encrypt_bytes_vec(Protected::new(vec![tag, 0]), vitaminc_aead::Aad::empty())
                .expect("encrypt raw");
            assert!(cipher.decrypt::<FfiValue>(bad).is_err());
        }
    }

    #[test]
    fn unknown_tag_fails() {
        let cipher = cipher();
        use vitaminc_aead::Cipher as _;
        let bad = (&cipher)
            .encrypt_bytes_vec(Protected::new(vec![0x7f]), vitaminc_aead::Aad::empty())
            .expect("encrypt raw");
        assert!(cipher.decrypt::<FfiValue>(bad).is_err());
        // Empty plaintext (no tag at all) also fails.
        let empty = (&cipher)
            .encrypt_bytes_vec(Protected::new(vec![]), vitaminc_aead::Aad::empty())
            .expect("encrypt raw");
        assert!(cipher.decrypt::<FfiValue>(empty).is_err());
    }

    #[test]
    fn rust_option_none_decrypts_as_null() {
        // A Rust `Option::None` sealed with `encrypt_none` surfaces as
        // `Null` through the self-describing path.
        let cipher = cipher();
        let ct = Option::<String>::None.encrypt(&cipher).expect("encrypt");
        let v: FfiValue = cipher.decrypt(ct).expect("decrypt");
        assert_eq!(v, FfiValue::Null);
    }

    #[test]
    fn swapped_object_keys_fail_decryption() {
        // End-to-end check that the map key binding protects objects.
        use vitaminc_encrypt::AesCipherText;
        let cipher = cipher();
        let value = FfiValue::Object(vec![
            ("a".into(), FfiValue::Int(1)),
            ("b".into(), FfiValue::Int(2)),
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
        assert!(cipher.decrypt::<FfiValue>(tampered).is_err());
    }
}
