use std::any::Any;
use std::borrow::Cow;

use crate::tagged::{
    TaggedBoolFalse, TaggedBoolTrue, TaggedBytes, TaggedFloat32, TaggedFloat64, TaggedInt32,
    TaggedInt64, TaggedNull, TaggedString, TaggedUInt32, TaggedUInt64, TaggedUndefined,
};
use crate::tags;
use vitaminc_aead::{
    Cipher, Decipher, DecipherVisitor, Decrypt, Encrypt, IntoAad, MapAccess, MapCipher, SeqAccess,
    Unspecified,
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
/// and JavaScript callers can. The numeric family divides the number space
/// by both signedness and width: [`Int32`](FfiValue::Int32) /
/// [`Int64`](FfiValue::Int64) / [`UInt32`](FfiValue::UInt32) /
/// [`UInt64`](FfiValue::UInt64) for exact integers and
/// [`Float32`](FfiValue::Float32) / [`Float64`](FfiValue::Float64) for
/// IEEE-754 values. The 32-bit widths exist for schema fidelity with the
/// EQL layer (Postgres `int4`/`float4`), not byte savings. See the crate
/// docs for the cross-language type mapping.
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
    /// 32-bit signed integer. For schema fidelity with `int4` at the EQL
    /// layer; integer-typed languages keep it distinct from
    /// [`Int64`](FfiValue::Int64).
    Int32(i32),
    /// 64-bit signed integer. Kept distinct from the float tags so
    /// integer-typed languages round-trip integers as integers.
    Int64(i64),
    /// 32-bit unsigned integer. For schema fidelity with the EQL layer.
    UInt32(u32),
    /// 64-bit unsigned integer. Kept distinct from [`Int64`](FfiValue::Int64)
    /// so unsigned values above `i64::MAX` — previously unrepresentable —
    /// round trip losslessly. This closes the model's only representational
    /// hole in the integer space.
    UInt64(u64),
    /// 32-bit floating-point number. Round-trips by IEEE-754 bit pattern
    /// (`NaN` payloads and `-0.0` survive). For schema fidelity with
    /// `float4` at the EQL layer.
    Float32(f32),
    /// 64-bit floating-point number. Round-trips by IEEE-754 bit pattern.
    /// This is the tag a JavaScript `number` maps to.
    Float64(f64),
    /// String as UTF-8 bytes. The [`Utf8String`] payload validates UTF-8 at
    /// construction — a `String` leaf can never seal bytes the decrypt side
    /// would refuse — and holds them inside [`Protected`] so the copy is
    /// wiped on drop.
    String(Utf8String),
    /// Binary data.
    Bytes(Protected<Vec<u8>>),
    /// Array. Encrypts via the cipher's sequence mode.
    Array(Vec<FfiValue>),
    /// String-keyed object/map. Encrypts via the cipher's map mode: keys
    /// travel in the clear (bound into each value's AAD — see
    /// [`Aad::for_map_entry`]); values are sealed.
    Object(Vec<(String, FfiValue)>),
    /// A subtree that travels alongside the ciphertext **unencrypted and
    /// unauthenticated**, via the cipher's passthrough channel (see
    /// [`Cipher::passthrough`]). The wrapped value — which may be any
    /// `FfiValue`, including a whole [`Array`](FfiValue::Array) or
    /// [`Object`](FfiValue::Object) subtree — is then entirely plaintext: it
    /// is neither sealed nor covered by any AEAD tag, so it can be read and
    /// altered by anyone holding the ciphertext.
    ///
    /// # ⚠️ Non-sensitive fields only
    ///
    /// Use this only for data that is safe in the clear and safe to have
    /// tampered with. The motivating shape is a user record where the
    /// non-secret keys pass through while the secrets are sealed:
    /// `{ id, created_at }` marked passthrough alongside a sealed
    /// `{ email, name }`. Never wrap secrets — there is no encryption, no
    /// authentication, and no zeroize discipline on the payload. Mirrors the
    /// container-level [`CipherText::Passthrough`] contract.
    ///
    /// [`Cipher::passthrough`]: vitaminc_aead::Cipher::passthrough
    /// [`CipherText::Passthrough`]: vitaminc_aead::CipherText::Passthrough
    // Skipped by `Zeroize`: the payload is non-sensitive by contract (it is
    // sent in the clear), and `Box<T>` is not `Zeroize` anyway. Wrapping a
    // secret here is a misuse the type documents against, not something the
    // zeroize path should paper over.
    #[zeroize(skip)]
    Passthrough(Box<FfiValue>),
}

// No `ZeroizeOnDrop` derive: it would add a `Drop` impl, and `Drop` types
// cannot be destructured — the `Encrypt` impl moves leaves out of `self`.
// The secret-bearing leaves are inside `Protected`, which wipes on drop on
// its own; container metadata (numbers, booleans, keys) can be wiped
// explicitly via `Zeroize` where callers need it.

/// UTF-8 string payload for [`FfiValue::String`], validated at construction.
///
/// Wraps `Protected<Vec<u8>>` with the invariant that the bytes are valid
/// UTF-8. The decrypt visitor only ever rebuilds one from bytes it has just
/// validated, and every constructor here validates (or starts from a
/// `String`, which is valid by type) — so a `String` leaf can never seal
/// bytes the decrypt side will refuse. Without this, a hand-built
/// `FfiValue::String` of arbitrary bytes would encrypt Ok and then fail
/// every decrypt forever: silent data loss discovered only at read time.
#[derive(Zeroize)]
pub struct Utf8String(Protected<Vec<u8>>);

impl Utf8String {
    /// The validated UTF-8 bytes. Same chain-of-custody caveats as
    /// [`Protected::risky_ref`]: the reference must not outlive its use.
    pub fn risky_ref(&self) -> &[u8] {
        self.0.risky_ref()
    }

    /// Unwrap to the protected byte payload (still valid UTF-8; the
    /// invariant is dropped with the type).
    pub fn into_inner(self) -> Protected<Vec<u8>> {
        self.0
    }
}

impl From<String> for Utf8String {
    fn from(s: String) -> Self {
        // A `String` is valid UTF-8 by construction; the bytes move into
        // `Protected` without copying.
        Self(Protected::new(s.into_bytes()))
    }
}

impl From<&str> for Utf8String {
    fn from(s: &str) -> Self {
        Self(Protected::new(s.as_bytes().to_vec()))
    }
}

impl TryFrom<Protected<Vec<u8>>> for Utf8String {
    type Error = Unspecified;

    /// Validates the bytes; on failure the rejected `Protected` payload is
    /// dropped (and wiped) here.
    fn try_from(bytes: Protected<Vec<u8>>) -> Result<Self, Self::Error> {
        std::str::from_utf8(bytes.risky_ref()).map_err(|_| Unspecified)?;
        Ok(Self(bytes))
    }
}

impl Encrypt for FfiValue {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        // Each leaf is assembled by a typed `Tagged*` plaintext (see
        // `crate::tagged`) that owns the `[tag] ++ payload` layout: the
        // fixed-width leaves seal from a stack array (no heap allocation),
        // the variable-width ones allocate once.
        match self {
            FfiValue::Null => TaggedNull::tag_only().encrypt_with_aad(cipher, aad),
            FfiValue::Undefined => TaggedUndefined::tag_only().encrypt_with_aad(cipher, aad),
            FfiValue::Bool(false) => TaggedBoolFalse::tag_only().encrypt_with_aad(cipher, aad),
            FfiValue::Bool(true) => TaggedBoolTrue::tag_only().encrypt_with_aad(cipher, aad),
            FfiValue::Int32(i) => TaggedInt32::from(i).encrypt_with_aad(cipher, aad),
            FfiValue::Int64(i) => TaggedInt64::from(i).encrypt_with_aad(cipher, aad),
            FfiValue::UInt32(u) => TaggedUInt32::from(u).encrypt_with_aad(cipher, aad),
            FfiValue::UInt64(u) => TaggedUInt64::from(u).encrypt_with_aad(cipher, aad),
            FfiValue::Float32(f) => TaggedFloat32::from(f).encrypt_with_aad(cipher, aad),
            FfiValue::Float64(f) => TaggedFloat64::from(f).encrypt_with_aad(cipher, aad),
            FfiValue::String(s) => TaggedString::new(s.into_inner()).encrypt_with_aad(cipher, aad),
            FfiValue::Bytes(b) => TaggedBytes::new(b).encrypt_with_aad(cipher, aad),
            // Delegate to the built-in `Vec<T>` impl (`FfiValue: Encrypt`)
            // so the sequence wire protocol has exactly one definition —
            // element positions are carried structurally, not authenticated;
            // see `Aad::for_sequence_element`. A nested `Passthrough`
            // element routes identically either way, via its own arm below.
            FfiValue::Array(items) => items.encrypt_with_aad(cipher, aad),
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
            FfiValue::Passthrough(inner) => {
                // Route the (non-sensitive, unauthenticated) subtree through
                // the cipher's type-erased passthrough channel. This impl is
                // generic over every cipher, so it cannot name a specific
                // cipher's `Passthrough` type; `passthrough_boxed` takes the
                // subtree as `Box<dyn Any + Send>` and each cipher absorbs it
                // (for the Rust-native ciphers that type *is* the box).
                // No AAD is consumed — passthrough values are not
                // authenticated. `FfiValueVisitor::visit_passthrough` downcasts
                // the box back to an `FfiValue` on decrypt.
                //
                // Passthrough nested *inside* an `Array`/`Object` needs no
                // special handling here: those arms recurse through
                // `encrypt_next`/`encrypt_entry` into each element's own
                // `Encrypt` impl, so a nested `Passthrough` element reaches
                // this arm against the same root cipher.
                let boxed: Box<dyn Any + Send + 'static> = Box::new(*inner);
                cipher.passthrough_boxed(boxed)
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
        // The `try_into` on each fixed-width arm rejects any payload that is
        // not exactly the tag's width — truncated or over-long leaves fail.
        match (t, payload) {
            (tags::NULL, []) => Ok(FfiValue::Null),
            (tags::UNDEFINED, []) => Ok(FfiValue::Undefined),
            (tags::BOOL_FALSE, []) => Ok(FfiValue::Bool(false)),
            (tags::BOOL_TRUE, []) => Ok(FfiValue::Bool(true)),
            (tags::INT32, bytes) => {
                let bytes: [u8; 4] = bytes.try_into().map_err(|_| Unspecified)?;
                Ok(FfiValue::Int32(i32::from_le_bytes(bytes)))
            }
            (tags::INT64, bytes) => {
                let bytes: [u8; 8] = bytes.try_into().map_err(|_| Unspecified)?;
                Ok(FfiValue::Int64(i64::from_le_bytes(bytes)))
            }
            (tags::UINT32, bytes) => {
                let bytes: [u8; 4] = bytes.try_into().map_err(|_| Unspecified)?;
                Ok(FfiValue::UInt32(u32::from_le_bytes(bytes)))
            }
            (tags::UINT64, bytes) => {
                let bytes: [u8; 8] = bytes.try_into().map_err(|_| Unspecified)?;
                Ok(FfiValue::UInt64(u64::from_le_bytes(bytes)))
            }
            (tags::FLOAT32, bits) => {
                let bits: [u8; 4] = bits.try_into().map_err(|_| Unspecified)?;
                Ok(FfiValue::Float32(f32::from_bits(u32::from_le_bytes(bits))))
            }
            (tags::FLOAT64, bits) => {
                let bits: [u8; 8] = bits.try_into().map_err(|_| Unspecified)?;
                Ok(FfiValue::Float64(f64::from_bits(u64::from_le_bytes(bits))))
            }
            (tags::STRING, utf8) => {
                // Validate now so host conversions later are infallible.
                std::str::from_utf8(utf8).map_err(|_| Unspecified)?;
                Ok(FfiValue::String(Utf8String(Protected::new(utf8.to_vec()))))
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

    /// Recover a passthrough subtree, preserving its marking so a decrypted
    /// tree records which fields travelled in the clear. The payload was boxed
    /// as an `FfiValue` by this crate's [`Encrypt`] impl; a box carrying any
    /// other concrete type (a foreign payload never produced here) is rejected
    /// with [`Unspecified`] rather than panicking on the downcast.
    fn visit_passthrough(
        self,
        value: Box<dyn Any + Send + 'static>,
    ) -> Result<Self::Value, Unspecified> {
        value
            .downcast::<FfiValue>()
            .map(FfiValue::Passthrough)
            .map_err(|_| Unspecified)
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
    /// secrets is required. Floats compare by raw bit pattern so `-0.0` and
    /// `NaN` payloads compare as they seal.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (FfiValue::Null, FfiValue::Null) => true,
            (FfiValue::Undefined, FfiValue::Undefined) => true,
            (FfiValue::Bool(a), FfiValue::Bool(b)) => a == b,
            (FfiValue::Int32(a), FfiValue::Int32(b)) => a == b,
            (FfiValue::Int64(a), FfiValue::Int64(b)) => a == b,
            (FfiValue::UInt32(a), FfiValue::UInt32(b)) => a == b,
            (FfiValue::UInt64(a), FfiValue::UInt64(b)) => a == b,
            (FfiValue::Float32(a), FfiValue::Float32(b)) => a.to_bits() == b.to_bits(),
            (FfiValue::Float64(a), FfiValue::Float64(b)) => a.to_bits() == b.to_bits(),
            (FfiValue::String(a), FfiValue::String(b)) => a.risky_ref() == b.risky_ref(),
            (FfiValue::Bytes(a), FfiValue::Bytes(b)) => a.risky_ref() == b.risky_ref(),
            (FfiValue::Array(a), FfiValue::Array(b)) => a == b,
            (FfiValue::Object(a), FfiValue::Object(b)) => a == b,
            (FfiValue::Passthrough(a), FfiValue::Passthrough(b)) => a == b,
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
            FfiValue::Int32(i) => write!(f, "Int32({i})"),
            FfiValue::Int64(i) => write!(f, "Int64({i})"),
            FfiValue::UInt32(u) => write!(f, "UInt32({u})"),
            FfiValue::UInt64(u) => write!(f, "UInt64({u})"),
            FfiValue::Float32(n) => write!(f, "Float32({n})"),
            FfiValue::Float64(n) => write!(f, "Float64({n})"),
            FfiValue::String(_) => f.write_str("String(<redacted>)"),
            FfiValue::Bytes(_) => f.write_str("Bytes(<redacted>)"),
            FfiValue::Array(items) => f.debug_tuple("Array").field(items).finish(),
            FfiValue::Object(entries) => f.debug_tuple("Object").field(entries).finish(),
            FfiValue::Passthrough(inner) => f.debug_tuple("Passthrough").field(inner).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_aead::SeqCipher;
    use vitaminc_encrypt::{Aes256Cipher, Key};

    fn cipher() -> Aes256Cipher {
        Aes256Cipher::new(&Key::from([7u8; 32])).expect("cipher")
    }

    fn s(v: &str) -> FfiValue {
        FfiValue::String(v.into())
    }

    /// The `Debug` impl exists for assertion failures, so a passing suite
    /// never formats one — exercise it explicitly, and pin the property that
    /// matters: secret-bearing leaves must render redacted, so a failing
    /// assertion in any downstream test can't spill plaintext into CI logs.
    #[test]
    fn debug_redacts_secret_leaves_and_renders_the_rest() {
        // Scalars render their value — the numeric tags are distinguishable,
        // which is the point of the split numeric family.
        assert_eq!(format!("{:?}", FfiValue::Null), "Null");
        assert_eq!(format!("{:?}", FfiValue::Undefined), "Undefined");
        assert_eq!(format!("{:?}", FfiValue::Bool(true)), "Bool(true)");
        assert_eq!(format!("{:?}", FfiValue::Int32(-1)), "Int32(-1)");
        assert_eq!(format!("{:?}", FfiValue::Int64(-1)), "Int64(-1)");
        assert_eq!(format!("{:?}", FfiValue::UInt32(1)), "UInt32(1)");
        assert_eq!(format!("{:?}", FfiValue::UInt64(1)), "UInt64(1)");
        assert_eq!(format!("{:?}", FfiValue::Float32(1.5)), "Float32(1.5)");
        assert_eq!(format!("{:?}", FfiValue::Float64(1.5)), "Float64(1.5)");

        // The two secret-bearing variants never show their contents.
        let secret = format!("{:?}", s("hunter2"));
        assert_eq!(secret, "String(<redacted>)");
        assert!(!secret.contains("hunter2"));
        let bytes = FfiValue::Bytes(Protected::new(vec![0xDE, 0xAD]));
        assert_eq!(format!("{bytes:?}"), "Bytes(<redacted>)");

        // Containers recurse, so nested secrets stay redacted too — including
        // through a passthrough wrapper.
        assert_eq!(
            format!("{:?}", FfiValue::Array(vec![FfiValue::Null, s("secret")])),
            "Array([Null, String(<redacted>)])"
        );
        let obj = FfiValue::Object(vec![("k".to_string(), s("secret"))]);
        let rendered = format!("{obj:?}");
        assert!(rendered.contains("String(<redacted>)"), "{rendered}");
        assert!(!rendered.contains("secret"), "{rendered}");
        assert_eq!(
            format!("{:?}", FfiValue::Passthrough(Box::new(s("secret")))),
            "Passthrough(String(<redacted>))"
        );
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

            fn passthrough_boxed(
                self,
                _value: Box<dyn Any + Send + 'static>,
            ) -> Result<Self::Ok, Self::Error> {
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
    fn kat_int32() {
        assert_eq!(
            leaf_bytes(FfiValue::Int32(42)),
            [0x04, 42, 0x00, 0x00, 0x00]
        );
        // -1: all ones (two's complement).
        assert_eq!(
            leaf_bytes(FfiValue::Int32(-1)),
            [0x04, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        // i32::MIN: sign bit only in the top byte.
        assert_eq!(
            leaf_bytes(FfiValue::Int32(i32::MIN)),
            [0x04, 0x00, 0x00, 0x00, 0x80]
        );
    }

    #[test]
    fn kat_int64() {
        assert_eq!(
            leaf_bytes(FfiValue::Int64(42)),
            [0x05, 42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        // -1: all ones (two's complement).
        assert_eq!(
            leaf_bytes(FfiValue::Int64(-1)),
            [0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(
            leaf_bytes(FfiValue::Int64(i64::MIN)),
            [0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]
        );
    }

    #[test]
    fn kat_uint32() {
        assert_eq!(
            leaf_bytes(FfiValue::UInt32(0)),
            [0x06, 0x00, 0x00, 0x00, 0x00]
        );
        // u32::MAX: all ones.
        assert_eq!(
            leaf_bytes(FfiValue::UInt32(u32::MAX)),
            [0x06, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn kat_uint64() {
        assert_eq!(
            leaf_bytes(FfiValue::UInt64(42)),
            [0x07, 42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        // u64::MAX: all ones — the value INT64 cannot represent.
        assert_eq!(
            leaf_bytes(FfiValue::UInt64(u64::MAX)),
            [0x07, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(
            leaf_bytes(FfiValue::UInt64(0)),
            [0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn kat_float32() {
        // 1.5f32 = 0x3FC00000, little-endian.
        assert_eq!(
            leaf_bytes(FfiValue::Float32(1.5)),
            [0x08, 0x00, 0x00, 0xC0, 0x3F]
        );
        // -0.0f32: sign bit only — distinct from +0.0 on the wire.
        assert_eq!(
            leaf_bytes(FfiValue::Float32(-0.0)),
            [0x08, 0x00, 0x00, 0x00, 0x80]
        );
        // A specific NaN bit pattern survives by raw bits.
        let nan = f32::from_bits(0x7fc0_0001);
        assert_eq!(
            leaf_bytes(FfiValue::Float32(nan)),
            [0x08, 0x01, 0x00, 0xC0, 0x7F]
        );
    }

    #[test]
    fn kat_float64() {
        // 1.5 = 0x3FF8000000000000, little-endian.
        assert_eq!(
            leaf_bytes(FfiValue::Float64(1.5)),
            [0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x3F]
        );
        // -0.0: sign bit only — distinct from +0.0 on the wire.
        assert_eq!(
            leaf_bytes(FfiValue::Float64(-0.0)),
            [0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]
        );
    }

    #[test]
    fn kat_string() {
        assert_eq!(leaf_bytes(s("abc")), [0x0A, b'a', b'b', b'c']);
        assert_eq!(leaf_bytes(s("")), [0x0A]);
    }

    #[test]
    fn kat_bytes() {
        assert_eq!(
            leaf_bytes(FfiValue::Bytes(Protected::new(vec![0xDE, 0xAD]))),
            [0x0B, 0xDE, 0xAD]
        );
    }

    #[test]
    fn kat_int64_and_uint64_never_collide() {
        // Int64(-1) and UInt64(u64::MAX) share payload bytes but differ by
        // tag, so they never collide on the wire.
        assert_ne!(
            leaf_bytes(FfiValue::Int64(-1)),
            leaf_bytes(FfiValue::UInt64(u64::MAX))
        );
    }

    #[test]
    fn kat_int32_and_int64_never_collide() {
        // Same small value, different widths AND tags: 32- and 64-bit
        // integers never collide on the wire.
        assert_ne!(
            leaf_bytes(FfiValue::Int32(7)),
            leaf_bytes(FfiValue::Int64(7))
        );
    }

    #[test]
    fn kat_float32_and_float64_never_collide() {
        // 1.5 in binary32 and binary64 differ by tag, width, and bits.
        assert_ne!(
            leaf_bytes(FfiValue::Float32(1.5)),
            leaf_bytes(FfiValue::Float64(1.5))
        );
    }

    #[test]
    fn kat_int64_and_float64_never_collide() {
        // Int64(1) and Float64(1.0) are different types AND different bytes.
        assert_ne!(
            leaf_bytes(FfiValue::Int64(1)),
            leaf_bytes(FfiValue::Float64(1.0))
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
            roundtrip(FfiValue::Float64(1234.5678)),
            FfiValue::Float64(1234.5678)
        );
        assert_eq!(
            roundtrip(FfiValue::Float32(1234.5f32)),
            FfiValue::Float32(1234.5f32)
        );
        assert_eq!(roundtrip(FfiValue::Int32(0)), FfiValue::Int32(0));
        assert_eq!(
            roundtrip(FfiValue::Int32(i32::MAX)),
            FfiValue::Int32(i32::MAX)
        );
        assert_eq!(
            roundtrip(FfiValue::Int32(i32::MIN)),
            FfiValue::Int32(i32::MIN)
        );
        assert_eq!(roundtrip(FfiValue::Int64(0)), FfiValue::Int64(0));
        assert_eq!(
            roundtrip(FfiValue::Int64(i64::MAX)),
            FfiValue::Int64(i64::MAX)
        );
        assert_eq!(
            roundtrip(FfiValue::Int64(i64::MIN)),
            FfiValue::Int64(i64::MIN)
        );
        assert_eq!(roundtrip(FfiValue::UInt32(0)), FfiValue::UInt32(0));
        assert_eq!(
            roundtrip(FfiValue::UInt32(u32::MAX)),
            FfiValue::UInt32(u32::MAX)
        );
        assert_eq!(roundtrip(FfiValue::UInt64(0)), FfiValue::UInt64(0));
        assert_eq!(
            roundtrip(FfiValue::UInt64(u64::MAX)),
            FfiValue::UInt64(u64::MAX)
        );
        assert_eq!(roundtrip(s("hello world")), s("hello world"));
        assert_eq!(
            roundtrip(FfiValue::Bytes(Protected::new(vec![0, 159, 146, 150]))),
            FfiValue::Bytes(Protected::new(vec![0, 159, 146, 150]))
        );
    }

    #[test]
    fn roundtrip_preserves_numeric_types() {
        // The decrypted variant matches the encrypted one — integers do not
        // collapse into floats, widths are preserved, and signedness holds.
        assert!(matches!(roundtrip(FfiValue::Int32(1)), FfiValue::Int32(1)));
        assert!(matches!(roundtrip(FfiValue::Int64(1)), FfiValue::Int64(1)));
        assert!(matches!(
            roundtrip(FfiValue::UInt32(1)),
            FfiValue::UInt32(1)
        ));
        assert!(matches!(
            roundtrip(FfiValue::UInt64(1)),
            FfiValue::UInt64(1)
        ));
        assert!(matches!(
            roundtrip(FfiValue::Float32(1.0)),
            FfiValue::Float32(_)
        ));
        assert!(matches!(
            roundtrip(FfiValue::Float64(1.0)),
            FfiValue::Float64(_)
        ));
    }

    #[test]
    fn roundtrip_float_edge_cases() {
        // Raw-bits round-trip: -0.0 and specific NaN payloads survive, in
        // both widths.
        assert_eq!(roundtrip(FfiValue::Float64(-0.0)), FfiValue::Float64(-0.0));
        assert_eq!(roundtrip(FfiValue::Float32(-0.0)), FfiValue::Float32(-0.0));
        assert_eq!(
            roundtrip(FfiValue::Float64(f64::INFINITY)),
            FfiValue::Float64(f64::INFINITY)
        );
        let nan64 = f64::from_bits(0x7ff8_dead_beef_0001);
        assert_eq!(
            roundtrip(FfiValue::Float64(nan64)),
            FfiValue::Float64(nan64)
        );
        let nan32 = f32::from_bits(0x7fc0_0001);
        assert_eq!(
            roundtrip(FfiValue::Float32(nan32)),
            FfiValue::Float32(nan32)
        );
    }

    #[test]
    fn roundtrip_nested_structure() {
        let make = || {
            FfiValue::Object(vec![
                ("name".into(), s("alice")),
                ("age".into(), FfiValue::Int64(30)),
                ("score".into(), FfiValue::Float64(99.5)),
                ("rank".into(), FfiValue::Int32(-3)),
                ("active".into(), FfiValue::Bool(true)),
                ("nickname".into(), FfiValue::Null),
                (
                    "tags".into(),
                    FfiValue::Array(vec![s("a"), s("b"), FfiValue::Int64(3)]),
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
        // Every numeric tag rejects a payload that is not exactly its width,
        // in both the too-short and too-long directions.
        let cipher = cipher();
        use vitaminc_aead::Cipher as _;
        // (tag, correct payload width)
        let cases = [
            (tags::INT32, 4usize),
            (tags::INT64, 8),
            (tags::UINT32, 4),
            (tags::UINT64, 8),
            (tags::FLOAT32, 4),
            (tags::FLOAT64, 8),
        ];
        for (tag, width) in cases {
            // One byte short.
            let mut short = vec![tag];
            short.extend(std::iter::repeat_n(0u8, width - 1));
            let bad = (&cipher)
                .encrypt_bytes_vec(Protected::new(short), vitaminc_aead::Aad::empty())
                .expect("encrypt raw");
            assert!(
                cipher.decrypt::<FfiValue>(bad).is_err(),
                "tag {tag:#x} width-1 must fail"
            );
            // One byte long.
            let mut long = vec![tag];
            long.extend(std::iter::repeat_n(0u8, width + 1));
            let bad = (&cipher)
                .encrypt_bytes_vec(Protected::new(long), vitaminc_aead::Aad::empty())
                .expect("encrypt raw");
            assert!(
                cipher.decrypt::<FfiValue>(bad).is_err(),
                "tag {tag:#x} width+1 must fail"
            );
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
            ("a".into(), FfiValue::Int64(1)),
            ("b".into(), FfiValue::Int64(2)),
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

    // ---------------------------------------------------------------
    // Passthrough: unencrypted, unauthenticated fields alongside sealed ones
    // ---------------------------------------------------------------

    fn pt(v: FfiValue) -> FfiValue {
        FfiValue::Passthrough(Box::new(v))
    }

    #[test]
    fn passthrough_free_value_is_unchanged() {
        // Regression guard for the new `Passthrough` variant: a value tree
        // that contains no passthrough nodes must seal exactly as before.
        // The scalar leaf bytes are still the frozen KATs, and a nested
        // passthrough-free structure still round-trips unchanged.
        assert_eq!(
            leaf_bytes(FfiValue::Int64(42)),
            [0x05, 42, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(leaf_bytes(s("abc")), [0x0A, b'a', b'b', b'c']);
        let make = || {
            FfiValue::Object(vec![
                ("name".into(), s("alice")),
                ("age".into(), FfiValue::Int64(30)),
                (
                    "tags".into(),
                    FfiValue::Array(vec![s("a"), FfiValue::Int64(3)]),
                ),
            ])
        };
        assert_eq!(roundtrip(make()), make());
    }

    #[test]
    fn roundtrip_passthrough_leaf() {
        // A scalar wrapped in passthrough round-trips, keeping its marking.
        assert_eq!(roundtrip(pt(FfiValue::Int64(42))), pt(FfiValue::Int64(42)));
        assert_eq!(roundtrip(pt(s("in-the-clear"))), pt(s("in-the-clear")));
    }

    #[test]
    fn roundtrip_mixed_map_sealed_and_passthrough() {
        // The motivating shape: id/created_at pass through in the clear while
        // email/name are sealed. Everything round-trips, marking preserved.
        let make = || {
            FfiValue::Object(vec![
                ("id".into(), pt(FfiValue::Int64(42))),
                ("created_at".into(), pt(s("2026-07-25T00:00:00Z"))),
                ("email".into(), s("ada@example.com")),
                ("name".into(), s("Ada Lovelace")),
            ])
        };
        assert_eq!(roundtrip(make()), make());
    }

    #[test]
    fn roundtrip_nested_passthrough_subtree() {
        // Passthrough may wrap a whole Object/Array subtree — the entire
        // subtree is then plaintext and round-trips as one passthrough node.
        let subtree = || {
            FfiValue::Object(vec![
                ("kind".into(), s("public")),
                (
                    "labels".into(),
                    FfiValue::Array(vec![s("a"), s("b"), FfiValue::Int32(3)]),
                ),
            ])
        };
        let make = || {
            FfiValue::Object(vec![
                ("meta".into(), pt(subtree())),
                ("secret".into(), s("classified")),
            ])
        };
        assert_eq!(roundtrip(make()), make());
    }

    #[test]
    fn passthrough_value_is_not_authenticated() {
        // Honest documentation of the property: a modified passthrough value
        // is NOT detected. We rebuild the ciphertext with a forged passthrough
        // payload — no key required — and decryption still succeeds, returning
        // the forged value.
        use vitaminc_encrypt::AesCipherText;
        let cipher = cipher();
        let value = FfiValue::Object(vec![
            ("id".into(), pt(FfiValue::Int64(42))),
            ("email".into(), s("ada@example.com")),
        ]);
        let ct = value.encrypt(&cipher).expect("encrypt");
        let tampered = match ct {
            AesCipherText::Map(mut entries) => {
                for (key, node) in entries.iter_mut() {
                    if key == "id" {
                        *node = AesCipherText::Passthrough(Box::new(FfiValue::Int64(999)));
                    }
                }
                AesCipherText::Map(entries)
            }
            _ => panic!("expected Map"),
        };
        let decrypted: FfiValue = cipher.decrypt(tampered).expect("decrypt");
        match decrypted {
            FfiValue::Object(entries) => {
                let id = entries.iter().find(|(k, _)| k == "id").expect("id");
                // The forged value is accepted — passthrough is unauthenticated.
                assert_eq!(id.1, pt(FfiValue::Int64(999)));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn sealed_sibling_authenticates_alongside_passthrough() {
        // The flip side: tampering a SEALED sibling of a passthrough field is
        // still detected — the passthrough field does not weaken the sealed
        // ones. Flip a byte in the sealed "email" leaf; decryption must fail.
        use vitaminc_aead::LocalCipherText;
        use vitaminc_encrypt::AesCipherText;
        let cipher = cipher();
        let value = FfiValue::Object(vec![
            ("id".into(), pt(FfiValue::Int64(42))),
            ("email".into(), s("ada@example.com")),
        ]);
        let ct = value.encrypt(&cipher).expect("encrypt");
        let tampered = match ct {
            AesCipherText::Map(mut entries) => {
                for (key, node) in entries.iter_mut() {
                    if key == "email" {
                        if let AesCipherText::Single(leaf) = node {
                            let mut bytes = leaf.as_ref().to_vec();
                            let mid = bytes.len() / 2;
                            bytes[mid] ^= 0x01;
                            *node = AesCipherText::Single(LocalCipherText::from(bytes));
                        }
                    }
                }
                AesCipherText::Map(entries)
            }
            _ => panic!("expected Map"),
        };
        assert!(cipher.decrypt::<FfiValue>(tampered).is_err());
    }

    #[test]
    fn foreign_passthrough_payload_is_rejected() {
        // A passthrough whose boxed payload is not an `FfiValue` (a raw u32,
        // as a Rust-native cipher user might store) must be rejected cleanly
        // on the self-describing decode path — an error, never a panic.
        use vitaminc_encrypt::AesCipherText;
        let cipher = cipher();
        let ct: AesCipherText = AesCipherText::Passthrough(Box::new(42u32));
        assert!(cipher.decrypt::<FfiValue>(ct).is_err());
    }

    #[test]
    fn passthrough_in_array_round_trips() {
        // Passthrough nested as an array element (not a map value) exercises
        // the seq recursion path into the passthrough arm.
        let make = || {
            FfiValue::Array(vec![
                s("sealed"),
                pt(FfiValue::Int64(7)),
                FfiValue::Int32(-1),
            ])
        };
        assert_eq!(roundtrip(make()), make());
    }

    #[test]
    fn all_passthrough_containers_are_rejected_at_encrypt() {
        // A container whose every element/entry is passthrough carries no
        // AEAD tag at all: nothing authenticates the AAD, and `decrypt_seq`/
        // `decrypt_map` refuse such containers. Refusing at *encrypt* time
        // means the caller learns immediately, instead of storing a
        // ciphertext that can never be read back.
        let cipher = cipher();
        let arr = FfiValue::Array(vec![pt(FfiValue::Int64(1)), pt(FfiValue::Int64(2))]);
        assert!(arr.encrypt(&cipher).is_err());
        let obj = FfiValue::Object(vec![
            ("a".into(), pt(FfiValue::Int64(1))),
            ("b".into(), pt(FfiValue::Int64(2))),
        ]);
        assert!(obj.encrypt(&cipher).is_err());
        // One sealed sibling makes the container authenticated again.
        let mixed = FfiValue::Array(vec![pt(FfiValue::Int64(1)), FfiValue::Int64(2)]);
        assert!(mixed.encrypt(&cipher).is_ok());
    }

    #[test]
    fn duplicate_object_keys_are_rejected_at_encrypt() {
        // `decrypt_map` rejects duplicate keys outright, so accepting one at
        // seal time would produce a permanently unreadable ciphertext. The
        // encrypt path now fails symmetrically.
        let cipher = cipher();
        let dup = FfiValue::Object(vec![
            ("a".into(), FfiValue::Int64(1)),
            ("a".into(), FfiValue::Int64(2)),
        ]);
        assert!(dup.encrypt(&cipher).is_err());
        let distinct = FfiValue::Object(vec![
            ("a".into(), FfiValue::Int64(1)),
            ("b".into(), FfiValue::Int64(2)),
        ]);
        assert!(distinct.encrypt(&cipher).is_ok());
        // The passthrough entry path enforces the same rejection.
        let dup_mixed = FfiValue::Object(vec![
            ("a".into(), FfiValue::Int64(1)),
            ("a".into(), pt(FfiValue::Int64(2))),
        ]);
        assert!(dup_mixed.encrypt(&cipher).is_err());
    }

    #[test]
    fn utf8_string_validates_at_construction() {
        // Valid UTF-8 is accepted from raw bytes...
        let ok = Utf8String::try_from(Protected::new("héllo".as_bytes().to_vec()));
        assert!(ok.is_ok());
        assert_eq!(ok.expect("valid utf-8").risky_ref(), "héllo".as_bytes());
        // ...invalid bytes are refused at construction, so a `String` leaf
        // can never seal a payload the decrypt side will reject.
        assert!(Utf8String::try_from(Protected::new(vec![0xFF, 0xFE])).is_err());
        // `From<String>`/`From<&str>` are valid by type.
        assert_eq!(Utf8String::from("abc").risky_ref(), b"abc");
        assert_eq!(Utf8String::from(String::from("xyz")).risky_ref(), b"xyz");
        // `into_inner` hands back the same bytes.
        assert_eq!(Utf8String::from("abc").into_inner().risky_ref(), b"abc");
    }
}
