use std::any::Any;
use std::borrow::Cow;

#[cfg(feature = "rust_decimal")]
use crate::tagged::TaggedDecimal;
use crate::tagged::{
    TaggedBoolFalse, TaggedBoolTrue, TaggedBytes, TaggedFloat32, TaggedFloat64, TaggedInt128,
    TaggedInt16, TaggedInt32, TaggedInt64, TaggedInt8, TaggedNull, TaggedString, TaggedUInt128,
    TaggedUInt16, TaggedUInt32, TaggedUInt64, TaggedUInt8, TaggedUndefined,
};
#[cfg(feature = "chrono")]
use crate::tagged::{TaggedDate, TaggedTimestamp};
use crate::tags;
use vitaminc_aead::{
    Cipher, Decipher, DecipherVisitor, Decrypt, Encrypt, IntoAad, MapAccess, MapCipher, SeqAccess,
    Unspecified,
};
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

/// An owned, `Send`, language-neutral value model for dynamically typed
/// data, usable with any [`Encrypt`]/[`Decrypt`] cipher. Bindings also use
/// it to bridge host values (typically bound to a host thread or environment
/// handle) into the thread-independent encryption traits.
///
/// Host values are converted into `Value` on the host's thread by the
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
/// by both signedness and width: 8-, 16-, 32-, 64- and 128-bit exact
/// integers, and
/// [`Float32`](Value::Float32) / [`Float64`](Value::Float64) for
/// IEEE-754 values. The 32-bit widths exist for schema fidelity with the
/// EQL layer (Postgres `int4`/`float4`), not byte savings. See the crate
/// docs for the cross-language type mapping.
///
/// The cross-language contract is the frozen tag table plus the leaf
/// encodings (see [`tags`]); this enum is merely Rust's materialization of
/// that model. Bindings in other languages implement the model, not this
/// enum.
///
/// Cloning makes a deep copy, including a fresh [`Protected`] allocation for
/// every string and byte leaf, also inside passthrough subtrees. A clone stays
/// under the same custody as its original: its protected leaves are wiped on
/// drop, and callers must uphold the same rules when exposing plaintext.
///
/// This enum is non-exhaustive so new kinds can be added. Downstream matches
/// must handle unsupported variants.
///
/// Optional chrono/decimal scalars are inline values, without protected
/// custody; their external types do not implement [`Zeroize`], so explicit
/// zeroization skips them. Strings and bytes remain inside [`Protected`].
#[derive(Clone, Zeroize)]
#[non_exhaustive]
pub enum Value {
    /// Null (JS `null`, Python `None`, Go `nil`).
    Null,
    /// JavaScript `undefined`. Languages without an analog decode this to
    /// their null value and never encode it.
    Undefined,
    /// Boolean.
    Bool(bool),
    /// 32-bit signed integer. For schema fidelity with `int4` at the EQL
    /// layer; integer-typed languages keep it distinct from
    /// [`Int64`](Value::Int64).
    Int32(i32),
    /// 64-bit signed integer. Kept distinct from the float tags so
    /// integer-typed languages round-trip integers as integers.
    Int64(i64),
    /// 32-bit unsigned integer. For schema fidelity with the EQL layer.
    UInt32(u32),
    /// 64-bit unsigned integer. Kept distinct from [`Int64`](Value::Int64)
    /// so unsigned values above `i64::MAX` — previously unrepresentable —
    /// round trip losslessly without widening to a 128-bit kind.
    UInt64(u64),
    /// 32-bit floating-point number. Round-trips by IEEE-754 bit pattern
    /// (`NaN` payloads and `-0.0` survive). For schema fidelity with
    /// `float4` at the EQL layer.
    Float32(f32),
    /// 64-bit floating-point number. Round-trips by IEEE-754 bit pattern.
    /// This is the tag a JavaScript `number` maps to.
    Float64(f64),
    /// 8-bit signed integer.
    Int8(i8),
    /// 8-bit unsigned integer.
    UInt8(u8),
    /// 16-bit signed integer.
    Int16(i16),
    /// 16-bit unsigned integer.
    UInt16(u16),
    /// 128-bit signed integer.
    Int128(i128),
    /// 128-bit unsigned integer.
    UInt128(u128),
    /// Calendar date; CE day count preserves the exact date. Requires `chrono`.
    #[cfg(feature = "chrono")]
    #[zeroize(skip)]
    Date(chrono::NaiveDate),
    /// UTC timestamp, preserving nanoseconds and chrono leap seconds. Requires `chrono`.
    #[cfg(feature = "chrono")]
    #[zeroize(skip)]
    Timestamp(chrono::DateTime<chrono::Utc>),
    /// Finite decimal, preserving the original scale (e.g. `1.50`). Requires `rust_decimal`.
    #[cfg(feature = "rust_decimal")]
    #[zeroize(skip)]
    Decimal(rust_decimal::Decimal),
    /// String as UTF-8 bytes. The [`Utf8String`] payload validates UTF-8 at
    /// construction — a `String` leaf can never seal bytes the decrypt side
    /// would refuse — and holds them inside [`Protected`] so the copy is
    /// wiped on drop.
    String(Utf8String),
    /// Binary data.
    Bytes(Protected<Vec<u8>>),
    /// Array. Encrypts via the cipher's sequence mode.
    Array(Vec<Value>),
    /// String-keyed object/map. Encrypts via the cipher's map mode: keys
    /// travel in the clear (bound into each value's AAD — see
    /// [`Context::for_map_entry`](vitaminc_aead::Context::for_map_entry)); values are
    /// sealed.
    Object(Vec<(String, Value)>),
    /// A subtree that travels alongside the ciphertext **unencrypted and
    /// unauthenticated**, via the cipher's passthrough channel (see
    /// [`Cipher::passthrough`]). The wrapped value — which may be any
    /// `Value`, including a whole [`Array`](Value::Array) or
    /// [`Object`](Value::Object) subtree — is then entirely plaintext: it
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
    Passthrough(Box<Value>),
}

// No `ZeroizeOnDrop` derive: it would add a `Drop` impl, and `Drop` types
// cannot be destructured — the `Encrypt` impl moves leaves out of `self`.
// The secret-bearing leaves are inside `Protected`, which wipes on drop on
// its own; container metadata (numbers, booleans, keys) can be wiped
// explicitly via `Zeroize` where callers need it. The optional chrono and
// rust_decimal scalars do not implement `Zeroize` and are skipped, as is
// passthrough. Like the other inline scalars, they are not protected storage.

/// UTF-8 string payload for [`Value::String`], validated at construction.
///
/// Wraps `Protected<Vec<u8>>` with the invariant that the bytes are valid
/// UTF-8. The decrypt visitor only ever rebuilds one from bytes it has just
/// validated, and every constructor here validates (or starts from a
/// `String`, which is valid by type) — so a `String` leaf can never seal
/// bytes the decrypt side will refuse. Without this, a hand-built
/// `Value::String` of arbitrary bytes would encrypt Ok and then fail
/// every decrypt forever: silent data loss discovered only at read time.
///
/// Cloning copies the bytes into a fresh [`Protected`] under the same custody.
#[derive(Clone, Zeroize)]
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

impl Encrypt for Value {
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
            Value::Null => TaggedNull::tag_only().encrypt_with_aad(cipher, aad),
            Value::Undefined => TaggedUndefined::tag_only().encrypt_with_aad(cipher, aad),
            Value::Bool(false) => TaggedBoolFalse::tag_only().encrypt_with_aad(cipher, aad),
            Value::Bool(true) => TaggedBoolTrue::tag_only().encrypt_with_aad(cipher, aad),
            Value::Int32(i) => TaggedInt32::from(i).encrypt_with_aad(cipher, aad),
            Value::Int64(i) => TaggedInt64::from(i).encrypt_with_aad(cipher, aad),
            Value::UInt32(u) => TaggedUInt32::from(u).encrypt_with_aad(cipher, aad),
            Value::UInt64(u) => TaggedUInt64::from(u).encrypt_with_aad(cipher, aad),
            Value::Float32(f) => TaggedFloat32::from(f).encrypt_with_aad(cipher, aad),
            Value::Float64(f) => TaggedFloat64::from(f).encrypt_with_aad(cipher, aad),
            Value::Int8(v) => TaggedInt8::from(v).encrypt_with_aad(cipher, aad),
            Value::UInt8(v) => TaggedUInt8::from(v).encrypt_with_aad(cipher, aad),
            Value::Int16(v) => TaggedInt16::from(v).encrypt_with_aad(cipher, aad),
            Value::UInt16(v) => TaggedUInt16::from(v).encrypt_with_aad(cipher, aad),
            Value::Int128(v) => TaggedInt128::from(v).encrypt_with_aad(cipher, aad),
            Value::UInt128(v) => TaggedUInt128::from(v).encrypt_with_aad(cipher, aad),
            #[cfg(feature = "chrono")]
            Value::Date(v) => TaggedDate::from(v).encrypt_with_aad(cipher, aad),
            #[cfg(feature = "chrono")]
            Value::Timestamp(v) => TaggedTimestamp::from(v).encrypt_with_aad(cipher, aad),
            #[cfg(feature = "rust_decimal")]
            Value::Decimal(v) => TaggedDecimal::from(v).encrypt_with_aad(cipher, aad),
            Value::String(s) => TaggedString::new(s.into_inner()).encrypt_with_aad(cipher, aad),
            Value::Bytes(b) => TaggedBytes::new(b).encrypt_with_aad(cipher, aad),
            // Delegate to the built-in `Vec<T>` impl (`Value: Encrypt`)
            // so the sequence wire protocol has exactly one definition —
            // element positions are carried structurally, not authenticated;
            // see `Context::for_sequence_element`. A nested `Passthrough`
            // element routes identically either way, via its own arm below.
            Value::Array(items) => items.encrypt_with_aad(cipher, aad),
            Value::Object(entries) => {
                // Mirror the built-in `HashMap` impls; the cipher binds each
                // key into its value's AAD via `Context::for_map_entry`.
                entries
                    .into_iter()
                    .try_fold(cipher.encrypt_map(aad), |c, (key, value)| {
                        c.encrypt_entry(Cow::Owned(key), value)
                    })?
                    .end()
            }
            Value::Passthrough(inner) => {
                // Route the (non-sensitive, unauthenticated) subtree through
                // the cipher's type-erased passthrough channel. This impl is
                // generic over every cipher, so it cannot name a specific
                // cipher's `Passthrough` type; `passthrough_boxed` takes the
                // subtree as `Box<dyn Any + Send>` and each cipher absorbs it
                // (for the Rust-native ciphers that type *is* the box).
                // No AAD is consumed — passthrough values are not
                // authenticated. `ValueVisitor::visit_passthrough` downcasts
                // the box back to a `Value` on decrypt.
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

struct ValueVisitor;

impl<'c> DecipherVisitor<'c> for ValueVisitor {
    type Value = Value;

    fn visit_bytes_vec(self, data: Protected<Vec<u8>>) -> Result<Self::Value, Unspecified> {
        let bytes = data.risky_ref();
        let (&t, payload) = bytes.split_first().ok_or(Unspecified)?;
        // The `try_into` on each fixed-width arm rejects any payload that is
        // not exactly the tag's width — truncated or over-long leaves fail.
        match (t, payload) {
            (tags::NULL, []) => Ok(Value::Null),
            (tags::UNDEFINED, []) => Ok(Value::Undefined),
            (tags::BOOL_FALSE, []) => Ok(Value::Bool(false)),
            (tags::BOOL_TRUE, []) => Ok(Value::Bool(true)),
            (tags::INT32, bytes) => {
                let bytes: [u8; 4] = bytes.try_into().map_err(|_| Unspecified)?;
                Ok(Value::Int32(i32::from_le_bytes(bytes)))
            }
            (tags::INT64, bytes) => {
                let bytes: [u8; 8] = bytes.try_into().map_err(|_| Unspecified)?;
                Ok(Value::Int64(i64::from_le_bytes(bytes)))
            }
            (tags::UINT32, bytes) => {
                let bytes: [u8; 4] = bytes.try_into().map_err(|_| Unspecified)?;
                Ok(Value::UInt32(u32::from_le_bytes(bytes)))
            }
            (tags::UINT64, bytes) => {
                let bytes: [u8; 8] = bytes.try_into().map_err(|_| Unspecified)?;
                Ok(Value::UInt64(u64::from_le_bytes(bytes)))
            }
            (tags::FLOAT32, bits) => {
                let bits: [u8; 4] = bits.try_into().map_err(|_| Unspecified)?;
                Ok(Value::Float32(f32::from_bits(u32::from_le_bytes(bits))))
            }
            (tags::FLOAT64, bits) => {
                let bits: [u8; 8] = bits.try_into().map_err(|_| Unspecified)?;
                Ok(Value::Float64(f64::from_bits(u64::from_le_bytes(bits))))
            }
            (tags::INT8, bytes) => {
                let bytes: [u8; 1] = bytes.try_into().map_err(|_| Unspecified)?;
                Ok(Value::Int8(i8::from_le_bytes(bytes)))
            }
            (tags::UINT8, bytes) => {
                let bytes: [u8; 1] = bytes.try_into().map_err(|_| Unspecified)?;
                Ok(Value::UInt8(u8::from_le_bytes(bytes)))
            }
            (tags::INT16, bytes) => {
                let bytes: [u8; 2] = bytes.try_into().map_err(|_| Unspecified)?;
                Ok(Value::Int16(i16::from_le_bytes(bytes)))
            }
            (tags::UINT16, bytes) => {
                let bytes: [u8; 2] = bytes.try_into().map_err(|_| Unspecified)?;
                Ok(Value::UInt16(u16::from_le_bytes(bytes)))
            }
            (tags::INT128, bytes) => {
                let bytes: [u8; 16] = bytes.try_into().map_err(|_| Unspecified)?;
                Ok(Value::Int128(i128::from_le_bytes(bytes)))
            }
            (tags::UINT128, bytes) => {
                let bytes: [u8; 16] = bytes.try_into().map_err(|_| Unspecified)?;
                Ok(Value::UInt128(u128::from_le_bytes(bytes)))
            }
            #[cfg(feature = "chrono")]
            (tags::DATE, bytes) => crate::scalar::decode_date(bytes).map(Value::Date),
            #[cfg(feature = "chrono")]
            (tags::TIMESTAMP, bytes) => {
                crate::scalar::decode_timestamp(bytes).map(Value::Timestamp)
            }
            #[cfg(feature = "rust_decimal")]
            (tags::DECIMAL, bytes) => crate::scalar::decode_decimal(bytes).map(Value::Decimal),
            (tags::STRING, utf8) => {
                // Validate now so host conversions later are infallible.
                std::str::from_utf8(utf8).map_err(|_| Unspecified)?;
                Ok(Value::String(Utf8String(Protected::new(utf8.to_vec()))))
            }
            (tags::BYTES, raw) => Ok(Value::Bytes(Protected::new(raw.to_vec()))),
            _ => Err(Unspecified),
        }
        // `data` drops (and wipes) here; leaf payloads were copied into
        // fresh `Protected` values.
    }

    fn visit_seq<A: SeqAccess<'c>>(self, mut seq: A) -> Result<Self::Value, Unspecified> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<Value>().map_err(|_| Unspecified)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'c>>(self, mut map: A) -> Result<Self::Value, Unspecified> {
        let mut entries = Vec::new();
        while let Some(entry) = map.next_entry::<Value>().map_err(|_| Unspecified)? {
            entries.push(entry);
        }
        Ok(Value::Object(entries))
    }

    /// A Rust-side `Option::None` sealed with `encrypt_none` maps onto
    /// [`Value::Null`] — the closest host analog of an authenticated
    /// absent value. (Host-originated values never produce this shape:
    /// `Null` and `Undefined` are tagged leaves.)
    fn visit_none(self) -> Result<Self::Value, Unspecified> {
        Ok(Value::Null)
    }

    /// Recover a passthrough subtree, preserving its marking so a decrypted
    /// tree records which fields travelled in the clear. The payload was boxed
    /// as a `Value` by this crate's [`Encrypt`] impl; a box carrying any
    /// other concrete type (a foreign payload never produced here) is rejected
    /// with [`Unspecified`] rather than panicking on the downcast.
    fn visit_passthrough(
        self,
        value: Box<dyn Any + Send + 'static>,
    ) -> Result<Self::Value, Unspecified> {
        value
            .downcast::<Value>()
            .map(Value::Passthrough)
            .map_err(|_| Unspecified)
    }
}

impl<'c> Decrypt<'c> for Value {
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        // The value's type is recovered from the ciphertext shape (and the
        // authenticated leaf tag), not fixed by the caller.
        decipher.decrypt_any(ValueVisitor, aad)
    }
}

#[cfg(test)]
impl PartialEq for Value {
    /// Structural equality for tests only. Variable-time — leaf comparisons
    /// use ordinary byte equality — which is why this is `cfg(test)`: use
    /// `vitaminc_protected::Equatable` where constant-time equality of
    /// secrets is required. Floats compare by raw bit pattern so `-0.0` and
    /// `NaN` payloads compare as they seal.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Undefined, Value::Undefined) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Int32(a), Value::Int32(b)) => a == b,
            (Value::Int64(a), Value::Int64(b)) => a == b,
            (Value::UInt32(a), Value::UInt32(b)) => a == b,
            (Value::UInt64(a), Value::UInt64(b)) => a == b,
            (Value::Float32(a), Value::Float32(b)) => a.to_bits() == b.to_bits(),
            (Value::Float64(a), Value::Float64(b)) => a.to_bits() == b.to_bits(),
            (Value::Int8(a), Value::Int8(b)) => a == b,
            (Value::UInt8(a), Value::UInt8(b)) => a == b,
            (Value::Int16(a), Value::Int16(b)) => a == b,
            (Value::UInt16(a), Value::UInt16(b)) => a == b,
            (Value::Int128(a), Value::Int128(b)) => a == b,
            (Value::UInt128(a), Value::UInt128(b)) => a == b,
            #[cfg(feature = "chrono")]
            (Value::Date(a), Value::Date(b)) => a == b,
            #[cfg(feature = "chrono")]
            (Value::Timestamp(a), Value::Timestamp(b)) => a == b,
            #[cfg(feature = "rust_decimal")]
            (Value::Decimal(a), Value::Decimal(b)) => a.serialize() == b.serialize(),
            (Value::String(a), Value::String(b)) => a.risky_ref() == b.risky_ref(),
            (Value::Bytes(a), Value::Bytes(b)) => a.risky_ref() == b.risky_ref(),
            (Value::Array(a), Value::Array(b)) => a == b,
            (Value::Object(a), Value::Object(b)) => a == b,
            (Value::Passthrough(a), Value::Passthrough(b)) => a == b,
            _ => false,
        }
    }
}

#[cfg(test)]
impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Null => f.write_str("Null"),
            Value::Undefined => f.write_str("Undefined"),
            Value::Bool(b) => write!(f, "Bool({b})"),
            Value::Int32(i) => write!(f, "Int32({i})"),
            Value::Int64(i) => write!(f, "Int64({i})"),
            Value::UInt32(u) => write!(f, "UInt32({u})"),
            Value::UInt64(u) => write!(f, "UInt64({u})"),
            Value::Float32(n) => write!(f, "Float32({n})"),
            Value::Float64(n) => write!(f, "Float64({n})"),
            Value::Int8(v) => write!(f, "Int8({v})"),
            Value::UInt8(v) => write!(f, "UInt8({v})"),
            Value::Int16(v) => write!(f, "Int16({v})"),
            Value::UInt16(v) => write!(f, "UInt16({v})"),
            Value::Int128(v) => write!(f, "Int128({v})"),
            Value::UInt128(v) => write!(f, "UInt128({v})"),
            #[cfg(feature = "chrono")]
            Value::Date(v) => write!(f, "Date({v})"),
            #[cfg(feature = "chrono")]
            Value::Timestamp(v) => write!(f, "Timestamp({v})"),
            #[cfg(feature = "rust_decimal")]
            Value::Decimal(v) => write!(f, "Decimal({v})"),
            Value::String(_) => f.write_str("String(<redacted>)"),
            Value::Bytes(_) => f.write_str("Bytes(<redacted>)"),
            Value::Array(items) => f.debug_tuple("Array").field(items).finish(),
            Value::Object(entries) => f.debug_tuple("Object").field(entries).finish(),
            Value::Passthrough(inner) => f.debug_tuple("Passthrough").field(inner).finish(),
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

    fn s(v: &str) -> Value {
        Value::String(v.into())
    }

    #[test]
    fn clone_preserves_every_variant_and_float_bits() {
        let values = [
            Value::Null,
            Value::Undefined,
            Value::Bool(false),
            Value::Bool(true),
            Value::Int32(i32::MIN),
            Value::Int64(i64::MIN),
            Value::UInt32(u32::MAX),
            Value::UInt64(u64::MAX),
            Value::Float32(f32::from_bits(0x7fc0_0001)),
            Value::Float32(-0.0),
            Value::Float64(f64::from_bits(0x7ff8_0000_0000_0001)),
            Value::Float64(-0.0),
            s("secret 🦀"),
            s(""),
            Value::Bytes(Protected::new(vec![0, 255])),
            Value::Bytes(Protected::new(vec![])),
            Value::Array(vec![s("nested")]),
            Value::Object(vec![("key".into(), s("nested"))]),
            Value::Passthrough(Box::new(s("clear"))),
        ];
        for value in values {
            assert_eq!(value.clone(), value);
        }
    }

    #[test]
    fn clone_owns_fresh_protected_leaves_through_nested_containers() {
        let original = Value::Object(vec![(
            "key".into(),
            Value::Array(vec![
                s("secret"),
                Value::Bytes(Protected::new(vec![1, 2, 3])),
                Value::Passthrough(Box::new(s("clear"))),
            ]),
        )]);
        let cloned = original.clone();

        // Compare allocations while both trees are alive, including the
        // protected string within a passthrough subtree.
        fn leaves(value: &Value) -> Vec<&[u8]> {
            match value {
                Value::String(s) => vec![s.risky_ref()],
                Value::Bytes(b) => vec![b.risky_ref()],
                Value::Array(items) => items.iter().flat_map(leaves).collect(),
                Value::Object(entries) => entries.iter().flat_map(|(_, v)| leaves(v)).collect(),
                Value::Passthrough(inner) => leaves(inner),
                _ => vec![],
            }
        }
        let originals = leaves(&original);
        let copies = leaves(&cloned);
        assert_eq!(originals.len(), 3);
        assert_eq!(copies.len(), originals.len());
        for (a, b) in originals.iter().zip(&copies) {
            assert_eq!(a, b);
            assert_ne!(a.as_ptr(), b.as_ptr());
        }

        // Wiping/dropping the original must not alter the clone.
        let expected = leaves(&cloned)
            .iter()
            .map(|b| b.to_vec())
            .collect::<Vec<_>>();
        let mut original = original;
        original.zeroize();
        drop(original);
        assert_eq!(leaves(&cloned), expected);
        assert_eq!(roundtrip(cloned.clone()), cloned);
    }

    /// The `Debug` impl exists for assertion failures, so a passing suite
    /// never formats one — exercise it explicitly, and pin the property that
    /// matters: secret-bearing leaves must render redacted, so a failing
    /// assertion in any downstream test can't spill plaintext into CI logs.
    #[test]
    fn debug_redacts_secret_leaves_and_renders_the_rest() {
        // Scalars render their value — the numeric tags are distinguishable,
        // which is the point of the split numeric family.
        assert_eq!(format!("{:?}", Value::Null), "Null");
        assert_eq!(format!("{:?}", Value::Undefined), "Undefined");
        assert_eq!(format!("{:?}", Value::Bool(true)), "Bool(true)");
        assert_eq!(format!("{:?}", Value::Int32(-1)), "Int32(-1)");
        assert_eq!(format!("{:?}", Value::Int64(-1)), "Int64(-1)");
        assert_eq!(format!("{:?}", Value::UInt32(1)), "UInt32(1)");
        assert_eq!(format!("{:?}", Value::UInt64(1)), "UInt64(1)");
        assert_eq!(format!("{:?}", Value::Float32(1.5)), "Float32(1.5)");
        assert_eq!(format!("{:?}", Value::Float64(1.5)), "Float64(1.5)");

        // The two secret-bearing variants never show their contents.
        let secret = format!("{:?}", s("hunter2"));
        assert_eq!(secret, "String(<redacted>)");
        assert!(!secret.contains("hunter2"));
        let bytes = Value::Bytes(Protected::new(vec![0xDE, 0xAD]));
        assert_eq!(format!("{bytes:?}"), "Bytes(<redacted>)");

        // Containers recurse, so nested secrets stay redacted too — including
        // through a passthrough wrapper.
        assert_eq!(
            format!("{:?}", Value::Array(vec![Value::Null, s("secret")])),
            "Array([Null, String(<redacted>)])"
        );
        let obj = Value::Object(vec![("k".to_string(), s("secret"))]);
        let rendered = format!("{obj:?}");
        assert!(rendered.contains("String(<redacted>)"), "{rendered}");
        assert!(!rendered.contains("secret"), "{rendered}");
        assert_eq!(
            format!("{:?}", Value::Passthrough(Box::new(s("secret")))),
            "Passthrough(String(<redacted>))"
        );
    }

    fn roundtrip(value: Value) -> Value {
        roundtrip_with_aad(value, ())
    }

    fn roundtrip_with_aad<'a, A: IntoAad<'a> + Clone>(value: Value, aad: A) -> Value {
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

            fn passthrough_entry_boxed<K>(
                self,
                _key: K,
                _value: Box<dyn std::any::Any + Send + 'static>,
            ) -> Result<Self, Self::Error>
            where
                K: Into<std::borrow::Cow<'static, str>>,
            {
                Ok(self)
            }

            fn end(self) -> Result<Self::Ok, Self::Error> {
                Err(Unspecified)
            }
        }
    }

    /// The exact leaf plaintext a value seals — the conformance vector.
    fn leaf_bytes(value: Value) -> Vec<u8> {
        let capture = kat::CapturingCipher {
            plaintext: std::cell::RefCell::new(Vec::new()),
        };
        value.encrypt(&capture).expect("leaf encrypt");
        let bytes = capture.plaintext.borrow().clone();
        bytes
    }

    // Pin encryption and transport independently to the same wire bytes,
    // and check that clone/decrypt preserve the exact value and decimal scale.
    fn assert_scalar(value: Value, expected: &[u8]) {
        let kind = value.kind().expect("scalar kind");
        assert_eq!(kind.tags(), &expected[..1]);
        assert_eq!(leaf_bytes(value.clone()), expected);
        assert_eq!(roundtrip(value.clone()), value);
        let mut wire = Vec::new();
        crate::transport::encode_value(value.clone(), &mut wire).expect("encode");
        assert_eq!(wire, expected);
        let decoded = crate::transport::decode_value(&mut crate::transport::Reader::new(&wire))
            .expect("decode");
        assert_eq!(decoded, value);
    }

    fn assert_invalid_scalar(bytes: Vec<u8>) {
        assert!(
            crate::transport::decode_value(&mut crate::transport::Reader::new(&bytes)).is_err()
        );
        let cipher = cipher();
        let ct = (&cipher)
            .encrypt_bytes_vec(Protected::new(bytes), vitaminc_aead::Context::empty())
            .expect("seal raw bytes");
        assert!(cipher.decrypt::<Value>(ct).is_err());
    }

    #[test]
    fn kat_new_integer_widths() {
        assert_scalar(Value::Int8(-1), &[0x0C, 0xFF]);
        assert_scalar(Value::Int8(i8::MIN), &[0x0C, 0x80]);
        assert_scalar(Value::Int8(i8::MAX), &[0x0C, 0x7F]);
        assert_scalar(Value::UInt8(u8::MAX), &[0x0D, 0xFF]);
        assert_scalar(Value::UInt8(0), &[0x0D, 0]);
        assert_scalar(Value::Int16(-1), &[0x0E, 0xFF, 0xFF]);
        assert_scalar(Value::Int16(i16::MIN), &[0x0E, 0, 0x80]);
        assert_scalar(Value::Int16(i16::MAX), &[0x0E, 0xFF, 0x7F]);
        assert_scalar(Value::UInt16(u16::MAX), &[0x0F, 0xFF, 0xFF]);
        assert_scalar(Value::UInt16(0x1234), &[0x0F, 0x34, 0x12]);
        assert_scalar(
            Value::Int128(-1),
            &[
                0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF,
            ],
        );
        assert_scalar(
            Value::Int128(i128::MIN),
            &[0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80],
        );
        assert_scalar(
            Value::Int128(i128::MAX),
            &[
                0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0x7F,
            ],
        );
        assert_scalar(
            Value::UInt128(u128::MAX),
            &[
                0x11, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF,
            ],
        );
        assert_scalar(
            Value::UInt128(0x0F0E0D0C0B0A09080706050403020100),
            &[0x11, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        );
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn kat_dates_and_nanosecond_timestamps() {
        assert_scalar(
            Value::Date(chrono::NaiveDate::from_ymd_opt(1, 1, 1).expect("date")),
            &[0x12, 1, 0, 0, 0],
        );
        assert_scalar(
            Value::Date(chrono::NaiveDate::from_ymd_opt(1970, 1, 1).expect("date")),
            &[0x12, 0x3B, 0xF9, 0x0A, 0],
        );
        assert_scalar(
            Value::Date(chrono::NaiveDate::from_num_days_from_ce_opt(-1).expect("date")),
            &[0x12, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_scalar(
            Value::Timestamp(chrono::DateTime::UNIX_EPOCH),
            &[0x13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        assert_scalar(
            Value::Timestamp(chrono::DateTime::from_timestamp(-1, 123_456_789).expect("timestamp")),
            &[
                0x13, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x15, 0xCD, 0x5B, 0x07,
            ],
        );
        // Chrono's leap-second representation is preserved, not normalized.
        assert_scalar(
            Value::Timestamp(
                chrono::DateTime::from_timestamp(59, 1_500_000_000).expect("leap second"),
            ),
            &[0x13, 59, 0, 0, 0, 0, 0, 0, 0, 0, 0x2F, 0x68, 0x59],
        );
        for date in [chrono::NaiveDate::MIN, chrono::NaiveDate::MAX] {
            assert_eq!(roundtrip(Value::Date(date)), Value::Date(date));
        }
        for timestamp in [
            chrono::DateTime::<chrono::Utc>::MIN_UTC,
            chrono::DateTime::<chrono::Utc>::MAX_UTC,
        ] {
            assert_eq!(
                roundtrip(Value::Timestamp(timestamp)),
                Value::Timestamp(timestamp)
            );
        }
    }

    #[cfg(feature = "rust_decimal")]
    #[test]
    fn kat_decimal_keeps_scale_sign_and_all_mantissa_words() {
        use rust_decimal::Decimal;
        assert_scalar(
            Value::Decimal(Decimal::new(150, 2)),
            &[0x14, 0, 0, 2, 0, 150, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        assert_scalar(
            Value::Decimal(Decimal::new(15, 1)),
            &[0x14, 0, 0, 1, 0, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        assert_scalar(
            Value::Decimal(Decimal::new(-150, 2)),
            &[0x14, 0, 0, 2, 0x80, 150, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        assert_scalar(
            Value::Decimal(Decimal::from_parts(
                0x03020100, 0x07060504, 0x0B0A0908, false, 28,
            )),
            &[0x14, 0, 0, 28, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        );
        for decimal in [
            Decimal::MIN,
            Decimal::MAX,
            Decimal::new(0, 28),
            Decimal::from_parts(0, 0, 0, true, 2),
        ] {
            let expected = decimal.serialize();
            let Value::Decimal(decoded) = roundtrip(Value::Decimal(decimal)) else {
                panic!("decimal")
            };
            assert_eq!(decoded.serialize(), expected);
            assert_eq!(decoded.scale(), decimal.scale());
        }
        let Value::Decimal(decoded) = roundtrip(Value::Decimal(Decimal::new(150, 2))) else {
            panic!("decimal")
        };
        assert_eq!(decoded.to_string(), "1.50");
    }

    #[test]
    fn new_fixed_width_payloads_reject_wrong_lengths() {
        for (tag, width) in [
            (0x0C, 1),
            (0x0D, 1),
            (0x0E, 2),
            (0x0F, 2),
            (0x10, 16),
            (0x11, 16),
            (0x12, 4),
            (0x13, 12),
            (0x14, 16),
        ] {
            for len in [width - 1, width + 1] {
                let mut bytes = vec![tag];
                bytes.resize(1 + len, 0);
                assert_invalid_scalar(bytes);
            }
        }
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn invalid_dates_and_timestamps_are_rejected() {
        for days in [i32::MIN, i32::MAX] {
            let mut bytes = vec![0x12];
            bytes.extend_from_slice(&days.to_le_bytes());
            assert_invalid_scalar(bytes);
        }
        for (seconds, nanos) in [
            (i64::MIN, 0u32),
            (i64::MAX, 0),
            (0, 1_000_000_000),
            (59, 2_000_000_000),
            (0, u32::MAX),
        ] {
            let mut bytes = vec![0x13];
            bytes.extend_from_slice(&seconds.to_le_bytes());
            bytes.extend_from_slice(&nanos.to_le_bytes());
            assert_invalid_scalar(bytes);
        }
    }

    #[cfg(feature = "rust_decimal")]
    #[test]
    fn invalid_decimal_flags_are_rejected_without_rounding() {
        for flags in [1u32, 1 << 24, 29 << 16, 30 << 16, 31 << 16, 255 << 16] {
            let mut bytes = vec![0x14];
            bytes.extend_from_slice(&flags.to_le_bytes());
            bytes.extend_from_slice(&[150, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            assert_invalid_scalar(bytes);
        }
    }

    #[test]
    fn disabled_optional_scalar_features_reject_their_tags() {
        for (tag, width, enabled) in [
            (0x12, 4, cfg!(feature = "chrono")),
            (0x13, 12, cfg!(feature = "chrono")),
            (0x14, 16, cfg!(feature = "rust_decimal")),
        ] {
            if !enabled {
                let mut bytes = vec![tag];
                bytes.resize(width + 1, 0);
                assert_invalid_scalar(bytes);
            }
        }
    }

    #[test]
    fn kat_null() {
        assert_eq!(leaf_bytes(Value::Null), [0x00]);
    }

    #[test]
    fn kat_undefined() {
        assert_eq!(leaf_bytes(Value::Undefined), [0x01]);
    }

    #[test]
    fn kat_bool() {
        assert_eq!(leaf_bytes(Value::Bool(false)), [0x02]);
        assert_eq!(leaf_bytes(Value::Bool(true)), [0x03]);
    }

    /// `ValueKind::tags()` is a second map from variant to tag; the first is
    /// the `match` in `encrypt_with_aad`. Each `kat_*` test pins one side
    /// against literal bytes. This pins the two sides against each other, so a
    /// tag moved in one and not the other fails here.
    #[test]
    fn every_kinded_leaf_seals_under_a_tag_its_kind_names() {
        for value in [
            Value::Bool(false),
            Value::Bool(true),
            Value::Int32(-3),
            Value::Int64(-4),
            Value::UInt32(34),
            Value::UInt64(35),
            Value::Float32(1.5),
            Value::Float64(2.5),
            s("alice"),
            Value::Bytes(Protected::new(b"ab".to_vec())),
        ] {
            let kind = value.kind().expect("a scalar leaf has a kind");
            let tag = leaf_bytes(value)[0];
            assert!(
                kind.tags().contains(&tag),
                "{kind} does not name tag {tag:#04x}"
            );
        }
    }

    #[test]
    fn kat_int32() {
        assert_eq!(leaf_bytes(Value::Int32(42)), [0x04, 42, 0x00, 0x00, 0x00]);
        // -1: all ones (two's complement).
        assert_eq!(leaf_bytes(Value::Int32(-1)), [0x04, 0xFF, 0xFF, 0xFF, 0xFF]);
        // i32::MIN: sign bit only in the top byte.
        assert_eq!(
            leaf_bytes(Value::Int32(i32::MIN)),
            [0x04, 0x00, 0x00, 0x00, 0x80]
        );
    }

    #[test]
    fn kat_int64() {
        assert_eq!(
            leaf_bytes(Value::Int64(42)),
            [0x05, 42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        // -1: all ones (two's complement).
        assert_eq!(
            leaf_bytes(Value::Int64(-1)),
            [0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(
            leaf_bytes(Value::Int64(i64::MIN)),
            [0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]
        );
    }

    #[test]
    fn kat_uint32() {
        assert_eq!(leaf_bytes(Value::UInt32(0)), [0x06, 0x00, 0x00, 0x00, 0x00]);
        // u32::MAX: all ones.
        assert_eq!(
            leaf_bytes(Value::UInt32(u32::MAX)),
            [0x06, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn kat_uint64() {
        assert_eq!(
            leaf_bytes(Value::UInt64(42)),
            [0x07, 42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        // u64::MAX: all ones — the value INT64 cannot represent.
        assert_eq!(
            leaf_bytes(Value::UInt64(u64::MAX)),
            [0x07, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(
            leaf_bytes(Value::UInt64(0)),
            [0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn kat_float32() {
        // 1.5f32 = 0x3FC00000, little-endian.
        assert_eq!(
            leaf_bytes(Value::Float32(1.5)),
            [0x08, 0x00, 0x00, 0xC0, 0x3F]
        );
        // -0.0f32: sign bit only — distinct from +0.0 on the wire.
        assert_eq!(
            leaf_bytes(Value::Float32(-0.0)),
            [0x08, 0x00, 0x00, 0x00, 0x80]
        );
        // A specific NaN bit pattern survives by raw bits.
        let nan = f32::from_bits(0x7fc0_0001);
        assert_eq!(
            leaf_bytes(Value::Float32(nan)),
            [0x08, 0x01, 0x00, 0xC0, 0x7F]
        );
    }

    #[test]
    fn kat_float64() {
        // 1.5 = 0x3FF8000000000000, little-endian.
        assert_eq!(
            leaf_bytes(Value::Float64(1.5)),
            [0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x3F]
        );
        // -0.0: sign bit only — distinct from +0.0 on the wire.
        assert_eq!(
            leaf_bytes(Value::Float64(-0.0)),
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
            leaf_bytes(Value::Bytes(Protected::new(vec![0xDE, 0xAD]))),
            [0x0B, 0xDE, 0xAD]
        );
    }

    #[test]
    fn kat_int64_and_uint64_never_collide() {
        // Int64(-1) and UInt64(u64::MAX) share payload bytes but differ by
        // tag, so they never collide on the wire.
        assert_ne!(
            leaf_bytes(Value::Int64(-1)),
            leaf_bytes(Value::UInt64(u64::MAX))
        );
    }

    #[test]
    fn kat_int32_and_int64_never_collide() {
        // Same small value, different widths AND tags: 32- and 64-bit
        // integers never collide on the wire.
        assert_ne!(leaf_bytes(Value::Int32(7)), leaf_bytes(Value::Int64(7)));
    }

    #[test]
    fn kat_float32_and_float64_never_collide() {
        // 1.5 in binary32 and binary64 differ by tag, width, and bits.
        assert_ne!(
            leaf_bytes(Value::Float32(1.5)),
            leaf_bytes(Value::Float64(1.5))
        );
    }

    #[test]
    fn kat_int64_and_float64_never_collide() {
        // Int64(1) and Float64(1.0) are different types AND different bytes.
        assert_ne!(leaf_bytes(Value::Int64(1)), leaf_bytes(Value::Float64(1.0)));
    }

    // ---------------------------------------------------------------
    // Round trips through a real cipher
    // ---------------------------------------------------------------

    #[test]
    fn roundtrip_leaves() {
        assert_eq!(roundtrip(Value::Null), Value::Null);
        assert_eq!(roundtrip(Value::Undefined), Value::Undefined);
        assert_eq!(roundtrip(Value::Bool(true)), Value::Bool(true));
        assert_eq!(roundtrip(Value::Bool(false)), Value::Bool(false));
        assert_eq!(
            roundtrip(Value::Float64(1234.5678)),
            Value::Float64(1234.5678)
        );
        assert_eq!(
            roundtrip(Value::Float32(1234.5f32)),
            Value::Float32(1234.5f32)
        );
        assert_eq!(roundtrip(Value::Int32(0)), Value::Int32(0));
        assert_eq!(roundtrip(Value::Int32(i32::MAX)), Value::Int32(i32::MAX));
        assert_eq!(roundtrip(Value::Int32(i32::MIN)), Value::Int32(i32::MIN));
        assert_eq!(roundtrip(Value::Int64(0)), Value::Int64(0));
        assert_eq!(roundtrip(Value::Int64(i64::MAX)), Value::Int64(i64::MAX));
        assert_eq!(roundtrip(Value::Int64(i64::MIN)), Value::Int64(i64::MIN));
        assert_eq!(roundtrip(Value::UInt32(0)), Value::UInt32(0));
        assert_eq!(roundtrip(Value::UInt32(u32::MAX)), Value::UInt32(u32::MAX));
        assert_eq!(roundtrip(Value::UInt64(0)), Value::UInt64(0));
        assert_eq!(roundtrip(Value::UInt64(u64::MAX)), Value::UInt64(u64::MAX));
        assert_eq!(roundtrip(s("hello world")), s("hello world"));
        assert_eq!(
            roundtrip(Value::Bytes(Protected::new(vec![0, 159, 146, 150]))),
            Value::Bytes(Protected::new(vec![0, 159, 146, 150]))
        );
    }

    #[test]
    fn roundtrip_preserves_numeric_types() {
        // The decrypted variant matches the encrypted one — integers do not
        // collapse into floats, widths are preserved, and signedness holds.
        assert!(matches!(roundtrip(Value::Int32(1)), Value::Int32(1)));
        assert!(matches!(roundtrip(Value::Int64(1)), Value::Int64(1)));
        assert!(matches!(roundtrip(Value::UInt32(1)), Value::UInt32(1)));
        assert!(matches!(roundtrip(Value::UInt64(1)), Value::UInt64(1)));
        assert!(matches!(roundtrip(Value::Float32(1.0)), Value::Float32(_)));
        assert!(matches!(roundtrip(Value::Float64(1.0)), Value::Float64(_)));
    }

    #[test]
    fn roundtrip_float_edge_cases() {
        // Raw-bits round-trip: -0.0 and specific NaN payloads survive, in
        // both widths.
        assert_eq!(roundtrip(Value::Float64(-0.0)), Value::Float64(-0.0));
        assert_eq!(roundtrip(Value::Float32(-0.0)), Value::Float32(-0.0));
        assert_eq!(
            roundtrip(Value::Float64(f64::INFINITY)),
            Value::Float64(f64::INFINITY)
        );
        let nan64 = f64::from_bits(0x7ff8_dead_beef_0001);
        assert_eq!(roundtrip(Value::Float64(nan64)), Value::Float64(nan64));
        let nan32 = f32::from_bits(0x7fc0_0001);
        assert_eq!(roundtrip(Value::Float32(nan32)), Value::Float32(nan32));
    }

    #[test]
    fn roundtrip_nested_structure() {
        let make = || {
            Value::Object(vec![
                ("name".into(), s("alice")),
                ("age".into(), Value::Int64(30)),
                ("score".into(), Value::Float64(99.5)),
                ("rank".into(), Value::Int32(-3)),
                ("active".into(), Value::Bool(true)),
                ("nickname".into(), Value::Null),
                (
                    "tags".into(),
                    Value::Array(vec![s("a"), s("b"), Value::Int64(3)]),
                ),
                (
                    "nested".into(),
                    Value::Object(vec![(
                        "key".into(),
                        Value::Bytes(Protected::new(vec![1, 2, 3])),
                    )]),
                ),
            ])
        };
        assert_eq!(roundtrip(make()), make());
    }

    #[test]
    fn roundtrip_empty_containers() {
        assert_eq!(roundtrip(Value::Array(vec![])), Value::Array(vec![]));
        assert_eq!(roundtrip(Value::Object(vec![])), Value::Object(vec![]));
        assert_eq!(roundtrip(s("")), s(""));
        assert_eq!(
            roundtrip(Value::Bytes(Protected::new(vec![]))),
            Value::Bytes(Protected::new(vec![]))
        );
    }

    #[test]
    fn roundtrip_with_aad_binds() {
        let cipher = cipher();
        let ct = s("secret")
            .encrypt_with_aad(&cipher, "ctx")
            .expect("encrypt");
        // Wrong AAD must fail.
        assert!(cipher.decrypt_with_aad::<Value, _>(ct, "other").is_err());
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
        let as_bytes = Value::Bytes(Protected::new(b"abc".to_vec()))
            .encrypt(&cipher)
            .expect("encrypt bytes");
        let rs: Value = cipher.decrypt(as_string).expect("decrypt");
        let rb: Value = cipher.decrypt(as_bytes).expect("decrypt");
        assert!(matches!(rs, Value::String(_)));
        assert!(matches!(rb, Value::Bytes(_)));
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
                vitaminc_aead::Context::empty(),
            )
            .expect("encrypt raw");
        assert!(cipher.decrypt::<Value>(bad).is_err());
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
                .encrypt_bytes_vec(Protected::new(short), vitaminc_aead::Context::empty())
                .expect("encrypt raw");
            assert!(
                cipher.decrypt::<Value>(bad).is_err(),
                "tag {tag:#x} width-1 must fail"
            );
            // One byte long.
            let mut long = vec![tag];
            long.extend(std::iter::repeat_n(0u8, width + 1));
            let bad = (&cipher)
                .encrypt_bytes_vec(Protected::new(long), vitaminc_aead::Context::empty())
                .expect("encrypt raw");
            assert!(
                cipher.decrypt::<Value>(bad).is_err(),
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
                .encrypt_bytes_vec(
                    Protected::new(vec![tag, 0]),
                    vitaminc_aead::Context::empty(),
                )
                .expect("encrypt raw");
            assert!(cipher.decrypt::<Value>(bad).is_err());
        }
    }

    #[test]
    fn unknown_tag_fails() {
        let cipher = cipher();
        use vitaminc_aead::Cipher as _;
        let bad = (&cipher)
            .encrypt_bytes_vec(Protected::new(vec![0x7f]), vitaminc_aead::Context::empty())
            .expect("encrypt raw");
        assert!(cipher.decrypt::<Value>(bad).is_err());
        // Empty plaintext (no tag at all) also fails.
        let empty = (&cipher)
            .encrypt_bytes_vec(Protected::new(vec![]), vitaminc_aead::Context::empty())
            .expect("encrypt raw");
        assert!(cipher.decrypt::<Value>(empty).is_err());
    }

    #[test]
    fn rust_option_none_decrypts_as_null() {
        // A Rust `Option::None` sealed with `encrypt_none` surfaces as
        // `Null` through the self-describing path.
        let cipher = cipher();
        let ct = Option::<String>::None.encrypt(&cipher).expect("encrypt");
        let v: Value = cipher.decrypt(ct).expect("decrypt");
        assert_eq!(v, Value::Null);
    }

    #[test]
    fn swapped_object_keys_fail_decryption() {
        // End-to-end check that the map key binding protects objects.
        use vitaminc_encrypt::AesCipherText;
        let cipher = cipher();
        let value = Value::Object(vec![
            ("a".into(), Value::Int64(1)),
            ("b".into(), Value::Int64(2)),
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
        assert!(cipher.decrypt::<Value>(tampered).is_err());
    }

    // ---------------------------------------------------------------
    // Passthrough: unencrypted, unauthenticated fields alongside sealed ones
    // ---------------------------------------------------------------

    fn pt(v: Value) -> Value {
        Value::Passthrough(Box::new(v))
    }

    #[test]
    fn passthrough_free_value_is_unchanged() {
        // Regression guard for the new `Passthrough` variant: a value tree
        // that contains no passthrough nodes must seal exactly as before.
        // The scalar leaf bytes are still the frozen KATs, and a nested
        // passthrough-free structure still round-trips unchanged.
        assert_eq!(
            leaf_bytes(Value::Int64(42)),
            [0x05, 42, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(leaf_bytes(s("abc")), [0x0A, b'a', b'b', b'c']);
        let make = || {
            Value::Object(vec![
                ("name".into(), s("alice")),
                ("age".into(), Value::Int64(30)),
                ("tags".into(), Value::Array(vec![s("a"), Value::Int64(3)])),
            ])
        };
        assert_eq!(roundtrip(make()), make());
    }

    #[test]
    fn roundtrip_passthrough_leaf() {
        // A scalar wrapped in passthrough round-trips, keeping its marking.
        assert_eq!(roundtrip(pt(Value::Int64(42))), pt(Value::Int64(42)));
        assert_eq!(roundtrip(pt(s("in-the-clear"))), pt(s("in-the-clear")));
    }

    #[test]
    fn roundtrip_mixed_map_sealed_and_passthrough() {
        // The motivating shape: id/created_at pass through in the clear while
        // email/name are sealed. Everything round-trips, marking preserved.
        let make = || {
            Value::Object(vec![
                ("id".into(), pt(Value::Int64(42))),
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
            Value::Object(vec![
                ("kind".into(), s("public")),
                (
                    "labels".into(),
                    Value::Array(vec![s("a"), s("b"), Value::Int32(3)]),
                ),
            ])
        };
        let make = || {
            Value::Object(vec![
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
        let value = Value::Object(vec![
            ("id".into(), pt(Value::Int64(42))),
            ("email".into(), s("ada@example.com")),
        ]);
        let ct = value.encrypt(&cipher).expect("encrypt");
        let tampered = match ct {
            AesCipherText::Map(mut entries) => {
                for (key, node) in entries.iter_mut() {
                    if key == "id" {
                        *node = AesCipherText::Passthrough(Box::new(Value::Int64(999)));
                    }
                }
                AesCipherText::Map(entries)
            }
            _ => panic!("expected Map"),
        };
        let decrypted: Value = cipher.decrypt(tampered).expect("decrypt");
        match decrypted {
            Value::Object(entries) => {
                let id = entries.iter().find(|(k, _)| k == "id").expect("id");
                // The forged value is accepted — passthrough is unauthenticated.
                assert_eq!(id.1, pt(Value::Int64(999)));
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
        let value = Value::Object(vec![
            ("id".into(), pt(Value::Int64(42))),
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
        assert!(cipher.decrypt::<Value>(tampered).is_err());
    }

    #[test]
    fn foreign_passthrough_payload_is_rejected() {
        // A passthrough whose boxed payload is not a `Value` (a raw u32,
        // as a Rust-native cipher user might store) must be rejected cleanly
        // on the self-describing decode path — an error, never a panic.
        use vitaminc_encrypt::AesCipherText;
        let cipher = cipher();
        let ct: AesCipherText = AesCipherText::Passthrough(Box::new(42u32));
        assert!(cipher.decrypt::<Value>(ct).is_err());
    }

    #[test]
    fn passthrough_in_array_round_trips() {
        // Passthrough nested as an array element (not a map value) exercises
        // the seq recursion path into the passthrough arm.
        let make = || Value::Array(vec![s("sealed"), pt(Value::Int64(7)), Value::Int32(-1)]);
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
        let arr = Value::Array(vec![pt(Value::Int64(1)), pt(Value::Int64(2))]);
        assert!(arr.encrypt(&cipher).is_err());
        let obj = Value::Object(vec![
            ("a".into(), pt(Value::Int64(1))),
            ("b".into(), pt(Value::Int64(2))),
        ]);
        assert!(obj.encrypt(&cipher).is_err());
        // One sealed sibling makes the container authenticated again.
        let mixed = Value::Array(vec![pt(Value::Int64(1)), Value::Int64(2)]);
        assert!(mixed.encrypt(&cipher).is_ok());
    }

    #[test]
    fn duplicate_object_keys_are_rejected_at_encrypt() {
        // `decrypt_map` rejects duplicate keys outright, so accepting one at
        // seal time would produce a permanently unreadable ciphertext. The
        // encrypt path now fails symmetrically.
        let cipher = cipher();
        let dup = Value::Object(vec![
            ("a".into(), Value::Int64(1)),
            ("a".into(), Value::Int64(2)),
        ]);
        assert!(dup.encrypt(&cipher).is_err());
        let distinct = Value::Object(vec![
            ("a".into(), Value::Int64(1)),
            ("b".into(), Value::Int64(2)),
        ]);
        assert!(distinct.encrypt(&cipher).is_ok());
        // The passthrough entry path enforces the same rejection.
        let dup_mixed = Value::Object(vec![
            ("a".into(), Value::Int64(1)),
            ("a".into(), pt(Value::Int64(2))),
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
