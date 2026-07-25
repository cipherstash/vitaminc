//! Tagged leaf plaintexts: the `[tag] ++ payload` assembly, typed.
//!
//! Every scalar [`FfiValue`](crate::FfiValue) seals as a one-byte type tag
//! followed by its payload (see [`tags`](crate::tags)). Rather than build
//! that byte string ad-hoc at each leaf, the two types here own the layout:
//!
//! - [`TaggedFixed`] for the fixed-width leaves (the numeric family and the
//!   payloadless Null/Undefined/Bool tags). The header byte is written into a
//!   stack array — **no heap allocation** — and sealed directly through the
//!   cipher's [`encrypt_bytes_array`](vitaminc_aead::Cipher::encrypt_bytes_array)
//!   entry point.
//! - [`TaggedVariable`] for the variable-length leaves (String, Bytes). It
//!   allocates the `1 + len` buffer once and seals through
//!   [`encrypt_bytes_vec`](vitaminc_aead::Cipher::encrypt_bytes_vec).
//!
//! # Why `N` includes the header byte
//!
//! [`TaggedFixed`]'s `N` is the **total** width — header byte plus payload —
//! because stable Rust cannot compute `N + 1` in a const-generic position.
//! The off-by-one is hidden behind the aliases ([`TaggedInt32`],
//! [`TaggedInt64`], …); nothing at a use site ever writes the raw number.
//!
//! # `TAG` and expectation-side binding
//!
//! Each alias exposes its tag as the associated const
//! [`TaggedFixed::TAG`] / [`TaggedVariable::TAG`]. A schema-aware caller (the
//! future `EqlCipher`) can mix the *expected* tag into AAD via
//! [`Aad::for_leaf_type`](vitaminc_aead::Aad::for_leaf_type) at both encrypt
//! and decrypt so a wrong type hypothesis fails authentication. The
//! self-describing [`FfiValue`](crate::FfiValue) path does **not** use that —
//! it relies on the inner authenticated tag, which is known only *after*
//! decryption.

use crate::tags;
use vitaminc_aead::{Cipher, Encrypt, IntoAad};
use vitaminc_protected::{Controlled, Protected};

/// A fixed-width tagged leaf plaintext: `HDR` in byte 0, payload in the
/// remaining `N - 1` bytes, held on the stack inside [`Protected`].
///
/// `N` is the **total** width including the header byte — see the module
/// docs for why the payload arithmetic is hidden behind the type aliases.
pub struct TaggedFixed<const HDR: u8, const N: usize>(Protected<[u8; N]>);

impl<const HDR: u8, const N: usize> TaggedFixed<HDR, N> {
    /// The leaf type tag this plaintext carries — used by schema-aware
    /// callers for [`Aad::for_leaf_type`](vitaminc_aead::Aad::for_leaf_type)
    /// binding.
    pub const TAG: u8 = HDR;

    /// Construct a payloadless tagged leaf (`N == 1`): the tag *is* the whole
    /// plaintext. Used for Null/Undefined/Bool.
    pub fn tag_only() -> Self {
        // No heap allocation: the one-byte plaintext lives on the stack until
        // it is sealed, then is wiped when the `Protected` drops.
        Self(Protected::new([HDR; N]))
    }

    /// Assemble from the raw little-endian payload bytes, writing the header
    /// into slot 0 on the stack. The `From` impls on the aliases are the
    /// ergonomic entry point; this is the shared core.
    fn from_payload(payload: &[u8]) -> Self {
        let mut buf = [0u8; N];
        buf[0] = HDR;
        buf[1..].copy_from_slice(payload);
        Self(Protected::new(buf))
    }
}

/// One generic [`Encrypt`] impl covers every fixed-width tagged leaf: seal
/// the stack array directly through the array entry point (no `to_vec`
/// detour). No new [`Cipher`] method is introduced — `encrypt_bytes_array`
/// is the existing entry point, and `Aes256Cipher` overrides it to seal
/// without an intermediate copy.
impl<const HDR: u8, const N: usize> Encrypt for TaggedFixed<HDR, N> {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.encrypt_bytes_array(self.0, aad)
    }
}

/// Payloadless: `TaggedFixed<{tags::NULL}, 1>`.
pub type TaggedNull = TaggedFixed<{ tags::NULL }, 1>;
/// Payloadless: `TaggedFixed<{tags::UNDEFINED}, 1>`.
pub type TaggedUndefined = TaggedFixed<{ tags::UNDEFINED }, 1>;
/// Payloadless: `TaggedFixed<{tags::BOOL_FALSE}, 1>`.
pub type TaggedBoolFalse = TaggedFixed<{ tags::BOOL_FALSE }, 1>;
/// Payloadless: `TaggedFixed<{tags::BOOL_TRUE}, 1>`.
pub type TaggedBoolTrue = TaggedFixed<{ tags::BOOL_TRUE }, 1>;

/// `INT32`: header + 4 payload bytes = 5 total.
pub type TaggedInt32 = TaggedFixed<{ tags::INT32 }, 5>;
/// `INT64`: header + 8 payload bytes = 9 total.
pub type TaggedInt64 = TaggedFixed<{ tags::INT64 }, 9>;
/// `UINT32`: header + 4 payload bytes = 5 total.
pub type TaggedUInt32 = TaggedFixed<{ tags::UINT32 }, 5>;
/// `UINT64`: header + 8 payload bytes = 9 total.
pub type TaggedUInt64 = TaggedFixed<{ tags::UINT64 }, 9>;
/// `FLOAT32`: header + 4 payload bytes = 5 total.
pub type TaggedFloat32 = TaggedFixed<{ tags::FLOAT32 }, 5>;
/// `FLOAT64`: header + 8 payload bytes = 9 total.
pub type TaggedFloat64 = TaggedFixed<{ tags::FLOAT64 }, 9>;

impl From<i32> for TaggedInt32 {
    fn from(v: i32) -> Self {
        Self::from_payload(&v.to_le_bytes())
    }
}
impl From<i64> for TaggedInt64 {
    fn from(v: i64) -> Self {
        Self::from_payload(&v.to_le_bytes())
    }
}
impl From<u32> for TaggedUInt32 {
    fn from(v: u32) -> Self {
        Self::from_payload(&v.to_le_bytes())
    }
}
impl From<u64> for TaggedUInt64 {
    fn from(v: u64) -> Self {
        Self::from_payload(&v.to_le_bytes())
    }
}
impl From<f32> for TaggedFloat32 {
    fn from(v: f32) -> Self {
        // Raw bit pattern, so NaN payloads and -0.0 survive.
        Self::from_payload(&v.to_bits().to_le_bytes())
    }
}
impl From<f64> for TaggedFloat64 {
    fn from(v: f64) -> Self {
        Self::from_payload(&v.to_bits().to_le_bytes())
    }
}

/// A variable-width tagged leaf plaintext: `HDR` in byte 0 followed by an
/// arbitrary-length payload, held inside [`Protected`]. Used for String and
/// Bytes.
pub struct TaggedVariable<const HDR: u8>(Protected<Vec<u8>>);

impl<const HDR: u8> TaggedVariable<HDR> {
    /// The leaf type tag this plaintext carries.
    pub const TAG: u8 = HDR;

    /// Prepend the header to `payload`, allocating the `1 + len` buffer once.
    ///
    /// The bare-bytes window between `risky_ref` and the re-wrap in
    /// [`Protected`] is bounded to this constructor, mirroring the built-in
    /// leaf `Encrypt` impls' chain-of-custody discipline: the incoming
    /// `payload` is wiped as it drops here, and the freshly built buffer is
    /// owned by the new `Protected`.
    pub fn new(payload: Protected<Vec<u8>>) -> Self {
        let bytes = payload.risky_ref();
        let mut buf = Vec::with_capacity(1 + bytes.len());
        buf.push(HDR);
        buf.extend_from_slice(bytes);
        // `payload` drops (and wipes) here; `buf` is owned by the new `Protected`.
        Self(Protected::new(buf))
    }
}

impl<const HDR: u8> Encrypt for TaggedVariable<HDR> {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.encrypt_bytes_vec(self.0, aad)
    }
}

/// `STRING`: header + UTF-8 payload.
pub type TaggedString = TaggedVariable<{ tags::STRING }>;
/// `BYTES`: header + raw payload.
pub type TaggedBytes = TaggedVariable<{ tags::BYTES }>;

#[cfg(test)]
mod tests {
    use super::*;

    // The associated `TAG` const must equal the underlying tag byte — this is
    // what a schema-aware caller reads for `Aad::for_leaf_type` binding.
    #[test]
    fn tag_consts_match_the_table() {
        assert_eq!(TaggedNull::TAG, tags::NULL);
        assert_eq!(TaggedUndefined::TAG, tags::UNDEFINED);
        assert_eq!(TaggedBoolFalse::TAG, tags::BOOL_FALSE);
        assert_eq!(TaggedBoolTrue::TAG, tags::BOOL_TRUE);
        assert_eq!(TaggedInt32::TAG, tags::INT32);
        assert_eq!(TaggedInt64::TAG, tags::INT64);
        assert_eq!(TaggedUInt32::TAG, tags::UINT32);
        assert_eq!(TaggedUInt64::TAG, tags::UINT64);
        assert_eq!(TaggedFloat32::TAG, tags::FLOAT32);
        assert_eq!(TaggedFloat64::TAG, tags::FLOAT64);
        assert_eq!(TaggedString::TAG, tags::STRING);
        assert_eq!(TaggedBytes::TAG, tags::BYTES);
    }

    // Byte layout of the fixed-width leaves, inspected directly on the stack
    // array (no cipher needed). Pins `[tag] ++ le(payload)`.
    #[test]
    fn fixed_layout_is_tag_then_le_payload() {
        assert_eq!(TaggedNull::tag_only().0.risky_ref(), &[0x00]);
        assert_eq!(TaggedUndefined::tag_only().0.risky_ref(), &[0x01]);
        assert_eq!(TaggedBoolFalse::tag_only().0.risky_ref(), &[0x02]);
        assert_eq!(TaggedBoolTrue::tag_only().0.risky_ref(), &[0x03]);

        assert_eq!(
            TaggedInt32::from(-1i32).0.risky_ref(),
            &[0x04, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(
            TaggedInt64::from(42i64).0.risky_ref(),
            &[0x05, 42, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            TaggedUInt32::from(u32::MAX).0.risky_ref(),
            &[0x06, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(
            TaggedUInt64::from(1u64).0.risky_ref(),
            &[0x07, 1, 0, 0, 0, 0, 0, 0, 0]
        );
        // 1.5f32 = 0x3FC00000, little-endian.
        assert_eq!(
            TaggedFloat32::from(1.5f32).0.risky_ref(),
            &[0x08, 0x00, 0x00, 0xC0, 0x3F]
        );
        // 1.5f64 = 0x3FF8000000000000, little-endian.
        assert_eq!(
            TaggedFloat64::from(1.5f64).0.risky_ref(),
            &[0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x3F]
        );
    }

    // Byte layout of the variable-width leaves.
    #[test]
    fn variable_layout_is_tag_then_payload() {
        let s = TaggedString::new(Protected::new(b"abc".to_vec()));
        assert_eq!(s.0.risky_ref(), &[0x0A, b'a', b'b', b'c']);
        let empty = TaggedString::new(Protected::new(Vec::new()));
        assert_eq!(empty.0.risky_ref(), &[0x0A]);
        let b = TaggedBytes::new(Protected::new(vec![0xDE, 0xAD]));
        assert_eq!(b.0.risky_ref(), &[0x0B, 0xDE, 0xAD]);
    }

    // End-to-end proof that `Aad::for_leaf_type` is the expectation-side type
    // binding: a leaf sealed with the expected tag mixed into AAD decrypts
    // only when the same tag is expected on decrypt; a different type
    // hypothesis fails authentication before any plaintext is released.
    #[test]
    fn for_leaf_type_binds_the_expected_leaf_tag() {
        use crate::FfiValue;
        use vitaminc_aead::Aad;
        use vitaminc_encrypt::{Aes256Cipher, Key};

        let cipher = Aes256Cipher::new(&Key::from([9u8; 32])).expect("cipher");
        let aad = Aad::from_slice(b"schema-ctx");

        let ct = TaggedInt64::from(42i64)
            .encrypt_with_aad(&cipher, aad.for_leaf_type(TaggedInt64::TAG))
            .expect("encrypt");

        // Same expected type → authenticates and decrypts.
        let ct_ok = TaggedInt64::from(42i64)
            .encrypt_with_aad(&cipher, aad.for_leaf_type(TaggedInt64::TAG))
            .expect("encrypt");
        let value: FfiValue = cipher
            .decrypt_with_aad(ct_ok, aad.for_leaf_type(TaggedInt64::TAG))
            .expect("decrypt with matching leaf-type AAD");
        assert_eq!(value, FfiValue::Int64(42));

        // Wrong type hypothesis (FLOAT64) → authentication fails.
        assert!(cipher
            .decrypt_with_aad::<FfiValue, _>(ct, aad.for_leaf_type(tags::FLOAT64))
            .is_err());
    }
}
