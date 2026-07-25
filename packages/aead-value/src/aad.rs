//! Expectation-side leaf-type binding as an [`IntoAad`] type.
//!
//! [`LeafTypeAad`] lets a **schema-aware** caller — one that already knows
//! what type a field must hold — bind the *expected* leaf tag into the AAD at
//! **both** encrypt and decrypt. A wrong-type hypothesis then fails
//! authentication before any plaintext is released, turning a type confusion
//! into an ordinary AEAD failure.
//!
//! This is the expectation side of the value model's type story. It is **not**
//! wired into [`FfiValue`](crate::FfiValue)'s own self-describing sealing:
//! that path recovers the type from the inner, authenticated
//! `[tag] ++ payload` leaf, which is knowable only *after* decryption. AAD, by
//! contrast, must be known *before* decryption, so it can only carry an
//! *expectation* the caller already holds — not the value's actual,
//! self-described type. The two mechanisms are complementary: the inner tag
//! makes a value self-describing; this AAD binding lets a schema enforce a
//! type up front.

use vitaminc_aead::{Aad, IntoAad};

/// Domain-separation label for the leaf-type AAD binding. The leading label
/// keeps the encoding disjoint from `Aad::for_map_entry` and from
/// user-supplied composite AAD.
const LEAF_TYPE_DOMAIN: &[u8] = b"vitaminc/aead-value/leaf-type/v1";

/// An [`IntoAad`] wrapper that binds an expected leaf type tag onto a base AAD.
///
/// Construct it with a base AAD (anything implementing [`IntoAad`], typically
/// the caller's schema context) and the expected tag — e.g. from a
/// `Tagged*::TAG` associated const:
///
/// ```ignore
/// let aad = LeafTypeAad::new(schema_ctx, TaggedInt64::TAG);
/// value.encrypt_with_aad(&cipher, aad);
/// ```
///
/// The resulting AAD is `PAE(domain, base_aad_bytes, [tag])`. The same tag
/// must be supplied on decrypt or authentication fails.
pub struct LeafTypeAad<'a> {
    base: Aad<'a>,
    tag: u8,
}

impl<'a> LeafTypeAad<'a> {
    /// Bind `tag` as the expected leaf type onto `base`.
    pub fn new(base: impl IntoAad<'a>, tag: u8) -> Self {
        Self {
            base: base.into_aad(),
            tag,
        }
    }
}

impl<'a> IntoAad<'a> for LeafTypeAad<'a> {
    fn into_aad(self) -> Aad<'a> {
        // PAE(domain, base, [tag]) — the pinned wire encoding. `Aad::pae` is
        // the generic PAE facility exposed by the AEAD crate; the leaf-type
        // semantics live here, in the value crate that owns the tag table.
        Aad::pae(&[LEAF_TYPE_DOMAIN, self.base.as_bytes(), &[self.tag]])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_type_pins_encoding() {
        // The exact bytes are the expectation-side type-binding commitment:
        // PAE(domain, aad, [tag]). Changing them breaks decryption of existing
        // schema-bound ciphertexts.
        let bound = LeafTypeAad::new(Aad::from_slice(b"ctx"), 0x05).into_aad();
        let expected = Aad::pae(&[b"vitaminc/aead-value/leaf-type/v1", b"ctx", &[0x05]]);
        assert_eq!(bound.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn leaf_type_differs_from_map_entry_and_tuple_aad() {
        // The domain label keeps leaf-type AAD disjoint from the map-entry
        // binding and from a user binding (aad, tag) as tuple AAD.
        let leaf = LeafTypeAad::new(Aad::from_slice(b"ctx"), b'n').into_aad();
        let map_entry = Aad::from_slice(b"ctx").for_map_entry("n");
        assert_ne!(leaf.as_bytes(), map_entry.as_bytes());
        let tuple = (Aad::from_slice(b"ctx"), [b'n']).into_aad();
        assert_ne!(leaf.as_bytes(), tuple.as_bytes());
    }

    #[test]
    fn leaf_type_is_tag_sensitive() {
        assert_ne!(
            LeafTypeAad::new(Aad::from_slice(b"ctx"), 0x05)
                .into_aad()
                .as_bytes(),
            LeafTypeAad::new(Aad::from_slice(b"ctx"), 0x09)
                .into_aad()
                .as_bytes()
        );
    }

    // End-to-end proof that `LeafTypeAad` is the expectation-side type binding:
    // a leaf sealed with the expected tag mixed into AAD decrypts only when the
    // same tag is expected on decrypt; a different type hypothesis fails
    // authentication before any plaintext is released.
    #[test]
    fn leaf_type_binds_the_expected_leaf_tag() {
        use crate::tagged::TaggedInt64;
        use crate::{tags, FfiValue};
        use vitaminc_aead::Encrypt;
        use vitaminc_encrypt::{Aes256Cipher, Key};

        let cipher = Aes256Cipher::new(&Key::from([9u8; 32])).expect("cipher");
        let base = Aad::from_slice(b"schema-ctx");

        let ct = TaggedInt64::from(42i64)
            .encrypt_with_aad(&cipher, LeafTypeAad::new(base.clone(), TaggedInt64::TAG))
            .expect("encrypt");

        // Same expected type → authenticates and decrypts.
        let ct_ok = TaggedInt64::from(42i64)
            .encrypt_with_aad(&cipher, LeafTypeAad::new(base.clone(), TaggedInt64::TAG))
            .expect("encrypt");
        let value: FfiValue = cipher
            .decrypt_with_aad(ct_ok, LeafTypeAad::new(base.clone(), TaggedInt64::TAG))
            .expect("decrypt with matching leaf-type AAD");
        assert_eq!(value, FfiValue::Int64(42));

        // Wrong type hypothesis (FLOAT64) → authentication fails.
        assert!(cipher
            .decrypt_with_aad::<FfiValue, _>(ct, LeafTypeAad::new(base, tags::FLOAT64))
            .is_err());
    }
}
