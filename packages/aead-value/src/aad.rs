//! Expectation-side leaf-type binding as a context type.
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

use std::borrow::Cow;

use vitaminc_aead::{ContextPiece, IntoContext};

/// Domain-separation label for the leaf-type binding. Leading the list
/// keeps the context disjoint from a caller binding `(base, tag)` as a pair
/// of its own.
const LEAF_TYPE_DOMAIN: &[u8] = b"vitaminc/aead-value/leaf-type/v1";

/// A context that binds an expected leaf type tag onto a base context.
///
/// Construct it with a base context (anything implementing [`IntoContext`],
/// typically the caller's schema context) and the expected tag — e.g. from a
/// `Tagged*::TAG` associated const:
///
/// ```ignore
/// let aad = LeafTypeAad::new(schema_ctx, TaggedInt64::TAG);
/// value.encrypt_with_aad(&cipher, aad);
/// ```
///
/// As a context it is the three-part list `(domain, base, tag)`, with the
/// base's own parts intact and the tag as a `u8` leaf. The same tag must be
/// supplied on decrypt or authentication fails.
pub struct LeafTypeAad<'a> {
    base: ContextPiece<'a>,
    tag: u8,
}

impl<'a> LeafTypeAad<'a> {
    /// Bind `tag` as the expected leaf type onto `base`.
    pub fn new(base: impl IntoContext<'a>, tag: u8) -> Self {
        Self {
            base: base.into_context(),
            tag,
        }
    }
}

impl<'a> IntoContext<'a> for LeafTypeAad<'a> {
    fn into_context(self) -> ContextPiece<'a> {
        ContextPiece::List(vec![
            ContextPiece::Bytes(Cow::Borrowed(LEAF_TYPE_DOMAIN)),
            self.base,
            ContextPiece::U8(self.tag),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_aead::{Context, IntoAad};

    #[test]
    fn leaf_type_pins_encoding() {
        // The exact bytes are the expectation-side type-binding commitment:
        // the list (domain, base, tag) of typed parts. Changing them breaks
        // decryption of existing schema-bound ciphertexts.
        let bound = LeafTypeAad::new("ctx", 0x05).into_aad();
        let expected = Context::pae(&[
            LEAF_TYPE_DOMAIN.into_aad().as_bytes(),
            "ctx".into_aad().as_bytes(),
            0x05u8.into_aad().as_bytes(),
        ]);
        assert_eq!(bound, expected);
    }

    #[test]
    fn leaf_type_keeps_the_base_parts_intact() {
        let parts = LeafTypeAad::new(("schema", 7u64), 0x05).into_context();
        assert_eq!(parts.to_string(), "(0x766974616d696e632f616561642d76616c75652f6c6561662d747970652f7631, (\"schema\", 7u64), 5u8)");
        assert_eq!(parts.leaves().count(), 4);
    }

    #[test]
    fn leaf_type_differs_from_map_entry_and_tuple_aad() {
        // The domain label keeps leaf-type AAD disjoint from the map-entry
        // binding and from a user binding (base, tag) as a pair.
        let leaf = LeafTypeAad::new("ctx", b'n').into_aad();
        let map_entry = "ctx".into_aad().for_map_entry("n");
        assert_ne!(leaf, map_entry);
        let tuple = ("ctx", b'n').into_aad();
        assert_ne!(leaf, tuple);
    }

    #[test]
    fn leaf_type_is_tag_sensitive() {
        assert_ne!(
            LeafTypeAad::new("ctx", 0x05).into_aad(),
            LeafTypeAad::new("ctx", 0x09).into_aad()
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
        let base = "schema-ctx";

        let ct = TaggedInt64::from(42i64)
            .encrypt_with_aad(&cipher, LeafTypeAad::new(base, TaggedInt64::TAG))
            .expect("encrypt");

        // Same expected type → authenticates and decrypts.
        let ct_ok = TaggedInt64::from(42i64)
            .encrypt_with_aad(&cipher, LeafTypeAad::new(base, TaggedInt64::TAG))
            .expect("encrypt");
        let value: FfiValue = cipher
            .decrypt_with_aad(ct_ok, LeafTypeAad::new(base, TaggedInt64::TAG))
            .expect("decrypt with matching leaf-type AAD");
        assert_eq!(value, FfiValue::Int64(42));

        // Wrong type hypothesis (FLOAT64) → authentication fails.
        assert!(cipher
            .decrypt_with_aad::<FfiValue, _>(ct, LeafTypeAad::new(base, tags::FLOAT64))
            .is_err());
    }
}
