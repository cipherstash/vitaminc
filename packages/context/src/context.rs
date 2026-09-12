//! The encoded bytes of a context, and the contexts derived from one.

use std::borrow::Cow;

use crate::{pae, ContextPiece, IntoContext};

const MAP_ENTRY_DOMAIN: &[u8] = b"vitaminc/context/map-entry/v1";
const MARKER_DOMAIN: &[u8] = b"vitaminc/context/marker/v1";
const LEAF_DOMAIN: &[u8] = b"vitaminc/context/leaf";
const SEQ_ELEMENT_DOMAIN: &[u8] = b"vitaminc/context/seq-element/v1";
const OPTION_SOME_DOMAIN: &[u8] = b"vitaminc/context/option-some/v1";
const REFINE_DOMAIN: &[u8] = b"vitaminc/context/refine/v1";

/// The canonical encoding of a context, as bytes.
///
/// A context is the same value whether an AEAD authenticates it as
/// associated data or a PRF derives under it: `x.into_aad()` and
/// `x.into_prf_context()` both produce this type and both hold the same
/// bytes. Those bytes come from one place, the encoding of the context's
/// [`ContextPiece`] tree, so no consumer can be given a different encoding
/// of the same context on one side than on the other.
///
/// The storage is copy-on-write. A context built from a borrowed encoded
/// slice ([`from_encoded`](Self::from_encoded)) borrows it; anything the
/// encoder produces is owned.
///
/// # Raw bytes
///
/// Two methods take raw bytes rather than a typed value, and both mean
/// something specific:
///
/// - [`from_encoded`](Self::from_encoded) takes bytes this encoder already
///   produced, for a context that was stored or crossed a language boundary
///   and is now being handed back. Passing it something else, say the raw
///   bytes of a string, gives a context that is not the encoding of that
///   string: `Context::from_encoded(b"7")` and `"7".into_aad()` are
///   different contexts.
/// - [`pae`](Self::pae) frames a list of byte pieces exactly as a composite
///   context is framed. A crate that defines its own domain-separated
///   context shapes builds them with it, leading with a domain label of its
///   own.
///
/// `Context` deliberately does not implement `MaybeEmpty`. An encoded
/// context can only be judged on its bytes, and framing makes the encoding
/// of an empty value non-empty, so `NonEmpty<Context>` would certify exactly
/// the degenerate value it exists to exclude. Prove non-emptiness on the
/// value before it is encoded: `NonEmpty<T>` where `T: IntoContext`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Context<'a>(pub(crate) Cow<'a, [u8]>);

impl<'a> Context<'a> {
    /// The empty context: no bytes at all. The same as `().into_context()`
    /// encoded, and the value [`Default`] gives.
    // `empty` and `Default::default` are intentionally identical, so replacing
    // this body with `Default::default` is an equivalent mutation.
    #[mutants::skip]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A context from bytes this encoder already produced.
    ///
    /// Use it to hand back a context that was stored, logged, or received
    /// across an FFI boundary as bytes. It does not encode anything: the
    /// bytes are the context, verbatim, and when the result is used as a
    /// part of a larger context it is written as a
    /// [`ContextPiece::Encoded`] leaf, untagged. Do not use it to turn a
    /// value into a context; implement or call [`IntoContext`] for that.
    ///
    /// ```rust
    /// use vitaminc_context::{Context, IntoContext};
    ///
    /// let stored = ("users", 7u64).into_context().encode();
    /// let restored = Context::from_encoded(stored.as_bytes());
    /// assert_eq!(restored, stored);
    /// // Re-encoding an encoded context leaves it unchanged.
    /// assert_eq!(restored.clone().into_context().encode(), stored);
    /// ```
    pub fn from_encoded(bytes: impl Into<Cow<'a, [u8]>>) -> Self {
        Self(bytes.into())
    }

    /// The encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Whether there are no bytes at all. Only the empty context and the
    /// encoding of `()` are empty; every framed context has at least a count
    /// word.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Copies the bytes if they are borrowed, so the context can outlive its
    /// source.
    pub fn into_owned(self) -> Context<'static> {
        Context(Cow::Owned(self.0.into_owned()))
    }

    /// Pre-Authentication Encoding of a list of byte pieces, from the PASETO
    /// specification: `LE64(count) || (LE64(len(piece)) || piece)*`.
    ///
    /// Structurally distinct inputs always encode to distinct byte strings.
    /// This is the framing every composite context in this crate uses, and
    /// the building block a crate uses to define a domain-separated context
    /// shape of its own. Lead such a shape with a domain label that is
    /// yours; the labels this crate reserves all begin `vitaminc/context/`.
    pub fn pae(pieces: &[&[u8]]) -> Context<'static> {
        pae::encode(pieces)
    }

    /// Adds a component under this context, with a domain tag so the result
    /// cannot collide with any context this crate derives on its own.
    ///
    /// The encoding is `PAE(domain, self, component)`. Without the leading
    /// domain, a caller could build the reserved option-some label as a
    /// context and refine it by `x` to reach the same bytes
    /// [`for_option_some`](Self::for_option_some) assigns under `x`.
    pub fn refine<'b, C>(&self, component: C) -> Context<'static>
    where
        C: IntoContext<'b>,
    {
        let component = component.into_context().encode();
        Self::pae(&[REFINE_DOMAIN, self.as_bytes(), component.as_bytes()])
    }

    /// The context a map entry's value is sealed or derived under, binding
    /// the entry `key` to this context.
    ///
    /// Map keys travel in the clear inside a ciphertext container, so
    /// without this binding an attacker holding a stored ciphertext could
    /// swap or rename keys undetected and silently reassign values to
    /// different fields. Every map cipher and map PRF derives each entry's
    /// context through this method, on both the writing and the reading
    /// side.
    ///
    /// The encoding is `PAE(domain, self, key)`. The leading domain keeps
    /// the result apart from a caller binding the tuple `(context, key)` as
    /// a context of its own, which is a two-piece list of typed leaves and
    /// so can never equal a three-piece labelled frame.
    pub fn for_map_entry(&self, key: &str) -> Context<'static> {
        Self::pae(&[MAP_ENTRY_DOMAIN, self.as_bytes(), key.as_bytes()])
    }

    /// The context a structural marker is sealed under.
    ///
    /// A marker is a sealed empty plaintext whose tag is the only thing
    /// authenticating a structural fact: this sequence is empty, this map is
    /// empty, this value is absent. The encoding is the labelled three-piece
    /// `PAE(domain, self, kind)`. The domain keeps marker contexts apart from
    /// caller-built composites, and the `kind` piece keeps the marker kinds
    /// apart from each other, so a stored marker can never be replayed as a
    /// different structural claim.
    fn for_marker(&self, kind: &[u8]) -> Context<'static> {
        Self::pae(&[MARKER_DOMAIN, self.as_bytes(), kind])
    }

    /// The context every sealed leaf is finally authenticated under, binding
    /// the wire-format `version` byte that prefixes the stored leaf.
    ///
    /// This is the outermost derivation. A cipher applies it at the AEAD
    /// seal and open boundary, after every structural derivation
    /// ([`for_map_entry`](Self::for_map_entry),
    /// [`for_sequence_element`](Self::for_sequence_element), the markers) has
    /// produced the caller-visible context. Binding the version under the
    /// tag is what makes it more than a parse hint: a stored leaf relabelled
    /// with a different version byte fails verification instead of selecting
    /// a different, perhaps weaker, set of parsing rules.
    ///
    /// The domain label carries no `/v1` suffix on purpose. The version is a
    /// parameter here, not part of the label.
    pub fn for_leaf(&self, version: u8) -> Context<'static> {
        Self::pae(&[LEAF_DOMAIN, &[version], self.as_bytes()])
    }

    /// The context a sequence element is sealed or derived under.
    ///
    /// Without this derivation a sequence element would share the caller's
    /// bare context with a top-level single value, byte for byte, so an
    /// attacker holding a stored ciphertext could rewrap a single leaf as a
    /// one-element sequence and a self-describing decrypt path would verify
    /// it. Sealing elements under a labelled derivation means a leaf
    /// verifies only in the position it was sealed for.
    ///
    /// The element index is deliberately not bound. Records are retrieved in
    /// a different order than they were inserted, so element order is a
    /// caller obligation, not an authenticated fact.
    pub fn for_sequence_element(&self) -> Context<'static> {
        Self::pae(&[SEQ_ELEMENT_DOMAIN, self.as_bytes(), b"element"])
    }

    /// Marker context for an empty sequence. See
    /// [`for_none`](Self::for_none) for the marker rule.
    pub fn for_empty_sequence(&self) -> Context<'static> {
        self.for_marker(b"empty-sequence")
    }

    /// Marker context for an empty map. See [`for_none`](Self::for_none)
    /// for the marker rule.
    pub fn for_empty_map(&self) -> Context<'static> {
        self.for_marker(b"empty-map")
    }

    /// Marker context for an authenticated absent value, `Option::None`.
    ///
    /// A marker is a sealed empty plaintext whose tag is the only thing
    /// authenticating a structural fact. Each marker kind is derived under
    /// its own labelled context, `PAE(domain, self, kind)`, so a single leaf
    /// sealed under the bare context can never be re-tagged as an absence
    /// marker (silent authenticated deletion), an absence marker can never
    /// validate as an encrypted empty byte string, and no marker can be
    /// replayed as a different structural claim.
    pub fn for_none(&self) -> Context<'static> {
        self.for_marker(b"none")
    }

    /// The context an optional value's `Some` is derived under.
    ///
    /// This is the value side of `Option`, distinct from the context side.
    /// `Some(x)` as a context is the one-element list `PAE([x])`, untagged,
    /// so that a runtime list of one part is the same context as the static
    /// `Some`. A `Some` value being derived under a context `c` uses
    /// `PAE(domain, c)` instead, keeping the derivation of an optional value
    /// apart from the derivation of its inner value under the same `c`.
    pub fn for_option_some(&self) -> Context<'static> {
        Self::pae(&[OPTION_SOME_DOMAIN, self.as_bytes()])
    }
}

/// An encoded context is a context. As a part of a larger context it is
/// the [`Encoded`](ContextPiece::Encoded) leaf, written verbatim and
/// untagged, so re-encoding a context leaves its bytes unchanged.
impl<'a> IntoContext<'a> for Context<'a> {
    fn into_context(self) -> ContextPiece<'a> {
        ContextPiece::Encoded(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;

    fn raw(bytes: &[u8]) -> Context<'_> {
        Context::from_encoded(bytes)
    }

    mod given_raw_bytes {
        use super::*;

        #[test]
        fn from_encoded_keeps_them_verbatim() {
            let borrowed = Context::from_encoded(&[1u8, 2, 3][..]);
            let owned = Context::from_encoded(vec![1u8, 2, 3]);
            assert_eq!(borrowed.as_bytes(), &[1, 2, 3]);
            assert_eq!(owned, borrowed, "ownership does not change the context");
            assert_eq!(
                borrowed.into_owned().as_bytes(),
                &[1, 2, 3],
                "into_owned keeps the bytes"
            );
        }

        #[test]
        fn re_encoding_is_the_identity() {
            let stored = ("users", 7u64).into_context().encode();
            let restored = Context::from_encoded(stored.as_bytes());
            assert_eq!(
                restored.into_context().encode(),
                stored,
                "an encoded context re-encodes to itself"
            );
        }

        #[test]
        fn from_encoded_is_not_a_typed_value() {
            // The documented footgun: raw bytes are not the encoding of the
            // string with those bytes.
            assert_ne!(
                raw(b"7").into_context().encode(),
                "7".into_context().encode()
            );
        }

        #[test]
        fn emptiness_is_judged_on_the_bytes_only() {
            assert!(Context::empty().is_empty());
            assert!(Context::default().is_empty());
            assert!(!raw(b"raw").is_empty());
            // Framing makes the encoding of an empty value non-empty, which
            // is why `Context` has no `MaybeEmpty` impl.
            assert!(!"".into_context().encode().is_empty());
            assert!(!Some("").into_context().encode().is_empty());
        }
    }

    /// The exact bytes of each derived context are a wire-format commitment.
    /// Changing them breaks decryption of every stored ciphertext and every
    /// saved index term derived through them.
    mod given_a_derived_context {
        use super::*;

        #[test]
        fn map_entry_pins_its_encoding() {
            assert_eq!(
                raw(b"ctx").for_map_entry("name"),
                Context::pae(&[b"vitaminc/context/map-entry/v1", b"ctx", b"name"])
            );
        }

        #[test]
        fn markers_pin_their_encoding() {
            let ctx = raw(b"ctx");
            for (derived, kind) in [
                (ctx.for_empty_sequence(), b"empty-sequence".as_slice()),
                (ctx.for_empty_map(), b"empty-map"),
                (ctx.for_none(), b"none"),
            ] {
                assert_eq!(
                    derived,
                    Context::pae(&[b"vitaminc/context/marker/v1", b"ctx", kind])
                );
            }
        }

        #[test]
        fn leaf_pins_its_encoding() {
            assert_eq!(
                raw(b"ctx").for_leaf(1),
                Context::pae(&[b"vitaminc/context/leaf", &[1u8], b"ctx"])
            );
        }

        #[test]
        fn sequence_element_pins_its_encoding() {
            assert_eq!(
                raw(b"ctx").for_sequence_element(),
                Context::pae(&[b"vitaminc/context/seq-element/v1", b"ctx", b"element"])
            );
        }

        #[test]
        fn option_some_pins_its_encoding() {
            assert_eq!(
                raw(b"ctx").for_option_some(),
                Context::pae(&[b"vitaminc/context/option-some/v1", b"ctx"])
            );
        }

        #[test]
        fn refine_pins_its_encoding() {
            assert_eq!(
                raw(b"parent").refine("child"),
                Context::pae(&[
                    b"vitaminc/context/refine/v1",
                    b"parent",
                    "child".into_context().encode().as_bytes(),
                ])
            );
        }

        #[test]
        fn every_derivation_differs_from_the_bare_context_and_each_other() {
            let ctx = raw(b"ctx");
            let derived = [
                ctx.for_map_entry("element"),
                ctx.for_leaf(1),
                ctx.for_sequence_element(),
                ctx.for_empty_sequence(),
                ctx.for_empty_map(),
                ctx.for_none(),
                ctx.for_option_some(),
                ctx.refine("element"),
            ];
            for (i, left) in derived.iter().enumerate() {
                assert_ne!(left, &ctx, "a derivation is never the bare context");
                for right in &derived[i + 1..] {
                    assert_ne!(left, right, "two derivations never coincide");
                }
            }
        }

        #[test]
        fn every_derivation_differs_from_a_tuple_of_the_same_parts() {
            // A caller binding the same pieces as a tuple builds a list of
            // typed leaves, which the labelled frame can never equal.
            let ctx = raw(b"ctx");
            assert_ne!(
                ctx.for_map_entry("name"),
                (ctx.clone(), "name").into_context().encode()
            );
            assert_ne!(
                ctx.for_leaf(1),
                (b"vitaminc/context/leaf".as_slice(), (1u8, ctx.clone()))
                    .into_context()
                    .encode()
            );
            assert_ne!(
                ctx.for_none(),
                (b"vitaminc/context/marker/v1".as_slice(), ctx.clone())
                    .into_context()
                    .encode()
            );
            assert_ne!(
                ctx.for_sequence_element(),
                (b"vitaminc/context/seq-element/v1".as_slice(), ctx.clone())
                    .into_context()
                    .encode()
            );
        }

        #[test]
        fn leaf_is_version_sensitive() {
            let ctx = raw(b"ctx");
            assert_ne!(
                ctx.for_leaf(1),
                ctx.for_leaf(2),
                "a relabelled version byte changes the context; that is the downgrade defence"
            );
        }

        #[test]
        fn refine_is_disjoint_from_the_reserved_derivations() {
            // Without its own domain, refining a context that happens to be a
            // reserved label would collide with the derivation that label
            // names.
            assert_ne!(
                raw(OPTION_SOME_DOMAIN).refine("child"),
                raw(b"child").for_option_some()
            );
            assert_ne!(
                raw(MAP_ENTRY_DOMAIN).refine("child"),
                raw(b"parent").for_map_entry("child")
            );
        }

        #[quickcheck]
        fn map_keys_are_separated(context: Vec<u8>, a: String, b: String) -> bool {
            let context = Context::from_encoded(context);
            a == b || context.for_map_entry(&a) != context.for_map_entry(&b)
        }

        #[test]
        fn map_entry_bytes_cannot_move_between_context_and_key() {
            assert_ne!(
                raw(b"ctxa").for_map_entry(""),
                raw(b"ctx").for_map_entry("a")
            );
            assert_ne!(
                Context::empty().for_map_entry("ab"),
                Context::empty().for_map_entry("a")
            );
        }
    }
}
