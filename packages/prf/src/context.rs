use std::borrow::Cow;

use vitaminc_protected::NonEmpty;

use crate::PrfEncoding;

const MAP_ENTRY_DOMAIN: &[u8] = b"vitaminc/prf/map-entry/v1";
const CONTEXT_VALUE_DOMAIN: &[u8] = b"vitaminc/prf/context-value/v1";
const OPTION_SOME_DOMAIN: &[u8] = b"vitaminc/prf/option-some/v1";
const REFINE_DOMAIN: &[u8] = b"vitaminc/prf/refine/v1";

/// Owned or borrowed domain-separation context for a PRF derivation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct PrfContext<'a>(Cow<'a, [u8]>);

impl<'a> PrfContext<'a> {
    // `empty` and `Default::default` are intentionally identical, so replacing
    // this body with `Default::default` is an equivalent mutation.
    #[mutants::skip]
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_slice(bytes: &'a [u8]) -> Self {
        Self(Cow::Borrowed(bytes))
    }

    pub fn new_owned(bytes: impl IntoIterator<Item = u8>) -> Self {
        Self(Cow::Owned(bytes.into_iter().collect()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_owned(self) -> PrfContext<'static> {
        PrfContext(Cow::Owned(self.0.into_owned()))
    }

    /// Prefix-free Pre-Authentication Encoding:
    /// `LE64(piece_count) || (LE64(piece_len) || piece)*`.
    pub fn pae(pieces: &[&[u8]]) -> PrfContext<'static> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&(pieces.len() as u64).to_le_bytes());
        for piece in pieces {
            encoded.extend_from_slice(&(piece.len() as u64).to_le_bytes());
            encoded.extend_from_slice(piece);
        }
        PrfContext(Cow::Owned(encoded))
    }

    /// Add a domain component without allowing concatenation ambiguities.
    ///
    /// The leading domain tag keeps caller-refined contexts disjoint from the
    /// contexts this crate assigns automatically. Without it, a context built
    /// as `PrfContext::from_slice(OPTION_SOME_DOMAIN).refine(x)` would encode
    /// identically to the one derived for `Some(x)`.
    pub fn refine<'b, C>(&self, component: C) -> PrfContext<'static>
    where
        C: IntoPrfContext<'b>,
    {
        let component = component.into_prf_context();
        Self::pae(&[REFINE_DOMAIN, self.as_bytes(), component.as_bytes()])
    }

    /// Context automatically assigned to a string-keyed map entry.
    pub fn for_map_entry(&self, key: &str) -> PrfContext<'static> {
        Self::pae(&[MAP_ENTRY_DOMAIN, self.as_bytes(), key.as_bytes()])
    }

    pub(crate) fn for_option_some(&self) -> PrfContext<'static> {
        Self::pae(&[OPTION_SOME_DOMAIN, self.as_bytes()])
    }

    fn typed(encoding: PrfEncoding, value: &[u8]) -> PrfContext<'static> {
        Self::pae(&[CONTEXT_VALUE_DOMAIN, encoding.as_bytes(), value])
    }
}

// `PrfContext` deliberately does NOT implement `MaybeEmpty`: an already-encoded
// context can only be judged on its bytes, and framing makes most encoded
// contexts non-empty even when built from an empty value — so
// `NonEmpty<PrfContext>` would certify exactly the degenerate value it exists
// to exclude. Prove non-emptiness on the raw value, before it is encoded, then
// convert: `NonEmpty<T>` where `T: IntoPrfContext`.

pub trait IntoPrfContext<'a> {
    fn into_prf_context(self) -> PrfContext<'a>;
}

/// `NonEmpty<T>` is transparent: it encodes exactly as `T` does. The wrapper
/// changes what the type promises, never the bytes derived from it.
impl<'a, T> IntoPrfContext<'a> for NonEmpty<T>
where
    T: IntoPrfContext<'a>,
{
    fn into_prf_context(self) -> PrfContext<'a> {
        self.into_inner().into_prf_context()
    }
}

impl<'a> IntoPrfContext<'a> for PrfContext<'a> {
    fn into_prf_context(self) -> PrfContext<'a> {
        self
    }
}

impl<'a> IntoPrfContext<'a> for () {
    // Unit is the default/empty context by definition. The generated return
    // replacement is therefore equivalent to the implementation.
    #[mutants::skip]
    fn into_prf_context(self) -> PrfContext<'a> {
        PrfContext::default()
    }
}

impl<'a> IntoPrfContext<'a> for &'a [u8] {
    fn into_prf_context(self) -> PrfContext<'a> {
        PrfContext::typed(PrfEncoding::BYTES, self)
    }
}

impl<'a, const N: usize> IntoPrfContext<'a> for &'a [u8; N] {
    fn into_prf_context(self) -> PrfContext<'a> {
        PrfContext::typed(PrfEncoding::BYTES, self)
    }
}

impl<'a, const N: usize> IntoPrfContext<'a> for [u8; N] {
    fn into_prf_context(self) -> PrfContext<'a> {
        PrfContext::typed(PrfEncoding::BYTES, &self)
    }
}

impl<'a> IntoPrfContext<'a> for Vec<u8> {
    fn into_prf_context(self) -> PrfContext<'a> {
        PrfContext::typed(PrfEncoding::BYTES, &self)
    }
}

impl<'a> IntoPrfContext<'a> for Cow<'a, [u8]> {
    fn into_prf_context(self) -> PrfContext<'a> {
        PrfContext::typed(PrfEncoding::BYTES, &self)
    }
}

impl<'a> IntoPrfContext<'a> for &'a str {
    fn into_prf_context(self) -> PrfContext<'a> {
        PrfContext::typed(PrfEncoding::UTF8, self.as_bytes())
    }
}

impl<'a> IntoPrfContext<'a> for String {
    fn into_prf_context(self) -> PrfContext<'a> {
        PrfContext::typed(PrfEncoding::UTF8, self.as_bytes())
    }
}

macro_rules! integer_context {
    ($($ty:ty => $encoding:expr),+ $(,)?) => {$ (
        impl<'a> IntoPrfContext<'a> for $ty {
            fn into_prf_context(self) -> PrfContext<'a> {
                PrfContext::typed($encoding, &self.to_le_bytes())
            }
        }
    )+};
}

integer_context!(
    u8 => PrfEncoding::U8,
    u16 => PrfEncoding::U16,
    u32 => PrfEncoding::U32,
    u64 => PrfEncoding::U64,
    u128 => PrfEncoding::U128,
    i8 => PrfEncoding::I8,
    i16 => PrfEncoding::I16,
    i32 => PrfEncoding::I32,
    i64 => PrfEncoding::I64,
    i128 => PrfEncoding::I128,
);

/// An `Option` context follows its parts view: `Some(x)` is the one-element
/// list `PAE([x])` and `None` the empty list `PAE([])`, exactly as
/// `IntoAad` encodes them. A context built at runtime from parts (an
/// `AadPiece` list of one) is therefore the same PRF context as the static
/// `Some(x)`, on this side as on the AEAD side.
///
/// This is deliberately *not* the `PrfValue` `Option` encoding, which tags
/// `Some` with a domain of its own: that tag keeps an optional *value*'s
/// derivation apart from its inner value's, and a value is never compared
/// with a context. Sharing the tag here bought nothing and cost the parts
/// identity.
impl<'a, T> IntoPrfContext<'a> for Option<T>
where
    T: IntoPrfContext<'a>,
{
    fn into_prf_context(self) -> PrfContext<'a> {
        match self {
            Some(value) => PrfContext::pae(&[value.into_prf_context().as_bytes()]),
            None => PrfContext::pae(&[]),
        }
    }
}

impl<'a, A, B> IntoPrfContext<'a> for (A, B)
where
    A: IntoPrfContext<'a>,
    B: IntoPrfContext<'a>,
{
    fn into_prf_context(self) -> PrfContext<'a> {
        let a = self.0.into_prf_context();
        let b = self.1.into_prf_context();
        PrfContext::pae(&[a.as_bytes(), b.as_bytes()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;

    #[test]
    fn constructors_and_empty_state_preserve_bytes() {
        let bytes = [1_u8, 2, 3];
        let borrowed = PrfContext::from_slice(&bytes);
        let owned = PrfContext::new_owned(bytes);

        assert_eq!(borrowed.as_bytes(), &[1, 2, 3]);
        assert_eq!(owned.as_bytes(), &[1, 2, 3]);
        assert!(!borrowed.is_empty());
        assert!(PrfContext::empty().is_empty());
    }

    #[test]
    fn pae_has_the_documented_little_endian_framing() {
        assert_eq!(
            PrfContext::pae(&[b"a", b"bc"]).as_bytes(),
            &[
                2, 0, 0, 0, 0, 0, 0, 0, // piece count
                1, 0, 0, 0, 0, 0, 0, 0, b'a', // first piece
                2, 0, 0, 0, 0, 0, 0, 0, b'b', b'c', // second piece
            ]
        );
    }

    #[test]
    fn refine_frames_the_parent_and_component() {
        let parent = PrfContext::from_slice(b"parent");
        let expected = PrfContext::pae(&[
            REFINE_DOMAIN,
            b"parent",
            PrfContext::typed(PrfEncoding::UTF8, b"child").as_bytes(),
        ]);

        assert_eq!(parent.refine("child"), expected);
    }

    #[test]
    fn refine_is_disjoint_from_the_automatic_domains() {
        // Without a domain tag of its own, `refine` on a context that happens
        // to equal a reserved constant collides with the derivation that
        // constant names.
        let forged = PrfContext::from_slice(OPTION_SOME_DOMAIN).refine("child");
        let assigned = PrfContext::from_slice(b"child").for_option_some();

        assert_ne!(forged, assigned);

        let forged = PrfContext::from_slice(MAP_ENTRY_DOMAIN).refine("child");
        let assigned = PrfContext::from_slice(b"parent").for_map_entry("child");

        assert_ne!(forged, assigned);
    }

    #[quickcheck]
    fn pae_is_prefix_free(a: Vec<u8>, b: Vec<u8>, c: Vec<u8>) -> bool {
        let left = PrfContext::pae(&[&a, &b]);
        let right = PrfContext::pae(&[&a, &b, &c]);
        left != right
    }

    #[quickcheck]
    fn map_keys_are_separated(context: Vec<u8>, a: String, b: String) -> bool {
        let context = PrfContext::new_owned(context);
        a == b || context.for_map_entry(&a) != context.for_map_entry(&b)
    }

    #[test]
    fn structurally_different_contexts_do_not_collide() {
        assert_ne!(
            PrfContext::pae(&[b"ab", b"c"]),
            PrfContext::pae(&[b"a", b"bc"])
        );
        assert_ne!(
            PrfContext::empty().for_map_entry("ab"),
            PrfContext::empty().for_map_entry("a")
        );
    }

    #[quickcheck]
    fn option_context_is_the_one_element_list(bytes: Vec<u8>) -> bool {
        // `Some(x)` is the single-piece PAE of `x`'s encoding — the same
        // shape `IntoAad` gives it, so a runtime list of one part is the
        // static `Some`. It is framed, so it is not `x` itself.
        let inner = bytes.clone().into_prf_context();
        let some = Some(bytes).into_prf_context();
        some == PrfContext::pae(&[inner.as_bytes()]) && some != inner
    }

    #[test]
    fn option_context_does_not_share_the_value_path_some_domain() {
        // The `PrfValue` Option path tags `Some` with its own domain; a
        // context does not. If this fails, the context encoding has grown a
        // tag again and runtime parts can no longer spell `Some`.
        assert_ne!(
            Some("value").into_prf_context(),
            "value".into_prf_context().for_option_some()
        );
        assert_eq!(None::<&str>.into_prf_context(), PrfContext::pae(&[]));
    }

    #[test]
    fn non_empty_is_transparent_to_the_encoding() {
        assert_eq!(
            NonEmpty::new("users/email").unwrap().into_prf_context(),
            "users/email".into_prf_context()
        );
        assert_eq!(
            Some(NonEmpty::new("users/email").unwrap()).into_prf_context(),
            Some("users/email").into_prf_context()
        );
        assert_eq!(
            NonEmpty::new(("users", "email"))
                .unwrap()
                .into_prf_context(),
            ("users", "email").into_prf_context()
        );
        assert_eq!(
            vitaminc_protected::nonempty!("users/email").into_prf_context(),
            "users/email".into_prf_context()
        );
    }

    #[test]
    fn encoded_contexts_report_emptiness_of_their_bytes_only() {
        assert!(PrfContext::empty().is_empty());
        assert!(!PrfContext::from_slice(b"raw").is_empty());
        // Framing makes an encoded empty value non-empty as bytes — which is
        // exactly why `PrfContext` has no `MaybeEmpty` impl: the structural check
        // belongs before encoding (`NonEmpty<T>` where `T: IntoPrfContext`).
        assert!(!"".into_prf_context().is_empty());
    }

    #[test]
    fn context_value_types_are_separated() {
        assert_ne!("a".into_prf_context(), b"a".into_prf_context());
        assert_ne!(1_u8.into_prf_context(), 1_i8.into_prf_context());
        assert_ne!(1_u16.into_prf_context(), [1_u8, 0].into_prf_context());
    }

    #[test]
    fn equivalent_context_containers_share_an_encoding() {
        assert_eq!("a".into_prf_context(), String::from("a").into_prf_context());
        assert_eq!(b"a".into_prf_context(), b"a".to_vec().into_prf_context());
        assert_eq!(
            Cow::<[u8]>::Borrowed(b"a").into_prf_context(),
            b"a".to_vec().into_prf_context()
        );
        assert_eq!(
            Cow::<[u8]>::Owned(b"a".to_vec()).into_prf_context(),
            b"a".to_vec().into_prf_context()
        );
    }

    #[test]
    fn every_context_conversion_preserves_structure() {
        let expected_bytes = PrfContext::typed(PrfEncoding::BYTES, b"abc");
        let slice: &[u8] = b"abc";
        assert_eq!(slice.into_prf_context(), expected_bytes);
        assert_eq!((*b"abc").into_prf_context(), expected_bytes);
        assert_eq!(b"abc".to_vec().into_prf_context(), expected_bytes);
        assert_eq!(().into_prf_context(), PrfContext::default());

        let some = Some("value").into_prf_context();
        let typed_value = PrfContext::typed(PrfEncoding::UTF8, b"value");
        assert_eq!(some, PrfContext::pae(&[typed_value.as_bytes()]));
        assert_eq!(None::<&str>.into_prf_context(), PrfContext::pae(&[]));

        let left = PrfContext::typed(PrfEncoding::UTF8, b"left");
        let right = PrfContext::typed(PrfEncoding::U16, &7_u16.to_le_bytes());
        assert_eq!(
            ("left", 7_u16).into_prf_context(),
            PrfContext::pae(&[left.as_bytes(), right.as_bytes()])
        );
    }
}
