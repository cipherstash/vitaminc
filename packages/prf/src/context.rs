use std::borrow::Cow;

use crate::PrfEncoding;

const MAP_ENTRY_DOMAIN: &[u8] = b"vitaminc/prf/map-entry/v1";
const CONTEXT_VALUE_DOMAIN: &[u8] = b"vitaminc/prf/context-value/v1";
const OPTION_SOME_DOMAIN: &[u8] = b"vitaminc/prf/option-some/v1";

/// Owned or borrowed domain-separation context for a PRF derivation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct PrfContext<'a>(Cow<'a, [u8]>);

impl<'a> PrfContext<'a> {
    pub fn empty() -> Self {
        Self(Cow::Borrowed(&[]))
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
        let capacity = 8 + pieces.iter().map(|piece| 8 + piece.len()).sum::<usize>();
        let mut encoded = Vec::with_capacity(capacity);
        encoded.extend_from_slice(&(pieces.len() as u64).to_le_bytes());
        for piece in pieces {
            encoded.extend_from_slice(&(piece.len() as u64).to_le_bytes());
            encoded.extend_from_slice(piece);
        }
        PrfContext(Cow::Owned(encoded))
    }

    /// Add a domain component without allowing concatenation ambiguities.
    pub fn refine<'b, C>(&self, component: C) -> PrfContext<'static>
    where
        C: IntoPrfContext<'b>,
    {
        let component = component.into_prf_context();
        Self::pae(&[self.as_bytes(), component.as_bytes()])
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

pub trait IntoPrfContext<'a> {
    fn into_prf_context(self) -> PrfContext<'a>;
}

impl<'a> IntoPrfContext<'a> for PrfContext<'a> {
    fn into_prf_context(self) -> PrfContext<'a> {
        self
    }
}

impl<'a> IntoPrfContext<'a> for () {
    fn into_prf_context(self) -> PrfContext<'a> {
        PrfContext::empty()
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

impl<'a, T> IntoPrfContext<'a> for Option<T>
where
    T: IntoPrfContext<'a>,
{
    fn into_prf_context(self) -> PrfContext<'a> {
        match self {
            Some(value) => {
                let value = value.into_prf_context();
                PrfContext::pae(&[value.as_bytes()])
            }
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
    }
}
