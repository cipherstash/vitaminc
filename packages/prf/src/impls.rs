use std::{
    any::Any,
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    hash::Hash,
};

use vitaminc_protected::{Controlled, Protected};

use crate::{IntoPrfContext, MapPrf, Prf, PrfEncoding, PrfValue, PrfVisitor, SeqPrf};

/// Marks an explicitly non-secret value that should pass through unchanged.
///
/// Passthrough values receive no cryptographic processing. They are suitable
/// for schema versions and similar public metadata, never secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Passthrough<T>(pub T);

impl<T> Passthrough<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> PrfValue for Passthrough<T>
where
    T: Send + 'static,
{
    fn prf_visit_with_context<'a, P, V, C>(self, prf: P, _context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        prf.passthrough_boxed(Box::new(self.0), visitor)
    }
}

impl<const N: usize> PrfValue for [u8; N] {
    fn prf_visit_with_context<'a, P, V, C>(self, prf: P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        prf.prf_bytes_array(
            Protected::new(self),
            PrfEncoding::BYTES,
            context.into_prf_context().into_owned(),
            visitor,
        )
    }
}

impl PrfValue for Box<[u8]> {
    fn prf_visit_with_context<'a, P, V, C>(self, prf: P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        prf.prf_bytes_vec(
            Protected::new(self.into_vec()),
            PrfEncoding::BYTES,
            context.into_prf_context().into_owned(),
            visitor,
        )
    }
}

impl PrfValue for &[u8] {
    fn prf_visit_with_context<'a, P, V, C>(self, prf: P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        prf.prf_bytes_vec(
            Protected::new(self.to_vec()),
            PrfEncoding::BYTES,
            context.into_prf_context().into_owned(),
            visitor,
        )
    }
}

macro_rules! integer_value {
    ($($ty:ty => $encoding:expr),+ $(,)?) => {$ (
        impl PrfValue for $ty {
            fn prf_visit_with_context<'a, P, V, C>(
                self,
                prf: P,
                context: C,
                visitor: V,
            ) -> P::Ok<V::Value>
            where
                P: Prf,
                V: PrfVisitor<P::Block, P::Passthrough>,
                C: IntoPrfContext<'a>,
            {
                prf.prf_bytes_array(
                    Protected::new(self.to_le_bytes()),
                    $encoding,
                    context.into_prf_context().into_owned(),
                    visitor,
                )
            }
        }
    )+};
}

integer_value!(
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

impl<const N: usize> PrfValue for Protected<[u8; N]> {
    fn prf_visit_with_context<'a, P, V, C>(self, prf: P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        prf.prf_bytes_array(
            self,
            PrfEncoding::BYTES,
            context.into_prf_context().into_owned(),
            visitor,
        )
    }
}

impl PrfValue for Protected<Vec<u8>> {
    fn prf_visit_with_context<'a, P, V, C>(self, prf: P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        prf.prf_bytes_vec(
            self,
            PrfEncoding::BYTES,
            context.into_prf_context().into_owned(),
            visitor,
        )
    }
}

macro_rules! protected_integer_value {
    ($($ty:ty => $encoding:expr),+ $(,)?) => {$ (
        impl PrfValue for Protected<$ty> {
            fn prf_visit_with_context<'a, P, V, C>(
                self,
                prf: P,
                context: C,
                visitor: V,
            ) -> P::Ok<V::Value>
            where
                P: Prf,
                V: PrfVisitor<P::Block, P::Passthrough>,
                C: IntoPrfContext<'a>,
            {
                let bytes = Protected::new(self.risky_ref().to_le_bytes());
                prf.prf_bytes_array(
                    bytes,
                    $encoding,
                    context.into_prf_context().into_owned(),
                    visitor,
                )
            }
        }
    )+};
}

protected_integer_value!(
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

impl PrfValue for String {
    fn prf_visit_with_context<'a, P, V, C>(self, prf: P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        prf.prf_bytes_vec(
            Protected::new(self.into_bytes()),
            PrfEncoding::UTF8,
            context.into_prf_context().into_owned(),
            visitor,
        )
    }
}

impl PrfValue for Protected<String> {
    fn prf_visit_with_context<'a, P, V, C>(self, prf: P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        let bytes = Protected::new(self.risky_ref().as_bytes().to_vec());
        prf.prf_bytes_vec(
            bytes,
            PrfEncoding::UTF8,
            context.into_prf_context().into_owned(),
            visitor,
        )
    }
}

impl PrfValue for &str {
    fn prf_visit_with_context<'a, P, V, C>(self, prf: P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        prf.prf_bytes_vec(
            Protected::new(self.as_bytes().to_vec()),
            PrfEncoding::UTF8,
            context.into_prf_context().into_owned(),
            visitor,
        )
    }
}

impl<T> PrfValue for Vec<T>
where
    T: PrfValue + Send + 'static,
{
    fn prf_visit_with_context<'a, P, V, C>(self, prf: P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        let context = context.into_prf_context().into_owned();
        let boxed: Box<dyn Any + Send> = Box::new(self);

        // Rust has no stable negative trait bounds with which to express
        // `Vec<T> except Vec<u8>`. A safe Any downcast keeps Vec<u8> as the
        // byte-leaf API while every other Vec remains a structural sequence.
        let values = match boxed.downcast::<Vec<u8>>() {
            Ok(bytes) => {
                return prf.prf_bytes_vec(
                    Protected::new(*bytes),
                    PrfEncoding::BYTES,
                    context,
                    visitor,
                );
            }
            Err(values) => match values.downcast::<Vec<T>>() {
                Ok(values) => *values,
                Err(_) => unreachable!("a failed downcast preserves the original Vec<T>"),
            },
        };

        let len = values.len();
        let seq = values
            .into_iter()
            .fold(prf.prf_seq(Some(len)), |seq, value| {
                seq.prf_next(value, context.clone())
            });
        seq.end(visitor)
    }
}

impl<T> PrfValue for Option<T>
where
    T: PrfValue,
{
    fn prf_visit_with_context<'a, P, V, C>(self, prf: P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        let context = context.into_prf_context().into_owned();
        match self {
            Some(value) => {
                let context = context.for_option_some();
                prf.prf_some(value, context, visitor)
            }
            None => prf.prf_none(context, visitor),
        }
    }
}

impl<K, T> PrfValue for HashMap<K, T>
where
    K: Into<Cow<'static, str>> + Eq + Hash,
    T: PrfValue,
{
    fn prf_visit_with_context<'a, P, V, C>(self, prf: P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        let context = context.into_prf_context().into_owned();
        let len = self.len();
        let map = self
            .into_iter()
            .fold(prf.prf_map(Some(len)), |map, (key, value)| {
                map.prf_entry(key, value, context.clone())
            });
        map.end(visitor)
    }
}

impl<K, T> PrfValue for BTreeMap<K, T>
where
    K: Into<Cow<'static, str>> + Ord,
    T: PrfValue,
{
    fn prf_visit_with_context<'a, P, V, C>(self, prf: P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        let context = context.into_prf_context().into_owned();
        let len = self.len();
        let map = self
            .into_iter()
            .fold(prf.prf_map(Some(len)), |map, (key, value)| {
                map.prf_entry(key, value, context.clone())
            });
        map.end(visitor)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        any::Any,
        collections::{BTreeMap, HashMap},
    };

    use vitaminc_protected::Protected;

    use crate::{
        BlockVisitor, HmacSha256Prf, MapAccess, PrfValue, PrfVisitor, PrfVisitorError, SeqAccess,
    };

    use super::Passthrough;

    fn backend() -> HmacSha256Prf {
        HmacSha256Prf::new(Protected::new((0_u8..32).collect()))
    }

    fn term<T: PrfValue>(value: T) -> [u8; 32] {
        value.prf(backend()).into_result().unwrap()
    }

    struct BlocksVisitor;

    impl<P> PrfVisitor<[u8; 32], P> for BlocksVisitor {
        type Value = Vec<[u8; 32]>;

        fn visit_seq(self, seq: SeqAccess<[u8; 32], P>) -> Result<Self::Value, PrfVisitorError> {
            seq.map(|node| node.visit(BlockVisitor)).collect()
        }
    }

    struct MapBlocksVisitor;

    impl<P> PrfVisitor<[u8; 32], P> for MapBlocksVisitor {
        type Value = BTreeMap<String, [u8; 32]>;

        fn visit_map(self, map: MapAccess<[u8; 32], P>) -> Result<Self::Value, PrfVisitorError> {
            map.map(|(key, node)| Ok((key, node.visit(BlockVisitor)?)))
                .collect()
        }
    }

    struct AbsentVisitor;

    impl<P> PrfVisitor<[u8; 32], P> for AbsentVisitor {
        type Value = ();

        fn visit_absent(self) -> Result<Self::Value, PrfVisitorError> {
            Ok(())
        }
    }

    struct U32PassthroughVisitor;

    impl PrfVisitor<[u8; 32], Box<dyn Any + Send + 'static>> for U32PassthroughVisitor {
        type Value = u32;

        fn visit_passthrough(
            self,
            value: Box<dyn Any + Send + 'static>,
        ) -> Result<Self::Value, PrfVisitorError> {
            value
                .downcast::<u32>()
                .map(|value| *value)
                .map_err(|_| PrfVisitorError::InvalidValue)
        }
    }

    #[test]
    fn passthrough_impl_preserves_the_owned_value() {
        let value = Passthrough::new(42_u32)
            .prf_visit(backend(), U32PassthroughVisitor)
            .into_result()
            .unwrap();
        assert_eq!(value, 42);
    }

    #[test]
    fn byte_array_impl_derives_one_block() {
        assert_ne!(term([1_u8, 2, 3]), [0; 32]);
    }

    #[test]
    fn boxed_byte_slice_impl_matches_the_same_bytes() {
        let boxed: Box<[u8]> = vec![1, 2, 3].into_boxed_slice();
        assert_eq!(term(boxed), term([1_u8, 2, 3]));
    }

    #[test]
    fn borrowed_byte_slice_impl_matches_the_same_bytes() {
        let slice: &[u8] = &[1, 2, 3];
        assert_eq!(term(slice), term([1_u8, 2, 3]));
    }

    macro_rules! integer_impl_test {
        ($($name:ident: $ty:ty),+ $(,)?) => {$ (
            #[test]
            fn $name() {
                let value: $ty = 7;
                assert_ne!(term(value), term(value.to_le_bytes()));
            }
        )+};
    }

    integer_impl_test!(
        u8_impl: u8,
        u16_impl: u16,
        u32_impl: u32,
        u64_impl: u64,
        u128_impl: u128,
        i8_impl: i8,
        i16_impl: i16,
        i32_impl: i32,
        i64_impl: i64,
        i128_impl: i128,
    );

    #[test]
    fn owned_string_impl_matches_borrowed_str() {
        assert_eq!(term(String::from("hello")), term("hello"));
    }

    #[test]
    fn borrowed_str_impl_is_separated_from_raw_utf8_bytes() {
        assert_ne!(term("hello"), term(b"hello".as_slice()));
    }

    #[test]
    fn byte_vector_impl_is_a_single_byte_leaf() {
        assert_eq!(term(vec![1_u8, 2, 3]), term([1_u8, 2, 3]));
    }

    #[test]
    fn generic_vector_impl_preserves_sequence_order() {
        let values = vec![String::from("first"), String::from("second")];
        let expected = values.iter().cloned().map(term).collect::<Vec<_>>();
        let actual = values
            .prf_visit(backend(), BlocksVisitor)
            .into_result()
            .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn option_some_impl_is_separated_from_the_bare_inner_value() {
        assert_ne!(term(Some(String::from("present"))), term("present"));
    }

    #[test]
    fn option_none_impl_visits_absence() {
        None::<String>
            .prf_visit(backend(), AbsentVisitor)
            .into_result()
            .unwrap();
    }

    #[test]
    fn protected_impl_matches_the_wrapped_value() {
        assert_eq!(term(Protected::new(String::from("secret"))), term("secret"));
    }

    #[test]
    fn protected_byte_containers_match_their_unwrapped_values() {
        assert_eq!(term(Protected::new([1_u8, 2, 3])), term([1_u8, 2, 3]));
        assert_eq!(
            term(Protected::new(vec![1_u8, 2, 3])),
            term(vec![1_u8, 2, 3])
        );
    }

    macro_rules! protected_integer_impl_test {
        ($($name:ident: $ty:ty),+ $(,)?) => {$ (
            #[test]
            fn $name() {
                let value: $ty = 7;
                assert_eq!(term(Protected::new(value)), term(value));
            }
        )+};
    }

    protected_integer_impl_test!(
        protected_u8_impl: u8,
        protected_u16_impl: u16,
        protected_u32_impl: u32,
        protected_u64_impl: u64,
        protected_u128_impl: u128,
        protected_i8_impl: i8,
        protected_i16_impl: i16,
        protected_i32_impl: i32,
        protected_i64_impl: i64,
        protected_i128_impl: i128,
    );

    #[test]
    fn hash_map_impl_preserves_keys_and_separates_their_contexts() {
        let values = HashMap::from([
            (String::from("left"), String::from("same")),
            (String::from("right"), String::from("same")),
        ]);
        let terms = values
            .prf_visit(backend(), MapBlocksVisitor)
            .into_result()
            .unwrap();
        assert_eq!(terms.len(), 2);
        assert_ne!(terms["left"], terms["right"]);
    }

    #[test]
    fn btree_map_impl_preserves_keys_and_separates_their_contexts() {
        let values = BTreeMap::from([
            ("left", String::from("same")),
            ("right", String::from("same")),
        ]);
        let terms = values
            .prf_visit(backend(), MapBlocksVisitor)
            .into_result()
            .unwrap();
        assert_eq!(
            terms.keys().map(String::as_str).collect::<Vec<_>>(),
            ["left", "right"]
        );
        assert_ne!(terms["left"], terms["right"]);
    }
}
