//! The one trait a context type implements.

use std::borrow::Cow;

use vitaminc_protected::NonEmpty;

use crate::ContextPiece;

/// Types that describe themselves as a context.
///
/// This is the only trait a context type implements. It names the parts,
/// as a [`ContextPiece`] tree, and never the bytes: the bytes come from
/// [`ContextPiece::encode`], which is the one encoder both the AEAD's
/// `IntoAad` and the PRF's `IntoPrfContext` are built on. A type that
/// implements `IntoContext` gets both of those for free, and cannot be
/// given a different encoding on one side than on the other.
///
/// Implementations are provided for text, bytes, every fixed-width integer,
/// `()`, `Option<T>`, pairs, `NonEmpty<T>`, an already-encoded
/// [`Context`](crate::Context) and the tree itself. Compose them: a
/// context type of your own describes itself in terms of the built-ins.
///
/// ```rust
/// use vitaminc_context::{ContextPiece, IntoContext};
///
/// struct TenantId(u64);
///
/// impl<'a> IntoContext<'a> for TenantId {
///     fn into_context(self) -> ContextPiece<'a> {
///         ("tenant", self.0).into_context()
///     }
/// }
///
/// let piece = TenantId(7).into_context();
/// assert_eq!(piece.to_string(), "(\"tenant\", 7u64)");
/// assert_eq!(piece.encode(), ("tenant", 7u64).into_context().encode());
/// ```
pub trait IntoContext<'a> {
    /// Describe `self` as a tree of parts.
    fn into_context(self) -> ContextPiece<'a>;
}

/// The tree of a tree is itself.
impl<'a> IntoContext<'a> for ContextPiece<'a> {
    fn into_context(self) -> ContextPiece<'a> {
        self
    }
}

/// `NonEmpty<T>` is transparent: it describes itself exactly as `T` does.
/// The wrapper changes what the type promises, never the context.
impl<'a, T> IntoContext<'a> for NonEmpty<T>
where
    T: IntoContext<'a>,
{
    fn into_context(self) -> ContextPiece<'a> {
        self.into_inner().into_context()
    }
}

/// The unit context, [`ContextPiece::Unit`]: no bytes at all.
impl<'a> IntoContext<'a> for () {
    fn into_context(self) -> ContextPiece<'a> {
        ContextPiece::Unit
    }
}

impl<'a> IntoContext<'a> for &'a str {
    fn into_context(self) -> ContextPiece<'a> {
        ContextPiece::Text(Cow::Borrowed(self))
    }
}

impl<'a> IntoContext<'a> for String {
    fn into_context(self) -> ContextPiece<'a> {
        ContextPiece::Text(Cow::Owned(self))
    }
}

impl<'a> IntoContext<'a> for &'a [u8] {
    fn into_context(self) -> ContextPiece<'a> {
        ContextPiece::Bytes(Cow::Borrowed(self))
    }
}

impl<'a> IntoContext<'a> for Vec<u8> {
    fn into_context(self) -> ContextPiece<'a> {
        ContextPiece::Bytes(Cow::Owned(self))
    }
}

impl<'a, const N: usize> IntoContext<'a> for [u8; N] {
    fn into_context(self) -> ContextPiece<'a> {
        ContextPiece::Bytes(Cow::Owned(self.to_vec()))
    }
}

impl<'a, const N: usize> IntoContext<'a> for &'a [u8; N] {
    fn into_context(self) -> ContextPiece<'a> {
        ContextPiece::Bytes(Cow::Borrowed(self.as_slice()))
    }
}

impl<'a> IntoContext<'a> for Cow<'a, [u8]> {
    fn into_context(self) -> ContextPiece<'a> {
        ContextPiece::Bytes(self)
    }
}

macro_rules! integer_context {
    ($($ty:ty => $variant:ident),+ $(,)?) => {$(
        /// An integer is its own kind of leaf, so its width and signedness
        /// are part of the context: `7u32` and `7i32` never encode alike.
        impl<'a> IntoContext<'a> for $ty {
            fn into_context(self) -> ContextPiece<'a> {
                ContextPiece::$variant(self)
            }
        }
    )+};
}

integer_context!(
    u8 => U8, u16 => U16, u32 => U32, u64 => U64, u128 => U128,
    i8 => I8, i16 => I16, i32 => I32, i64 => I64, i128 => I128,
);

/// `Some(x)` is the one-element list and `None` is the empty list, so a
/// runtime list of one part is the same context as the static `Some`.
impl<'a, T> IntoContext<'a> for Option<T>
where
    T: IntoContext<'a>,
{
    fn into_context(self) -> ContextPiece<'a> {
        ContextPiece::List(self.into_iter().map(T::into_context).collect())
    }
}

/// A pair is the two-element list.
impl<'a, A, B> IntoContext<'a> for (A, B)
where
    A: IntoContext<'a>,
    B: IntoContext<'a>,
{
    fn into_context(self) -> ContextPiece<'a> {
        let (a, b) = self;
        ContextPiece::List(vec![a.into_context(), b.into_context()])
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use quickcheck_macros::quickcheck;

    use super::*;
    use crate::Context;

    fn encoded<'a>(value: impl IntoContext<'a>) -> Context<'a> {
        value.into_context().encode()
    }

    mod given_a_text_context {
        use super::*;

        #[test]
        fn is_a_text_leaf_however_it_is_owned() {
            assert_eq!("a".into_context(), ContextPiece::Text(Cow::Borrowed("a")));
            assert_eq!(
                String::from("a").into_context(),
                ContextPiece::Text(Cow::Owned(String::from("a")))
            );
            assert_eq!(encoded("a"), encoded(String::from("a")));
        }
    }

    mod given_a_bytes_context {
        use super::*;

        #[test]
        fn every_byte_container_is_the_same_bytes_leaf() {
            let expected = encoded(b"abc".as_slice());
            assert_eq!(encoded(*b"abc"), expected, "an owned array");
            assert_eq!(encoded(b"abc"), expected, "a borrowed array");
            assert_eq!(encoded(b"abc".to_vec()), expected, "a vector");
            assert_eq!(
                encoded(Cow::<[u8]>::Borrowed(b"abc")),
                expected,
                "a borrowed cow"
            );
            assert_eq!(
                encoded(Cow::<[u8]>::Owned(b"abc".to_vec())),
                expected,
                "an owned cow"
            );
        }

        #[test]
        fn text_and_bytes_are_different_contexts() {
            assert_eq!("ab".into_context().leaves().count(), 1);
            assert_ne!(encoded("ab"), encoded(b"ab".as_slice()));
        }
    }

    mod given_an_integer_context {
        use super::*;

        #[test]
        fn keeps_its_type() {
            assert_eq!(7u32.into_context(), ContextPiece::U32(7));
            assert_eq!((-7i16).into_context(), ContextPiece::I16(-7));
        }

        #[test]
        fn width_and_signedness_are_part_of_the_context() {
            assert_ne!(encoded(7u32), encoded(7u64), "different widths");
            assert_ne!(encoded(7u32), encoded(7i32), "different signedness");
            assert_ne!(encoded(1u16), encoded([1u8, 0]), "not its raw bytes");
            assert_ne!(
                encoded(0u64),
                encoded(Option::<u64>::None),
                "`0u64` is not `None`"
            );
        }
    }

    mod given_the_unit_context {
        use super::*;

        #[test]
        fn is_the_empty_context() {
            assert_eq!(().into_context(), ContextPiece::Unit);
            assert_eq!(encoded(()), Context::empty());
        }

        #[test]
        fn differs_from_none_and_from_empty_text() {
            assert_ne!(encoded(()), encoded(Option::<&str>::None));
            assert_ne!(encoded(()), encoded(""));
        }
    }

    mod given_an_option_context {
        use super::*;

        #[quickcheck]
        fn some_is_the_one_element_list(bytes: Vec<u8>) -> bool {
            let inner = encoded(bytes.clone());
            let some = encoded(Some(bytes));
            some == Context::pae(&[inner.as_bytes()]) && some != inner
        }

        #[test]
        fn none_is_the_empty_list() {
            assert_eq!(None::<&str>.into_context(), ContextPiece::List(vec![]));
            assert_eq!(encoded(None::<&str>), Context::pae(&[]));
            assert_eq!(encoded(None::<&str>).as_bytes(), &[0u8; 8]);
        }

        #[test]
        fn none_differs_from_some_of_an_empty_value() {
            assert_ne!(encoded(None::<&str>), encoded(Some("")));
        }

        #[test]
        fn some_does_not_carry_the_value_side_domain() {
            // The value side of `Option` tags `Some` with its own domain; the
            // context side does not, so a runtime list of one part matches.
            assert_ne!(encoded(Some("value")), encoded("value").for_option_some());
        }
    }

    mod given_a_pair_context {
        use super::*;

        #[test]
        fn is_the_two_element_list_of_typed_parts() {
            assert_eq!(
                ("users/email", 7u64).into_context(),
                ContextPiece::List(vec![
                    ContextPiece::Text(Cow::Borrowed("users/email")),
                    ContextPiece::U64(7),
                ])
            );
            let left = encoded("left");
            let right = encoded(7u16);
            assert_eq!(
                encoded(("left", 7u16)),
                Context::pae(&[left.as_bytes(), right.as_bytes()])
            );
        }

        #[test]
        fn is_injective_across_its_boundary() {
            assert_ne!(encoded(("ab", "cd")), encoded(("a", "bcd")));
            assert_ne!(encoded(("foobar", ())), encoded(("foo", "bar")));
        }

        #[test]
        fn unit_inside_a_pair_is_a_zero_length_part() {
            assert_eq!(
                encoded(("x", ())),
                Context::pae(&[encoded("x").as_bytes(), b""])
            );
            assert_ne!(encoded(("x", ())), encoded("x"));
        }
    }

    mod given_a_proven_context {
        use super::*;

        #[test]
        fn non_empty_is_transparent() {
            assert_eq!(
                NonEmpty::new("users/email").unwrap().into_context(),
                "users/email".into_context()
            );
            assert_eq!(
                encoded(Some(NonEmpty::new("users/email").unwrap())),
                encoded(Some("users/email"))
            );
            assert_eq!(
                encoded(NonEmpty::new(("users", "email")).unwrap()),
                encoded(("users", "email"))
            );
            assert_eq!(
                encoded(vitaminc_protected::nonempty!("users/email").with(42u64)),
                encoded(("users/email", 42u64)),
                "a pair extended from a proven head is the bare pair"
            );
        }
    }

    mod given_an_encoded_context {
        use super::*;

        #[test]
        fn is_the_encoded_leaf() {
            let stored = encoded(("a", 1u8));
            assert_eq!(
                stored.clone().into_context(),
                ContextPiece::Encoded(Cow::Borrowed(stored.as_bytes())).into_owned()
            );
            assert_eq!(encoded(stored.clone()), stored);
        }

        #[test]
        fn inside_a_composite_is_written_verbatim() {
            // A derived context re-passed as a value, as a map cipher does
            // with an entry's context, is framed as itself.
            let derived = Context::empty().for_map_entry("name");
            assert_eq!(
                encoded((derived.clone(), 7u8)),
                Context::pae(&[derived.as_bytes(), encoded(7u8).as_bytes()])
            );
        }
    }
}
