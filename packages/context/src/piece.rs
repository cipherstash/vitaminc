//! A context's parts, and the one encoding of them.
//!
//! [`ContextPiece`] is the tree a context is made of: text, bytes, integers
//! and unit at the leaves, lists at the branches. Every context type
//! describes itself as one through [`IntoContext`], and
//! [`ContextPiece::encode`] is the only place that turns a tree into bytes.
//! That is what makes the AEAD's associated data and the PRF's context the
//! same bytes for the same value: both are views of this encoding, and
//! neither has an encoder of its own.
//!
//! # Encoding
//!
//! A typed leaf (text, bytes, an integer) encodes as a three-piece frame
//! naming what it is:
//!
//! ```text
//! PAE(b"vitaminc/context/value/v1", type_tag, value_bytes)
//! ```
//!
//! where the type tag is `vitaminc/context/utf8/v1`,
//! `vitaminc/context/bytes/v1`, `vitaminc/context/u64-le/v1`, and so on,
//! and the value bytes are UTF-8 for text, the bytes themselves for bytes,
//! and little-endian two's complement for an integer. Two values of
//! different types therefore never encode alike, even when their bytes do:
//! `7u32` and `7i32` are different contexts, and so are `"ab"` and `b"ab"`.
//!
//! A list encodes as the PAE of its parts' encodings, at every level.
//! `Some(x)` is the one-element list, `None` the empty list, `(a, b)` the
//! two-element list, and `nonempty!(a).with(b).with(c)` the nested list
//! `((a, b), c)`.
//!
//! Two leaves are not typed. [`Unit`](ContextPiece::Unit) is `()`, the
//! empty context, and encodes as no bytes at all. [`Encoded`](ContextPiece::Encoded)
//! is bytes this encoder already produced, and encodes as itself. Neither
//! can be confused with a typed leaf, which is never empty and always
//! begins with the value frame.

use std::borrow::Cow;
use std::fmt;

use vitaminc_protected::MaybeEmpty;

use crate::{pae, Context};

/// The first piece of every typed leaf.
const VALUE_DOMAIN: &[u8] = b"vitaminc/context/value/v1";

/// The type tag of a typed leaf, its second piece.
mod tag {
    pub(super) const UTF8: &[u8] = b"vitaminc/context/utf8/v1";
    pub(super) const BYTES: &[u8] = b"vitaminc/context/bytes/v1";
    pub(super) const U8: &[u8] = b"vitaminc/context/u8-le/v1";
    pub(super) const U16: &[u8] = b"vitaminc/context/u16-le/v1";
    pub(super) const U32: &[u8] = b"vitaminc/context/u32-le/v1";
    pub(super) const U64: &[u8] = b"vitaminc/context/u64-le/v1";
    pub(super) const U128: &[u8] = b"vitaminc/context/u128-le/v1";
    pub(super) const I8: &[u8] = b"vitaminc/context/i8-le/v1";
    pub(super) const I16: &[u8] = b"vitaminc/context/i16-le/v1";
    pub(super) const I32: &[u8] = b"vitaminc/context/i32-le/v1";
    pub(super) const I64: &[u8] = b"vitaminc/context/i64-le/v1";
    pub(super) const I128: &[u8] = b"vitaminc/context/i128-le/v1";
}

/// One part of a context, or a list of parts.
///
/// [`IntoContext::into_context`](crate::IntoContext::into_context) builds
/// one from any context type, and [`encode`](Self::encode) turns it into the
/// bytes both the AEAD and the PRF use. The tree is a stand-in for the value
/// it was built from: a runtime list with the same parts is the same context
/// as the static value, on both sides, because there is only one encoding.
///
/// ```rust
/// use std::borrow::Cow;
/// use vitaminc_context::{ContextPiece, IntoContext};
///
/// let value = ("users/email", 7u64);
/// let runtime = ContextPiece::List(vec![
///     ContextPiece::Text(Cow::Borrowed("users/email")),
///     ContextPiece::U64(7),
/// ]);
/// assert_eq!(runtime.encode(), value.into_context().encode());
/// ```
///
/// This matters for a context that arrives as data rather than as a Rust
/// type, for example across an FFI boundary. It needs no mirror type of its
/// own:
///
/// - `Some(x)` is the one-element list and `None` is the empty list;
/// - `(a, b)` is the two-element list;
/// - `nonempty!(a).with(b).with(c)` is the nested list `((a, b), c)`;
/// - `()` is [`Unit`](Self::Unit).
///
/// A flat list of three or more parts is also a valid context. It has no
/// tuple spelling in Rust, so build it with [`List`](Self::List) directly.
///
/// [`Display`](fmt::Display) renders a tree so that different trees never
/// print the same, for example `("users/email", 7u64)`, and
/// [`leaves`](Self::leaves) walks the parts in encoding order for a caller
/// that wants to render or bind them itself.
///
/// `PartialEq` compares trees, not encodings, and since every typed leaf is
/// tagged, trees that differ encode differently too. The one exception is
/// [`Encoded`](Self::Encoded): a `Bytes` leaf and an `Encoded` leaf holding
/// that leaf's encoding are unequal as trees and equal as bytes, which is
/// what `Encoded` is for.
///
/// [`MaybeEmpty`] is implemented by the same rule the static types use, so
/// a tree can be wrapped in [`NonEmpty`](vitaminc_protected::NonEmpty):
/// text, bytes and encoded bytes are empty at zero length, unit is empty,
/// an integer never is, and a list is empty only when every part is.
///
/// The enum is `#[non_exhaustive]`, so a new kind of leaf must not break a
/// downstream `match`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContextPiece<'a> {
    /// Text; a typed leaf of its UTF-8 bytes. `&str`, `String`.
    Text(Cow<'a, str>),
    /// Opaque bytes; a typed leaf of the bytes themselves. Byte slices and
    /// arrays, `Vec<u8>`, `Cow<[u8]>`.
    Bytes(Cow<'a, [u8]>),
    /// The unit context, `()`. Encodes as no bytes at all. Not the same as
    /// empty bytes, which are a typed leaf, or the empty list, which is
    /// framed.
    Unit,
    /// A `u8`; a typed leaf of one little-endian byte.
    U8(u8),
    /// A `u16`; a typed leaf of two little-endian bytes.
    U16(u16),
    /// A `u32`; a typed leaf of four little-endian bytes.
    U32(u32),
    /// A `u64`; a typed leaf of eight little-endian bytes.
    U64(u64),
    /// A `u128`; a typed leaf of sixteen little-endian bytes.
    U128(u128),
    /// An `i8`; a typed leaf of one two's-complement byte.
    I8(i8),
    /// An `i16`; a typed leaf of two little-endian two's-complement bytes.
    I16(i16),
    /// An `i32`; a typed leaf of four little-endian two's-complement bytes.
    I32(i32),
    /// An `i64`; a typed leaf of eight little-endian two's-complement bytes.
    I64(i64),
    /// An `i128`; a typed leaf of sixteen little-endian two's-complement
    /// bytes.
    I128(i128),
    /// Bytes this encoder already produced; encodes as itself, untagged. The
    /// parts view of a [`Context`], which is how a stored or derived context
    /// is passed back in as a value. Only [`Context::from_encoded`] and the
    /// derived-context methods on [`Context`] produce one.
    Encoded(Cow<'a, [u8]>),
    /// A list of parts; encodes as their PAE. A tuple is the list of its
    /// halves, `Some(x)` the one-element list, `None` the empty list.
    List(Vec<ContextPiece<'a>>),
}

impl<'a> ContextPiece<'a> {
    /// The canonical bytes of this context.
    ///
    /// A typed leaf and a list allocate exactly once, sized up front. `Unit`
    /// allocates nothing. `Encoded` hands its bytes through as they are, so
    /// a borrowed encoded context stays borrowed.
    pub fn encode(self) -> Context<'a> {
        match self {
            ContextPiece::Unit => Context::empty(),
            ContextPiece::Encoded(bytes) => Context(bytes),
            piece => {
                let len = piece.encoded_len();
                let mut buf = Vec::with_capacity(len);
                piece.write_into(&mut buf);
                debug_assert_eq!(buf.len(), len, "encoded_len must equal the bytes written");
                Context(Cow::Owned(buf))
            }
        }
    }

    /// Copy every borrowed part, so the tree can outlive its source.
    pub fn into_owned(self) -> ContextPiece<'static> {
        match self {
            ContextPiece::Text(text) => ContextPiece::Text(Cow::Owned(text.into_owned())),
            ContextPiece::Bytes(bytes) => ContextPiece::Bytes(Cow::Owned(bytes.into_owned())),
            ContextPiece::Unit => ContextPiece::Unit,
            ContextPiece::U8(v) => ContextPiece::U8(v),
            ContextPiece::U16(v) => ContextPiece::U16(v),
            ContextPiece::U32(v) => ContextPiece::U32(v),
            ContextPiece::U64(v) => ContextPiece::U64(v),
            ContextPiece::U128(v) => ContextPiece::U128(v),
            ContextPiece::I8(v) => ContextPiece::I8(v),
            ContextPiece::I16(v) => ContextPiece::I16(v),
            ContextPiece::I32(v) => ContextPiece::I32(v),
            ContextPiece::I64(v) => ContextPiece::I64(v),
            ContextPiece::I128(v) => ContextPiece::I128(v),
            ContextPiece::Encoded(bytes) => ContextPiece::Encoded(Cow::Owned(bytes.into_owned())),
            ContextPiece::List(parts) => {
                ContextPiece::List(parts.into_iter().map(ContextPiece::into_owned).collect())
            }
        }
    }

    /// The non-list parts, depth first, in the order they are encoded.
    /// A leaf piece yields itself; an empty list yields nothing.
    ///
    /// Nesting is dropped, so distinct contexts can share a leaf sequence:
    /// `(("a", 1u8), "b")` and `("a", (1u8, "b"))` both yield `a, 1, b`
    /// while encoding to different bytes. Use this to render or bind the
    /// parts, not to identify the context; the bytes from
    /// [`encode`](Self::encode) are its identity.
    pub fn leaves(&self) -> impl Iterator<Item = &ContextPiece<'a>> {
        fn walk<'p, 'a>(piece: &'p ContextPiece<'a>, out: &mut Vec<&'p ContextPiece<'a>>) {
            match piece {
                ContextPiece::List(parts) => parts.iter().for_each(|part| walk(part, out)),
                leaf => out.push(leaf),
            }
        }
        let mut out = Vec::new();
        walk(self, &mut out);
        out.into_iter()
    }

    /// The type tag and value length of a typed leaf, or `None` for the
    /// three kinds that are not typed leaves.
    fn typed(&self) -> Option<(&'static [u8], usize)> {
        Some(match self {
            ContextPiece::Text(text) => (tag::UTF8, text.len()),
            ContextPiece::Bytes(bytes) => (tag::BYTES, bytes.len()),
            ContextPiece::U8(_) => (tag::U8, 1),
            ContextPiece::U16(_) => (tag::U16, 2),
            ContextPiece::U32(_) => (tag::U32, 4),
            ContextPiece::U64(_) => (tag::U64, 8),
            ContextPiece::U128(_) => (tag::U128, 16),
            ContextPiece::I8(_) => (tag::I8, 1),
            ContextPiece::I16(_) => (tag::I16, 2),
            ContextPiece::I32(_) => (tag::I32, 4),
            ContextPiece::I64(_) => (tag::I64, 8),
            ContextPiece::I128(_) => (tag::I128, 16),
            ContextPiece::Unit | ContextPiece::Encoded(_) | ContextPiece::List(_) => return None,
        })
    }

    /// The length of this piece's encoding, without producing it.
    fn encoded_len(&self) -> usize {
        match self {
            ContextPiece::Unit => 0,
            ContextPiece::Encoded(bytes) => bytes.len(),
            ContextPiece::List(parts) => pae::encoded_len(parts.iter().map(Self::encoded_len)),
            typed => {
                let (tag, value_len) = typed
                    .typed()
                    .expect("every other kind of piece is a typed leaf");
                pae::encoded_len([VALUE_DOMAIN.len(), tag.len(), value_len].into_iter())
            }
        }
    }

    /// Appends this piece's encoding to `buf`. A typed leaf is written as
    /// its three-piece frame. A list is written in one pass: each part's
    /// length word is reserved before the part is written and filled in
    /// after, from the bytes actually produced, so a tree of any depth is
    /// written without intermediate buffers and without rescanning subtrees.
    fn write_into(&self, buf: &mut Vec<u8>) {
        match self {
            ContextPiece::Unit => {}
            ContextPiece::Encoded(bytes) => buf.extend_from_slice(bytes),
            ContextPiece::List(parts) => {
                buf.extend_from_slice(&(parts.len() as u64).to_le_bytes());
                for part in parts {
                    let length_word = buf.len();
                    buf.extend_from_slice(&[0u8; 8]);
                    let start = buf.len();
                    part.write_into(buf);
                    let written = (buf.len() - start) as u64;
                    buf[length_word..start].copy_from_slice(&written.to_le_bytes());
                }
            }
            ContextPiece::Text(text) => write_typed(buf, tag::UTF8, text.as_bytes()),
            ContextPiece::Bytes(bytes) => write_typed(buf, tag::BYTES, bytes),
            ContextPiece::U8(v) => write_typed(buf, tag::U8, &v.to_le_bytes()),
            ContextPiece::U16(v) => write_typed(buf, tag::U16, &v.to_le_bytes()),
            ContextPiece::U32(v) => write_typed(buf, tag::U32, &v.to_le_bytes()),
            ContextPiece::U64(v) => write_typed(buf, tag::U64, &v.to_le_bytes()),
            ContextPiece::U128(v) => write_typed(buf, tag::U128, &v.to_le_bytes()),
            ContextPiece::I8(v) => write_typed(buf, tag::I8, &v.to_le_bytes()),
            ContextPiece::I16(v) => write_typed(buf, tag::I16, &v.to_le_bytes()),
            ContextPiece::I32(v) => write_typed(buf, tag::I32, &v.to_le_bytes()),
            ContextPiece::I64(v) => write_typed(buf, tag::I64, &v.to_le_bytes()),
            ContextPiece::I128(v) => write_typed(buf, tag::I128, &v.to_le_bytes()),
        }
    }
}

/// Appends the typed-leaf frame `PAE(VALUE_DOMAIN, tag, value)` to `buf`.
fn write_typed(buf: &mut Vec<u8>, tag: &[u8], value: &[u8]) {
    pae::write(buf, &[VALUE_DOMAIN, tag, value]);
}

/// The same emptiness rule the static types use, applied to the tree. Text,
/// bytes and encoded bytes are empty at zero length. Unit is empty. An
/// integer is never empty, because even zero is information the caller
/// chose. A list is empty only when every part is, so `None` and `Some("")`
/// are empty and `("", 7u64)` is not, matching what `Option<T>` and `(A, B)`
/// decide.
impl MaybeEmpty for ContextPiece<'_> {
    fn is_empty(&self) -> bool {
        match self {
            ContextPiece::Text(text) => text.is_empty(),
            ContextPiece::Bytes(bytes) | ContextPiece::Encoded(bytes) => bytes.is_empty(),
            ContextPiece::Unit => true,
            ContextPiece::U8(_)
            | ContextPiece::U16(_)
            | ContextPiece::U32(_)
            | ContextPiece::U64(_)
            | ContextPiece::U128(_)
            | ContextPiece::I8(_)
            | ContextPiece::I16(_)
            | ContextPiece::I32(_)
            | ContextPiece::I64(_)
            | ContextPiece::I128(_) => false,
            ContextPiece::List(parts) => parts.iter().all(MaybeEmpty::is_empty),
        }
    }
}

/// Renders the tree in Rust literal syntax, and different trees never
/// render the same. Text is quoted and escaped as `Debug` does, integers
/// carry their type suffix, bytes print as `0x`-prefixed hex, encoded bytes
/// print as `Encoded(0x…)`, unit prints as `()`, a list is parenthesised and
/// comma-separated, and the empty list prints as `None` (the context it
/// is). So `("users/email", 7u64)` prints as `("users/email", 7u64)`.
///
/// Each kind starts differently: `"` for text, a digit or `-` for an
/// integer, `0x` for bytes, `E` for encoded bytes, `()` for unit, `(`
/// followed by a part for a list, and `None` for the empty list. Integer
/// suffixes keep types of the same width apart, and quoting keeps
/// separators inside text from reading as structure. Two contexts that
/// encode to different bytes therefore never share a log line.
impl fmt::Display for ContextPiece<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
            f.write_str("0x")?;
            bytes.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
        }
        match self {
            ContextPiece::Text(text) => write!(f, "{text:?}"),
            ContextPiece::Bytes(bytes) => hex(f, bytes),
            ContextPiece::Encoded(bytes) => {
                f.write_str("Encoded(")?;
                hex(f, bytes)?;
                f.write_str(")")
            }
            ContextPiece::Unit => f.write_str("()"),
            ContextPiece::U8(v) => write!(f, "{v}u8"),
            ContextPiece::U16(v) => write!(f, "{v}u16"),
            ContextPiece::U32(v) => write!(f, "{v}u32"),
            ContextPiece::U64(v) => write!(f, "{v}u64"),
            ContextPiece::U128(v) => write!(f, "{v}u128"),
            ContextPiece::I8(v) => write!(f, "{v}i8"),
            ContextPiece::I16(v) => write!(f, "{v}i16"),
            ContextPiece::I32(v) => write!(f, "{v}i32"),
            ContextPiece::I64(v) => write!(f, "{v}i64"),
            ContextPiece::I128(v) => write!(f, "{v}i128"),
            ContextPiece::List(parts) if parts.is_empty() => f.write_str("None"),
            ContextPiece::List(parts) => {
                f.write_str("(")?;
                for (i, part) in parts.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    fmt::Display::fmt(part, f)?;
                }
                f.write_str(")")
            }
        }
    }
}

/// A random tree, depth-bounded, over every kind of leaf. Available with
/// the `arbitrary` feature, so a downstream crate can state a property over
/// every tree this crate can encode.
#[cfg(feature = "arbitrary")]
impl quickcheck::Arbitrary for ContextPiece<'static> {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        fn gen(g: &mut quickcheck::Gen, depth: u8) -> ContextPiece<'static> {
            let kinds = if depth == 0 { 14 } else { 15 };
            match u8::arbitrary(g) % kinds {
                0 => ContextPiece::Text(Cow::Owned(String::arbitrary(g))),
                1 => ContextPiece::Bytes(Cow::Owned(Vec::arbitrary(g))),
                2 => ContextPiece::Unit,
                3 => ContextPiece::U8(u8::arbitrary(g)),
                4 => ContextPiece::U16(u16::arbitrary(g)),
                5 => ContextPiece::U32(u32::arbitrary(g)),
                6 => ContextPiece::U64(u64::arbitrary(g)),
                7 => ContextPiece::U128(u128::arbitrary(g)),
                8 => ContextPiece::I8(i8::arbitrary(g)),
                9 => ContextPiece::I16(i16::arbitrary(g)),
                10 => ContextPiece::I32(i32::arbitrary(g)),
                11 => ContextPiece::I64(i64::arbitrary(g)),
                12 => ContextPiece::I128(i128::arbitrary(g)),
                13 => ContextPiece::Encoded(Cow::Owned(Vec::arbitrary(g))),
                _ => {
                    let n = usize::arbitrary(g) % 4;
                    ContextPiece::List((0..n).map(|_| gen(g, depth - 1)).collect())
                }
            }
        }
        gen(g, 3)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use quickcheck_macros::quickcheck;
    use vitaminc_protected::NonEmpty;

    use super::*;
    use crate::IntoContext;

    fn text(s: &'static str) -> ContextPiece<'static> {
        ContextPiece::Text(Cow::Borrowed(s))
    }

    fn bytes(b: &'static [u8]) -> ContextPiece<'static> {
        ContextPiece::Bytes(Cow::Borrowed(b))
    }

    /// The typed-leaf frame, built by hand so the test shares no code with
    /// the encoder it checks.
    fn typed_frame(tag: &[u8], value: &[u8]) -> Vec<u8> {
        let pieces: [&[u8]; 3] = [b"vitaminc/context/value/v1", tag, value];
        let mut out = (pieces.len() as u64).to_le_bytes().to_vec();
        for piece in pieces {
            out.extend_from_slice(&(piece.len() as u64).to_le_bytes());
            out.extend_from_slice(piece);
        }
        out
    }

    /// One of each kind, for the exhaustive per-arm checks below.
    fn every_kind() -> Vec<ContextPiece<'static>> {
        vec![
            text("t"),
            bytes(b"b"),
            ContextPiece::Unit,
            ContextPiece::U8(1),
            ContextPiece::U16(2),
            ContextPiece::U32(3),
            ContextPiece::U64(4),
            ContextPiece::U128(5),
            ContextPiece::I8(-1),
            ContextPiece::I16(-2),
            ContextPiece::I32(-3),
            ContextPiece::I64(-4),
            ContextPiece::I128(-5),
            ContextPiece::Encoded(Cow::Borrowed(b"e")),
            ContextPiece::List(vec![ContextPiece::U8(9)]),
        ]
    }

    /// A random tree for the property tests. Wraps the `arbitrary` feature's
    /// generator so the tests do not depend on the feature being on.
    #[derive(Debug, Clone)]
    struct Tree(ContextPiece<'static>);

    impl quickcheck::Arbitrary for Tree {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            fn gen(g: &mut quickcheck::Gen, depth: u8) -> ContextPiece<'static> {
                let kinds = if depth == 0 { 14 } else { 15 };
                match u8::arbitrary(g) % kinds {
                    0 => ContextPiece::Text(Cow::Owned(String::arbitrary(g))),
                    1 => ContextPiece::Bytes(Cow::Owned(Vec::arbitrary(g))),
                    2 => ContextPiece::Unit,
                    3 => ContextPiece::U8(u8::arbitrary(g)),
                    4 => ContextPiece::U16(u16::arbitrary(g)),
                    5 => ContextPiece::U32(u32::arbitrary(g)),
                    6 => ContextPiece::U64(u64::arbitrary(g)),
                    7 => ContextPiece::U128(u128::arbitrary(g)),
                    8 => ContextPiece::I8(i8::arbitrary(g)),
                    9 => ContextPiece::I16(i16::arbitrary(g)),
                    10 => ContextPiece::I32(i32::arbitrary(g)),
                    11 => ContextPiece::I64(i64::arbitrary(g)),
                    12 => ContextPiece::I128(i128::arbitrary(g)),
                    13 => ContextPiece::Encoded(Cow::Owned(Vec::arbitrary(g))),
                    _ => {
                        let n = usize::arbitrary(g) % 4;
                        ContextPiece::List((0..n).map(|_| gen(g, depth - 1)).collect())
                    }
                }
            }
            Tree(gen(g, 3))
        }
    }

    mod given_a_typed_leaf {
        use super::*;

        #[test]
        fn encodes_as_the_documented_frame() {
            assert_eq!(
                text("ab").encode().as_bytes(),
                typed_frame(b"vitaminc/context/utf8/v1", b"ab"),
                "text is the utf8 frame"
            );
            assert_eq!(
                bytes(b"ab").encode().as_bytes(),
                typed_frame(b"vitaminc/context/bytes/v1", b"ab"),
                "bytes are the bytes frame"
            );
            assert_eq!(
                ContextPiece::U16(7).encode().as_bytes(),
                typed_frame(b"vitaminc/context/u16-le/v1", &7u16.to_le_bytes()),
                "an integer is its width's frame over little-endian bytes"
            );
            assert_eq!(
                ContextPiece::I128(-7).encode().as_bytes(),
                typed_frame(b"vitaminc/context/i128-le/v1", &(-7i128).to_le_bytes()),
                "a signed integer is two's complement"
            );
        }

        #[test]
        fn every_width_and_signedness_has_its_own_tag() {
            let tags = [
                (ContextPiece::U8(0), "vitaminc/context/u8-le/v1"),
                (ContextPiece::U16(0), "vitaminc/context/u16-le/v1"),
                (ContextPiece::U32(0), "vitaminc/context/u32-le/v1"),
                (ContextPiece::U64(0), "vitaminc/context/u64-le/v1"),
                (ContextPiece::U128(0), "vitaminc/context/u128-le/v1"),
                (ContextPiece::I8(0), "vitaminc/context/i8-le/v1"),
                (ContextPiece::I16(0), "vitaminc/context/i16-le/v1"),
                (ContextPiece::I32(0), "vitaminc/context/i32-le/v1"),
                (ContextPiece::I64(0), "vitaminc/context/i64-le/v1"),
                (ContextPiece::I128(0), "vitaminc/context/i128-le/v1"),
            ];
            for (piece, tag) in tags {
                let encoded = piece.clone().encode();
                let needle = tag.as_bytes();
                assert!(
                    encoded
                        .as_bytes()
                        .windows(needle.len())
                        .any(|window| window == needle),
                    "{piece} must carry the tag {tag}"
                );
            }
        }

        #[test]
        fn same_bytes_different_type_is_a_different_context() {
            // The collisions #315 found on the AAD side, now gone.
            assert_ne!(text("ab").encode(), bytes(b"ab").encode());
            assert_ne!(ContextPiece::U32(7).encode(), ContextPiece::I32(7).encode());
            assert_ne!(ContextPiece::U8(1).encode(), ContextPiece::I8(1).encode());
            assert_ne!(ContextPiece::U16(1).encode(), bytes(&[1, 0]).encode());
            assert_ne!(
                ContextPiece::U64(0).encode(),
                ContextPiece::List(vec![]).encode(),
                "`0u64` is not `None`"
            );
        }

        #[test]
        fn is_never_empty_as_bytes() {
            assert!(!text("").encode().is_empty(), "empty text is still framed");
            assert!(
                !bytes(b"").encode().is_empty(),
                "empty bytes are still framed"
            );
        }
    }

    mod given_the_unit_leaf {
        use super::*;

        #[test]
        fn encodes_as_no_bytes() {
            assert!(ContextPiece::Unit.encode().is_empty());
            assert_eq!(ContextPiece::Unit.encode(), Context::empty());
            assert_eq!(ContextPiece::Unit.to_string(), "()");
        }

        #[test]
        fn is_not_empty_bytes_and_not_the_empty_list() {
            // Three different contexts: `()` encodes as no bytes, empty bytes
            // are a typed leaf, and the empty list is framed. The tree keeps
            // them apart, and so do the bytes and `Display`.
            let empty_bytes = bytes(b"");
            let none = ContextPiece::List(vec![]);
            assert_ne!(ContextPiece::Unit, empty_bytes);
            assert_ne!(ContextPiece::Unit, none);
            assert_ne!(ContextPiece::Unit.encode(), empty_bytes.clone().encode());
            assert_ne!(ContextPiece::Unit.encode(), none.clone().encode());
            assert_ne!(ContextPiece::Unit.to_string(), empty_bytes.to_string());
            assert_ne!(ContextPiece::Unit.to_string(), none.to_string());
        }

        #[test]
        fn inside_a_list_frames_a_zero_length_part() {
            let mut expected = 1u64.to_le_bytes().to_vec();
            expected.extend_from_slice(&0u64.to_le_bytes());
            assert_eq!(
                ContextPiece::List(vec![ContextPiece::Unit])
                    .encode()
                    .as_bytes(),
                expected
            );
        }
    }

    mod given_the_encoded_leaf {
        use super::*;

        #[test]
        fn encodes_as_itself() {
            let piece = ContextPiece::Encoded(Cow::Borrowed(b"anything"));
            assert_eq!(piece.encode().as_bytes(), b"anything");
        }

        #[test]
        fn is_the_only_untagged_leaf() {
            // `Bytes` of a frame and `Encoded` of that same frame are
            // different trees, and only the `Encoded` one is that frame.
            let frame = text("t").encode();
            let as_encoded = ContextPiece::Encoded(Cow::Borrowed(frame.as_bytes()));
            let as_bytes = ContextPiece::Bytes(Cow::Borrowed(frame.as_bytes()));
            assert_ne!(as_encoded, as_bytes);
            assert_eq!(as_encoded.encode(), frame);
            assert_ne!(as_bytes.encode(), frame);
        }

        #[test]
        fn stays_borrowed() {
            let stored = vec![1u8, 2, 3];
            let piece = ContextPiece::Encoded(Cow::Borrowed(&stored));
            assert!(
                matches!(piece.encode().0, Cow::Borrowed(_)),
                "an encoded context is handed through without a copy"
            );
        }

        #[test]
        fn renders_apart_from_bytes() {
            assert_eq!(
                ContextPiece::Encoded(Cow::Borrowed(b"\x01\x02")).to_string(),
                "Encoded(0x0102)"
            );
            assert_ne!(
                ContextPiece::Encoded(Cow::Borrowed(b"\x01\x02")).to_string(),
                bytes(b"\x01\x02").to_string()
            );
        }
    }

    mod given_a_runtime_list {
        use super::*;

        #[test]
        fn one_part_spells_some() {
            let some = ContextPiece::List(vec![ContextPiece::U64(7)]);
            assert_eq!(
                some.clone(),
                Some(7u64).into_context(),
                "a list of one is `Some` as a tree"
            );
            assert_eq!(
                some.encode(),
                Some(7u64).into_context().encode(),
                "a list of one is `Some` as bytes"
            );
        }

        #[test]
        fn no_parts_spells_none() {
            let none = ContextPiece::List(vec![]);
            assert_eq!(none.encode(), Option::<u64>::None.into_context().encode());
        }

        #[test]
        fn two_parts_spell_the_pair() {
            let pair = ContextPiece::List(vec![text("users/age"), ContextPiece::U64(7)]);
            assert_eq!(pair.encode(), ("users/age", 7u64).into_context().encode());
        }

        #[test]
        fn two_parts_spell_the_proven_chain() {
            let pair = ContextPiece::List(vec![text("users/age"), ContextPiece::U64(7)]);
            assert_eq!(
                pair.encode(),
                NonEmpty::new("users/age")
                    .unwrap()
                    .with(7u64)
                    .into_context()
                    .encode(),
                "a list of two is `nonempty!(a).with(b)`"
            );
        }

        #[test]
        fn a_nested_list_spells_the_left_nested_chain() {
            let chained = ContextPiece::List(vec![
                ContextPiece::List(vec![text("users/age"), ContextPiece::U64(7)]),
                text("eu"),
            ]);
            assert_eq!(
                chained.encode(),
                NonEmpty::new("users/age")
                    .unwrap()
                    .with(7u64)
                    .with("eu")
                    .into_context()
                    .encode(),
                "`with` chains nest to the left"
            );
        }

        #[test]
        fn a_flat_list_is_its_own_context_not_a_chain() {
            let flat =
                ContextPiece::List(vec![text("users/age"), ContextPiece::U64(7), text("eu")]);
            assert_ne!(
                flat.encode(),
                NonEmpty::new("users/age")
                    .unwrap()
                    .with(7u64)
                    .with("eu")
                    .into_context()
                    .encode(),
                "a flat n-ary list is its own context, not a chain"
            );
        }
    }

    mod given_a_tree {
        use super::*;

        #[quickcheck]
        fn a_list_encodes_as_the_pae_of_its_parts(tree: Tree) -> bool {
            // The single-pass writer must produce `LE64(count) || (LE64(len)
            // || part)*` over the separately encoded parts, at every level.
            // The expected value is framed by hand rather than with
            // `Context::pae`, so the test shares no code with the writer.
            fn expected(piece: &ContextPiece<'_>) -> Vec<u8> {
                match piece {
                    ContextPiece::List(parts) => {
                        let parts: Vec<Vec<u8>> = parts.iter().map(expected).collect();
                        let mut out = (parts.len() as u64).to_le_bytes().to_vec();
                        for part in parts {
                            out.extend_from_slice(&(part.len() as u64).to_le_bytes());
                            out.extend_from_slice(&part);
                        }
                        out
                    }
                    leaf => leaf.clone().encode().as_bytes().to_vec(),
                }
            }
            let len = tree.0.encoded_len();
            let actual = tree.0.clone().encode();
            actual.as_bytes() == expected(&tree.0).as_slice() && actual.as_bytes().len() == len
        }

        #[quickcheck]
        fn into_owned_preserves_the_tree_and_the_bytes(tree: Tree) -> bool {
            let owned = tree.0.clone().into_owned();
            owned == tree.0 && owned.encode() == tree.0.encode()
        }

        #[quickcheck]
        fn display_is_injective(a: Tree, b: Tree) -> bool {
            a.0 == b.0 || a.0.to_string() != b.0.to_string()
        }

        #[quickcheck]
        fn a_pae_of_encoded_parts_is_the_list_of_those_parts(parts: Vec<Vec<u8>>) -> bool {
            // `Context::pae` and a list of `Encoded` leaves are the same
            // framing, which is what lets a crate build its own composite
            // shapes with `pae` and still be a list as a tree.
            let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
            let list = ContextPiece::List(
                parts
                    .iter()
                    .map(|p| ContextPiece::Encoded(Cow::Borrowed(p)))
                    .collect(),
            );
            Context::pae(&refs) == list.encode()
        }

        #[test]
        fn deep_left_nested_lists_encode_in_one_pass() {
            let mut piece = ContextPiece::U8(1);
            for i in 0..=255u8 {
                piece = ContextPiece::List(vec![piece, ContextPiece::U8(i)]);
            }
            // Reference: encode bottom-up with `Context::pae`, one level at a
            // time.
            let mut expected = ContextPiece::U8(1).encode();
            for i in 0..=255u8 {
                let leaf = ContextPiece::U8(i).encode();
                expected = Context::pae(&[expected.as_bytes(), leaf.as_bytes()]);
            }
            let len = piece.encoded_len();
            let actual = piece.encode();
            assert_eq!(actual, expected);
            assert_eq!(actual.as_bytes().len(), len);
        }

        #[test]
        fn every_kind_round_trips_through_into_owned_and_writes_its_own_length() {
            for piece in every_kind() {
                let owned = piece.clone().into_owned();
                assert_eq!(owned, piece, "into_owned must not change the tree");
                assert_eq!(
                    owned.encode(),
                    piece.clone().encode(),
                    "into_owned must not change the bytes"
                );
                let mut buf = Vec::new();
                piece.write_into(&mut buf);
                assert_eq!(buf.len(), piece.encoded_len(), "{piece}");
                assert_eq!(buf, piece.clone().encode().as_bytes(), "{piece}");
            }
        }

        #[test]
        fn every_kind_renders_as_documented() {
            let rendered: Vec<String> = every_kind().iter().map(ToString::to_string).collect();
            assert_eq!(
                rendered,
                [
                    "\"t\"",
                    "0x62",
                    "()",
                    "1u8",
                    "2u16",
                    "3u32",
                    "4u64",
                    "5u128",
                    "-1i8",
                    "-2i16",
                    "-3i32",
                    "-4i64",
                    "-5i128",
                    "Encoded(0x65)",
                    "(9u8)",
                ]
            );
        }

        #[test]
        fn display_is_injective_where_it_could_collide() {
            // Same width, different type; text that looks like an integer;
            // text that looks like hex; `Some("")` against `None`; `()`
            // against `None`; text containing the separators; bytes against
            // encoded bytes.
            let pairs: [(ContextPiece<'_>, ContextPiece<'_>); 7] = [
                (7u64.into_context(), 7i64.into_context()),
                (("x", 7u64).into_context(), ("x", "7").into_context()),
                ("0xdead".into_context(), [0xdeu8, 0xad].into_context()),
                (Some("").into_context(), Option::<&str>::None.into_context()),
                (().into_context(), Option::<&str>::None.into_context()),
                (("a, b", "c").into_context(), ("a", "b, c").into_context()),
                (
                    bytes(b"\x01"),
                    ContextPiece::Encoded(Cow::Borrowed(b"\x01")),
                ),
            ];
            for (left, right) in pairs {
                assert_ne!(left.to_string(), right.to_string());
            }
            assert_eq!(
                ("a, b", (7u8, [1u8])).into_context().to_string(),
                "(\"a, b\", (7u8, 0x01))"
            );
            assert_eq!(Some("").into_context().to_string(), "(\"\")");
            assert_eq!((-7i16).into_context().to_string(), "-7i16");
            assert_eq!(Option::<&str>::None.into_context().to_string(), "None");
            assert_eq!(Some("a").into_context().to_string(), "(\"a\")");
        }

        #[test]
        fn leaves_walk_in_encoding_order_and_drop_nesting() {
            let piece = ((("a", 1u8), Option::<&str>::None), (Some("b"), [9u8])).into_context();
            let leaves: Vec<String> = piece.leaves().map(ToString::to_string).collect();
            assert_eq!(leaves, ["\"a\"", "1u8", "\"b\"", "0x09"]);
            assert_eq!(
                "x".into_context().leaves().count(),
                1,
                "a leaf is its own only leaf"
            );
            assert_eq!(Option::<&str>::None.into_context().leaves().count(), 0);
            // Nesting is not recoverable from the leaves, as the doc says.
            let left = (("a", 1u8), "b").into_context();
            let right = ("a", (1u8, "b")).into_context();
            assert!(left.leaves().eq(right.leaves()));
            assert_ne!(left.encode(), right.encode());
        }
    }

    mod given_emptiness {
        use super::*;

        #[quickcheck]
        fn agrees_with_the_static_types(s: String, n: u64, o: Option<String>) -> bool {
            s.is_empty() == s.as_str().into_context().is_empty()
                && !n.into_context().is_empty()
                && o.is_empty() == o.clone().into_context().is_empty()
                && (s.as_str(), n).is_empty() == (s.as_str(), n).into_context().is_empty()
                && (o.clone(), s.as_str()).is_empty() == (o, s.as_str()).into_context().is_empty()
        }

        #[test]
        fn fixed_shapes_follow_the_static_rule() {
            assert!(
                ContextPiece::List(vec![]).is_empty(),
                "the empty list is empty"
            );
            assert!(
                ContextPiece::List(vec![text("")]).is_empty(),
                "a list of empty parts is empty"
            );
            assert!(
                !ContextPiece::List(vec![text(""), ContextPiece::U64(0)]).is_empty(),
                "an integer part makes a list non-empty, even zero"
            );
            assert!(
                !ContextPiece::List(vec![ContextPiece::List(vec![bytes(b"x")])]).is_empty(),
                "emptiness looks through nested lists"
            );
            assert!(ContextPiece::Unit.is_empty(), "unit is empty");
            assert!(
                ContextPiece::Encoded(Cow::Borrowed(b"")).is_empty(),
                "encoded bytes are empty at zero length"
            );
            assert!(
                !ContextPiece::Encoded(Cow::Borrowed(b"x")).is_empty(),
                "encoded bytes are non-empty otherwise"
            );
            assert!(
                NonEmpty::new(ContextPiece::List(vec![ContextPiece::U8(0)])).is_ok(),
                "a tree with an integer is provable non-empty"
            );
            assert!(
                NonEmpty::new(text("")).is_err(),
                "an empty text leaf is not provable non-empty"
            );
        }
    }
}
