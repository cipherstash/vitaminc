# vitaminc-context

One canonical encoding for a *context*: the value an AEAD authenticates as
associated data and a PRF derives under. Both `vitaminc-aead` and
`vitaminc-prf` are views of this crate, so for every context `x`:

```text
x.into_aad().as_bytes() == x.into_prf_context().as_bytes()
```

That equality holds by construction, not by test. A context type implements
one trait, [`IntoContext`](https://docs.rs/vitaminc-context/latest/vitaminc_context/trait.IntoContext.html),
which names its parts as a [`ContextPiece`](https://docs.rs/vitaminc-context/latest/vitaminc_context/enum.ContextPiece.html)
tree. `IntoAad` and `IntoPrfContext` are blanket implementations over it
and cannot be implemented by hand, so no type can be given one encoding on
one side and a different encoding on the other.

```rust
use vitaminc_context::{ContextPiece, IntoContext};

struct TenantId(u64);

impl<'a> IntoContext<'a> for TenantId {
    fn into_context(self) -> ContextPiece<'a> {
        ("tenant", self.0).into_context()
    }
}

let piece = TenantId(7).into_context();
assert_eq!(piece.to_string(), "(\"tenant\", 7u64)");
assert_eq!(piece.encode(), ("tenant", 7u64).into_context().encode());
```

## The encoding

A typed leaf (text, bytes, an integer) is framed with what it is, so values
of different types never encode alike even when their bytes do. `7u32` and
`7i32` are different contexts, and so are `"ab"` and `b"ab"`:

```text
PAE(b"vitaminc/context/value/v1", type_tag, value_bytes)
```

A list is the PAE (Pre-Authentication Encoding, from the PASETO
specification) of its parts, `LE64(count) || (LE64(len) || part)*`, at every
level. `Some(x)` is the one-element list, `None` the empty list, `(a, b)` the
two-element list and `nonempty!(a).with(b).with(c)` the nested list
`((a, b), c)`. `()` is `ContextPiece::Unit` and encodes as no bytes at all.

Because there is only one encoding, a context that arrives as data rather
than as a Rust type, for example across an FFI boundary, needs no mirror
type: a `ContextPiece` list with the same parts is the same context.

```rust
use std::borrow::Cow;
use vitaminc_context::{ContextPiece, IntoContext};

let runtime = ContextPiece::List(vec![
    ContextPiece::Text(Cow::Borrowed("users/email")),
    ContextPiece::U64(7),
]);
assert_eq!(runtime.encode(), ("users/email", 7u64).into_context().encode());
```

## Derived contexts

A cipher or PRF that walks a structure derives the context each part is
sealed or derived under from the caller's context, with a reserved domain
label so it can never equal a caller-built composite:
[`Context::for_map_entry`](https://docs.rs/vitaminc-context/latest/vitaminc_context/struct.Context.html#method.for_map_entry),
`for_sequence_element`, `for_leaf`, the empty-sequence, empty-map and none
markers, `for_option_some` and `refine`. There is one set, shared by both
derivations, because a derived context describes the shape of the
plaintext, not the primitive consuming it.

## Raw bytes

Two entry points take bytes rather than a value, and both are explicit about
what the bytes are. `Context::from_encoded` takes bytes this encoder already
produced, for a context that was stored or crossed a language boundary; as
a part of a larger context it is the `ContextPiece::Encoded` leaf, written
verbatim. `Context::pae` frames a list of pieces exactly as a composite is
framed, for a crate that defines a domain-separated shape of its own under
a label that is not `vitaminc/context/…`.
