# vitaminc-prf

`vitaminc-prf` provides a serde-style API for deriving structured,
domain-separated pseudorandom values. Inputs cross backend boundaries in
`Protected` containers, maps bind their keys into the derivation context, and
backend output is always awaitable so local and remote batched implementations
share one interface.

This crate defines only the abstraction: the [`PrfValue`](https://docs.rs/vitaminc-prf/latest/vitaminc_prf/trait.PrfValue.html),
[`Prf`](https://docs.rs/vitaminc-prf/latest/vitaminc_prf/trait.Prf.html), and
[`PrfKeyInit`](https://docs.rs/vitaminc-prf/latest/vitaminc_prf/trait.PrfKeyInit.html)
traits, context and encoding domains, and the visitor machinery. It contains
no cryptography. Concrete backends live in their own crates; the local
HMAC-SHA256 backend is [`vitaminc-hmac`](https://docs.rs/vitaminc-hmac),
and its documentation carries runnable end-to-end examples.

Key ownership lives in exactly one place. `PrfKeyInit` constructs a backend
from key material taken **by value**, so the key moves into the backend and is
wiped when the backend drops. Every `Prf` derivation method then borrows the
backend (`&self`): a derivation is a pure function of the key and the input,
so nothing is consumed and one instance serves any number of derivations
without being cloned.

Every protected leaf carries an explicit [`PrfEncoding`](https://docs.rs/vitaminc-prf/latest/vitaminc_prf/struct.PrfEncoding.html)
domain. Built-in text, bytes, and fixed-width integers are separated even when
their byte representations happen to match. Custom leaf implementations must
provide a stable, namespaced encoding identifier, preventing accidental
untagged derivation.

## Implementing `PrfValue` for a struct

Struct implementations describe their fields with a map driver. The final
visitor receives resolved child nodes, so each field can produce a different
owned output while a deferred backend still executes the structure as one
batch.

```rust
use vitaminc_prf::{
    BlockVisitor, IntoPrfContext, MapAccess, MapPrf, Prf,
    PrfValue, PrfVisitor, PrfVisitorError, SeqAccess,
};

struct User {
    email: String,
    aliases: Vec<String>,
}

impl PrfValue for User {
    fn prf_visit_with_context<'a, P, V, C>(
        self,
        prf: &P,
        context: C,
        visitor: V,
    ) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        let context = context.into_prf_context().into_owned();
        prf.prf_map(Some(2))
            .prf_entry("email", self.email, context.clone())
            .prf_entry("aliases", self.aliases, context)
            .end(visitor)
    }
}

struct BlockListVisitor;

impl<P> PrfVisitor<[u8; 32], P> for BlockListVisitor {
    type Value = Vec<[u8; 32]>;

    fn visit_seq(self, seq: SeqAccess<[u8; 32], P>) -> Result<Self::Value, PrfVisitorError> {
        seq.map(|node| node.visit(BlockVisitor)).collect()
    }
}

#[derive(Debug, PartialEq, Eq)]
struct UserTerms {
    email: [u8; 32],
    aliases: Vec<[u8; 32]>,
}

struct UserTermsVisitor;

impl<P> PrfVisitor<[u8; 32], P> for UserTermsVisitor {
    type Value = UserTerms;

    fn visit_map(
        self,
        mut map: MapAccess<[u8; 32], P>,
    ) -> Result<Self::Value, PrfVisitorError> {
        let (email_key, email) = map.next_entry().ok_or(PrfVisitorError::InvalidValue)?;
        let (aliases_key, aliases) = map.next_entry().ok_or(PrfVisitorError::InvalidValue)?;

        if email_key != "email" || aliases_key != "aliases" || map.next_entry().is_some() {
            return Err(PrfVisitorError::InvalidValue);
        }

        Ok(UserTerms {
            email: email.visit(BlockVisitor)?,
            aliases: aliases.visit(BlockListVisitor)?,
        })
    }
}
```

Executing the derivation requires a backend; with `vitaminc-hmac` in
scope the value above resolves through
`user.prf_visit_with_context(&prf, "tenant/acme/users/v1", UserTermsVisitor).await`.

### Equality terms from `Value`

With the `value` feature, `PrfValue` is implemented for
`&vitaminc_aead_value::Value`. It borrows the source and derives one scalar
equality term. Booleans, containers, null, undefined and passthrough return
`PrfError::Canonical`; text with code points unassigned in Unicode 16 is also
refused. The `chrono` and `rust_decimal` features enable `value` and the
corresponding value variants. Without `value`, this crate does not depend on
`vitaminc-aead-value` or its Unicode tables.

The shared `vitaminc_aead_value::canonical` module owns the exhaustive value
dispatch and returns each term's domain with its bytes. Every integer kind,
`int8` through `uint128`, shares one domain and a 17-byte encoding (a sign
byte, then a big-endian 128-bit two's-complement word), so equal numbers give
equal terms whatever width wrote them: a JavaScript `BigInt` stored as `int8`
matches the same number stored as `int64` from Go. Both float kinds share one
domain: a `float32` widens exactly to `float64` (in integer operations, so
subnormals take no slow path), then signed zero and every NaN fold to one
positive quiet NaN. Equal numbers match across widths; `float32` 0.1 and
`float64` 0.1 are different numbers and do not. Integer and float domains are
distinct, so a JavaScript `number` 5 (`float64`) does not match an `int64` 5;
use `BigInt` for integer data. Other scalars use `orderable-bytes` at their
natural width: timestamps truncate fractional nanoseconds to
microseconds while retaining the 12-byte seconds/nanoseconds layout, and
decimal encodings normalize scale and signed zero. Text equality is Unicode 16
NFC without accent or case folding; the Unicode assignment table is pinned
exactly, and NFC stability keeps newer normalization tables compatible.
Ciphertext retains the original value, including its integer width, scale and
sub-microsecond data.

`PrfEncoding::for_value_kind` exposes the new, versioned domains. Existing
primitive `PrfValue` implementations retain their established little-endian or
raw UTF-8 domains. Applications must use the same input API and context for
writes and queries. Every new domain has an independently calculated HMAC
known-answer vector in `vitaminc-hmac/tests/value_equality.rs`.

**Merge gate for #373:** Dan Draper's written sign-off on canonical order bytes
as PRF inputs is required before merge. The temporary `orderable-bytes` Git pin
tracks ore.rs #97 and must become its registry release before publication.
