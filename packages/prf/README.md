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
