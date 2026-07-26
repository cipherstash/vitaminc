# vitaminc-prf

`vitaminc-prf` provides a serde-style API for deriving structured,
domain-separated pseudorandom values. Inputs cross backend boundaries in
`Protected` containers, maps bind their keys into the derivation context, and
backend output is always awaitable so local and remote batched implementations
share one interface.

Every protected leaf carries an explicit [`PrfEncoding`](https://docs.rs/vitaminc-prf/latest/vitaminc_prf/struct.PrfEncoding.html)
domain. Built-in text, bytes, and fixed-width integers are separated even when
their byte representations happen to match. Custom leaf implementations must
provide a stable, namespaced encoding identifier, preventing accidental
untagged derivation.

## Deriving a block

Built-in values return the backend's raw block through `prf`. Use
`prf_with_context` to separate the same value across indexes or applications.

```rust
use vitaminc_prf::{HmacSha256Prf, PrfValue};
use vitaminc_protected::Protected;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let prf = HmacSha256Prf::new(Protected::new(vec![7; 32]));
let term = "alice@example.com"
    .prf_with_context(prf, "users/email/exact/v1")
    .await?;
assert_eq!(term.len(), 32);
# Ok(())
# }
```

## Producing application-specific output

`prf_visit` lets a visitor interpret a raw block without placing Bloom, ORE,
or other policy in this crate.

```rust
use vitaminc_prf::{HmacSha256Prf, PrfValue, PrfVisitor, PrfVisitorError};
use vitaminc_protected::Protected;

struct BloomPositions {
    count: usize,
    modulus: i16,
}

impl<P> PrfVisitor<[u8; 32], P> for BloomPositions {
    type Value = Vec<i16>;

    fn visit_block(self, block: [u8; 32]) -> Result<Self::Value, PrfVisitorError> {
        Ok(block
            .chunks_exact(2)
            .take(self.count)
            .map(|chunk| {
                i16::from_le_bytes([chunk[0], chunk[1]]).rem_euclid(self.modulus)
            })
            .collect())
    }
}

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let prf = HmacSha256Prf::new(Protected::new(vec![7; 32]));
let positions = "alice@example.com"
    .prf_visit(
        prf,
        BloomPositions {
            count: 4,
            modulus: 2048,
        },
    )
    .await?;

assert_eq!(positions.len(), 4);
# Ok(())
# }
```

## Implementing `PrfValue` for a struct

Struct implementations describe their fields with a map driver. The final
visitor receives resolved child nodes, so each field can produce a different
owned output while a deferred backend still executes the structure as one
batch.

```rust
use vitaminc_prf::{
    BlockVisitor, HmacSha256Prf, IntoPrfContext, MapAccess, MapPrf, Prf,
    PrfValue, PrfVisitor, PrfVisitorError, SeqAccess,
};
use vitaminc_protected::Protected;

struct User {
    email: String,
    aliases: Vec<String>,
}

impl PrfValue for User {
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
        let context = context.into_prf_context().into_owned();
        prf.prf_map(Some(2))
            .prf_entry("email", self.email, context.clone())
            .prf_entry("aliases", self.aliases, context)
            .end(visitor)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct UserTerms {
    email: [u8; 32],
    aliases: Vec<[u8; 32]>,
}

struct BlockListVisitor;

impl<P> PrfVisitor<[u8; 32], P> for BlockListVisitor {
    type Value = Vec<[u8; 32]>;

    fn visit_seq(self, seq: SeqAccess<[u8; 32], P>) -> Result<Self::Value, PrfVisitorError> {
        seq.map(|node| node.visit(BlockVisitor)).collect()
    }
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

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let user = User {
    email: "alice@example.com".into(),
    aliases: vec!["alice".into(), "a.smith".into()],
};
let prf = HmacSha256Prf::new(Protected::new(vec![7; 32]));
let terms = user
    .prf_visit_with_context(prf, "tenant/acme/users/v1", UserTermsVisitor)
    .await?;

assert_eq!(terms.aliases.len(), 2);
# Ok(())
# }
```
