# vitaminc-hmac

`vitaminc-hmac` is the local HMAC-SHA256 backend for
[`vitaminc-prf`](https://docs.rs/vitaminc-prf), the serde-style API for
deriving structured, domain-separated pseudorandom values.

Keys stay in `Protected` allocations, the keyed digest state lives behind
`ProtectedDigest`, and the RFC 2104 keying is performed with every key-derived
buffer in a wiped allocation, so no unwiped copy of the key material is left
behind by construction. Each leaf derives
`HMAC-SHA256(key, PAE(encoding, context, input))`.

## Keying and ownership

`HmacSha256Prf::new` takes a `Protected<[u8; 32]>`, so the key length is
guaranteed by the type and construction cannot fail. Key material whose length
is only known at runtime — a KMS response, an environment variable — goes
through `try_from_bytes`, which rejects anything shorter than `MIN_KEY_LEN`
with a `WeakKeyError`. HMAC itself accepts a key of any length, including an
empty one, which would silently produce derivations anybody can recompute.

Both constructors take the key **by value**, and that is the whole ownership
story: the key moves into the PRF, lives there in one `Protected` allocation,
and is wiped when the PRF drops. `HmacSha256Prf` is deliberately not `Clone`,
so there is never a second handle whose lifetime could postpone that wipe.
Derivation borrows the PRF (`&prf`), so one instance serves as many
derivations as you like. Code that is generic over "any PRF I can build from a
key" bounds on `vitaminc_prf::PrfKeyInit`, which `HmacSha256Prf` implements
with the same two constructors.

```rust
use vitaminc_hmac::{HmacSha256Prf, WeakKeyError};
use vitaminc_protected::Protected;

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let from_kms: Vec<u8> = vec![7; 32];
let prf = HmacSha256Prf::try_from_bytes(Protected::new(from_kms))?;

let too_short = HmacSha256Prf::try_from_bytes(Protected::new(vec![7; 16]));
assert!(too_short.is_err());
# Ok(())
# }
```

## Deriving a block

Built-in values return the backend's raw block through `prf`. Use
`prf_with_context` to separate the same value across indexes or applications.

```rust
use vitaminc_prf::PrfValue;
use vitaminc_hmac::HmacSha256Prf;
use vitaminc_protected::Protected;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let prf = HmacSha256Prf::new(Protected::new([7; 32]));
let term = "alice@example.com"
    .prf_with_context(&prf, "users/email/exact/v1")
    .await?;
assert_eq!(term.len(), 32);

// The same instance keeps serving; nothing was consumed.
let again = "bob@example.com"
    .prf_with_context(&prf, "users/email/exact/v1")
    .await?;
assert_ne!(term, again);
# Ok(())
# }
```

## Producing application-specific output

`prf_visit` lets a visitor interpret a raw block without placing Bloom, ORE,
or other policy in the PRF crates.

```rust
use vitaminc_prf::{PrfValue, PrfVisitor, PrfVisitorError};
use vitaminc_hmac::HmacSha256Prf;
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
let prf = HmacSha256Prf::new(Protected::new([7; 32]));
let positions = "alice@example.com"
    .prf_visit(
        &prf,
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
    BlockVisitor, IntoPrfContext, MapAccess, MapPrf, Prf,
    PrfValue, PrfVisitor, PrfVisitorError, SeqAccess,
};
use vitaminc_hmac::HmacSha256Prf;
use vitaminc_protected::Protected;

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
let prf = HmacSha256Prf::new(Protected::new([7; 32]));
let terms = user
    .prf_visit_with_context(&prf, "tenant/acme/users/v1", UserTermsVisitor)
    .await?;

assert_eq!(terms.aliases.len(), 2);
# Ok(())
# }
```
