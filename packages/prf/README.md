# vitaminc-prf

`vitaminc-prf` defines an API for deriving pseudorandom values from scalars,
sequences, maps, and structs. It supports both local computation and remote
batch requests.

The crate defines two sides of the API:

- **Input types implement [`PrfValue`](https://docs.rs/vitaminc-prf/latest/vitaminc_prf/trait.PrfValue.html).**
  This describes the values to process and their structure: for example, a
  struct's fields and their map keys. It does not choose the cryptographic
  algorithm.
- **Providers implement [`Prf`](https://docs.rs/vitaminc-prf/latest/vitaminc_prf/trait.Prf.html).**
  This defines the backend that computes results from those values, using an
  algorithm such as HMAC-SHA256. A provider can compute locally or send work
  to a remote service.

This is similar to Serde's `Serialize` and `Serializer`: `PrfValue` describes
the input, while `Prf` supplies the operation. The same input type can work
with different providers, and one provider can handle many input types.

A `PrfVisitor` converts the provider's results into the output type the
application needs, such as a struct containing a block for each field. Results
can be awaited whether the provider computes them immediately or makes a
remote request.

This crate provides the interfaces and supporting types. The cryptographic
implementations live in other crates, such as
[`vitaminc-hmac`](https://docs.rs/vitaminc-hmac), which implements `Prf` using
HMAC-SHA256. Its documentation includes complete usage examples.

## Keys, context, and input types

[`PrfKeyInit`](https://docs.rs/vitaminc-prf/latest/vitaminc_prf/trait.PrfKeyInit.html)
constructs a backend by taking ownership of a protected key. The backend owns
the key and must wipe it when dropped. Derivation methods borrow the backend,
so you can reuse it without cloning it. The input value and visitor are
consumed by each call.

Leaf inputs are passed to the backend in `Protected` containers. Each leaf
also has a context and an explicit
[`PrfEncoding`](https://docs.rs/vitaminc-prf/latest/vitaminc_prf/struct.PrfEncoding.html)
identifier. These are included in the derivation to keep results for different
uses and input types separate. Map entries add their keys to the context;
sequence elements share the supplied context without adding an index.

The built-in encodings distinguish text, bytes, and each integer type, even
when their bytes match. A custom leaf implementation must choose a stable,
versioned encoding identifier in its own namespace. The optional normalization
API below uses different encodings so that equivalent values can match across
types.

## Implementing `PrfValue` for a struct

Describe a struct's fields as map entries. A visitor then reads the computed
results and builds an output value. In this example, `UserTermsVisitor` builds
a `UserTerms` containing one block for the email and a list of blocks for the
aliases. A remote backend can collect the field operations into a batch.

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

To run this example, create a backend such as `vitaminc_hmac::HmacSha256Prf`
and a `User`, then call
`user.prf_visit_with_context(&prf, "tenant/acme/users/v1", UserTermsVisitor).await`.
The context in this call identifies the tenant and the use of the data.

## Equality terms with normalization

Enable the `normalize` feature to derive matching terms from equivalent values
that may have different representations. For example, an `i8` and an `i64`
containing the same number will produce the same term after normalization,
provided they use the same key and context.

For a document, use the index sink in `vitaminc-normalize`. It produces
`Normalized` values, each containing a stable domain label and protected bytes.
`Normalized` implements `PrfValue`, so the backend can derive a term directly
without normalizing the value again.

For a single value, such as a query parameter, use
`EqualityTerm::new(logical, physical)`. When you derive its term, it normalizes
the value first. Derivation returns `PrfError::Normalize` for:

- Values with no equality domain, including booleans and `undefined`.
- Logical types the normalizer does not support.
- Text containing code points unassigned in Unicode 16.
- Values that are invalid for their logical type.

Null is supported. All nulls use the `vitaminc/prf/value/null/v1` domain and
produce the same term for the same key and context.

### Normalization rules

`vitaminc-normalize` defines the supported logical types and their encodings.
Each row below uses a separate domain, so an integer, a float, and a date remain
distinct even if they have the same underlying numeric value.

| Value | Normalization |
| --- | --- |
| Integers | All widths share a 17-byte encoding: a sign byte followed by a big-endian 128-bit two's-complement word. Equal integer values match across widths. |
| Floats | `f32` values are converted exactly to `f64`. `-0.0` and `+0.0` both become `+0.0`; all NaNs use one positive quiet NaN representation. Equal values match across widths. |
| Dates | Use a date domain, separate from ordinary integers. |
| Timestamps | All units are converted to microsecond precision. Differences smaller than that precision may be lost. |
| Decimals | Scale and the sign of zero are normalized, so equivalent decimal values match. |
| UUIDs | Use the sixteen raw bytes under `vitaminc/prf/value/uuid/v1`. |
| Text | Unicode 16 NFC normalization, without case or accent folding. |
| Null | All nulls share one representation. |

For example, a JavaScript `BigInt` stored as `i8` matches the same integer
stored as `i64` from Go. A JavaScript `number` 5 is an `f64`, so it does not
match an integer 5; use `BigInt` for integer data. Also, `f32` 0.1 and `f64`
0.1 represent different values and do not match.

Float widening uses integer operations, including for subnormal values, to
avoid a slower floating-point path for those inputs. The Unicode assignment
table is pinned to version 16. NFC stability allows newer normalization tables
to be used without changing results for the accepted code points.

Normalization applies to equality terms. Ciphertext still retains the original
value, including integer width, decimal scale, and sub-microsecond timestamp
precision.

### Matching writes and queries

Use the same input API, key, and context when deriving terms for stored values
and queries. The primitive `PrfValue` implementations keep their original
little-endian integer and raw UTF-8 encodings; enabling `normalize` does not
change them. Use `Normalized` or `EqualityTerm` on both sides when you need
normalized equality.

Without the `normalize` feature, this crate does not depend on
`vitaminc-normalize`, `vitaminc-aead`, or the Unicode tables. Each normalization
domain has an independently calculated HMAC test vector in
`vitaminc-hmac/tests/normalized_equality.rs`.
