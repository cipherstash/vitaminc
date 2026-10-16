# Vitamin C ORE

[![Crates.io](https://img.shields.io/crates/v/vitaminc-ore.svg)](https://crates.io/crates/vitaminc-ore)
[![Workflow Status](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml)

Order terms for the plaintext data model of
[`vitaminc-aead`](https://docs.rs/vitaminc-aead). Part of the
[Vitamin C](https://github.com/cipherstash/vitaminc) framework.

An order index lets a database answer `<`, `>` and `ORDER BY` on
encrypted values. This crate is the bottom of that stack. It decides,
for each scalar kind that can be ordered, a frozen **domain label** and
an **order encoding**: bytes whose lexicographic order is the value's
order. It seals the result as an [`OrderPlaintext`] that only it can
build, and it defines [`OrderScheme`], the trait a scheme implements to
encrypt one. The schemes themselves, block ORE in `ore-rs` and CLLW ORE
and OPE in `cllw-ore`, depend on this crate and implement the trait, so
no scheme can be handed bytes that skipped the encoding, and this crate
depends on no scheme.

The encodings share their plaintext layer with
[`vitaminc-normalize`](https://docs.rs/vitaminc-normalize), whose terms
an equality index derives from, so the two indexes agree about which
values are equal. They differ where ordering needs it: an order term
keeps each integer and float at its own width, and folds accents and
case out of text, which an equality term must not.

## One scalar

```rust
use vitaminc_aead::{Int, Logical, Physical};
use vitaminc_ore::{domain, order, order_term, OrderError, NormalizeError, OrderScheme};
# use vitaminc_ore::{Context, OrderPlaintext};
# /// Keeps the bytes as they are, for the example. Any scheme will do.
# struct Clear;
# impl OrderScheme for Clear {
#     const NAME: &'static str = "clear";
#     type Term = Vec<u8>;
#     type Error = core::convert::Infallible;
#     fn encrypt(&self, p: &OrderPlaintext, _: &Context<'_>) -> Result<Vec<u8>, OrderError<Self::Error>> {
#         use vitaminc_protected::Controlled;
#         Ok(p.bytes().risky_ref().clone())
#     }
# }
# let scheme = Clear;

let three = order(None, Physical::Int(Int::I32(3)))?;
let forty = order(None, Physical::Int(Int::I32(40)))?;
assert_eq!(three.domain(), domain::INT32);
assert_eq!(three.width(), Some(4));

// `order_term` is `order` then the scheme, for a scalar in hand, and it
// refuses a scalar with no term rather than returning nothing.
let day = Physical::Int(Int::I32(19_000));
let a_date = order_term(&scheme, Some(Logical::Date), day, "birthdays")?;
assert_eq!(
    order_term(&scheme, None, Physical::Bool(true), "flags"),
    Err(OrderError::Term(NormalizeError::NoDomain))
);
# Ok::<(), OrderError<core::convert::Infallible>>(())
```

## A whole value

`order_terms` walks a value and collects one sealed term per orderable
scalar with the path to it, as `vitaminc_normalize::terms` does for
equality, and refuses every value encryption would refuse. The `Order`
normalizer puts the same walk beside any other sink: one pass of the
value gives its equality terms and its order terms, or either beside
encryption.

```rust
use std::collections::BTreeMap;
use vitaminc_aead::{Encrypt, Tee};
use vitaminc_normalize::{Terms, TermsError};
use vitaminc_ore::{domain, order_terms, Order};

let mut user = BTreeMap::new();
user.insert("email", "Ada@Example.com");
user.insert("age", "36");

let terms = order_terms(&user)?;
assert_eq!(terms.len(), 2);
assert_eq!(terms[1].normalized.domain(), domain::TEXT);

// Equality and order terms from one walk.
let (mut equality, mut order) = (Vec::new(), Vec::new());
user.visit(Tee(
    Terms::<TermsError>::new(&mut equality),
    Terms::by(Order, &mut order),
))?;
assert_eq!(equality.len(), order.len());
# Ok::<(), vitaminc_normalize::TermsError>(())
```

A null, a boolean or an `undefined` has no order term and does not stop
the walk. A logical type with no order domain does stop it, as it stops
`terms`: a term silently missing from an index is worse than an error.

## Implementing a scheme

A scheme reads the plaintext's bytes, binds the salt, and refuses what it
cannot take by domain. It never pads or truncates: a fixed-width scheme
reads [`OrderPlaintext::width`] and refuses a kind, not a value.

```rust
use core::convert::Infallible;
use vitaminc_ore::{Context, OrderError, OrderPlaintext, OrderScheme};
use vitaminc_protected::Controlled;

/// A toy scheme over exactly four bytes.
struct FourBytes;

impl OrderScheme for FourBytes {
    const NAME: &'static str = "four-bytes";
    type Term = Vec<u8>;
    type Error = Infallible;

    fn encrypt(
        &self,
        plaintext: &OrderPlaintext,
        context: &Context<'_>,
    ) -> Result<Vec<u8>, OrderError<Infallible>> {
        if plaintext.width() != Some(4) {
            return Err(OrderError::unsupported::<Self>(plaintext));
        }
        // Bind the salt and encrypt the bytes; here, concatenate them.
        let mut term = self.salt(plaintext, context).as_bytes().to_vec();
        term.extend_from_slice(plaintext.bytes().risky_ref());
        Ok(term)
    }
}
```

The salt is `PAE("vitaminc/ore/v1", scheme, domain, context)`, derived
by the plaintext so every scheme binds the same three things: a CLLW
scheme passes it as its salt, and a scheme without one, block ORE,
derives its keys under it. [`OrderKeyInit`] keys a scheme from a
protected array or from bytes of a length only known at runtime, the way
a PRF is keyed, so an index layer constructs any scheme the same way.

A term compares only with terms of the same scheme, key, domain and
context, which is what a column is. A column's leakage is the combined
leakage of every term it holds: an order term reveals order, an equality
term reveals equality, and a column that carries both reveals both.

## Encodings

These are protocol data. Changing any of them, or a domain label, means
a new label.

| Kind | Domain | Bytes |
| --- | --- | --- |
| `i8`, `i16`, `i32`, `i64`, `i128` | `vitaminc/ore/value/int{8,16,32,64,128}/v1` | big-endian at the type's width, sign bit flipped |
| `u8`, `u16`, `u32`, `u64`, `u128` | `vitaminc/ore/value/uint{8,16,32,64,128}/v1` | big-endian at the type's width |
| `f32` | `vitaminc/ore/value/float32/v1` | four bytes: `-0.0` folded to `0.0`, every NaN to one quiet NaN, then negatives flip every bit and positives the sign bit |
| `f64` | `vitaminc/ore/value/float64/v1` | eight bytes, the same rule: the `f64` equality encoding |
| date | `vitaminc/ore/value/date/v1` | the equality encoding: orderable days from 0001-01-01 |
| timestamp, any unit | `vitaminc/ore/value/timestamp-micros/v1` | the equality encoding: orderable seconds, then nanoseconds truncated to microseconds |
| decimal | `vitaminc/ore/value/decimal/v1` | the equality encoding: the 14-byte orderable decimal, scale and signed zero normalized |
| text | `vitaminc/ore/value/text-folded/unicode-16/v1` | Unicode 16 NFC with accents and case folded, below |
| bytes | `vitaminc/ore/value/bytes/v1` | as they are |
| uuid | `vitaminc/ore/value/uuid/v1` | the sixteen raw bytes |

The integer and float encodings are the ones the frozen
`orderable-bytes` 0.2.0 produces, checked against it byte for byte in
the tests. Text is folded by Unicode's canonical caseless matching (NFD,
full default case folding, NFD), then every combining mark is dropped
and the result put back into NFC: `École` and `ecole` are one term, as
are `Straße` and `strasse`. The case-folding table is generated from
Unicode 16's `CaseFolding.txt` and pinned, as the assignment table is,
so a code point unassigned in Unicode 16 is refused. Text processing is
variable-time. The integer and float paths use no floating-point
arithmetic.

## Known exceptions

Booleans, nulls and `undefined` have no order term. Block ORE in `ore-rs`
takes one to fifteen bytes, so `i128`, `u128` and uuid terms have no
block ORE, and nor does text, whose terms vary in length, until chained
block ORE is available (ore.rs #95); the CLLW schemes take every domain.
A scheme reports such a refusal as [`OrderError::Unsupported`].
