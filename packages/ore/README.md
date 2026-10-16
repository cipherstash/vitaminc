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
keeps an integer at the width its column declares, and folds accents
and case out of text, which an equality term must not.

## One column

An order index declares the type of what it holds, as an
[`OrderTarget`]: an `i32` column, a date column, a text column. The
target, not the value, decides the encoding, so values from every
language land in one domain and compare. A JavaScript `BigInt` arrives
as the narrowest integer that holds it (`100n` as an `i8`, `300n` as an
`i16`) and a Rust field at its own type; both widen to the column's
target. A value that does not fit is refused, never truncated, and a
value of another kind is refused too: an integer is not a float, a date
or a decimal.

A caller opens a column on a scheme with its target and the context
its terms compare within, and encrypts values there:

```rust
use vitaminc_ore::{Int, Logical, NormalizeError, OrderEncrypt, OrderError, OrderTarget, Physical, Raw};
# use vitaminc_ore::{Context, OrderPlaintext, OrderScheme};
# /// Keeps the bytes as they are, for the example. Any scheme will do.
# struct Clear;
# impl OrderScheme for Clear {
#     const NAME: &'static str = "clear";
#     type Term = Vec<u8>;
#     type Error = core::convert::Infallible;
#     fn encrypt_plaintext(&self, p: &OrderPlaintext, _: &Context<'_>) -> Result<Vec<u8>, OrderError<Self::Error>> {
#         use vitaminc_protected::Controlled;
#         Ok(p.bytes().risky_ref().clone())
#     }
# }
# let scheme = Clear;

let total = scheme.column(OrderTarget::I32, ("orders", "total"));
let three = total.encrypt(3i8)?;
let forty = total.encrypt(40i64)?;
assert!(three < forty);

// Outside the column's type, or of another kind: refused.
assert!(matches!(
    total.encrypt(1i64 << 40),
    Err(OrderError::Term(NormalizeError::OutOfRange))
));
assert!(matches!(
    total.encrypt("40"),
    Err(OrderError::Term(NormalizeError::Mismatch))
));

// A typed scalar goes into the column of its type.
let placed = scheme.column(OrderTarget::Date, ("orders", "placed"));
let day = placed.encrypt(Raw(Some(Logical::Date), Physical::Int(Int::I32(19_000))))?;

// A scalar with no order term is refused rather than returning nothing.
assert!(matches!(
    total.encrypt(true),
    Err(OrderError::Term(NormalizeError::NoDomain))
));
# Ok::<(), OrderError<core::convert::Infallible>>(())
```

A layer above maps its own column types onto targets: an EQL `int`
column is `OrderTarget::I32`. This crate knows nothing of that layer.

## A whole value

`order_terms` walks a value and collects one sealed term per orderable
scalar with the path to it, every one encoded as one target, as
`vitaminc_normalize::terms` does for equality. It refuses every value
encryption would refuse, and a scalar that does not fit the target. The
`Order` normalizer puts the same walk beside any other sink: one pass of
the value gives its equality terms and its order terms, or either beside
encryption. It suits a value of one kind throughout, such as an array
column; a document whose fields have types of their own is the index
layer's to walk field by field.

```rust
use vitaminc_aead::{Encrypt, Tee};
use vitaminc_normalize::{Terms, TermsError};
use vitaminc_ore::{domain, order_terms, Order, OrderTarget};

let scores: Vec<i16> = vec![7, 300];

let terms = order_terms(OrderTarget::I32, &scores)?;
assert_eq!(terms.len(), 2);
assert_eq!(terms[1].normalized.domain(), domain::INT32);

// Equality and order terms from one walk.
let (mut equality, mut order) = (Vec::new(), Vec::new());
scores.visit(Tee(
    Terms::<TermsError>::new(&mut equality),
    Terms::by(Order(OrderTarget::I32), &mut order),
))?;
assert_eq!(equality.len(), order.len());
# Ok::<(), vitaminc_normalize::TermsError>(())
```

A null, a boolean or an `undefined` has no order term and does not stop
the walk. Anything else without a term stops it: a term silently missing
from an index is worse than an error. A collected term goes into its
column with `OrderColumn::encrypt_term`, which refuses a term of another
target.

## Implementing a scheme

A scheme implements one method, `encrypt_plaintext`, over the sealed
[`OrderPlaintext`] the column builds from the caller's value and the
salt the column derives. It reads the plaintext's bytes, binds the salt,
and refuses what it cannot take by target. It never pads or truncates: a
fixed-width scheme reads [`OrderPlaintext::width`] and refuses a target,
not a value. Callers reach every scheme through [`OrderEncrypt`], which
is implemented for every scheme and cannot be overridden, so no scheme
can change what its terms are bound to.

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

    fn encrypt_plaintext(
        &self,
        plaintext: &OrderPlaintext,
        salt: &Context<'_>,
    ) -> Result<Vec<u8>, OrderError<Infallible>> {
        if plaintext.width() != Some(4) {
            return Err(OrderError::unsupported::<Self>(plaintext));
        }
        // Bind the salt and encrypt the bytes; here, concatenate them.
        let mut term = salt.as_bytes().to_vec();
        term.extend_from_slice(plaintext.bytes().risky_ref());
        Ok(term)
    }
}
```

The salt is `PAE("vitaminc/ore/v1", scheme, domain, context)`, derived
once when the column is opened, so every scheme binds the same three
things: a CLLW scheme passes it as its salt, and a scheme without one,
block ORE, derives its keys under it. [`OrderKeyInit`] keys a scheme
from a protected array or from bytes of a length only known at runtime,
the way a PRF is keyed, so an index layer constructs any scheme the same
way.

A term compares only with terms of the same scheme, key, target and
context, which is what a column is. A column's leakage is the combined
leakage of every term it holds: an order term reveals order, an equality
term reveals equality, and a column that carries both reveals both.

## Encodings

These are protocol data. Changing any of them, or a domain label, means
a new label.

| Target | Domain | Bytes |
| --- | --- | --- |
| `I8`, `I16`, `I32`, `I64`, `I128` | `vitaminc/ore/value/int{8,16,32,64,128}/v1` | big-endian at the target's width, sign bit flipped |
| `U8`, `U16`, `U32`, `U64`, `U128` | `vitaminc/ore/value/uint{8,16,32,64,128}/v1` | big-endian at the target's width |
| `F64` | `vitaminc/ore/value/float64/v1` | the `f64` equality encoding: `-0.0` folded to `0.0`, every NaN to one quiet NaN, then negatives flip every bit and positives the sign bit; an `f32` widened exactly first |
| `Date` | `vitaminc/ore/value/date/v1` | the equality encoding: orderable days from 0001-01-01 |
| `Timestamp`, any unit | `vitaminc/ore/value/timestamp-micros/v1` | the equality encoding: orderable seconds, then nanoseconds truncated to microseconds |
| `Decimal` | `vitaminc/ore/value/decimal/v1` | the equality encoding: the 14-byte orderable decimal, scale and signed zero normalized |
| `Text` | `vitaminc/ore/value/text-folded/unicode-16/v1` | Unicode 16 NFC with accents and case folded, below |
| `Bytes` | `vitaminc/ore/value/bytes/v1` | as they are |
| `Uuid` | `vitaminc/ore/value/uuid/v1` | the sixteen raw bytes |

An integer of any width goes into an integer target it fits: `100` as
an `i8` and `100` as a `u64` are one term of an `I32` column. There is
no `f32` target: JavaScript numbers are always `f64`, and an `f32`
widens to `f64` exactly.

The integer and float encodings are the ones the frozen
`orderable-bytes` 0.2.0 produces, checked against it byte for byte in
the tests. Text is folded by Unicode's canonical caseless matching (NFD,
full default case folding, NFD), then every accent is dropped and the
result put back into NFC: `École` and `ecole` are one term, as are
`Straße` and `strasse`. An accent is a mark with a non-zero canonical
combining class. A mark of class zero, such as a Devanagari or Thai
vowel sign, is a letter of its script and is kept, so `कि` and `की` stay
two words. The Devanagari virama and nukta have non-zero classes and
are dropped. The case-folding table is generated from
Unicode 16's `CaseFolding.txt` and pinned, as the assignment table is,
so a code point unassigned in Unicode 16 is refused. Text processing is
variable-time. The integer and float paths use no floating-point
arithmetic.

## Known exceptions

Booleans, nulls and `undefined` have no order term under any target.
The fixed-width block ORE scheme in `ore-rs` takes one to fifteen
bytes, so `i128`, `u128` and
uuid terms have no fixed-width block ORE, and nor do text and bytes,
whose terms vary in length; `ore-rs`'s chained block ORE scheme and the
CLLW schemes take every domain. A scheme reports such a refusal as
[`OrderError::Unsupported`].
