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

## One space

An order index declares the type of what it holds: its **target**. An
`i32` column, a date column, a text column. The target, not the value,
decides the encoding, so values from every language land in one domain
and compare. A JavaScript `BigInt` arrives as the narrowest integer that
holds it (`100n` as an `i8`, `300n` as an `i16`) and a Rust field at its
own type; both widen to the target. A value that does not fit is refused,
never truncated, and a value of another kind is refused too: an integer
is not a float, a date or a decimal.

The set of terms that compare with each other is a **space**: one scheme
and key, one target, and one context (a table and column, a tenant,
whatever the terms must compare within). A caller opens a space by
chaining a target and a context on a scheme, and encrypts values there.
Every step of the chain is usable, and a step left out takes its
default: a target alone is under the empty context, and a value alone is
encoded as the target its Rust type is.

```rust
use std::cmp::Ordering;
use vitaminc_ore::target::{Date, I32};
use vitaminc_ore::{NormalizeError, OrderEncrypt, OrderError, OrderTarget};
# use vitaminc_ore::{Context, OrderPlaintext, OrderScheme};
# /// Keeps the bytes as they are, for the example. Any scheme will do.
# struct Clear;
# impl OrderScheme for Clear {
#     const NAME: &'static str = "clear";
#     type Term = Vec<u8>;
#     type Error = core::convert::Infallible;
#     fn encrypt_plaintext(&self, p: &OrderPlaintext, _: &Context<'_>) -> Result<Vec<u8>, Self::Error> {
#         use vitaminc_protected::Controlled;
#         Ok(p.bytes().risky_ref().clone())
#     }
#     fn compare(a: &Vec<u8>, b: &Vec<u8>) -> Option<Ordering> {
#         Some(a.cmp(b))
#     }
# }
# vitaminc_ore::supports_every_target!(Clear);
# let scheme = Clear;

// Held, for many values. The target is a marker, so the compiler checks
// what goes in: an `i8` always fits an `i32`.
let total = scheme.target(I32).context(("orders", "total"));
let three = total.encrypt(3i8)?;
// An `i64` may not fit, so `encrypt(40i64)` does not compile; it is
// checked while the program runs instead.
let forty = total.encrypt_checked(40i64)?;
// The space compares its terms; a term alone has no order.
assert_eq!(total.compare(&three, &forty), Some(Ordering::Less));

// Outside the target, or of another kind: refused.
assert!(matches!(
    total.encrypt_checked(1i64 << 40),
    Err(OrderError::Term(NormalizeError::OutOfRange))
));
assert!(matches!(
    total.encrypt_checked("40"),
    Err(OrderError::Term(NormalizeError::Mismatch))
));

// One-shot chains.
scheme.target(I32).encrypt(3i8)?; // under the empty context
scheme.context("tenant-7").encrypt(40i64)?; // as the type's own target, I64
scheme.encrypt(40i64)?; // both defaults

// A typed value goes into the space of its type.
let day = chrono::NaiveDate::from_ymd_opt(2022, 1, 8).expect("a date");
scheme.target(Date).context(("orders", "placed")).encrypt(day)?;
scheme.encrypt(day)?;

// A target chosen while the program runs, as an index layer that reads
// its column types from a schema needs. Every value is checked then.
let index = scheme.target(OrderTarget::I32).context(("orders", "total"));
index.encrypt_checked(3i8)?;
assert!(matches!(
    index.encrypt_checked(true),
    Err(OrderError::Term(NormalizeError::NoDomain))
));
# Ok::<(), Box<dyn std::error::Error>>(())
```

`encrypt` takes a value that always fits, as the sealed `FitsIn` table
says: a narrower integer, an `f32` into `F64`, bytes (`&[u8]`,
`Vec<u8>`, `[u8; N]`) into `Bytes`, a `chrono::NaiveDate` into `Date`,
a `vitaminc_aead::Timestamp` into `Timestamp`, a `rust_decimal::Decimal`
into `Decimal`, a `uuid::Uuid` into `Uuid` (the typed rows behind the
`chrono`, `rust_decimal` and `uuid` features). Its only error is the
scheme's own, so a scheme whose error is `Infallible` cannot fail at
all. `encrypt_checked` takes any value of the data model and checks it
while the program runs: an integer that may not fit, text (a code point
Unicode 16 does not assign is refused), a `chrono::DateTime<Utc>` (a
leap second has no count, which is what `vitaminc_aead::Timestamp`
refuses when it is built), or a value whose type the index layer does
not know. A chain that names no target uses the Rust type's own, from
the sealed `OwnTarget` table; a target is never inferred from a value.

A term is an `OrderTerm`, labelled with its target. Under a marker the
label is a zero-sized type, so two targets' terms cannot meet in
`compare`. Under an `OrderTarget` the label is stored, and two terms of
different targets compare as `None` rather than as noise. Storage reads
the scheme's bytes through `AsRef<[u8]>`.

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
space with `OrderSpace::encrypt_term`, which refuses a term of another
target.

## Implementing a scheme

A scheme implements `encrypt_plaintext` over the sealed
[`OrderPlaintext`] the space builds from the caller's value and the salt
the space derives, `compare` over its own terms, and says which targets
it takes through `Supports`. It reads the plaintext's bytes and binds
the salt. It never pads, truncates or refuses by width: the space asks
`Supports` and refuses a target the scheme does not take before the
scheme sees a plaintext of it. Callers reach every scheme through
[`OrderEncrypt`], which is implemented for every scheme and cannot be
overridden, so no scheme can change what its terms are bound to.

```rust
use core::cmp::Ordering;
use core::convert::Infallible;
use vitaminc_ore::{Context, OrderPlaintext, OrderScheme};
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
    ) -> Result<Vec<u8>, Infallible> {
        // Bind the salt and encrypt the bytes; here, concatenate them.
        let mut term = salt.as_bytes().to_vec();
        term.extend_from_slice(plaintext.bytes().risky_ref());
        Ok(term)
    }

    /// The scheme's own comparison, without a key. `None` for a term that
    /// is not this scheme's, or for two terms of different spaces: here,
    /// a term shorter than its four bytes, or two salts that differ.
    fn compare(a: &Vec<u8>, b: &Vec<u8>) -> Option<Ordering> {
        let (a_salt, a_bytes) = a.split_at(a.len().checked_sub(4)?);
        let (b_salt, b_bytes) = b.split_at(b.len().checked_sub(4)?);
        (a_salt == b_salt).then(|| a_bytes.cmp(b_bytes))
    }
}

// Which targets it takes, from one list: the answer for a target chosen
// while the program runs, and one `Supports` impl per marker, so that
// `scheme.target(Text)` does not compile. A scheme that takes every
// target writes `vitaminc_ore::supports_every_target!(Scheme)`.
vitaminc_ore::supports_targets!(FourBytes; I32, U32, Date);

assert_eq!(FourBytes::compare(&b"salt\0\0\0\x01".to_vec(), &b"salt\0\0\0\x02".to_vec()), Some(Ordering::Less));
assert_eq!(FourBytes::compare(&b"salt\0\0\0\x01".to_vec(), &b"SALT\0\0\0\x02".to_vec()), None);
assert_eq!(FourBytes::compare(&vec![], &vec![]), None);
```

The salt is `PAE("vitaminc/ore/v1", scheme, domain, context)`, derived
once when the space is opened, so every scheme binds the same three
things: a CLLW scheme passes it as its salt, and a scheme without one,
block ORE, derives its keys under it. [`OrderKeyInit`] keys a scheme
from a protected array or from bytes of a length only known at runtime,
the way a PRF is keyed, so an index layer constructs any scheme the same
way.

A term compares only with terms of the same scheme, key, target and
context, which is what a space is, through `space.compare(&a, &b)` (the
scheme's [`OrderScheme::compare`], which needs no key). The scheme's own
term is plain bytes and records nothing of its space, so it is not
`Ord`: a promise to order any two terms is one no order scheme can keep
across spaces, and a caller keeps a space's terms together. A space's
leakage is the combined leakage of every term it holds: an order term
reveals order, an equality term reveals equality, and a column that
carries both reveals both.

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
| `Text` | `vitaminc/ore/value/text-folded/unicode-16/v1` | `0x01`, then Unicode 16 NFC with accents and case folded, below |
| `Bytes` | `vitaminc/ore/value/bytes/v1` | `0x01`, then the bytes as they are |
| `Uuid` | `vitaminc/ore/value/uuid/v1` | the sixteen raw bytes |

An integer of any width goes into an integer target it fits: `100` as
an `i8` and `100` as a `u64` are one term of an `I32` space. There is
no `f32` target: JavaScript numbers are always `f64`, and an `f32`
widens to `f64` exactly.

The two variable-width encodings, text and bytes, start with a marker
byte, `VARIABLE_WIDTH_MARKER` (`0x01`), so that no order plaintext is
ever empty. Without it an empty string and an empty byte string encoded
to nothing, and both scheme crates encrypted that into a term that never
touched the key or the salt: the same term under every key and context,
which anyone could write into any index. A constant leading byte keeps
the order. Fixed-width encodings are never empty and carry no marker. A
scheme can rely on every plaintext having at least one byte, and every
term it makes must depend on the key and the salt; `test_support`
(behind the `test-support` feature) checks a real scheme for both.

**A recorded exception to the label rule.** The marker changed the text
and bytes encodings in vitaminc-ore 0.7 without a new domain label
([cipherstash/vitaminc#471](https://github.com/cipherstash/vitaminc/issues/471)).
That is allowed here, and only here, for two reasons. No released term
was ever made from the old encodings: cllw-ore `0.5.2-rc.1`, the only
release with its `vitaminc` feature, shipped with the marker already in
front of what this crate handed it, and ore-rs's `vitaminc` feature was
unreleased, so every stored term always had the marker. And after the
change the labels describe what was actually stored all along. Moving
the marker into this crate changes no stored byte: each scheme crate
drops its own marker in the same release that moves it to vitaminc-ore
0.7, and pins its stored format with literal bytes so a doubled or
missing marker fails its tests. This is not a precedent for changing an
encoding that has stored data. The rule itself is set in ADR 0002
([cipherstash/stack#1139](https://github.com/cipherstash/stack/pull/1139)),
which records the same exception.

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

## License

MIT, except the case-folding table, which is derived from Unicode's
data files and is under the Unicode License v3
(`UNICODE-LICENSE.txt`). The script that generates it,
`tools/generate_casefold.py`, is in the repository and not in the
published crate.

## Known exceptions

Booleans, nulls and `undefined` have no order term under any target.
The fixed-width block ORE scheme in `ore-rs` takes one to fifteen
bytes, so `i128`, `u128` and
uuid terms have no fixed-width block ORE, and nor do text and bytes,
whose terms vary in length; `ore-rs`'s chained block ORE scheme and the
CLLW schemes take every domain. A scheme reports such a refusal as
[`OrderError::Unsupported`].
