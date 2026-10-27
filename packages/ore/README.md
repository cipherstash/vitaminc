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
encrypt one. The schemes themselves, block ORE in `ore-rs` and CLWW ORE
and OPE in `cllw-ore`, depend on this crate and implement the trait, so
no scheme can be handed bytes that skipped the encoding, and this crate
depends on no scheme.

The encodings share their plaintext layer with
[`vitaminc-normalize`](https://docs.rs/vitaminc-normalize), whose terms
an equality index derives from, so the two indexes agree about which
values are equal. They differ where ordering needs it: an order term
keeps an integer at the width its column declares, and folds accents
and case out of text, which an equality term must not.

## Installation

```sh
cargo add vitaminc-ore
```

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
and key, one target, one context (a table and column, a tenant,
whatever the terms must compare within), and where it places nulls, if
it places them at all. A caller opens a space by
chaining a target and a context on a scheme, and encrypts values there.
Every step of the chain is usable for terms, and a step left out takes
its default: a target alone is under the empty context, and a value
alone is encoded as the target its Rust type is. Queries come from a
space, so a chain that makes one names its target.

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
#     type Space = ();
#     fn open(&self, _: vitaminc_ore::OrderTarget, _: &Context<'_>) -> Result<(), Self::Error> {
#         Ok(())
#     }
#     fn encrypt_plaintext(&self, _: &(), p: &OrderPlaintext) -> Result<Vec<u8>, Self::Error> {
#         use vitaminc_protected::Controlled;
#         Ok(p.bytes().risky_ref().clone())
#     }
#     fn compare(a: &Vec<u8>, b: &Vec<u8>) -> Option<Ordering> {
#         Some(a.cmp(b))
#     }
# }
# vitaminc_ore::supports_every_target!(Clear);
# impl vitaminc_ore::OrderQuery for Clear {
#     type Query = Vec<u8>;
#     fn encrypt_query(&self, _: &(), p: &OrderPlaintext) -> Result<Vec<u8>, Self::Error> {
#         use vitaminc_protected::Controlled;
#         Ok(p.bytes().risky_ref().clone())
#     }
#     fn compare_query(q: &Vec<u8>, t: &Vec<u8>) -> Option<Ordering> {
#         Some(q.cmp(t))
#     }
# }
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
// A query is made from the value searched for and compared against the
// stored terms; it is not a term, and need not be stored.
let at_least_ten = total.encrypt_query(10i8)?;
assert_eq!(total.compare_query(&at_least_ten, &three), Some(Ordering::Greater));
assert_eq!(total.compare_query(&at_least_ten, &forty), Some(Ordering::Less));

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

A query is a `QueryTerm`, labelled the same way, from `encrypt_query`
or `encrypt_query_checked` on a scheme that implements `OrderQuery`.
Block ORE has one: the half of a term a comparison needs from the
searching side, smaller than a stored term. A scheme whose terms are
their own queries, as the CLWW schemes are, has `Query = Term`.
`compare_query(&query, &term)` gives the order of the queried value
relative to the stored one. A query has its own type, so it cannot be
compared where a term is expected: `compare(&query, &term)` does not
compile. Its bytes are bytes, though, which a caller needs in order to
send the query to wherever the terms are, and nothing stops a caller
writing them into a term's place. Under block ORE every later `compare`
against those bytes returns `None`; under a scheme whose query is its
term the mistake is invisible.

In a space that places nulls, `null_query` is the sentinel's query, and
so is `encrypt_query_checked` of any null. A layer answers `IS NULL`
with an equality comparison against it, and `IS NOT NULL` with the
negation. A range in such a space must exclude the sentinel itself,
because a SQL comparison never matches a null: under nulls-first
`age < 10` is "above the sentinel and below 10", and under nulls-last
`age > 10` is "above 10 and below the sentinel". Building the predicate
is the layer's work, as it is for every other predicate. In a space
without a policy a null query is refused with `NoDomain`.

A query exists for the comparison at hand, and should not be persisted
or logged. Held beside the stored terms, it orders every one of them
against the searched value. And block ORE's queries are deterministic,
one value in one space giving one query, so `==` on two queries is
equality of the values searched for, and a log of queries is a log of
what was searched.

A layer above maps its own column types onto targets: an EQL `int`
column is `OrderTarget::I32`. This crate knows nothing of that layer.

### Nulls first or last

By default a space gives a null no term: `encrypt_checked` refuses one
and a walk skips it, so the term column holds a SQL `NULL` exactly where
the value was absent. A space can instead place its nulls, as SQL's
`NULLS FIRST` and `NULLS LAST` do, so that an absent value is indexed
like any other and `ORDER BY ... NULLS FIRST` can be answered from the
index alone. The policy is fixed when the space is made, like the
target and the context, and it follows the target. On a marker target
it is a marker too, `First` or `Last` from the `target` module, and it
becomes part of the space's type, `Nulls<I32, Last>`, so the compiler
keeps a nulls-first term out of a nulls-last space's comparison as it
keeps an `I64` term out of an `I32` space's. On a target chosen while
the program runs it is a [`NullOrder`], chosen then too, which every
term carries, so a nulls-first and a nulls-last term compare as `None`:

```rust
use std::cmp::Ordering;
use vitaminc_ore::target::{Last, I32};
use vitaminc_ore::{NormalizeError, NullOrder, OrderEncrypt, OrderError, OrderTarget};
# use vitaminc_ore::{Context, OrderPlaintext, OrderScheme};
# struct Clear;
# impl OrderScheme for Clear {
#     const NAME: &'static str = "clear";
#     type Term = Vec<u8>;
#     type Error = core::convert::Infallible;
#     type Space = ();
#     fn open(&self, _: vitaminc_ore::OrderTarget, _: &Context<'_>) -> Result<(), Self::Error> {
#         Ok(())
#     }
#     fn encrypt_plaintext(&self, _: &(), p: &OrderPlaintext) -> Result<Vec<u8>, Self::Error> {
#         use vitaminc_protected::Controlled;
#         Ok(p.bytes().risky_ref().clone())
#     }
#     fn compare(a: &Vec<u8>, b: &Vec<u8>) -> Option<Ordering> {
#         Some(a.cmp(b))
#     }
# }
# vitaminc_ore::supports_every_target!(Clear);
# let scheme = Clear;

let ages = scheme.context("users.age").target(I32).nulls(Last);
let (age, absent) = (ages.encrypt_checked(36i32)?, ages.encrypt_checked(None::<i32>)?);
assert_eq!(ages.compare(&age, &absent), Some(Ordering::Less));

// The column cannot hold its type's maximum.
assert!(matches!(
    ages.encrypt_checked(i32::MAX),
    Err(OrderError::Term(NormalizeError::Reserved))
));

// A target chosen while the program runs takes a policy chosen then, and
// text and bytes take none.
let column = scheme.target(OrderTarget::I32).context("users.age");
let (first, last) = (column.nulls(NullOrder::First)?, column.nulls(NullOrder::Last)?);
let (a, b) = (first.encrypt_checked(36i32)?, last.encrypt_checked(36i32)?);
assert_eq!(last.compare(&a, &b), None);
assert_eq!(
    scheme.target(OrderTarget::Text).nulls(NullOrder::First).err(),
    Some(NormalizeError::NoDomain)
);
# Ok::<(), Box<dyn std::error::Error>>(())
```

In a space that places nulls, every null, typed or plain, encodes to the
space's sentinel: the lowest code of the target's width (all `0x00`) for
nulls-first, the highest (all `0xFF`) for nulls-last. No byte is added,
so every width and every scheme stays as it is. For an integer or uuid
target that code belongs to a value, so the space makes room: under
nulls-first every code moves up by one, and under both policies the one
value refused is the target's maximum, with `NormalizeError::Reserved`.
The rule is one sentence: a column that places nulls cannot hold its
type's maximum. Float, date, timestamp and decimal codes never reach
either extreme, so those targets move nothing and refuse nothing. An
`undefined` has no term under any policy: it is not a value and not a
null.

Only a fixed-width target takes a policy. On a marker, `nulls` compiles
only for the fixed-width ones; on an `OrderTarget` it refuses text and
bytes with `NormalizeError::NoDomain` rather than make a space that
refuses every value. A text or bytes null already shows by its length,
so placing it would hide nothing. A space that places nulls has no
`encrypt`, only `encrypt_checked`, because it can refuse a value that
fits the target.

A policy is a space of its own, with its own domain labels (see
Encodings), and the salt binds the label. So a term of a nulls-last
space never compares with a term of the plain space of the same target,
and turning a policy on for a column is a re-index, visibly, rather than
a column whose stored maximums silently became nulls.

**What a placed null reveals.** In any order index whose stored terms
compare with each other, the nulls are visible as the tied group at one
end, and in a sparse domain as the group that differs from every value
at the top of the encoding. That is never more than the SQL `NULL` it
replaces, which needs no inference to read, and the term column no
longer carries a plaintext signal. Both schemes in use leak where two
terms first differ, so in a sparse domain (ages in an `I32`, say) the
nulls are the one group that differs from every value in its top bytes;
in a dense domain the group is only the tied extreme.

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
    Terms::by(Order::new(OrderTarget::I32), &mut order),
))?;
assert_eq!(equality.len(), order.len());
# Ok::<(), vitaminc_normalize::TermsError>(())
```

A boolean or an `undefined` has no order term and does not stop the
walk, and nor does a null, unless the normalizer places nulls:
`Order::new(target).nulls(NullOrder::Last)` gives every null of the walk
the space's sentinel, at its path, where the equality walk puts the
null's equality term. Anything else without a term stops it: a term
silently missing from an index is worse than an error. A collected term goes into its
space with `OrderSpace::encrypt_term`, which refuses a term of another
target.

## Implementing a scheme

A scheme implements `open`, which derives what it keeps for one space
from the salt the space derives and the space's target, `encrypt_plaintext`
over that and the sealed [`OrderPlaintext`] the space builds from the
caller's value, `compare` over its own terms, and says which targets it
takes through `Supports`. A scheme with a query side implements
`OrderQuery` beside it; one whose terms are their own queries does so
with `Query = Term`. It reads the plaintext's bytes and binds the salt through
what it opened. It never pads, truncates or refuses by width: the space
asks `Supports` and refuses a target the scheme does not take before
the scheme sees a plaintext of it. Callers reach every scheme through
[`OrderEncrypt`], which is implemented for every scheme and cannot be
overridden, so no scheme can change what its terms are bound to.

```rust
use core::cmp::Ordering;
use core::convert::Infallible;
use vitaminc_ore::{Context, OrderPlaintext, OrderQuery, OrderScheme};
use vitaminc_protected::{Controlled, Protected};

/// A toy scheme over exactly four bytes.
struct FourBytes;

impl OrderScheme for FourBytes {
    const NAME: &'static str = "four-bytes";
    type Term = Vec<u8>;
    type Error = Infallible;
    /// What it keeps for a space, which must wipe itself on drop. A real
    /// scheme keeps what it derives from the salt under its key, which is
    /// secret; this toy has nothing to derive and keeps the salt's bytes.
    type Space = Protected<Vec<u8>>;

    fn open(&self, _: vitaminc_ore::OrderTarget, salt: &Context<'_>) -> Result<Self::Space, Infallible> {
        Ok(Protected::new(salt.as_bytes().to_vec()))
    }

    fn encrypt_plaintext(
        &self,
        salt: &Self::Space,
        plaintext: &OrderPlaintext,
    ) -> Result<Vec<u8>, Infallible> {
        // Bind the salt and encrypt the bytes; here, concatenate them.
        let mut term = salt.risky_ref().clone();
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

// Its terms are their own queries, so the query side is the term side.
impl OrderQuery for FourBytes {
    type Query = Vec<u8>;

    fn encrypt_query(
        &self,
        salt: &Self::Space,
        plaintext: &OrderPlaintext,
    ) -> Result<Vec<u8>, Infallible> {
        self.encrypt_plaintext(salt, plaintext)
    }

    fn compare_query(query: &Vec<u8>, term: &Vec<u8>) -> Option<Ordering> {
        Self::compare(query, term)
    }
}

assert_eq!(FourBytes::compare(&b"salt\0\0\0\x01".to_vec(), &b"salt\0\0\0\x02".to_vec()), Some(Ordering::Less));
assert_eq!(FourBytes::compare(&b"salt\0\0\0\x01".to_vec(), &b"SALT\0\0\0\x02".to_vec()), None);
assert_eq!(FourBytes::compare(&vec![], &vec![]), None);
```

The salt is `PAE("vitaminc/ore/v1", scheme, domain, context)`, derived
once when the space is made, so every scheme binds the same three
things: a CLWW scheme passes it as its salt, and a scheme without one,
block ORE, derives its keys under it. The scheme does that per space,
not per term, in `open`, which the space calls when its first value is
encrypted (or earlier, through `OrderSpace::open`); `open` may run again
after a failure or when threads race, so it is a pure derivation. A
space is `Send` when the scheme is `Sync` and what it opened is `Send`,
and `Sync` when that is `Sync` too.
[`OrderKeyInit`] keys a scheme from a protected array or from bytes of
a length only known at runtime, the way a PRF is keyed, so an index
layer constructs any scheme the same way.

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
| `I16`, `I32`, `I64`, `I128` | `vitaminc/ore/value/int{16,32,64,128}/v1` | big-endian at the target's width, sign bit flipped |
| `U16`, `U32`, `U64`, `U128` | `vitaminc/ore/value/uint{16,32,64,128}/v1` | big-endian at the target's width |
| `F64` | `vitaminc/ore/value/float64/v1` | the `f64` equality encoding: `-0.0` folded to `0.0`, every NaN to one quiet NaN, then negatives flip every bit and positives the sign bit; an `f32` widened exactly first |
| `Date` | `vitaminc/ore/value/date/v1` | the equality encoding: orderable days from 0001-01-01 |
| `Timestamp`, any unit | `vitaminc/ore/value/timestamp-micros/v1` | the equality encoding: orderable seconds, then nanoseconds truncated to microseconds |
| `Decimal` | `vitaminc/ore/value/decimal/v1` | the equality encoding: the 14-byte orderable decimal, scale and signed zero normalized |
| `Text` | `vitaminc/ore/value/text-folded/unicode-16/v1` | `0x01`, then Unicode 16 NFC with accents and case folded, below |
| `Bytes` | `vitaminc/ore/value/bytes/v1` | `0x01`, then the bytes as they are |
| `Uuid` | `vitaminc/ore/value/uuid/v1` | the sixteen raw bytes |

A space that places nulls has its own label for each fixed-width target:
the plain label with the policy before its version, `<kind>` as above.

| Target | Domain | Bytes |
| --- | --- | --- |
| any fixed-width, nulls first | `vitaminc/ore/value/<kind>/nulls-first/v1` | a null is all `0x00` at the target's width; integer and uuid codes are one higher than in the plain space, as a big-endian number over the width (zero as `U16` is `00 01`, the nil uuid `00…01`); every other code as in the plain space; an integer or uuid target's maximum is refused |
| any fixed-width, nulls last | `vitaminc/ore/value/<kind>/nulls-last/v1` | a null is all `0xFF` at the target's width; every code as in the plain space; an integer or uuid target's maximum is refused |
| `Text`, `Bytes` | none | no null policy |

So `I32` places nulls under `vitaminc/ore/value/int32/nulls-first/v1`
and `vitaminc/ore/value/int32/nulls-last/v1`, and `Timestamp` under
`vitaminc/ore/value/timestamp-micros/nulls-last/v1`: twenty-six labels,
listed with the plain ones in `domain::ALL`. The float, date, timestamp
and decimal extremes are never reached: all `0x00` or all `0xFF` as an
`f64` would be a NaN other than the one every NaN folds to, as a date or
a timestamp's seconds it is outside the admitted range (and all `0xFF`
sub-seconds are more than a second), and as a decimal its exponent field
would be one no value has.

An integer of any width goes into an integer target it fits: `100` as
an `i8` and `100` as a `u64` are one term of an `I32` space. There is
no `f32` target: JavaScript numbers are always `f64`, and an `f32`
widens to `f64` exactly. There is no 8-bit target either, for the reason
under Known exceptions: an `i8` or `u8` value goes into `I16` or wider.

The two variable-width encodings, text and bytes, start with a marker
byte, `VARIABLE_WIDTH_MARKER` (`0x01`), so that no order plaintext is
ever empty. Without it an empty string and an empty byte string encoded
to nothing, and both scheme crates encrypted that into a term that never
touched the key or the salt: the same term under every key and context,
which anyone could write into any index. A constant leading byte keeps
the order. Fixed-width encodings are never empty and carry no marker. A
scheme can rely on every plaintext having at least one byte, and every
term it makes must depend on the key and the salt.

In vitaminc-ore 0.7, the text and bytes marker moved from scheme adapters
into this crate without changing the domain labels or stored terms.
Adapters upgrading to 0.7 or later must not prepend a second marker.

The integer and float encodings match `orderable-bytes` 0.2.1 byte for byte. Text is folded by Unicode's canonical caseless matching (NFD,
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
(`UNICODE-LICENSE.txt`).

## Known exceptions

Booleans and `undefined` have no order term under any target, and a
null has one only in a space that places nulls (see Nulls first or
last).
An order term reveals the order of the values it encrypts, which is
safe only when there are enough possible values that the order of the
rows does not give the values away. A boolean has two, so an order term
over a boolean column says which rows are `true`. The same argument
holds at 256: an order index over an 8-bit column is a frequency table
of the column with the order on top, and anyone who knows a few rows'
values, or the rough shape of the data (ages, quantities, ratings),
reads the rest off. So the narrowest integer target is `I16`. An `i8`
or `u8` value still goes into any wider target, and
`scheme.encrypt(42i8)` does not compile, because an `i8` has no target
of its own. The floor removes only the case where the type guarantees
few values: an `I16` or `I32` column of ages or ratings leaks the same
frequency table, because the leak is about how many distinct values the
column holds, not its width. Whether a column should have an order
index at all is a question about its data; a column of few distinct
values wants an equality index.
The fixed-width block ORE scheme in `ore-rs` takes one to fifteen
bytes, so `i128`, `u128` and
uuid terms have no fixed-width block ORE, and nor do text and bytes,
whose terms vary in length; `ore-rs`'s chained block ORE scheme and the
CLWW schemes take every domain. A scheme reports such a refusal as
[`OrderError::Unsupported`].

## Cargo features

No optional features are enabled by default.

| Feature | Effect |
| --- | --- |
| `chrono` | Adds order targets for date and timestamp types and enables AEAD date support. |
| `rust_decimal` | Adds decimal order targets and enables AEAD decimal support. |
| `uuid` | Adds UUID order targets and enables AEAD UUID support. |

## Compatibility

Requires Rust <!-- msrv:vitaminc-ore -->**1.88.0**<!-- /msrv --> and the Rust standard library (`std`).
MSRV increases require a minor release; patch releases retain the existing
floor. See the [workspace compatibility policy](https://github.com/cipherstash/vitaminc#compatibility).

<!-- GitHub API links target the latest release; src/lib.rs resolves these for rustdoc. -->
[`NullOrder`]: https://docs.rs/vitaminc-ore/latest/vitaminc_ore/enum.NullOrder.html
[`OrderEncrypt`]: https://docs.rs/vitaminc-ore/latest/vitaminc_ore/trait.OrderEncrypt.html
[`OrderError::Unsupported`]: https://docs.rs/vitaminc-ore/latest/vitaminc_ore/enum.OrderError.html#variant.Unsupported
[`OrderKeyInit`]: https://docs.rs/vitaminc-ore/latest/vitaminc_ore/trait.OrderKeyInit.html
[`OrderPlaintext`]: https://docs.rs/vitaminc-ore/latest/vitaminc_ore/struct.OrderPlaintext.html
[`OrderScheme::compare`]: https://docs.rs/vitaminc-ore/latest/vitaminc_ore/trait.OrderScheme.html#tymethod.compare
[`OrderScheme`]: https://docs.rs/vitaminc-ore/latest/vitaminc_ore/trait.OrderScheme.html
