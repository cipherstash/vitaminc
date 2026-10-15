# Vitamin C Normalize

[![Crates.io](https://img.shields.io/crates/v/vitaminc-normalize.svg)](https://crates.io/crates/vitaminc-normalize)
[![Workflow Status](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml)

Normalized equality terms for the plaintext data model of
[`vitaminc-aead`](https://docs.rs/vitaminc-aead). Part of the
[Vitamin C](https://github.com/cipherstash/vitaminc) framework.

An equality index derives a key from a value. Two values that are equal
must derive the same key whichever width, scale or spelling wrote them,
and two values that merely look alike (a date and the integer it is stored
as, a uuid and the same sixteen bytes) must not. This crate decides both:
each scalar kind that can be indexed has a frozen **domain label** and a
**normalization** to bytes, and everything else has no term.

There is no cryptography here and no PAE: the crate's own dependencies
are the Unicode tables, `orderable-bytes` and `rust_decimal`. (It builds
on `vitaminc-aead` for the data model, which brings that crate's
dependencies with it.) A PRF crate such as
[`vitaminc-prf`](https://docs.rs/vitaminc-prf) takes a [`Normalized`]
and derives under its domain.

## One scalar

```rust
use vitaminc_normalize::{domain, normalize};
use vitaminc_aead::{Int, Logical, Physical};
use vitaminc_protected::Controlled;

// Every integer width is one term.
let a = normalize(None, Physical::Int(Int::I8(34)))?;
let b = normalize(None, Physical::Int(Int::U64(34)))?;
assert_eq!(a.domain, domain::INTEGER);
assert_eq!(a.bytes.risky_ref(), b.bytes.risky_ref());

// A date is not the integer it is stored as.
let day = normalize(Some(Logical::Date), Physical::Int(Int::I32(34)))?;
assert_eq!(day.domain, domain::DATE);
assert_ne!(day.bytes.risky_ref(), a.bytes.risky_ref());
# Ok::<(), vitaminc_normalize::NormalizeError>(())
```

Logical types opt in: a date, a timestamp, a decimal and a uuid have
domains of their own. A null, a boolean, an `undefined` and a logical type
this crate does not know have no term, and `normalize` refuses them with
[`NormalizeError::NoDomain`].

## A whole value, beside encryption

[`Terms`] is a sink that collects one [`Term`] per indexable scalar, with
the path to it. Teed with the encrypting sink it sees the same walk, so
the terms are complete before any cipher call:

```rust
use std::collections::BTreeMap;
use vitaminc_normalize::{domain, encrypt_with_terms, Step};
# use vitaminc_aead::{seal::Cipher, Context};
# use vitaminc_protected::{Controlled, Protected};
# /// Keeps the plaintext in the clear, for the example. Any `Cipher` will do.
# struct Clear;
# impl Cipher for Clear {
#     type Leaf = Vec<u8>;
#     type Error = core::convert::Infallible;
#     fn seal(&self, plaintext: Protected<Vec<u8>>, _: &Context<'_>) -> Result<Vec<u8>, Self::Error> {
#         Ok(plaintext.risky_unwrap())
#     }
#     fn open(&self, leaf: Vec<u8>, _: &Context<'_>) -> Result<Protected<Vec<u8>>, Self::Error> {
#         Ok(Protected::new(leaf))
#     }
# }
# let cipher = Clear;

let mut user = BTreeMap::new();
user.insert("email", "ada@example.com");
user.insert("name", "Ada");

let (ciphertext, terms) = encrypt_with_terms(user, &cipher, "users/v1")?;
assert_eq!(terms.len(), 2);
assert_eq!(terms[0].path.steps(), [Step::Key("email".into())]);
assert_eq!(terms[0].normalized.domain, domain::TEXT);
# Ok::<(), vitaminc_aead::EncryptError<core::convert::Infallible>>(())
```

`encrypt_with_terms_async` does the same through an async cipher and has
every term before its first await. `plan_with_terms` walks without
sealing at all, and `terms` collects the terms with no encryption in the
walk.

`terms` refuses every value encryption refuses, for the same reason and
at the same path, so an index never holds terms for a value that cannot
be stored. It keeps the same shape rules, through the same code: no
duplicate key, no value nested too deep, every scalar valid for its
logical type, every passthrough framable, and something sealed in every
container with children, even though it seals nothing itself. Read such a
refusal with `TermsError::refusal`; encryption reports the same one as
`EncryptError::Shape`.

A scalar whose kind has no domain (a null, a boolean, an `undefined`)
produces no term and does not stop the walk; passthrough subtrees get none
either. A scalar whose *logical type* has no domain, one from a newer
client, stops the walk: encrypting it with no term and no error would leave
an index silently incomplete. That refusal and an unassigned code point
arrive as `EncryptError::Source` carrying a `TermError` (from `terms`, as
`TermsError::term`), which holds the `NormalizeError` and the path to the
refused field. Downcast to `TermError`; the `NormalizeError` is also its
`source()`, so a reporter that walks the error chain reaches it. The
message names neither the field nor the value, because map keys can be
user data; read the path with `TermError::path`.

## Encodings

These are protocol data. Changing any of them, or a domain label, means a
new label.

| Kind | Domain | Bytes |
| --- | --- | --- |
| integer, any width | `vitaminc/prf/value/integer-orderable/v1` | sign byte (`0x00` negative, `0x01` otherwise), then the big-endian 128-bit two's-complement word |
| float, either width | `vitaminc/prf/value/float-orderable/v1` | the `f64` value's orderable bytes; `f32` widened exactly, zero signs and NaN payloads folded |
| date | `vitaminc/prf/value/date-orderable/v1` | orderable days from 0001-01-01 |
| timestamp, any unit | `vitaminc/prf/value/timestamp-micros-orderable/v1` | orderable seconds, then nanoseconds truncated to microseconds |
| decimal | `vitaminc/prf/value/decimal-orderable/v1` | `rust_decimal`'s orderable bytes, scale and signed zero normalized |
| text | `vitaminc/prf/value/text-nfc/unicode-16/v1` | Unicode 16 NFC; a code point unassigned in Unicode 16 is refused |
| bytes | `vitaminc/prf/value/bytes/v1` | as they are |
| uuid | `vitaminc/prf/value/uuid/v1` | the sixteen raw bytes |

Text normalization is variable-time. The integer and float paths use no
floating-point arithmetic.
