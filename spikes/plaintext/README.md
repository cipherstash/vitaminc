# Plaintext data model spike

A spike, not a proposal. It doesn't change any vitaminc crate. It depends on
them by path and lives on the local branch `spike/plaintext-data-model`.

It assumes vitaminc's encryption traits are open to change, since Stack
Encrypt is unreleased. There's no `Encrypt`, no `Decrypt` and no `Value`.

## The idea

vitaminc's `Encrypt`/`Cipher` split is modelled on serde, but `Encrypt` does
two jobs at once. It *describes* a value and it *targets* the cipher's
bytes-only data model, in the same step. Hosts (Go, Node) therefore convert
into `Value` first, because `Value` is the only place a scalar's type survives
long enough for index terms to see it.

This spike splits the two, the way serde splits `Serialize` from
`Serializer`:

- [`Plaintext`](src/model.rs): a source describes itself once, through
  scalars and containers.
- [`Sink`](src/model.rs): consumes that description. Every consumer is a sink.

A scalar is a physical value plus an optional logical type (see
[Kinds](#kinds-physical-plus-logical)), so `Sink` has four methods:
`scalar`, `seq`, `map` and `passthrough`.

```text
 sources (implement Plaintext)        sinks (implement Sink)
 ─────────────────────────────        ─────────────────────────────────────────
 Rust primitives, Vec, BTreeMap  ┐    EncryptSink   tagged leaves, container rules
 chrono, Decimal, Uuid           │    Terms         equality terms, per leaf
 Frame<'_>     (Go's bytes)      ├──► FrameWriter   transport bytes (Go)
 JsRef<'_>     (live JS value)   │    JsBuilder     JS values (Node)
 Raw           (any one scalar)  ┘    Decode        typed Rust
                                      Describe      a readable dump
                                      Tee(A, B)     two sinks, one walk
```

Decryption walks the ciphertext tree and feeds any sink:
`decrypt_into(backend, ct, aad, sink)`.

| Today | Spike |
|---|---|
| `Encrypt` (describe and encrypt in one trait) | `Plaintext` (describe) plus `encrypt(p, backend, aad)` |
| `Cipher`, `SeqCipher`, `MapCipher` | `Backend` (seal and open one leaf, bytes only) plus `EncryptSink` (types to tagged leaves, container rules) |
| `Decrypt`, `Decipher`, `DecipherVisitor`, `SeqAccess`, `MapAccess` | `decrypt_into(backend, ct, aad, sink)` |
| `Decrypt for Value` | `decrypt_into` with any sink: a `FrameWriter` for Go, a JS builder for Node |
| `Decrypt` for a static Rust type | `Decode`, a typed sink (`src/typed.rs`) |
| Passthrough as `Box<dyn Any>` holding a `Value` | `PassthroughFrame`, the frame bytes the transport already wrote |
| `SeqCipher::encrypt_next(value)` (pull) | `SeqSink::element() -> Sink` (push) |
| No way for a source to fail | `Sink::Error: Error`, so a source can call `Error::source` |
| A `Value` variant (and a tag) per kind, 19 scalar kinds | Six physical kinds plus open logical types: `scalar(ty, value)` |

## Reading order

1. `src/model.rs`: the traits.
2. `src/kinds.rs`: physical kinds and logical types.
3. `src/scalar.rs`: scalars on the wire. Today's tags as shorthand, plus
   the logical envelope.
4. `src/encrypt.rs`: `Backend`, and `EncryptSink` with today's container
   rules (element and entry AAD, empty markers, nothing-sealed refusal,
   duplicate keys) gathered in one place.
5. `src/decrypt.rs`: one recursive walk that feeds any sink.
6. `src/frame.rs`: Go's frame walked in place.
7. `src/hosts/go_guest.rs`: the wasm guest's `encrypt`/`decrypt`, today and
   spike, side by side.
8. `src/tee.rs` and `src/terms.rs`: encrypt plus terms is
   `Tee(EncryptSink, Terms)`. `terms::equality` is where an index opts in
   to logical types.
9. `src/hosts/js.rs`: walks live JS with no snapshot, and decrypts straight
   into JS values.
10. `src/typed.rs`: typed decryption for Rust.
11. `tests/`: the evidence. `tests/kinds.rs` for the kinds.

To see what any source says, `describe` it:

```rust,ignore
describe(Frame::parse(bytes)?)?  // {"age": u32 34, "joined": date i32 19782, ...}
```

## Running

```sh
cargo test                     # from spikes/plaintext
cargo check --features napi    # compile-check the Node code
```

If mise complains about an untrusted config in the worktree, run
`mise trust` or use `cargo --manifest-path spikes/plaintext/Cargo.toml`.

## What the tests show

With real AES-256-GCM:

- **Wire compatibility with today** (`tests/interop.rs`). The spike's guest
  and today's guest decrypt each other's ciphertext for every vector in
  `testdata/value-conformance.json`, plus a nested sample, except the two
  with no physical-plus-logical form (see [Kinds](#kinds-physical-plus-logical)).
- **A byte-identical codec.** The ciphertext codec matches
  `transport::encode_ciphertext` byte for byte, passthrough included.
- **`Frame::parse` agrees with the transport decoder** (`tests/frame.rs`)
  on the corpus, the malformed corpus and 20k mutated inputs. The only
  differences are the intended ones: it also accepts the logical envelope,
  and it refuses leap-second timestamps and decimal negative zero.
- **Equality input matches `canonical::equality_input`** for every vector
  (`tests/terms.rs`), and one `Tee` walk gives both ciphertext and terms,
  with paths for nested leaves.
- **The error channel works.** A failing source stops the walk with its own
  error.
- **Lengths can be unknown.** They're patched into the frame at the end.
- **Typed decryption works.** `u32`, `Vec<String>` and `Vec<Vec<u32>>`
  round-trip, and the wrong target kind is refused.
- **The kinds work** (`tests/kinds.rs`):
  - today's tags read as physical plus logical;
  - a JS-style millisecond timestamp decrypts as a Rust `DateTime` and
    gives the same equality term as the same instant in nanoseconds;
  - a uuid, which has no tag today, round-trips in the envelope;
  - an unknown logical type passes through encrypt and decrypt byte for
    byte, gets no equality term, and isn't accepted as its physical value;
  - a value that doesn't fit its logical type is refused.

## Kinds: physical plus logical

Today there are 19 scalar kinds, each a `Value` variant, a tag and (before
this spike) a `Sink` method. They mix two things: how a value is stored and
what it means. The spike splits them.

**Physical kinds** are a small closed set:

| Physical | Holds |
|---|---|
| null | |
| bool | |
| int | `i8` to `u128`. The width is a host-fidelity hint |
| float | `f32` or `f64` |
| text | UTF-8 |
| bytes | |

`Physical` is an exhaustive enum. A new physical kind fails to compile in
every sink, on purpose.

**Logical types** say what a physical value means, with parameters carried
per value:

| Logical | Over | Parameter |
|---|---|---|
| `undefined` | null | |
| `date` | int: days since 1970-01-01 | |
| `timestamp` | int: count since the Unix epoch | unit (s, ms, us, ns) |
| `decimal` | int: the mantissa | scale |
| `uuid` | 16 bytes | |
| unknown | anything | an id and a parameter from the wire |

`Logical` is `#[non_exhaustive]`, so a sink outside the crate must say what
it does with one it doesn't know. The rule:

- **Structural sinks carry it through.** Encrypt, the frame writer and the
  codec never look at the logical type. The JS builder turns an unknown one
  into `{logical, param, value}` rather than the bare physical value, since
  a decimal's mantissa isn't its value.
- **Index sinks opt in.** `terms::equality` lists each logical type it
  knows, with its own domain and normalization. Anything else, uuid
  included, gets `TermError::NoDomain`, never a term for the physical
  value.

**On the wire**, today's tags become shorthand. `DATE` reads as
`date` over an int, `UINT32` as a plain int, and so on. So every existing
frame and leaf is still valid, byte for byte. A logical type without a tag
uses a new envelope, `0xF3, id, param`, followed by the plain physical
scalar. One encoding per value: an envelope is refused where a shorthand
exists.

So, **does a timestamp need its own kind?** Not a physical one: it's an int
with a unit. But it does need a logical type. Without one, the host gets a
number back instead of a `Date`, and the index can't tell a timestamp from
the integer it's stored as. The units also pay off. A JS `Date` is
`timestamp(ms)` over its own millisecond count, so there's no conversion
on the way in, and the index folds the unit away.

## Findings

1. **Nothing on the path needs `Value`.** The only use left is
   `terms::via_value`. aead-value keeps the float, date, timestamp, decimal
   and bytes equality encodings private, reachable only through `Value`, so
   the spike builds a one-scalar `Value` for them. Exposing them per scalar
   would remove it. `src/scalar.rs` reimplements aead-value's private
   scalar codec for the same reason (and to add the envelope).
2. **Push-style containers make composition free.** With GATs, an element
   sink borrows its parent. `Tee` is about 100 lines and works at any
   depth. Terms are a plain sink.
3. **The backend really is bytes-only.** `Backend` is `seal` and `open`.
   Everything else that today's `Aes{Seq,Map}Cipher` and `AesDecipher` do
   is backend-independent and now sits in one sink and one walk.
4. **Go needs no `Value`.** The frame *is* the foreign type, from Rust's
   point of view. Encrypt walks it in place. Decrypt writes frame bytes
   directly.
5. **Native bindings can walk live objects.** `js::JsRef` reads JS straight
   into any sink. A getter that throws comes back as a JS error. A snapshot
   is only needed to move work off the JS thread, and then it's
   `to_frame(JsRef(v))`. For Rustler, terms are immutable, so a direct walk
   is also consistent. For PyO3 and JS, getters can run code, so a direct
   walk is as consistent as the object is.
6. **The exhaustiveness question splits in two.** A new physical kind is a
   compile error everywhere (exhaustive `match` on `Physical`). A new
   logical type is *not*: structural sinks never match on it, and index
   sinks and host builders have a deliberate default (refuse, or keep the
   annotation). That's what you want for an open set. A `_ =>` arm on
   `Physical` would defeat the first half; `clippy::wildcard_enum_match_arm`
   can catch it.
7. **Adding a logical type is local.** Uuid touched `kinds.rs` (variant,
   wire id, validity), a Rust source and a typed target, plus an optional JS
   arm. Encrypt, decrypt, the codec, frames, `Tee` and terms needed no
   change; the envelope and the defaults covered them.
8. **Typed decoding got short.** A scalar target is one function from
   `(logical, physical)` to the type. A derive is still the answer for
   structs.
9. **Two of today's values have no int form.**
   - A leap second (`23:59:60.5`) isn't a count of nanoseconds. The spike
     refuses it. Arrow, Go, JS and Postgres can't hold one either.
   - Decimal negative zero isn't a `(scale, int)`. The spike reads it as
     zero, which equality already treated as equal.

   Both are in the conformance corpus, so this is a format change, if a
   small one.
10. **Under a logical type, the int's width isn't kept.** `DATE` reads back
    as an `i32` day count however the source wrote it, `TIMESTAMP` as `i128`
    nanoseconds. The logical type fixes the representation.
11. **Integer width is a hint, end to end.** Equality never sees it. Typed
    decoding reads the value: a `u32` target accepts an `i8` leaf holding
    34 and refuses one holding -1. Only the frame, the leaf tag and the host
    builders keep it.
12. **`Option::None` loses its own node.** `CipherText::None` only comes from
    today's static `Option` impl. The spike writes `None` as a tagged null
    and reads a `None` node as null. That's a decision to make: keep
    "absent" distinct from "null", or not. (It could be another logical
    type over null, like `undefined`.)
13. **Static Rust gets tagged leaves too.** There's one leaf format. Today,
    static Rust seals untagged leaves (4 bytes for a `u32`). Tagging
    everything costs one byte per leaf and makes every ciphertext
    self-describing.

Not tried:

- an ORE sink. It would opt in to logical types the same way, with its own
  per-domain transforms (truncating a timestamp to the day, say);
- richer logical parameters than one byte (a timezone, a precision and
  scale pair);
- `#[derive(Plaintext)]` and `#[derive(Decode)]` for Rust structs;
- the hardening `convert.rs` does on the Node side.
