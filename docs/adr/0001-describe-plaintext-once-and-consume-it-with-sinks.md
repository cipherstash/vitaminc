---
status: proposed
---

# Describe plaintext once and consume it with sinks

Stack Encrypt is unreleased, so vitaminc's encryption data model is open to
change. This decision replaces the `Encrypt`/`Cipher` and
`Decrypt`/`Decipher` trait pairs and the `Value` enum with a serde-style
split between a type that describes itself (`Plaintext`) and the things
that consume that description (`Sink`). Encryption, index terms, transport
frames, host-language builders and typed decoding are all sinks over one
walk. The spike in `spikes/plaintext` is the evidence; this document
records what was decided and why.

## Context

Today `Encrypt` does two jobs at once. It describes a value and it targets
the cipher's bytes-only data model, in the same step. A scalar's type does
not survive past `Cipher::encrypt_bytes_vec`, so anything that needs the
type later, such as equality terms, has to see the value first. That is why
hosts (Go, Node) convert into `Value`, and why `Value` grew a variant, a
wire tag and a cipher method per scalar kind, nineteen so far. Container
rules (element and entry AAD, empty markers, duplicate keys, refusing an
all-passthrough container) live inside each `Cipher` implementation, so a
second backend reimplements them. Decryption is pull-style
(`SeqAccess::next_element`), so only one consumer can drive a walk, and
decrypting into a host value goes through `Value` again.

## Decision

**Two traits carry the data model.** `Plaintext` is implemented by anything
that can describe itself once: Rust primitives and containers, chrono and
`Decimal` types, Go's transport frame walked in place, a live JavaScript
value, a `Raw` scalar. `Sink` is implemented by anything that consumes a
description, with four methods: `scalar`, `seq`, `map` and `passthrough`.
Containers are push-style: `SeqSink::element` and `MapSink::entry` hand
back a sink for the next child, so any number of sinks can share one walk
and `Tee(a, b)` composes them at any depth. Every sink error implements
`Error::source`, so a source can stop the walk with its own failure, which
is what lets a native binding walk a live host object without a snapshot.

**A scalar is a physical value plus an optional logical type.** The
physical kinds are a closed set, as in Arrow and Parquet: null, bool, int
(with its width as a host-fidelity hint), float, text, bytes. `Physical` is
an exhaustive enum, so a new physical kind fails to compile in every sink.
Logical types say what a physical value means and are open:
`#[non_exhaustive]`, carried per value with a one-byte parameter. Today's
set is undefined, date, timestamp with a unit, decimal with a scale, and
uuid; a logical type this build does not know is carried as `Unknown`.
Structural sinks (encrypt, frames, the ciphertext codec) pass a logical
type through untouched. Index sinks opt in: `equality` lists each logical
type it knows with its domain and normalization, and refuses the rest. A
timestamp is therefore an int with a unit, not a physical kind of its own,
and a JavaScript `Date` is `timestamp(ms)` over its own millisecond count.

**The wire format is unchanged for everything that exists today.** Today's
tags become shorthand: `DATE` reads as date over an int, `UINT32` as a
plain int. A logical type without a tag travels in a new envelope,
`0xF3, id, param`, followed by the plain physical scalar. There is one
encoding per value: an envelope is refused where a shorthand exists. Every
existing frame and leaf stays valid byte for byte, and the spike's guest
and today's guest decrypt each other's ciphertext across the conformance
corpus, except a leap-second timestamp and a decimal negative zero, which
have no physical-plus-logical form and are refused.

**Encryption is a sink over a bytes-only backend, and the backend may be
async.** `EncryptSink` turns scalars into tagged leaf plaintext and owns
the container rules in one place. It never calls a backend: it produces a
tree of pending leaves, each with its plaintext and the AAD its position
derives. `seal_all` then seals the leaves, one at a time through a sync
`Cipher` or all at once through an async one. The walk is synchronous
whatever the backend is, which a native binding needs, and a remote key
provider such as 0KMS seals every leaf of a document in one `seal_many`
round trip. Decryption mirrors it: `open_all`, then a synchronous walk of
the opened tree into any sink. The backend trait is `seal` and `open` on
one leaf, plus `seal_many` and `open_many` with per-leaf defaults. Only the
leaf calls are async, so a plain `async fn` trait expresses it and the
`Decipher::Ok<T>` GAT is no longer needed. Static Rust gets tagged leaves
too, so there is one leaf format and every ciphertext is self-describing.

**Names stay close to today's.** The backend trait is `Cipher` (sync) and
`AsyncCipher`, implemented by `Aes256Cipher` and by key providers. A typed
decryption target implements `Decrypt`. Sources implement `Plaintext`.
`Sink` is the consumer and is only implemented inside vitaminc and its host
bindings, the way most serde users never implement `Serializer`. The
functions are `encrypt`, `encrypt_async`, `decrypt` and `decrypt_async`.
`Value` and `ValueKind` are deleted.

**The code splits into four crates.**

- `vitaminc-aead` holds the model: `Plaintext`, `Sink`, physical kinds and
  logical types, the leaf codec, `Cipher`, `AsyncCipher`, `EncryptSink`,
  the leaf traversals, and typed `Decrypt`. chrono, `rust_decimal` and uuid
  sources sit behind features.
- `vitaminc-encrypt` shrinks to `impl Cipher for Aes256Cipher` and `Key`.
  Its container logic moves up into `EncryptSink`.
- The transport crate, today `vitaminc-aead-value`, keeps the frame
  (`Frame`, `FrameWriter`, the ciphertext codec, `PassthroughFrame`) and is
  renamed, since `Value` is gone.
- `vitaminc-normalize`, today the `canonical` feature of
  `vitaminc-aead-value`, becomes its own crate: the per-scalar equality
  encoders made public, the frozen domain labels, the `equality` opt-in
  table, the `Terms` sink and `encrypt_with_terms`. It returns
  `Normalized { domain, bytes }`. It has no crypto in it and never imports
  PAE, which stays in `vitaminc-context` beneath everything. `vitaminc-prf`
  consumes `Normalized`.

The Node binding walks live JavaScript values through `JsRef` and builds
them back with `JsBuilder`, replacing its `Value` conversion. The Go guest
walks the frame in place and writes frame bytes directly on decrypt.
`#[derive(Plaintext)]` and `#[derive(Decrypt)]` replace today's derives.

## Consequences

- Hosts need no intermediate value type. Go encrypts from its frame and
  decrypts into one; Node walks live objects and builds live objects.
- Adding a logical type is local: a variant, a wire id, a validity rule, a
  Rust source and a typed target. Encrypt, decrypt, frames, the codec,
  `Tee` and terms need no change. Adding a physical kind is deliberately a
  compile error everywhere.
- Index sinks never index a logical value as its physical value. A date's
  day count does not collide with the integer it equals, and a logical
  type with no domain gets `NoDomain`, not a term.
- A second backend cannot diverge on container rules, because it has none.
  A 0KMS backend is `seal`, `open` and a batching `seal_many`.
- Every leaf's plaintext exists at once before sealing, in `Protected`,
  instead of streaming leaf by leaf. Memory is of the order of the
  plaintext itself.
- A leap-second timestamp and a decimal negative zero are refused. Both are
  in the conformance corpus today, so this is a small format change.
- Under a logical type the int's width is not kept: `DATE` reads back as an
  `i32` day count however it was written. Integer width is a hint end to
  end; equality never sees it and typed decoding reads the value.
- Static Rust leaves gain one tag byte each.
- `Aes256Cipher` is not `Sync` today (its nonce generator is a `RefCell`).
  An async backend is shared across tasks, so a local backend needs to
  become `Sync`.
- `Value`, `ValueKind`, `Encrypt`, `Decrypt` (in its current form),
  `Cipher`'s container methods, `Decipher`, `DecipherVisitor`, `SeqAccess`
  and `MapAccess` are removed. Stack Encrypt's async `Decipher`
  implementation becomes an `AsyncCipher` implementation with no container
  logic.

## Open questions

These are decisions the spike surfaced but did not make.

- Whether `Option::None` keeps a node of its own (`CipherText::None`) or
  reads as null, possibly as another logical type over null like
  `undefined`.
- Whether the leaf type bound into the AAD is the physical tag alone or the
  physical tag plus the logical id and parameter. PAE makes either
  unambiguous; it is a protocol choice.
- Whether uuid gets an equality domain, which would be the bytes encoding
  under its own label.
- Whether logical parameters ever need more than one byte (a timezone, a
  precision and scale pair).
- Whether to normalize decimal negative zero to zero, as the spike does, or
  refuse it as it refuses leap seconds.
