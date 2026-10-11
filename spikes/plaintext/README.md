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

- [`Plaintext`](src/model.rs): a source describes itself once, through typed
  scalars and containers.
- [`Sink`](src/model.rs): consumes that description. Every consumer is a sink.

```text
 sources (implement Plaintext)        sinks (implement Sink)
 ─────────────────────────────        ─────────────────────────────────────────
 Rust primitives, Vec, BTreeMap  ┐    EncryptSink   tagged leaves, container rules
 Frame<'_>     (Go's bytes)      ├──► Terms         equality terms, per leaf
 JsRef<'_>     (live JS value)   ┘    FrameWriter   transport bytes (Go)
                                      JsBuilder     JS values (Node)
                                      Decode        typed Rust
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

## Reading order

1. `src/model.rs`: the traits.
2. `src/encrypt.rs`: `Backend`, and `EncryptSink` with today's container
   rules (element and entry AAD, empty markers, nothing-sealed refusal,
   duplicate keys) gathered in one place.
3. `src/decrypt.rs`: one recursive walk that feeds any sink.
4. `src/frame.rs`: Go's frame walked in place.
5. `src/hosts/go_guest.rs`: the wasm guest's `encrypt`/`decrypt`, today and
   spike, side by side.
6. `src/tee.rs` and `src/terms.rs`: encrypt plus terms is
   `Tee(EncryptSink, Terms)`.
7. `src/hosts/js.rs`: walks live JS with no snapshot, and decrypts straight
   into JS values.
8. `src/typed.rs`: typed decryption for Rust.
9. `tests/`: the evidence.

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
  `testdata/value-conformance.json`, plus a nested sample.
- **A byte-identical codec.** The ciphertext codec matches
  `transport::encode_ciphertext` byte for byte, passthrough included.
- **`Frame::parse` accepts exactly what the transport decoder accepts**
  (`tests/frame.rs`): the corpus, the malformed corpus and about 20k mutated
  inputs.
- **Equality input matches `canonical::equality_input`** for every vector
  (`tests/terms.rs`), and one `Tee` walk gives both ciphertext and terms,
  with paths for nested leaves.
- **The error channel works.** A failing source stops the walk with its own
  error.
- **Lengths can be unknown.** They're patched into the frame at the end.
- **Typed decryption works.** `u32`, `Vec<String>` and `Vec<Vec<u32>>`
  round-trip, and the wrong target kind is refused.

## Findings

1. **Nothing on the path needs `Value`.** The only use left is
   `terms::via_value`. aead-value keeps the float, date, timestamp, decimal
   and bytes equality encodings private, reachable only through `Value`, so
   the spike builds a one-scalar `Value` for them. Exposing them per scalar
   would remove it. `src/scalar.rs` is a copy of aead-value's private tag
   table for the same reason.
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
6. **Required methods answer the exhaustiveness question.** Every `Sink`
   method is required, so a new kind is a compile error in every sink
   instead of a silent wildcard arm.
7. **Typed decoding is verbose without a derive.** A scalar target refuses
   19 methods, done here with a macro. Default methods would bring back
   the silent fallthrough that required methods prevent, so a derive is
   the better answer.
8. **`Option::None` loses its own node.** `CipherText::None` only comes from
   today's static `Option` impl. The spike writes `None` as a tagged null and
   reads a `None` node as null. That's a decision to make: keep "absent"
   distinct from "null", or not.
9. **Static Rust gets tagged leaves too.** There's one leaf format. Today,
   static Rust seals untagged leaves (4 bytes for a `u32`). Tagging
   everything costs one byte per leaf and makes every ciphertext
   self-describing.

Not tried:

- an ORE sink (the equality sink already shows the typed-scalar need);
- `#[derive(Plaintext)]` and `#[derive(Decode)]` for Rust structs;
- the hardening `convert.rs` does on the Node side.
