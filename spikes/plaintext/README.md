# Plaintext data model spike

A spike, not a proposal. It doesn't change any vitaminc crate. It depends on
them by path and lives on the local branch `spike/plaintext-data-model`.

There are two stages:

- **Stage 1** (`src/model.rs`, `src/sources`, `src/sinks`, `src/decrypt.rs`):
  the data model on top of today's `Cipher`/`Encrypt` API, unchanged.
- **Stage 2** (`src/next`): the same idea with the API open. There's no
  `Encrypt`, no `Decrypt` and no `Value`. Containers are push-style and
  sources have an error channel. See [Stage 2](#stage-2-the-api-open) below.

## The idea

vitaminc's `Encrypt`/`Cipher` split is modelled on serde, but `Encrypt` does
two jobs at once. It *describes* a value and it *targets* the cipher's
bytes-only data model, in the same step. Hosts (Go, Node) therefore convert
into `Value` first, because `Value` is the only place a scalar's type survives
long enough for index terms to see it.

This spike adds the missing layer, the way serde splits `Serialize` from
`Serializer`:

- [`Plaintext`](src/model.rs): a source describes itself once, through typed
  scalars (`u32`, `i8`, `str`, `date`, ...) and containers.
- [`Sink`](src/model.rs): consumes that description. Every consumer is a sink.

```text
 sources (implement Plaintext)          sinks (implement Sink)
 ─────────────────────────────          ──────────────────────────────────────
 Rust primitives, Vec, BTreeMap   ┐     Tagged<P>      encrypt, tagged leaves
 &Value / Value                   ├──►  EqualityTerm   canonical PRF input
 Frame<'_>   (Go's bytes)         │     WithTerms<S>   S + terms, one walk
 js_to_frame (Node, via Frame)    ┘     FrameWriter    transport bytes
                                        ValueBuilder   owned Value snapshot
```

`Value` stops being the hub. It becomes one source and one sink, used only
when someone wants an owned snapshot.

## Reading order

1. `src/model.rs`: the two traits. Short.
2. `src/sinks/encrypt.rs`: `Tagged<P>: Encrypt`. Each scalar method is one
   line that builds the same `Tagged*` leaf `impl Encrypt for Value` uses.
3. `src/sources/frame.rs`: Go's frame walked in place.
4. `src/hosts/go_guest.rs`: the guest's `encrypt`/`decrypt`, today and spike,
   side by side.
5. `src/sinks/terms.rs`: encrypt and collect equality terms in one walk,
   including nested containers.
6. `src/decrypt.rs`: decrypt straight to frame bytes.
7. `src/hosts/js.rs`: the Node side, and why it snapshots.
8. `tests/`: the evidence.

## Running

```sh
cargo test                     # from spikes/plaintext
cargo check --features napi    # compile-check the Node sketch
```

## What the tests show

- **The ciphertext is the same one `Value` produces.** `tests/parity.rs` runs
  every valid vector in `testdata/value-conformance.json`, plus a nested
  sample, through a recording `Cipher`. It checks that `Tagged(frame)`,
  `Tagged(&value)` and `impl Encrypt for Value` make the same calls, with
  the same leaf plaintext and the same AAD.
- **`Frame::parse` accepts exactly what the transport decoder accepts.**
  Checked on the corpus, the malformed corpus and about 20k mutated inputs.
- **Equality input matches `canonical::equality_input`** for every vector.
- **The new guest code is wire-compatible with today's.** `tests/aes.rs`
  encrypts with each and decrypts with the other, using real AES-256-GCM.
- **One walk gives both ciphertext and terms,** with paths for nested leaves.

## Findings

What worked:

1. **Go needs no `Value` at all.** The frame *is* the foreign type, from
   Rust's point of view. Encrypt walks it in place. Decrypt writes frame
   bytes directly, since a fixed-width scalar's sealed plaintext is
   byte-identical to its frame. Numbers never leave a protected buffer.
2. **Index terms fit the model.** They need typed scalars, not bytes, and the
   data model keeps the type. `EqualityTerm` writes integers and text
   natively. The sign byte for `i32` versus `u32` is exactly the information
   `Cipher` drops.
3. **One walk for encrypt plus terms, even through containers.** The cipher
   drives each element's walk (`encrypt_next` takes a value). `Tracked`
   re-wraps whatever sink the cipher uses, so the term collector rides
   along. That works because the term side is push-only.
4. **The visitor answers the exhaustiveness question.** The `match` on
   `Value` lives in one `impl Plaintext for &Value`. Inside aead-value it
   would be exhaustive. Downstream code implements `Sink`, whose methods are
   all required, so a new kind is a compile error there instead of a
   wildcard arm. This is the "visitor" option from the open decision.

Friction:

5. **`Encrypt` has no error channel for the source.** The only error type
   inside `encrypt_with_aad` is the cipher's, and a source can't construct
   one. So sources must be infallible. A frame gets that by validating
   first. Live JS can't do it, because a getter can throw part way through.
   Fixing this would mean changing the `Cipher`/`Encrypt` signatures.
6. **Node still takes a snapshot, but the snapshot is a frame.** Point 5,
   plus `!Send` JS handles, rule out walking JS straight into the cipher.
   A flat frame in `Protected` is a better snapshot than `Value`:
   - it is `Send + 'static`;
   - it keeps numbers in protected memory;
   - it is what Go already sends.

   After that, Node and Go share one path.
7. **`SeqCipher::encrypt_next` is pull-style.** A sink can't drive two
   pull-style consumers from one walk. Point 3 works only because terms are
   push-only. A push-style `next_element_cipher()` would make sinks fully
   composable. It would also be an API change.
8. **Passthrough is still `Value`-shaped.** The cipher's passthrough channel
   is `Box<dyn Any>`, and decrypt downcasts it to `Value`. So a passthrough
   subtree is still built as a `Value`. It's cleartext by design, so this is
   a shape constraint, not a custody one.
9. **aead-value's internals are `Value`-shaped.** The scalar tag table and
   the canonical encodings for float, date, timestamp, decimal and bytes are
   private, reachable only through `Value`. The spike copies the table
   (`src/scalar.rs`) and builds a one-scalar `Value` for those encodings
   (`via_value`). Exposing them per scalar would remove both shortcuts.
10. **There are two leaf formats.** Static Rust `u32: Encrypt` seals 4
    untagged bytes. `Tagged(34u32)` seals 5 tagged bytes. That is true
    today too (`u32` versus `Value::UInt32`). The data model just makes the
    choice explicit as a choice of sink. An untagged sink for statically
    typed Rust would be another sink, not tried here.

Not tried:

- an ORE sink (the equality sink already shows the typed-scalar need);
- `#[derive(Plaintext)]` for Rust structs;
- the hardening `convert.rs` does on the Node side.

## Stage 2: the API open

`src/next` assumes vitaminc's encryption traits can change. It deletes
`Encrypt`, `Decrypt` and `Value` from the path entirely.

| Today | Stage 2 |
|---|---|
| `Encrypt` (describe and encrypt in one trait) | `Plaintext` (describe) plus `encrypt(p, backend, aad)` |
| `Cipher`, `SeqCipher`, `MapCipher` | `Backend` (seal and open one leaf, bytes only) plus `EncryptSink` (types to tagged leaves, container rules) |
| `Decrypt`, `Decipher`, `DecipherVisitor`, `SeqAccess`, `MapAccess` | `decrypt_into(backend, ct, aad, sink)` |
| `Decrypt for Value` | `decrypt_into` with any sink: a `FrameWriter` for Go, a JS builder for Node |
| `Decrypt` for a static Rust type | `Decode`, a typed sink (`src/next/typed.rs`) |
| Passthrough as `Box<dyn Any>` holding a `Value` | `PassthroughFrame`, the frame bytes the transport already wrote |
| `SeqCipher::encrypt_next(value)` (pull) | `SeqSink::element() -> Sink` (push) |
| No way for a source to fail | `Sink::Error: Error`, so a source can call `Error::source` |

Reading order:

1. `src/next/model.rs`: the traits, with the two changes.
2. `src/next/encrypt.rs`: `Backend`, and `EncryptSink` with today's
   container rules (element and entry AAD, empty markers, nothing-sealed
   refusal, duplicate keys) gathered in one place.
3. `src/next/decrypt.rs`: one recursive walk that feeds any sink.
4. `src/next/tee.rs` and `src/next/terms.rs`: encrypt plus terms is
   `Tee(EncryptSink, Terms)`. Stage 1's `Tracked`/`WithTerms` aren't needed.
5. `src/hosts/go_guest.rs` (`mod next`) and `src/hosts/js.rs` (`mod next`):
   - Go: a frame in, a frame out.
   - Node: walks live JS with no snapshot, and decrypts straight into JS
     values.
6. `src/next/typed.rs`: typed decryption for Rust.
7. `tests/next.rs`.

What `tests/next.rs` shows, with real AES-256-GCM:

- **Wire compatibility with today.** The stage-2 guest and today's guest
  decrypt each other's ciphertext for every corpus vector.
- **A byte-identical codec.** The ciphertext codec matches
  `transport::encode_ciphertext` byte for byte, passthrough included.
- **The error channel works.** A failing source stops the walk with its
  own error.
- **Lengths can be unknown.** They're patched into the frame at the end.
- **Typed decryption works.**
  - `u32`, `Vec<String>` and `Vec<Vec<u32>>` round-trip.
  - The wrong target kind is refused.
- **One walk through `Tee` gives the same terms as stage 1**, and the
  ciphertext from that walk decrypts back to the original frame.

### Stage 2 findings

1. **Nothing on the path needs `Value`.** The only use left is stage 1's
   `EqualityTerm::via_value`. That is the canonical-encodings shortcut
   (finding 9 above), not a design need.
2. **Push-style containers make composition free.** With GATs, an element
   sink borrows its parent. `Tee` is about 100 lines and works at any
   depth. Terms are a plain sink.
3. **The backend really is bytes-only.** `Backend` is `seal` and `open`.
   Everything else that today's `Aes{Seq,Map}Cipher` and `AesDecipher` do
   is backend-independent and now sits in one sink and one walk.
4. **Native bindings can walk live objects.** `js::next::JsRef` reads JS
   straight into any sink. A getter that throws comes back as a JS error.
   A snapshot is only needed to move work off the JS thread, and then it's
   `to_frame(JsRef(v))`. For Rustler, terms are immutable, so a direct walk
   is also consistent. For PyO3 and JS, getters can run code, so a direct
   walk is as consistent as the object is.
5. **Typed decoding is verbose without a derive.** A scalar target refuses
   19 methods, done here with a macro. Serde has the same shape and solves
   it with derives and default methods. Default methods would bring back
   the silent fallthrough that required methods prevent, so a derive is
   the better answer.
6. **`Option::None` loses its own node.** `CipherText::None` only comes from
   today's static `Option` impl. Stage 2 writes `None` as a tagged null and
   reads a `None` node as null. That's a decision to make: keep "absent"
   distinct from "null", or not.
7. **Static Rust gets tagged leaves too.** Stage 2 has one leaf format.
   Today, static Rust seals untagged leaves (4 bytes for a `u32`). Tagging
   everything costs one byte per leaf and makes every ciphertext
   self-describing. An untagged policy is possible (a type parameter on
   `EncryptSink`) but wasn't needed for anything here.
8. **Size.** `src/next` is about 1,700 lines with comments. It does a lot of
   what aead's traits and impls plus encrypt's dynamic cipher do. It
   doesn't cover hlist, derives or the long tail of std impls, so that is
   not a like-for-like comparison.
