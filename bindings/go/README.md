# vitaminc Go bindings (WASI spike)

Go bindings for the vitaminc AEAD encryption stack. The Rust code is compiled
to a **wasm32-wasip1** module and run in-process with
[wazero](https://github.com/tetratelabs/wazero) — pure Go, `CGO_ENABLED=0`,
no shared libraries, no cross-compilation matrix.

**Status: spike.** The API shape and transport encoding are not stable.

## Three modules, on purpose

This directory holds **three separate Go modules**, each with its own `go.mod`:

- **[`vcvalue/`](vcvalue)** — the durable value layer: the value model — the
  types application code holds and stores (`Sealed` and the marker leaves,
  `Plain`, the ordered `Object` decode shape). **Zero dependencies** (no
  wazero, no crypto, no wire format). This is the module a stack-encrypt Go
  SDK imports for the model.
  Module path: `github.com/cipherstash/vitaminc/bindings/go/vcvalue`.

- **[`vcffi/`](vcffi)** — the shared FFI transport codec: the wire encoding
  that carries value and ciphertext trees across a wasm boundary, plus the
  `Encryptable`/`Encoder` extension point. Depends only on `vcvalue`. One
  codec for every binding that owns such a boundary — the encoding must
  never fork per binding. Its ciphertext decoder is parameterised over a
  `LeafSet`, so each binding materializes its **own** sealed-leaf types (a
  stack-encrypt leaf is not a `vcvalue.Sealed`).
  Module path: `github.com/cipherstash/vitaminc/bindings/go/vcffi`.

- **[`vcencrypt/`](vcencrypt)** — the demonstration binding of the
  `vitaminc-encrypt` crate specifically: the wazero `Client`, the embedded
  `.wasm`, and the Rust guest (`vcencrypt/guest/`). Single static key **by
  design** — that is what `vitaminc-encrypt` is; key management / ZeroKMS
  belongs to stack-encrypt, out of scope here.
  Module path: `github.com/cipherstash/vitaminc/bindings/go/vcencrypt`.

`vcencrypt` depends on `vcffi` and `vcvalue`; `vcffi` depends on `vcvalue`.
All three live in this repo and none is published, so the dependencies
resolve with local `replace` directives:

```
replace github.com/cipherstash/vitaminc/bindings/go/vcffi => ../vcffi
replace github.com/cipherstash/vitaminc/bindings/go/vcvalue => ../vcvalue
```

That is self-contained — `go test ./...` works from any module directory
with no `go.work` file required.

### Why modules, not packages

`vcvalue` **is not a binding at all** — it is the Go materialization of the
frozen data model, which real applications (via stack-encrypt) will depend on
directly. `vcencrypt` is a reference tool that proves the model works
end-to-end through wasm. A hard module boundary is what guarantees the
wazero/crypto dependencies of the reference tool can never leak into the layer
applications ship. `vcffi` sits between them for the same reason from the
other side: the codec must be shared across bindings (one implementation, one
hostile-input suite, one fuzz corpus) without pulling transport machinery
into the model module or wazero into codec consumers.

## Design decisions and non-decisions

Settled choices for this spike, and things deliberately left out of scope:

1. **The data model is the tag table + leaf encodings.** The cross-language
   contract is the frozen sealed-leaf tags (`[tag] ++ payload` inside the AEAD
   envelope, defined in `vitaminc-aead-value`), not any particular language's
   types. Rust's `FfiValue` and Go's `vcvalue` channels / decode natives are
   materializations of that model. It is deliberately narrow (JSON/CBOR-class,
   not serde-class): a new tag is added only when a value class *cannot be
   represented* in the existing model, and requires a defined decode mapping
   for every supported language before it ships. `UINT64` is the worked
   example; passthrough (`PASSTHROUGH` / `CT_PASSTHROUGH`) is transport-local
   framing, not a new sealed-leaf tag.

2. **Passthrough is opt-in and non-sensitive.** Fields that are not secret can
   travel in the clear (unencrypted *and* unauthenticated) beside the sealed
   ones — a user record's `id`/`created_at` alongside a sealed `email`/`name`.
   It never happens implicitly: reflection encode requires the `vcvalue.Plain`
   marker, and the Encoder exposes an explicit `Passthrough()` channel.

3. **A cipher is a session handle.** The key is loaded once (`NewCipher` →
   `vc_cipher_init`) and addressed by handle thereafter, so it crosses the
   boundary a single time and the guest owns the key schedule for the handle's
   lifetime. The old key-per-call ABI is gone (this is a spike; no shims).

4. **Typed Rust-static ↔ Go interop is out of scope.** Reusing Rust's untagged
   `impl Encrypt for u32` leaf formats to carry static Rust types across to Go
   is a non-goal. Typed fidelity comes from the schema layer, not value tags.
   The value model is dynamically typed by design.

5. **Wasm component model / WIT is the likely future, not adopted yet.** A
   WIT-defined component interface is the probable direction, but it is blocked
   on pure-Go host support (wazero has no component-model runtime; wasmtime-go
   reintroduces cgo). Tracked, not adopted; the hand-written `vc_*` ABI stands
   in for now.

6. **A chatty per-leaf ABI was rejected.** Having Go drive the live cipher
   across the boundary call-by-call was considered and dropped: it pays
   per-crossing cost and forces the guest to hold half-built builder state,
   with no byte-format-authority benefit over the replay design (host hands
   over a whole transport tree, guest replays it through the cipher in one
   call).

7. **suite PR #2099's conventions are one option, not an inherited idiom.** The
   hand-written ABI, packed-`u64` returns, and committed `.wasm` follow what
   the cipherstash-suite WASI bridge proved out, but they are treated as one
   workable approach for the spike, not a house style.

## Trade-offs (accepted for the spike)

- On wasm32 `vitaminc-encrypt` uses its pure-Rust RustCrypto backend: no
  AES-NI, roughly an order of magnitude slower than aws-lc-rs. Fine for
  envelope/field workloads; not for bulk streams.
- A wasm instance is single-threaded; `Client` serializes calls with a mutex.
  A process-wide compilation cache removes the per-`Client` compile cost;
  instantiate multiple `Client`s for parallelism.
- Guest-side buffers are zeroized before free, but copies on the Go heap
  (keys, plaintext values) cannot be reliably wiped from Go.
- The transport encoding is transport-only. The only frozen byte format is the
  sealed leaf (`[tag] ++ payload`, see `vitaminc-aead-value`); durable database
  interop belongs to a schema-aware layer, which these modules know nothing
  about.
