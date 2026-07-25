# vitaminc Go bindings (WASI spike)

Go bindings for the vitaminc AEAD encryption stack. The Rust code is compiled
to a **wasm32-wasip1** module and run in-process with
[wazero](https://github.com/tetratelabs/wazero) — pure Go, `CGO_ENABLED=0`,
no shared libraries, no cross-compilation matrix. One `.wasm` file ships
inside the harness package.

**Status: spike.** The API shape and transport encoding are not stable.

## Two packages, on purpose

One Go module rooted at `bindings/go`, split into two packages:

- **`vcvalue/`** — the durable layer: the value currency (Encoder /
  Encryptable / reflection encode, and a natives decode) plus the transport
  codec and the `CipherText` projection. **Zero dependencies on wazero or any
  crypto.** This is the package a future stack-encrypt Go SDK is expected to
  import.
- **`vitaminc/`** — the reference harness: the wazero `Client`, the embedded
  `.wasm`, and the end-to-end tests. It is explicitly a reference tool that
  proves the currency and transport work end-to-end; the product surface is
  the forthcoming stack-encrypt SDK, not this package.
- **`guest/`** — the Rust crate (`vitaminc-wasi-guest`, its own workspace,
  outside the release-plz version group) exposing `vc_alloc`/`vc_dealloc`/
  `vc_encrypt`/`vc_decrypt`. It imports the transport codec from
  `vitaminc_aead_value::transport`; it needs no host imports beyond WASI
  itself (`random_get` supplies nonce entropy).

## Usage

Any Go value goes in — builtins, slices, maps, and structs are handled by
reflection, and a type can implement `vcvalue.Encryptable` to control its own
sealing (the Go analog of Rust's `impl Encrypt`, since Go has no orphan
impls):

```go
type Person struct{ Name string; Age uint64 }

func (p Person) EncryptValue(enc vcvalue.Encoder) error {
    m := enc.Map()
    m.Field("name").String(p.Name)
    m.Field("age").UInt(p.Age)
    return m.End()
}

client, _ := vitaminc.NewClient(ctx)
defer client.Close(ctx)

ct, _ := client.Encrypt(ctx, key, Person{"Ada", 36}, aad)
value, _ := client.Decrypt(ctx, key, ct, aad) // vcvalue natives + Object
```

`Encrypt` takes `any`; `Decrypt` returns the vcvalue decode shape (Go
natives — `nil`, `bool`, `float64`, `int64`, `uint64`, `string`, `[]byte`,
`[]any` — and the ordered `vcvalue.Object` for maps). `Int`, `UInt` and
`Number` stay distinct across the boundary; a `uint64` above `int64` uses the
`UINT64` tag. Object keys travel in the clear but are bound into each value's
AAD — renaming or swapping keys fails decryption; reordering entries does
not.

## Rebuilding the guest

```sh
cd guest
cargo build --release --target wasm32-wasip1
cp target/wasm32-wasip1/release/vitaminc_wasi_guest.wasm ../vitaminc/wasm/vitaminc_guest.wasm
cargo run --example gen_fixture   # only if the fixture value/codec changed
cd .. && CGO_ENABLED=0 go test ./...
```

## Design decisions and non-decisions

Settled choices for this spike, and things deliberately left out of scope:

1. **Two layers on purpose.** `vcvalue` is the durable, dependency-free
   currency + transport codec; a future stack-encrypt Go SDK will consume it.
   `vitaminc` is a reference harness that proves the model end-to-end through
   wasm. Keeping them separate stops wazero/crypto leaking into the layer that
   real applications will depend on.

2. **The data model is the tag table + leaf encodings.** The cross-language
   contract is the frozen sealed-leaf tags (`[tag] ++ payload` inside the AEAD
   envelope, defined in `vitaminc-aead-value`), not any particular language's
   types. Rust's `FfiValue` and Go's Encoder channels / decode natives are
   materializations of that model. It is deliberately narrow (JSON/CBOR-class,
   not serde-class): a new tag is added only when a value class *cannot be
   represented* in the existing model, and requires a defined decode mapping
   for every supported language before it ships. `UINT64` is the worked
   example.

3. **Typed Rust-static ↔ Go interop is out of scope.** Reusing Rust's
   untagged `impl Encrypt for u32` leaf formats to carry static Rust types
   across to Go is a non-goal. Typed fidelity comes from the schema layer (EQL
   domains carry bigint/double/text), not from value tags. The value model is
   dynamically typed by design.

4. **Wasm component model / WIT is the likely future, not adopted yet.** A
   WIT-defined component interface is the probable direction for the
   function-binding layer, but it is blocked on pure-Go host support: wazero
   has no component-model runtime, and wasmtime-go reintroduces cgo. Tracked,
   not adopted; the hand-written `vc_*` ABI stands in for now.

5. **A chatty per-leaf ABI was rejected.** Having Go drive the live cipher
   across the boundary call-by-call (one crossing per leaf) was considered and
   dropped: it pays per-crossing cost and forces the guest to hold session
   state for half-built seq/map builders, with no byte-format-authority
   benefit over the current replay design (host hands over a whole transport
   tree, guest replays it through the cipher in one call).

6. **suite PR #2099's conventions are one option, not an inherited idiom.**
   The hand-written ABI, packed-`u64` returns, and committed `.wasm` follow
   what the cipherstash-suite WASI bridge proved out, but they are treated as
   one workable approach for the spike, not a house style to adopt by default.

## Trade-offs (accepted for the spike)

- On wasm32 `vitaminc-encrypt` uses its pure-Rust RustCrypto backend: no
  AES-NI, roughly an order of magnitude slower than aws-lc-rs. Fine for
  envelope/field workloads; not for bulk streams.
- A wasm instance is single-threaded; `Client` serializes calls with a mutex.
  Instantiate multiple Clients for parallelism (a compiled-module cache would
  remove the per-Client compile cost — deferred).
- Guest-side buffers are zeroized before free, but copies on the Go heap
  (keys, plaintext values) cannot be reliably wiped from Go.
- The transport encoding is transport-only. The only frozen byte format is
  the sealed leaf (`[tag] ++ payload`, see `vitaminc-aead-value`); durable
  database interop belongs to the EQL layer, which this module knows nothing
  about.
```
