# vitaminc Go bindings (WASI spike)

Go bindings for the vitaminc AEAD encryption stack, built the way the
cipherstash-suite WASI bridge (suite PR #2099) proved out: the Rust code is
compiled to a **wasm32-wasip1** module and run in-process with
[wazero](https://github.com/tetratelabs/wazero) — pure Go, `CGO_ENABLED=0`,
no shared libraries, no cross-compilation matrix. One `.wasm` file ships
inside the module.

**Status: spike.** The API shape and transport encoding are not stable.

## Layout

- `guest/` — Rust crate (`vitaminc-wasi-guest`, its own workspace, outside
  the release-plz version group) exposing `vc_alloc`/`vc_dealloc`/
  `vc_encrypt`/`vc_decrypt`. Needs no host imports beyond WASI itself
  (`random_get` supplies nonce entropy).
- `wasm/vitaminc_guest.wasm` — the committed build artifact (see
  *Rebuilding*).
- `*.go` — the host package: `Value` (the Go projection of `FfiValue`),
  `CipherText`, and `Client` (wazero runtime + the transport codec).
- `testdata/cross_lang.bin` — ciphertext produced by **native** Rust
  (aws-lc-rs backend); `TestCrossLanguageFixture` decrypts it through the
  wasm guest (RustCrypto backend), pinning key format, transport encoding,
  sealed-leaf tags and AAD handling across languages *and* backends.

## Usage

```go
client, err := vitaminc.NewClient(ctx)
defer client.Close(ctx)

ct, err := client.Encrypt(ctx, key, vitaminc.Object{
    {"email", vitaminc.String("ada@example.com")},
    {"logins", vitaminc.Int(42)},
}, aad)

value, err := client.Decrypt(ctx, key, ct, aad)
```

`Int` and `Number` are distinct: an `Int` round-trips as an integer in
every language (a JS host surfaces it as `BigInt` beyond 2^53−1). Object
keys travel in the clear but are cryptographically bound to their sealed
values — renaming or swapping keys fails decryption; reordering entries
does not.

## Rebuilding the guest

```sh
cd guest
cargo run --example gen_fixture          # only if the fixture value/codec changed
cargo build --release --target wasm32-wasip1
cp target/wasm32-wasip1/release/vitaminc_wasi_guest.wasm ../wasm/vitaminc_guest.wasm
cd .. && go test ./...
```

## Trade-offs (accepted for the spike)

- On wasm32 `vitaminc-encrypt` uses its pure-Rust RustCrypto backend: no
  AES-NI, roughly an order of magnitude slower than aws-lc-rs. Fine for
  envelope/field workloads; not for bulk streams.
- A wasm instance is single-threaded; `Client` serializes calls with a
  mutex. Instantiate multiple Clients for parallelism (a compiled-module
  cache would remove the per-Client compile cost — deferred).
- Guest-side buffers are zeroized before free, but copies on the Go heap
  (keys, plaintext values) cannot be reliably wiped from Go.
- The transport encoding is transport-only. The only frozen byte format is
  the sealed leaf (`[tag] ++ payload`, see `vitaminc-aead-value`); durable
  database interop belongs to the EQL layer, which this module knows
  nothing about.
