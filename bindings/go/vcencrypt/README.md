# vcencrypt — demonstration binding of `vitaminc-encrypt`

`vcencrypt` runs the Rust `vitaminc-encrypt` cipher as a **wasm32-wasip1**
guest under [wazero](https://github.com/tetratelabs/wazero) — pure Go,
`CGO_ENABLED=0`, no shared libraries, no cross-compilation matrix. One `.wasm`
file ships embedded in the package.

```
import "github.com/cipherstash/vitaminc/bindings/go/vcencrypt"
```

**Status: spike.** The API shape and transport encoding are not stable.

## Single static key, by design

`vitaminc-encrypt` is a **single-static-key** AES-256-GCM cipher — that is
exactly what this package binds. Key management, rotation, and ZeroKMS envelope
keys belong to the forthcoming stack-encrypt SDK and are deliberately **out of
scope** here. This package exists to prove the value currency and transport
work end-to-end through wasm; it is a reference tool, not the product surface.
Application code that wants only the value currency (no wasm, no crypto) should
import the sibling [`vcvalue`](../vcvalue) module.

## Usage

```go
client, _ := vcencrypt.NewClient(ctx)   // one wasm instance
defer client.Close(ctx)

cipher, _ := client.NewCipher(ctx, key) // a key schedule (handle) in the guest
defer cipher.Close(ctx)

// id/created_at travel in the clear; email/name are sealed.
record := map[string]any{
    "id":    vcvalue.Plain{V: int64(42)},
    "email": "ada@example.com",
}
ct, _  := cipher.Encrypt(ctx, record, aad)
got, _ := cipher.Decrypt(ctx, ct, aad) // vcvalue natives + Object + Plain
```

`Encrypt` takes `any` (encoded through the `vcvalue` currency); `Decrypt`
returns the `vcvalue` decode shape. A runnable, end-to-end walk-through of the
user-record shape is the testable `Example` in `example_test.go`.

## Error surface

Decryption reveals nothing about the plaintext, but the binding separates
failure *kinds* as sentinel errors (use `errors.Is`):

| error                        | cause                                            |
| ---------------------------- | ------------------------------------------------ |
| `ErrAuthentication`          | wrong key, wrong AAD, or tampered ciphertext (indistinguishable) |
| `ErrEncoding`                | malformed transport bytes                        |
| `ErrBadHandle`               | cipher used after `Close`, or an unknown handle  |
| `ErrInternal`                | guest panic or other unexpected failure          |

## The cipher handle ABI

A cipher is a **session handle** inside the guest. `NewCipher` loads the key
once (`vc_cipher_init`), returning a handle; `Encrypt`/`Decrypt` pass that
handle (`vc_encrypt`/`vc_decrypt`) so the key crosses the boundary a single
time; `Close` drops it (`vc_cipher_free`). The guest zeroizes the key bytes
right after building the key schedule; the Go-side key copy is wiped after
init. Neither wipe can cover copies the Go runtime may hold — treat process
memory as sensitive.

Results are packed into a `u64`: a non-zero high 32 bits carry the output
pointer (and low bits the length) or the handle; a zero high field means the
low bits are a status code (which maps to the sentinel errors above).

## Rebuilding the guest

```sh
cd guest
cargo build --release --target wasm32-wasip1
cp target/wasm32-wasip1/release/vitaminc_wasi_guest.wasm ../wasm/vitaminc_guest.wasm
cargo run --example gen_fixture   # only if the fixture value/codec changed
cd .. && CGO_ENABLED=0 go test ./...
```

## Trade-offs (accepted for the spike)

- On wasm32 `vitaminc-encrypt` uses its pure-Rust RustCrypto backend: no
  AES-NI, roughly an order of magnitude slower than aws-lc-rs. Fine for
  envelope/field workloads; not for bulk streams.
- A wasm instance is single-threaded; `Client` serializes calls with a mutex,
  and its ciphers share that serialization. A process-wide compilation cache
  means only the first `Client` pays the module compile cost; instantiate
  multiple `Client`s for parallelism.
- Guest-side buffers are zeroized before free, but copies on the Go heap (keys,
  plaintext values) cannot be reliably wiped from Go.
- The transport encoding is transport-only. The only frozen byte format is the
  sealed leaf (`[tag] ++ payload`, see `vitaminc-aead-value`); durable database
  interop belongs to a schema-aware layer, which this module knows nothing
  about.
