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
```

`Encrypt` takes `any` (encoded through the `vcvalue` currency); `Decrypt`
returns the `vcvalue` decode shape. A runnable, end-to-end walk-through of
everything below is the testable `Example` in `example_test.go`.

### Encrypting a user record with mixed fields

A type controls its own sealing by implementing `vcvalue.Encryptable` (the Go
analog of Rust's `impl Encrypt`, since Go has no orphan impls). Non-secret
fields opt into passthrough explicitly — they travel **unencrypted and
unauthenticated**, so a database can read and index them without the key:

```go
type User struct {
    ID        int64
    CreatedAt string
    Email     string
    Name      string
}

func (u User) EncryptValue(enc vcvalue.Encoder) error {
    m := enc.Map()
    m.Field("id").Passthrough().Int64(u.ID)
    m.Field("created_at").Passthrough().String(u.CreatedAt)
    m.Field("email").String(u.Email)
    m.Field("name").String(u.Name)
    return m.End()
}

aad := []byte("user:42") // bind the ciphertext to the row identity
ct, err := cipher.Encrypt(ctx, User{42, "2026-07-25", "ada@example.com", "Ada Lovelace"}, aad)
```

Dynamic shapes encode the same way via reflection, with `vcvalue.Plain`
as the explicit passthrough marker — passthrough never happens implicitly:

```go
record := map[string]any{
    "id":    vcvalue.Plain{V: int64(42)},
    "email": "ada@example.com",
}
```

(Reflection sorts map keys for determinism; an `Encryptable` writes fields in
the order of its choosing.)

### The ciphertext is structured, not a blob

`Encrypt` returns the tree. Each sealed field is an independent
`nonce || ciphertext || tag` leaf and passthrough fields are readable in
place, so a user record maps naturally onto table columns:

```go
for _, f := range ct.Fields {
    switch f.Node.Kind {
    case vcvalue.KindPassthrough:
        fmt.Println(f.Key, "=", f.Node.Passthrough) // id = 42 — no key involved
    case vcvalue.KindSingle:
        storeColumn(f.Key, f.Node.Leaf) // email → its own column of sealed bytes
    }
}
```

### Decrypting — the whole record, or one column

Map keys travel in the clear but each is cryptographically bound into its
value's AAD, and there is no whole-map seal — so any subset of entries
decrypts independently. To read one column back, rebuild a one-entry map
around the stored leaf:

```go
one := vcvalue.CipherText{
    Kind:   vcvalue.KindMap,
    Fields: []vcvalue.CipherTextField{{Key: "email", Node: loadedNode}},
}
got, err := cipher.Decrypt(ctx, one, aad) // Object{{"email", "ada@example.com"}}
```

The binding cuts the other way too: presenting that same leaf under a renamed
key, or bare outside its map entry, fails with `ErrAuthentication`.

Decrypted passthrough fields come back wrapped in `vcvalue.Plain`, so a
caller can always tell which fields were never sealed:

```go
for _, f := range got.(vcvalue.Object) {
    if p, ok := f.Value.(vcvalue.Plain); ok {
        fmt.Println(f.Key, "was in the clear:", p.V)
    }
}
```

### An array of user records

A slice works directly — reflection consults `Encryptable` for each element,
so `[]User` produces a sequence of the per-user trees from above:

```go
users := []User{
    {1, "2026-07-24", "ada@example.com", "Ada Lovelace"},
    {2, "2026-07-25", "grace@example.com", "Grace Hopper"},
}
ct, err := cipher.Encrypt(ctx, users, aad)

// ct.Kind == vcvalue.KindSeq; one KindMap per user.
for i, row := range ct.Items {
    for _, f := range row.Fields {
        fmt.Println(i, f.Key, f.Node.Kind) // id: KindPassthrough, email: KindSingle, …
    }
}
```

`Decrypt` of the whole tree returns `[]any` of `vcvalue.Object`. Rows are
independent: a single element decrypts on its own (wrapped in a one-item
sequence, or directly as the root), which suits row-at-a-time reads. The flip
side is that the sequence itself carries no seal — element order and
membership are **not authenticated**, just as a map has no whole-map seal. A
caller that needs those properties must bind them itself, e.g. a per-row AAD
carrying the row's identity.

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
