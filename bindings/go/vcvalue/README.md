# vcvalue — the durable value layer

`vcvalue` is the Go materialization of vitaminc's **frozen data model**: the
value currency (encoder / `Encryptable` / reflection encode, plus a natives
decode), the transport codec, and the `CipherText` projection.

It has **zero dependencies** — no wazero, no crypto, nothing. It is the module
a future stack-encrypt Go SDK is expected to import for its encode/decode
surface. Keeping it dependency-free is the point: the wasm reference harness
(`vcencrypt`, next door) is just *one* consumer, and its wazero/crypto
dependencies must never leak into the layer real applications depend on.

```
import "github.com/cipherstash/vitaminc/bindings/go/vcvalue"
```

## The model, not this package

The cross-language contract is the frozen sealed-leaf tag table
(`[tag] ++ payload`, sealed **inside** the AEAD envelope, defined in the Rust
crate `vitaminc-aead-value`) — not any language's types. This package's
`Encoder` channels and decode natives *implement* that model; they are not the
contract. A new tag is added only when a value class cannot be represented in
the existing model, and needs a defined decode mapping in every supported
language before it ships.

The transport encoding used to hand a tree across an FFI boundary in one copy
(`Marshal` / `Unmarshal`, `MarshalTransport` / `UnmarshalCipherText`) is
**transport-only**, not a storage format. Durable cross-language database
interop is a schema-aware layer's job, which this package knows nothing about.

## Encoding

- Types implement `Encryptable` to control their own sealing (Go's answer to
  Rust's `Encrypt`, since Go has no orphan impls).
- Everything else goes through `Encode`/`Marshal` with `encoding/json`-style
  reflection: builtins, slices, maps (keys sorted for a deterministic
  structure), and structs (by field name, honoring `vc:"..."` tags).
- The numeric family stays distinct by signedness **and** width: `int16`→
  `INT32`, `int`/`int64`→`INT64`, `uint`/`uintptr`→`UINT64`, `float32`→
  `FLOAT32`, and so on. Go maps **exactly in both directions**.

## Passthrough — fields in the clear

Some fields are not secret and should travel unencrypted alongside the sealed
ones. `vcvalue` carries them as **passthrough**: unencrypted *and*
unauthenticated, non-sensitive fields only.

Passthrough never happens implicitly — you opt in:

```go
// Reflection encode: wrap the value in Plain.
value := map[string]any{
    "id":    vcvalue.Plain{V: int64(42)}, // in the clear
    "email": "ada@example.com",           // sealed
}

// Or drive the Encoder channel directly:
m := enc.Map()
m.Field("id").Passthrough().Int64(42)
m.Field("email").String("ada@example.com")
m.End()
```

On decode a passthrough field surfaces back as `Plain{V: <decoded value>}`, so
the marking round-trips and a caller can tell which fields were in the clear. A
`CipherText` node for a passthrough field is `KindPassthrough`, and its
readable value is in the `Passthrough` field — legible with no key.

## Decoding

`Unmarshal` turns value transport bytes into Go natives (`nil`, `bool`,
`int32`, `int64`, `uint32`, `uint64`, `float32`, `float64`, `string`,
`[]byte`, `[]any`, the ordered `Object` for maps, and `Plain` for passthrough).
A reflection-based `Unmarshal` into caller structs (the mirror of `Encode`) is
future work.
