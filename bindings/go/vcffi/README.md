# vcffi — the shared FFI transport codec

`vcffi` is the wire encoding that carries a **value tree** into a wasm guest
and a **ciphertext tree** back out, plus the `Encryptable`/`Encoder`
extension point for types that control their own encoding. It exists as its
own module so every binding that owns a wasm boundary speaks the same bytes
from one implementation — one codec, one hostile-input test suite, one fuzz
corpus. Consumers: [`vcencrypt`](../vcencrypt) (the `vitaminc-encrypt`
reference binding) and the stack-encrypt Go SDK.

```
import "github.com/cipherstash/vitaminc/bindings/go/vcffi"
```

Depends only on the sibling [`vcvalue`](../vcvalue) module (the value model —
`Plain`, `Object`, the sealed leaf family), via a local `replace` directive.
No wazero, no crypto.

## Transport, not storage

These bytes are an FFI detail with **no compatibility commitment**. The only
frozen format is the sealed leaf inside the AEAD envelope (see
`vcvalue.Sealed` and the Rust crate `vitaminc-aead-value`). Nothing this
package encodes should ever be persisted.

## The `LeafSet` parameter

The ciphertext codec's structural nodes (`[]any`, `map[string]any`,
`vcvalue.Plain`) are common to every binding, but the sealed-leaf marker
types are deliberately **not**: each binding hands the codec a `LeafSet`
mapping its own leaf types onto the framing. A stack-encrypt leaf is not
decryptable by `vitaminc-encrypt`, and keeping the Go types distinct means
one can never scan or marshal where the other belongs. `VCValueLeaves` is
the set for the `vcvalue` model types.

The seam stops at the leaves. The structural nodes — including
`vcvalue.Plain` and the `vcvalue.Object` decode shape — are shared and **not**
parameterised: a binding brings its own leaves, not its own model. That is
deliberate. `Plain` is cleartext with no key binding, so none of the "a leaf
sealed by one cipher must never be mistaken for another's" reasoning applies
to it, and a second model would fork the wire encoding this module exists to
keep single.

## Hostile input

`Unmarshal` and `UnmarshalCipherText` treat their input as untrusted:
recursion depth, length prefixes and item counts are bounded, strings are
UTF-8 validated, duplicate map keys are rejected, and every malformed input
fails with `ErrMalformed` rather than panicking or over-allocating. The fuzz
targets in this package pin that contract, and CI runs the whole suite on
32-bit GOARCH, where the u32-bound guards are load-bearing.

`ErrMalformed` covers hostile bytes, not caller mistakes: a `LeafSet` that is
partially wired, or that does not materialize a kind the buffer carries,
fails with its own attributable error. So `errors.Is(err, ErrMalformed)` is a
test for bad input, not a total branch over decode failures. Encode-side
depth exhaustion has its own sentinel, `ErrTooDeep`.

## Usage

### Value tree in, ciphertext tree out

`Marshal` encodes a Go value into the bytes a wasm guest expects;
`UnmarshalCipherText` decodes what comes back, materializing sealed leaves
through the caller's `LeafSet`.

```go
type User struct {
	Email string `vc:"email"`
	Age   int    `vc:"age"`
	Notes string `vc:"-"` // never leaves the process
}

buf, err := vcffi.Marshal(User{Email: "a@example.com", Age: 42})
if err != nil {
	return err
}

// ... hand buf to the guest, get ciphertext bytes back ...

ct, err := vcffi.UnmarshalCipherText(vcffi.VCValueLeaves(), ctBytes)
if err != nil {
	return err // errors.Is(err, vcffi.ErrMalformed) for hostile input
}
sealed := ct.(map[string]any)["email"].(vcvalue.Sealed)
```

The reverse pair is `MarshalCipherText` (ciphertext tree to bytes, for the
decrypt call) and `Unmarshal` (guest response to a plaintext tree).

### A type that controls its own encoding

Implement `Encryptable` when reflection is not the encoding you want. The
`Encoder` writes exactly one value: one terminal channel, or one container
closed with `End`.

```go
type Money struct {
	Cents    int64
	Currency string
}

func (m Money) EncryptValue(enc vcffi.Encoder) error {
	mp := enc.Map()
	mp.Field("cents").Int64(m.Cents)
	// Currency is not a secret — mark it so it travels in the clear.
	mp.Field("currency").Passthrough().String(m.Currency)
	return mp.End()
}
```

Errors accumulate on the encoder, so writes chain without a check after each
one; `End` (or `Marshal`) surfaces the first failure. A zero-value
`vcffi.Encoder` is unusable — usable ones only ever arrive as the argument to
`EncryptValue` or from `Passthrough`, `Elem` and `Field`.

### A binding's own leaf types

A second binding defines its own sealed-leaf types and maps them onto the
framing, so its leaves can never be mistaken for another cipher's.

```go
type stackSealed []byte

var stackLeaves = vcffi.LeafSet{
	Classify: func(v any) (vcffi.LeafKind, []byte, bool) {
		if s, ok := v.(stackSealed); ok {
			return vcffi.LeafSingle, s, true
		}
		return 0, nil, false // not ours — the codec handles the rest
	},
	Make: func(kind vcffi.LeafKind, b []byte) any {
		if kind == vcffi.LeafSingle {
			return stackSealed(b)
		}
		return nil // an unwired kind is an error, never a nil node
	},
}
```

`Classify` is offered only non-structural values, so it cannot claim `[]any`,
`map[string]any` or `vcvalue.Plain`. A real binding covers all four kinds
(`LeafSingle`, `LeafNone`, `LeafEmptySeq`, `LeafEmptyMap`); returning nil for
a kind the wire carries fails the decode attributably rather than injecting an
untyped nil.
