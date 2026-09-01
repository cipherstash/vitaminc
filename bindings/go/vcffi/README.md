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

## Hostile input

`Unmarshal` and `UnmarshalCipherText` treat their input as untrusted:
recursion depth, length prefixes and item counts are bounded, strings are
UTF-8 validated, duplicate map keys are rejected, and every malformed shape
fails with `ErrMalformed` rather than panicking or over-allocating. The fuzz
targets in this package pin that contract, and CI runs the whole suite on
32-bit GOARCH, where the u32-bound guards are load-bearing.
