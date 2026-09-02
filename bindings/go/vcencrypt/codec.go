package vcencrypt

import (
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
)

// The transport codec lives in the sibling vcffi module, shared with every
// binding that owns a wasm boundary, so the encoding can never fork per
// binding. This file re-exports the extension-point surface under the names
// this package has always had — aliases, so a type implementing
// vcencrypt.Encryptable IS a vcffi.Encryptable — and wires the codec's
// ciphertext leaves to the vcvalue types this binding materializes.

// Encryptable is the extension point for user types: implement it to control
// how a type is sealed, the way a Rust type implements `Encrypt`. Alias of
// [vcffi.Encryptable].
type Encryptable = vcffi.Encryptable

// Encoder records a single value in transport form. Alias of [vcffi.Encoder].
type Encoder = vcffi.Encoder

// SeqEncoder records the elements of a sequence. Alias of [vcffi.SeqEncoder].
type SeqEncoder = vcffi.SeqEncoder

// MapEncoder records the entries of a map. Alias of [vcffi.MapEncoder].
type MapEncoder = vcffi.MapEncoder

// Encode records v into enc following encoding/json-style rules, consulting
// [Encryptable] first — see [vcffi.Encode]. It composes: an Encryptable can
// delegate a sub-value with vcencrypt.Encode(m.Field(k), x).
func Encode(enc Encoder, v any) error {
	return vcffi.Encode(enc, v)
}

// Plaintext value trees cross the boundary through vcffi.Marshal/Unmarshal
// directly — no wrapper, so there is exactly one spelling in this package.
// The ciphertext pair below earns its wrappers by binding the vcvalue leaves.

func marshalCipherText(v any) ([]byte, error) {
	return vcffi.MarshalCipherText(vcffi.VCValueLeaves(), v)
}

func unmarshalCipherText(buf []byte) (any, error) {
	return vcffi.UnmarshalCipherText(vcffi.VCValueLeaves(), buf)
}
