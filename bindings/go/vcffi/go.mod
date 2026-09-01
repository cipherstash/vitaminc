// The shared FFI transport codec: the wire encoding that carries value and
// ciphertext trees across a wasm boundary, plus the Encryptable/Encoder
// extension point. One codec, consumed by every binding that owns such a
// boundary (vcencrypt here; the stack-encrypt Go SDK elsewhere) — the
// encoding must never be forked per binding. Depends only on the sibling
// vcvalue module via a local replace directive (both live in this repo;
// neither is published), so `go test ./...` resolves it without a go.work
// file. NOT a storage format: see doc.go.
module github.com/cipherstash/vitaminc/bindings/go/vcffi

go 1.23

require github.com/cipherstash/vitaminc/bindings/go/vcvalue v0.0.0-00010101000000-000000000000

replace github.com/cipherstash/vitaminc/bindings/go/vcvalue => ../vcvalue
