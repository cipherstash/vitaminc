// The demonstration binding of the vitaminc-encrypt crate: a wazero host
// running the Rust AEAD stack as a wasm32-wasip1 guest. Depends on the
// durable vcvalue module and the shared vcffi transport codec via local
// replace directives (all three live in this repo; none is published), so
// `go test ./...` resolves them without a go.work file.
module github.com/cipherstash/vitaminc/bindings/go/vcencrypt

go 1.25.0

require (
	github.com/cipherstash/vitaminc/bindings/go/vcffi v0.0.0-00010101000000-000000000000
	github.com/cipherstash/vitaminc/bindings/go/vcvalue v0.0.0-00010101000000-000000000000
	github.com/tetratelabs/wazero v1.12.0
)

require golang.org/x/sys v0.44.0 // indirect

replace github.com/cipherstash/vitaminc/bindings/go/vcffi => ../vcffi

replace github.com/cipherstash/vitaminc/bindings/go/vcvalue => ../vcvalue
