// The demonstration binding of the vitaminc-encrypt crate: a wazero host
// running the Rust AEAD stack as a wasm32-wasip1 guest. Depends on the
// durable vcvalue module via a local replace directive (both live in this
// repo; neither is published), so `go test ./...` resolves it without a
// go.work file.
module github.com/cipherstash/vitaminc/bindings/go/vcencrypt

go 1.25.0

require (
	github.com/cipherstash/vitaminc/bindings/go/vcvalue v0.0.0-00010101000000-000000000000
	github.com/tetratelabs/wazero v1.12.0
)

require golang.org/x/sys v0.44.0 // indirect

replace github.com/cipherstash/vitaminc/bindings/go/vcvalue => ../vcvalue
