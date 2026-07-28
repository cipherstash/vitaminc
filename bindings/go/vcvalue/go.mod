// The durable value layer: value model + transport codec + ciphertext
// projection, with ZERO dependencies (no wazero, no crypto). A future
// stack-encrypt Go SDK is expected to import this module directly.
module github.com/cipherstash/vitaminc/bindings/go/vcvalue

go 1.26.5
