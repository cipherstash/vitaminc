// The durable value layer: the value model application code holds and
// stores, with ZERO dependencies (no wazero, no crypto, no wire format —
// the transport codec lives in the sibling vcffi module). A future
// stack-encrypt Go SDK is expected to import this module directly.
module github.com/cipherstash/vitaminc/bindings/go/vcvalue

go 1.23
