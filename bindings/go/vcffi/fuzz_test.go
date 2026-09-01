package vcffi

import (
	"testing"
)

// Unmarshal and UnmarshalCipherText are the package's entire hostile-input
// surface: arbitrary bytes from the wasm boundary or a database column. The
// fuzz targets assert the decoders never panic, and that anything they accept
// re-encodes without panicking — errors are fine, crashes are not. Run in CI
// as ordinary tests over the seed corpus; run `go test -fuzz` locally for
// exploration.

func FuzzUnmarshal(f *testing.F) {
	// Seeds: one of each node kind, plus known-hostile shapes.
	f.Add([]byte{0x00})                                    // Null
	f.Add([]byte{0x04, 7, 0, 0, 0})                        // Int32
	f.Add([]byte{0x0A, 2, 0, 0, 0, 'h', 'i'})              // String
	f.Add([]byte{0x10, 1, 0, 0, 0, 0x03})                  // Array[true]
	f.Add([]byte{0x11, 1, 0, 0, 0, 1, 0, 0, 0, 'a', 0x00}) // Object{a: null}
	f.Add([]byte{0x12, 0x05})                              // Passthrough(Int64) truncated
	f.Add([]byte{0x10, 0xFF, 0xFF, 0xFF, 0xFF})            // hostile count
	f.Add([]byte{0x11, 2, 0, 0, 0, 1, 0, 0, 0, 'a', 0x00}) // short object

	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := Unmarshal(data)
		if err != nil {
			return
		}
		if _, err := Marshal(v); err != nil {
			t.Fatalf("accepted decode failed to re-encode: %v (value %#v)", err, v)
		}
	})
}

func FuzzUnmarshalCipherText(f *testing.F) {
	f.Add([]byte{0x01, 1, 0, 0, 0, 0xAB})                                    // ctSingle leaf
	f.Add([]byte{0x02, 1, 0, 0, 0, 0xAB})                                    // ctNone
	f.Add([]byte{0x03, 1, 0, 0, 0, 0x01, 1, 0, 0, 0, 0xAB})                  // ctSeq[leaf]
	f.Add([]byte{0x04, 1, 0, 0, 0, 1, 0, 0, 0, 'a', 0x01, 1, 0, 0, 0, 0xAB}) // ctMap{a: leaf}
	f.Add([]byte{0x05, 0x00})                                                // ctPassthrough(Null)
	f.Add([]byte{0x03, 0xFF, 0xFF, 0xFF, 0xFF})                              // hostile count

	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := UnmarshalCipherText(VCValueLeaves(), data)
		if err != nil {
			return
		}
		if _, err := MarshalCipherText(VCValueLeaves(), v); err != nil {
			t.Fatalf("accepted ciphertext decode failed to re-encode: %v (value %#v)", err, v)
		}
	})
}
