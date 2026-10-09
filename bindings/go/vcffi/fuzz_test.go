package vcffi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Unmarshal and UnmarshalCipherText are the package's entire hostile-input
// surface: arbitrary bytes from the wasm boundary or a database column. The
// fuzz targets assert the decoders never panic, and that anything they accept
// re-encodes to the same bytes (see requireCanonical) — errors are fine,
// crashes and drift are not. Run in CI as ordinary tests over the seed corpus,
// nightly as real fuzzing (.github/workflows/fuzz.yml), and with
// `go test -fuzz` locally for exploration.

// addCorpusSeeds seeds a fuzz target with every valid and malformed vector in
// the shared value corpus, so the fuzzer starts from each scalar tag.
func addCorpusSeeds(f *testing.F, wrap func([]byte) []byte) {
	data, err := os.ReadFile("../../../testdata/value-conformance.json")
	if err != nil {
		f.Fatal(err)
	}
	var corpus struct{ Vectors, Malformed []struct{ Transport string } }
	if err := json.Unmarshal(data, &corpus); err != nil {
		f.Fatal(err)
	}
	for _, row := range append(corpus.Vectors, corpus.Malformed...) {
		raw, err := hex.DecodeString(row.Transport)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(wrap(raw))
	}
}

// requireCanonical fails unless out re-encodes data exactly. The one allowed
// difference is Go's documented projection of Undefined to nil: both are
// one-byte tags, so a lossless re-encode keeps the length and may differ
// only where an Undefined tag (0x01) became Null (0x00).
func requireCanonical(t *testing.T, data, out []byte) {
	t.Helper()
	if len(out) != len(data) {
		t.Fatalf("accepted %x re-encoded with a different length: %x", data, out)
	}
	for i := range data {
		if data[i] != out[i] && (data[i] != 0x01 || out[i] != 0x00) {
			t.Fatalf("accepted %x re-encoded differently at byte %d: %x", data, i, out)
		}
	}
}

func FuzzUnmarshal(f *testing.F) {
	// Seeds: one of each node kind, plus known-hostile shapes.
	f.Add([]byte{0x00})                                    // Null
	f.Add([]byte{0x04, 7, 0, 0, 0})                        // Int32
	f.Add([]byte{0x0A, 2, 0, 0, 0, 'h', 'i'})              // String
	f.Add([]byte{0xF0, 1, 0, 0, 0, 0x03})                  // Array[true]
	f.Add([]byte{0xF1, 1, 0, 0, 0, 1, 0, 0, 0, 'a', 0x00}) // Object{a: null}
	f.Add([]byte{0xF2, 0x05})                              // Passthrough(Int64) truncated
	f.Add([]byte{0xF0, 0xFF, 0xFF, 0xFF, 0xFF})            // hostile count
	f.Add([]byte{0xF1, 2, 0, 0, 0, 1, 0, 0, 0, 'a', 0x00}) // short object
	addCorpusSeeds(f, func(raw []byte) []byte { return raw })
	// Extended scalars nested in containers and passthrough.
	addCorpusSeeds(f, func(raw []byte) []byte { return append([]byte{0xF0, 1, 0, 0, 0}, raw...) })
	addCorpusSeeds(f, func(raw []byte) []byte { return append([]byte{0xF2}, raw...) })

	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := Unmarshal(data)
		if err != nil {
			return
		}
		out, err := Marshal(v)
		if err != nil {
			t.Fatalf("accepted decode failed to re-encode: %v (value %#v)", err, v)
		}
		requireCanonical(t, data, out)
		// The re-encoding holds no Undefined, so it must be a fixed point.
		again, err := Unmarshal(out)
		if err != nil {
			t.Fatalf("re-encoding %x does not decode: %v", out, err)
		}
		if twice, err := Marshal(again); err != nil || !bytes.Equal(twice, out) {
			t.Fatalf("re-encoding %x is not stable: %x (%v)", out, twice, err)
		}
	})
}

func FuzzUnmarshalCipherText(f *testing.F) {
	f.Add([]byte{0x01, 1, 0, 0, 0, 0xAB})                                    // ctSingle leaf
	f.Add([]byte{0x02, 1, 0, 0, 0, 0xAB})                                    // ctNone
	f.Add([]byte{0x03, 1, 0, 0, 0, 0x01, 1, 0, 0, 0, 0xAB})                  // ctSeq[leaf]
	f.Add([]byte{0x04, 1, 0, 0, 0, 1, 0, 0, 0, 'a', 0x01, 1, 0, 0, 0, 0xAB}) // ctMap{a: leaf}
	f.Add([]byte{0x06, 1, 0, 0, 0, 0xAB})                                    // ctEmptySeq
	f.Add([]byte{0x07, 1, 0, 0, 0, 0xAB})                                    // ctEmptyMap
	f.Add([]byte{0x05, 0x00})                                                // ctPassthrough(Null)
	f.Add([]byte{0x03, 0xFF, 0xFF, 0xFF, 0xFF})                              // hostile count
	// Extended scalars as clear passthrough nodes inside a ciphertext.
	addCorpusSeeds(f, func(raw []byte) []byte { return append([]byte{0x05}, raw...) })

	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := UnmarshalCipherText(VCValueLeaves(), data)
		if err != nil {
			return
		}
		out, err := MarshalCipherText(VCValueLeaves(), v)
		if err != nil {
			t.Fatalf("accepted ciphertext decode failed to re-encode: %v (value %#v)", err, v)
		}
		requireCanonical(t, data, out)
	})
}
