package vcffi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
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

// requireCanonical fails unless out re-encodes data exactly, apart from Go's
// documented projection of Undefined to nil: each offset in undefinedAt is an
// Undefined tag (0x01) that must come back as Null (0x00). Every other byte,
// including a 0x01 inside a payload, must be unchanged.
func requireCanonical(t *testing.T, data, out []byte, undefinedAt []int) {
	t.Helper()
	want := bytes.Clone(data)
	for _, at := range undefinedAt {
		want[at] = tagNull
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("accepted %x re-encoded as %x, want %x", data, out, want)
	}
}

// valueUndefinedTags returns the offset of every Undefined value-node tag in
// an accepted value tree, nested ones included. It walks the transport format
// independently of the decoder, so a walk that falls out of step with it
// reports the wrong offsets and fails requireCanonical rather than passing.
func valueUndefinedTags(data []byte) []int {
	r := &reader{buf: data}
	var at []int
	walkValue(r, &at)
	return at
}

func walkValue(r *reader, at *[]int) {
	pos := r.pos
	tag, _ := r.byteTag()
	switch tag {
	case tagUndefined:
		*at = append(*at, pos)
	case tagInt32, tagUint32, tagFloat32:
		_, _ = r.take(4)
	case tagInt64, tagUint64, tagFloat64:
		_, _ = r.take(8)
	case tagString, tagBytes:
		n, _ := r.count()
		_, _ = r.take(n)
	case tagArray:
		n, _ := r.count()
		for range n {
			walkValue(r, at)
		}
	case tagObject:
		n, _ := r.count()
		for range n {
			_, _ = r.str()
			walkValue(r, at)
		}
	case tagPassthrough:
		walkValue(r, at)
	default:
		// Null, booleans and the fixed-width extended scalars.
		_, _ = r.take(scalarWidth(tag))
	}
}

// cipherUndefinedTags is valueUndefinedTags for an accepted ciphertext tree,
// where Undefined can only appear inside passthrough nodes.
func cipherUndefinedTags(data []byte) []int {
	r := &reader{buf: data}
	var at []int
	var walk func()
	walk = func() {
		tag, _ := r.byteTag()
		if _, ok := leafKind(tag); ok {
			n, _ := r.count()
			_, _ = r.take(n)
			return
		}
		switch tag {
		case ctSeq:
			n, _ := r.count()
			for range n {
				walk()
			}
		case ctMap:
			n, _ := r.count()
			for range n {
				_, _ = r.str()
				walk()
			}
		case ctPassthrough:
			walkValue(r, &at)
		}
	}
	walk()
	return at
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
		requireCanonical(t, data, out, valueUndefinedTags(data))
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
		requireCanonical(t, data, out, cipherUndefinedTags(data))
	})
}

// The walkers decide which bytes may legitimately change, so pin that they
// find nested Undefined tags and nothing else.
func TestUndefinedTagWalkers(t *testing.T) {
	for _, tc := range []struct {
		name string
		walk func([]byte) []int
		data []byte
		want []int
	}{
		{"bare", valueUndefinedTags, []byte{0x01}, []int{0}},
		{"bytes payload of 0x01", valueUndefinedTags, []byte{0x0B, 1, 0, 0, 0, 0x01}, nil},
		{"array", valueUndefinedTags, []byte{0xF0, 2, 0, 0, 0, 0x0B, 1, 0, 0, 0, 0x01, 0x01}, []int{11}},
		{"object", valueUndefinedTags, []byte{0xF1, 1, 0, 0, 0, 1, 0, 0, 0, 0x01, 0x01}, []int{10}},
		{"passthrough", valueUndefinedTags, []byte{0xF2, 0x01}, []int{1}},
		{"extended scalar", valueUndefinedTags, []byte{0xF0, 2, 0, 0, 0, 0x0D, 0x01, 0x01}, []int{7}},
		{"sealed leaf of 0x01", cipherUndefinedTags, []byte{0x01, 1, 0, 0, 0, 0x01}, nil},
		{"ciphertext passthrough", cipherUndefinedTags, []byte{0x03, 1, 0, 0, 0, 0x05, 0xF0, 1, 0, 0, 0, 0x01}, []int{11}},
	} {
		if got := tc.walk(tc.data); !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
