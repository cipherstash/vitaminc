package vitaminc_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"reflect"
	"testing"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
	"github.com/cipherstash/vitaminc/bindings/go/vitaminc"
)

var testKey = bytes.Repeat([]byte{7}, vitaminc.KeySize)

func newTestClient(t *testing.T) *vitaminc.Client {
	t.Helper()
	client, err := vitaminc.NewClient(t.Context())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	return client
}

// record is a struct exercising the reflection encode path: field names
// become map keys (in declaration order), and each Go type maps to a leaf.
type record struct {
	Name   string
	Age    int64
	Score  float64
	Active bool
	Huge   uint64 // above int64: forces the UInt64 channel
	Tags   []string
	Blob   []byte
}

func sampleRecord() record {
	return record{
		Name:   "Ada",
		Age:    36,
		Score:  1.5,
		Active: true,
		Huge:   math.MaxUint64,
		Tags:   []string{"math", "engines"},
		Blob:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
}

// wantRecord is the decode shape of sampleRecord: an ordered Object of Go
// natives (Int→int64, Number→float64, UInt→uint64, Bytes→[]byte, Seq→[]any).
func wantRecord() vcvalue.Object {
	return vcvalue.Object{
		{Key: "Name", Value: "Ada"},
		{Key: "Age", Value: int64(36)},
		{Key: "Score", Value: 1.5},
		{Key: "Active", Value: true},
		{Key: "Huge", Value: uint64(math.MaxUint64)},
		{Key: "Tags", Value: []any{"math", "engines"}},
		{Key: "Blob", Value: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
	}
}

func TestRoundTrip(t *testing.T) {
	client := newTestClient(t)
	aad := []byte("round-trip")

	ct, err := client.Encrypt(t.Context(), testKey, sampleRecord(), aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if ct.Kind != vcvalue.KindMap {
		t.Fatalf("expected map-mode ciphertext, got kind %#x", ct.Kind)
	}

	got, err := client.Decrypt(t.Context(), testKey, ct, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !reflect.DeepEqual(got, wantRecord()) {
		t.Fatalf("round trip mismatch:\n got %#v\nwant %#v", got, wantRecord())
	}
}

// person shows the Encryptable consumer UX: a user type controls its own
// sealing in a handful of lines, the Go analog of `impl Encrypt`.
type person struct {
	Name string
	Age  uint64
}

func (p person) EncryptValue(enc vcvalue.Encoder) error {
	m := enc.Map()
	m.Field("name").String(p.Name)
	m.Field("age").UInt64(p.Age)
	return m.End()
}

func TestEncryptableRoundTrip(t *testing.T) {
	client := newTestClient(t)

	ct, err := client.Encrypt(t.Context(), testKey, person{Name: "Ada", Age: 36}, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := client.Decrypt(t.Context(), testKey, ct, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	want := vcvalue.Object{
		{Key: "name", Value: "Ada"},
		{Key: "age", Value: uint64(36)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// Int64, Float64 and UInt64 must remain distinct across the boundary even
// when they denote the same magnitude — and UInt64 must carry values above
// int64.
func TestInt64Float64UInt64Distinction(t *testing.T) {
	client := newTestClient(t)

	value := []any{int64(42), float64(42), uint64(math.MaxUint64)}
	ct, err := client.Encrypt(t.Context(), testKey, value, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := client.Decrypt(t.Context(), testKey, ct, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	want := []any{int64(42), float64(42), uint64(math.MaxUint64)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// The 32- and 64-bit widths of a numeric value must be preserved across the
// boundary: Go maps exactly in both directions, so a value written as int32
// comes back int32, never widened to int64 (and likewise for the unsigned
// and float families).
func TestNumericWidthPreserved(t *testing.T) {
	client := newTestClient(t)

	value := []any{
		int32(-7), int64(-7),
		uint32(4000000000), uint64(4000000000),
		float32(0.5), float64(0.5),
	}
	ct, err := client.Encrypt(t.Context(), testKey, value, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := client.Decrypt(t.Context(), testKey, ct, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	want := []any{
		int32(-7), int64(-7),
		uint32(4000000000), uint64(4000000000),
		float32(0.5), float64(0.5),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestWrongKeyFails(t *testing.T) {
	client := newTestClient(t)

	ct, err := client.Encrypt(t.Context(), testKey, "secret", nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	wrongKey := bytes.Repeat([]byte{8}, vitaminc.KeySize)
	if _, err := client.Decrypt(t.Context(), wrongKey, ct, nil); !errors.Is(err, vitaminc.ErrUnspecified) {
		t.Fatalf("expected ErrUnspecified, got %v", err)
	}
}

func TestAadMismatchFails(t *testing.T) {
	client := newTestClient(t)

	ct, err := client.Encrypt(t.Context(), testKey, "secret", []byte("right"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := client.Decrypt(t.Context(), testKey, ct, []byte("wrong")); !errors.Is(err, vitaminc.ErrUnspecified) {
		t.Fatalf("expected ErrUnspecified, got %v", err)
	}
}

func TestTamperedLeafFails(t *testing.T) {
	client := newTestClient(t)

	ct, err := client.Encrypt(t.Context(), testKey, "secret", nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct.Leaf[len(ct.Leaf)/2] ^= 0x01
	if _, err := client.Decrypt(t.Context(), testKey, ct, nil); !errors.Is(err, vitaminc.ErrUnspecified) {
		t.Fatalf("expected ErrUnspecified, got %v", err)
	}
}

// Map keys travel in the clear but are bound into each value's AAD: renaming
// or swapping them must fail decryption.
func TestMapKeyRenameFails(t *testing.T) {
	client := newTestClient(t)

	ct, err := client.Encrypt(t.Context(), testKey, map[string]int64{
		"salary": 100,
		"bonus":  5,
	}, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(ct.Fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(ct.Fields))
	}

	renamed := ct
	renamed.Fields = append([]vcvalue.CipherTextField(nil), ct.Fields...)
	renamed.Fields[0].Key = "renamed"
	if _, err := client.Decrypt(t.Context(), testKey, renamed, nil); !errors.Is(err, vitaminc.ErrUnspecified) {
		t.Fatalf("expected rename to fail, got %v", err)
	}

	swapped := ct
	swapped.Fields = []vcvalue.CipherTextField{
		{Key: ct.Fields[1].Key, Node: ct.Fields[0].Node},
		{Key: ct.Fields[0].Key, Node: ct.Fields[1].Node},
	}
	if _, err := client.Decrypt(t.Context(), testKey, swapped, nil); !errors.Is(err, vitaminc.ErrUnspecified) {
		t.Fatalf("expected swap to fail, got %v", err)
	}
}

// Reordering map entries WITHOUT reassigning values is legitimate (order is
// not authenticated; the key↔value binding is).
func TestMapReorderSucceeds(t *testing.T) {
	client := newTestClient(t)

	// Keys sort deterministically on encode, so Fields is [a, b].
	ct, err := client.Encrypt(t.Context(), testKey, map[string]int64{
		"a": 1,
		"b": 2,
	}, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct.Fields[0], ct.Fields[1] = ct.Fields[1], ct.Fields[0]

	got, err := client.Decrypt(t.Context(), testKey, ct, nil)
	if err != nil {
		t.Fatalf("Decrypt after reorder: %v", err)
	}
	want := vcvalue.Object{{Key: "b", Value: int64(2)}, {Key: "a", Value: int64(1)}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// TestCrossLanguageFixture decrypts a ciphertext produced by NATIVE Rust
// (aws-lc-rs backend, see guest/examples/gen_fixture.rs) through the wasm
// guest (RustCrypto backend): the true cross-language, cross-backend vector
// test. The fixture exercises the whole numeric family across languages —
// a UInt64(u64::MAX) field plus edge-value Int32/UInt32/Float32 fields —
// proving Go's exact-width decode against native Rust's encoding.
func TestCrossLanguageFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/cross_lang.bin")
	if err != nil {
		t.Fatalf("reading fixture (regenerate with `cargo run --example gen_fixture` in guest/): %v", err)
	}

	const magic = "VCGO1"
	if len(raw) < len(magic)+vitaminc.KeySize || string(raw[:len(magic)]) != magic {
		t.Fatal("fixture is malformed")
	}
	raw = raw[len(magic):]
	key := raw[:vitaminc.KeySize]
	raw = raw[vitaminc.KeySize:]

	chunk := func() []byte {
		if len(raw) < 4 {
			t.Fatal("fixture is truncated")
		}
		n := binary.LittleEndian.Uint32(raw)
		raw = raw[4:]
		if uint32(len(raw)) < n {
			t.Fatal("fixture is truncated")
		}
		c := raw[:n]
		raw = raw[n:]
		return c
	}
	aad, ctBytes, valBytes := chunk(), chunk(), chunk()

	ct, err := vcvalue.UnmarshalCipherText(ctBytes)
	if err != nil {
		t.Fatalf("decoding fixture ciphertext: %v", err)
	}
	want, err := vcvalue.Unmarshal(valBytes)
	if err != nil {
		t.Fatalf("decoding fixture expected value: %v", err)
	}

	client := newTestClient(t)
	got, err := client.Decrypt(t.Context(), key, ct, aad)
	if err != nil {
		t.Fatalf("Decrypt(fixture): %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cross-language mismatch:\n got %#v\nwant %#v", got, want)
	}
}

func TestConcurrentUse(t *testing.T) {
	client := newTestClient(t)
	done := make(chan error, 8)
	for i := range 8 {
		go func(i int) {
			value := map[string]int64{"n": int64(i)}
			ct, err := client.Encrypt(context.Background(), testKey, value, nil)
			if err == nil {
				var got any
				got, err = client.Decrypt(context.Background(), testKey, ct, nil)
				want := vcvalue.Object{{Key: "n", Value: int64(i)}}
				if err == nil && !reflect.DeepEqual(got, want) {
					err = errors.New("mismatch")
				}
			}
			done <- err
		}(i)
	}
	for range 8 {
		if err := <-done; err != nil {
			t.Fatalf("concurrent use: %v", err)
		}
	}
}

func TestShortKeyRejected(t *testing.T) {
	client := newTestClient(t)
	if _, err := client.Encrypt(t.Context(), []byte("short"), nil, nil); err == nil {
		t.Fatal("expected short key to be rejected")
	}
}
