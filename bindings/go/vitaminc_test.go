package vitaminc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"reflect"
	"testing"
)

var testKey = bytes.Repeat([]byte{7}, KeySize)

func newTestClient(t *testing.T) *Client {
	t.Helper()
	client, err := NewClient(t.Context())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	return client
}

func sampleValue() Value {
	return Object{
		{"name", String("Ada")},
		{"age", Int(36)},
		{"score", Number(1.5)},
		{"active", Bool(true)},
		{"nothing", Null{}},
		{"tags", Array{String("a"), Bytes{1, 2, 3}, Undefined{}}},
		{"nested", Object{{"deep", Array{Int(-1), Number(0.0)}}}},
	}
}

func TestRoundTrip(t *testing.T) {
	client := newTestClient(t)
	aad := []byte("round-trip")

	ct, err := client.Encrypt(t.Context(), testKey, sampleValue(), aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if ct.Kind != KindMap {
		t.Fatalf("expected map-mode ciphertext, got kind %#x", ct.Kind)
	}

	got, err := client.Decrypt(t.Context(), testKey, ct, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !reflect.DeepEqual(got, sampleValue()) {
		t.Fatalf("round trip mismatch:\n got %#v\nwant %#v", got, sampleValue())
	}
}

// Int and Number must remain distinct types across the boundary even when
// they denote the same mathematical value.
func TestIntNumberDistinction(t *testing.T) {
	client := newTestClient(t)

	ct, err := client.Encrypt(t.Context(), testKey, Array{Int(42), Number(42)}, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := client.Decrypt(t.Context(), testKey, ct, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	want := Array{Int(42), Number(42)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestWrongKeyFails(t *testing.T) {
	client := newTestClient(t)

	ct, err := client.Encrypt(t.Context(), testKey, String("secret"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	wrongKey := bytes.Repeat([]byte{8}, KeySize)
	if _, err := client.Decrypt(t.Context(), wrongKey, ct, nil); !errors.Is(err, ErrUnspecified) {
		t.Fatalf("expected ErrUnspecified, got %v", err)
	}
}

func TestAadMismatchFails(t *testing.T) {
	client := newTestClient(t)

	ct, err := client.Encrypt(t.Context(), testKey, String("secret"), []byte("right"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := client.Decrypt(t.Context(), testKey, ct, []byte("wrong")); !errors.Is(err, ErrUnspecified) {
		t.Fatalf("expected ErrUnspecified, got %v", err)
	}
}

func TestTamperedLeafFails(t *testing.T) {
	client := newTestClient(t)

	ct, err := client.Encrypt(t.Context(), testKey, String("secret"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct.Leaf[len(ct.Leaf)/2] ^= 0x01
	if _, err := client.Decrypt(t.Context(), testKey, ct, nil); !errors.Is(err, ErrUnspecified) {
		t.Fatalf("expected ErrUnspecified, got %v", err)
	}
}

// Map keys travel in the clear but are bound into each value's AAD:
// renaming or swapping them must fail decryption.
func TestMapKeyRenameFails(t *testing.T) {
	client := newTestClient(t)

	ct, err := client.Encrypt(t.Context(), testKey, Object{
		{"salary", Int(100)},
		{"bonus", Int(5)},
	}, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	renamed := ct
	renamed.Fields = append([]CipherTextField(nil), ct.Fields...)
	renamed.Fields[0].Key = "bonus2"
	if _, err := client.Decrypt(t.Context(), testKey, renamed, nil); !errors.Is(err, ErrUnspecified) {
		t.Fatalf("expected rename to fail, got %v", err)
	}

	swapped := ct
	swapped.Fields = []CipherTextField{
		{Key: ct.Fields[1].Key, Node: ct.Fields[0].Node},
		{Key: ct.Fields[0].Key, Node: ct.Fields[1].Node},
	}
	if _, err := client.Decrypt(t.Context(), testKey, swapped, nil); !errors.Is(err, ErrUnspecified) {
		t.Fatalf("expected swap to fail, got %v", err)
	}
}

// Reordering map entries WITHOUT reassigning values is legitimate (order
// is not authenticated; the key↔value binding is).
func TestMapReorderSucceeds(t *testing.T) {
	client := newTestClient(t)

	ct, err := client.Encrypt(t.Context(), testKey, Object{
		{"a", Int(1)},
		{"b", Int(2)},
	}, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct.Fields[0], ct.Fields[1] = ct.Fields[1], ct.Fields[0]

	got, err := client.Decrypt(t.Context(), testKey, ct, nil)
	if err != nil {
		t.Fatalf("Decrypt after reorder: %v", err)
	}
	want := Object{{"b", Int(2)}, {"a", Int(1)}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// TestCrossLanguageFixture decrypts a ciphertext produced by NATIVE Rust
// (aws-lc-rs backend, see guest/examples/gen_fixture.rs) through the wasm
// guest (RustCrypto backend): the true cross-language, cross-backend
// vector test.
func TestCrossLanguageFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/cross_lang.bin")
	if err != nil {
		t.Fatalf("reading fixture (regenerate with `cargo run --example gen_fixture` in guest/): %v", err)
	}

	const magic = "VCGO1"
	if len(raw) < len(magic)+KeySize || string(raw[:len(magic)]) != magic {
		t.Fatal("fixture is malformed")
	}
	raw = raw[len(magic):]
	key := raw[:KeySize]
	raw = raw[KeySize:]

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

	r := &reader{buf: ctBytes}
	ct, err := decodeCipherText(r, 0)
	if err != nil || !r.finished() {
		t.Fatalf("decoding fixture ciphertext: %v", err)
	}
	r = &reader{buf: valBytes}
	want, err := decodeValue(r, 0)
	if err != nil || !r.finished() {
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
			value := Object{{"n", Int(int64(i))}}
			ct, err := client.Encrypt(context.Background(), testKey, value, nil)
			if err == nil {
				var got Value
				got, err = client.Decrypt(context.Background(), testKey, ct, nil)
				if err == nil && !reflect.DeepEqual(got, value) {
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
	if _, err := client.Encrypt(t.Context(), []byte("short"), Null{}, nil); err == nil {
		t.Fatal("expected short key to be rejected")
	}
}
