package vcencrypt_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"reflect"
	"testing"

	"github.com/cipherstash/vitaminc/bindings/go/vcencrypt"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

var testKey = bytes.Repeat([]byte{7}, vcencrypt.KeySize)

func newClient(t *testing.T) *vcencrypt.Client {
	t.Helper()
	client, err := vcencrypt.NewClient(t.Context())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	return client
}

// newCipher returns a cipher bound to testKey, cleaned up with the test.
func newCipher(t *testing.T) *vcencrypt.Cipher {
	t.Helper()
	cipher, err := newClient(t).NewCipher(t.Context(), testKey)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	t.Cleanup(func() { _ = cipher.Close(context.Background()) })
	return cipher
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
	cipher := newCipher(t)
	aad := []byte("round-trip")

	ct, err := cipher.Encrypt(t.Context(), sampleRecord(), aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if ct.Kind != vcvalue.KindMap {
		t.Fatalf("expected map-mode ciphertext, got kind %#x", ct.Kind)
	}

	got, err := cipher.Decrypt(t.Context(), ct, aad)
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
	cipher := newCipher(t)

	ct, err := cipher.Encrypt(t.Context(), person{Name: "Ada", Age: 36}, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := cipher.Decrypt(t.Context(), ct, nil)
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

// TestPassthroughRoundTrip: a Plain-marked field travels in the clear. It is
// readable in the ciphertext WITHOUT decrypting, and it round-trips as Plain.
func TestPassthroughRoundTrip(t *testing.T) {
	cipher := newCipher(t)
	aad := []byte("user:42")

	value := map[string]any{
		"id":    vcvalue.Plain{V: int64(42)},
		"email": "ada@example.com",
	}
	ct, err := cipher.Encrypt(t.Context(), value, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// The passthrough field is readable straight from the ciphertext — no key,
	// no Decrypt call.
	var idField *vcvalue.CipherTextField
	for i := range ct.Fields {
		if ct.Fields[i].Key == "id" {
			idField = &ct.Fields[i]
		}
	}
	if idField == nil || idField.Node.Kind != vcvalue.KindPassthrough {
		t.Fatalf("expected id to be a passthrough node, got %#v", ct.Fields)
	}
	if idField.Node.Passthrough != int64(42) {
		t.Fatalf("passthrough value = %#v, want int64(42)", idField.Node.Passthrough)
	}

	got, err := cipher.Decrypt(t.Context(), ct, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	// Keys sort on encode: email, id.
	want := vcvalue.Object{
		{Key: "email", Value: "ada@example.com"},
		{Key: "id", Value: vcvalue.Plain{V: int64(42)}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// A modified passthrough value is NOT detected (passthrough is unauthenticated)
// while its sealed sibling still authenticates.
func TestPassthroughIsUnauthenticated(t *testing.T) {
	cipher := newCipher(t)
	value := map[string]any{
		"id":    vcvalue.Plain{V: int64(42)},
		"email": "ada@example.com",
	}
	ct, err := cipher.Encrypt(t.Context(), value, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// Forge the passthrough value in place — no key needed.
	for i := range ct.Fields {
		if ct.Fields[i].Key == "id" {
			ct.Fields[i].Node.Passthrough = int64(999)
		}
	}
	got, err := cipher.Decrypt(t.Context(), ct, nil)
	if err != nil {
		t.Fatalf("Decrypt after forging passthrough: %v", err)
	}
	want := vcvalue.Object{
		{Key: "email", Value: "ada@example.com"},
		{Key: "id", Value: vcvalue.Plain{V: int64(999)}}, // forged value accepted
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestInt64Float64UInt64Distinction(t *testing.T) {
	cipher := newCipher(t)

	value := []any{int64(42), float64(42), uint64(math.MaxUint64)}
	ct, err := cipher.Encrypt(t.Context(), value, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := cipher.Decrypt(t.Context(), ct, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	want := []any{int64(42), float64(42), uint64(math.MaxUint64)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestNumericWidthPreserved(t *testing.T) {
	cipher := newCipher(t)

	value := []any{
		int32(-7), int64(-7),
		uint32(4000000000), uint64(4000000000),
		float32(0.5), float64(0.5),
	}
	ct, err := cipher.Encrypt(t.Context(), value, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := cipher.Decrypt(t.Context(), ct, nil)
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

// --- Error surface: distinguishable failure kinds ---

func TestWrongKeyGivesAuthenticationError(t *testing.T) {
	client := newClient(t)
	cipher, err := client.NewCipher(t.Context(), testKey)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	defer func() { _ = cipher.Close(context.Background()) }()

	ct, err := cipher.Encrypt(t.Context(), "secret", nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	wrong, err := client.NewCipher(t.Context(), bytes.Repeat([]byte{8}, vcencrypt.KeySize))
	if err != nil {
		t.Fatalf("NewCipher(wrong): %v", err)
	}
	defer func() { _ = wrong.Close(context.Background()) }()

	if _, err := wrong.Decrypt(t.Context(), ct, nil); !errors.Is(err, vcencrypt.ErrAuthentication) {
		t.Fatalf("expected ErrAuthentication, got %v", err)
	}
}

func TestAadMismatchGivesAuthenticationError(t *testing.T) {
	cipher := newCipher(t)

	ct, err := cipher.Encrypt(t.Context(), "secret", []byte("right"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := cipher.Decrypt(t.Context(), ct, []byte("wrong")); !errors.Is(err, vcencrypt.ErrAuthentication) {
		t.Fatalf("expected ErrAuthentication, got %v", err)
	}
}

func TestTamperedLeafGivesAuthenticationError(t *testing.T) {
	cipher := newCipher(t)

	ct, err := cipher.Encrypt(t.Context(), "secret", nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct.Leaf[len(ct.Leaf)/2] ^= 0x01
	if _, err := cipher.Decrypt(t.Context(), ct, nil); !errors.Is(err, vcencrypt.ErrAuthentication) {
		t.Fatalf("expected ErrAuthentication, got %v", err)
	}
}

// Garbage transport bytes (a ciphertext map key that is not valid UTF-8) are
// rejected by the guest's decoder as ErrEncoding, distinct from an auth error.
func TestGarbageTransportGivesEncodingError(t *testing.T) {
	cipher := newCipher(t)

	ct := vcvalue.CipherText{
		Kind: vcvalue.KindMap,
		Fields: []vcvalue.CipherTextField{
			{
				Key:  string([]byte{0xff}), // invalid UTF-8 key
				Node: vcvalue.CipherText{Kind: vcvalue.KindSingle, Leaf: []byte{1, 2, 3}},
			},
		},
	}
	if _, err := cipher.Decrypt(t.Context(), ct, nil); !errors.Is(err, vcencrypt.ErrEncoding) {
		t.Fatalf("expected ErrEncoding, got %v", err)
	}
}

// A cipher used after Close reports ErrBadHandle.
func TestFreedHandleGivesBadHandleError(t *testing.T) {
	client := newClient(t)
	cipher, err := client.NewCipher(t.Context(), testKey)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	if err := cipher.Close(t.Context()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := cipher.Encrypt(t.Context(), "x", nil); !errors.Is(err, vcencrypt.ErrBadHandle) {
		t.Fatalf("expected ErrBadHandle, got %v", err)
	}
}

// Map keys travel in the clear but are bound into each value's AAD: renaming
// or swapping them must fail decryption.
func TestMapKeyRenameFails(t *testing.T) {
	cipher := newCipher(t)

	ct, err := cipher.Encrypt(t.Context(), map[string]int64{
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
	if _, err := cipher.Decrypt(t.Context(), renamed, nil); !errors.Is(err, vcencrypt.ErrAuthentication) {
		t.Fatalf("expected rename to fail with ErrAuthentication, got %v", err)
	}

	swapped := ct
	swapped.Fields = []vcvalue.CipherTextField{
		{Key: ct.Fields[1].Key, Node: ct.Fields[0].Node},
		{Key: ct.Fields[0].Key, Node: ct.Fields[1].Node},
	}
	if _, err := cipher.Decrypt(t.Context(), swapped, nil); !errors.Is(err, vcencrypt.ErrAuthentication) {
		t.Fatalf("expected swap to fail with ErrAuthentication, got %v", err)
	}
}

// Reordering map entries WITHOUT reassigning values is legitimate.
func TestMapReorderSucceeds(t *testing.T) {
	cipher := newCipher(t)

	ct, err := cipher.Encrypt(t.Context(), map[string]int64{"a": 1, "b": 2}, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct.Fields[0], ct.Fields[1] = ct.Fields[1], ct.Fields[0]

	got, err := cipher.Decrypt(t.Context(), ct, nil)
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
// guest (RustCrypto backend): the cross-language, cross-backend vector test.
// The fixture now also carries passthrough fields (id, created_at) — they must
// arrive intact and be readable from the ciphertext WITHOUT the key path.
func TestCrossLanguageFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/cross_lang.bin")
	if err != nil {
		t.Fatalf("reading fixture (regenerate with `cargo run --example gen_fixture` in guest/): %v", err)
	}

	const magic = "VCGO1"
	if len(raw) < len(magic)+vcencrypt.KeySize || string(raw[:len(magic)]) != magic {
		t.Fatal("fixture is malformed")
	}
	raw = raw[len(magic):]
	key := raw[:vcencrypt.KeySize]
	raw = raw[vcencrypt.KeySize:]

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

	// Prove the passthrough fields are readable straight from the native-Rust
	// ciphertext, without any decryption.
	fields := ct.Fields
	byKey := map[string]vcvalue.CipherText{}
	for _, f := range fields {
		byKey[f.Key] = f.Node
	}
	if n := byKey["id"]; n.Kind != vcvalue.KindPassthrough || n.Passthrough != int64(42) {
		t.Fatalf("id should be a readable passthrough int64(42), got %#v", n)
	}
	if n := byKey["created_at"]; n.Kind != vcvalue.KindPassthrough || n.Passthrough != "2026-07-25T00:00:00Z" {
		t.Fatalf("created_at should be a readable passthrough string, got %#v", n)
	}

	client := newClient(t)
	cipher, err := client.NewCipher(t.Context(), key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	defer func() { _ = cipher.Close(context.Background()) }()

	got, err := cipher.Decrypt(t.Context(), ct, aad)
	if err != nil {
		t.Fatalf("Decrypt(fixture): %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cross-language mismatch:\n got %#v\nwant %#v", got, want)
	}
}

func TestConcurrentUse(t *testing.T) {
	cipher := newCipher(t)
	done := make(chan error, 8)
	for i := range 8 {
		go func(i int) {
			value := map[string]int64{"n": int64(i)}
			ct, err := cipher.Encrypt(context.Background(), value, nil)
			if err == nil {
				var got any
				got, err = cipher.Decrypt(context.Background(), ct, nil)
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
	client := newClient(t)
	if _, err := client.NewCipher(t.Context(), []byte("short")); err == nil {
		t.Fatal("expected short key to be rejected")
	}
}
