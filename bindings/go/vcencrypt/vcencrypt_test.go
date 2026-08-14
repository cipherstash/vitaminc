package vcencrypt_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"reflect"
	"sort"
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

// wantRecord lists fields key-sorted: a ciphertext map is unordered (entry
// order is not authenticated), so decryption returns fields sorted by key.
func wantRecord() vcvalue.Object {
	return vcvalue.Object{
		{Key: "Active", Value: true},
		{Key: "Age", Value: int64(36)},
		{Key: "Blob", Value: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{Key: "Huge", Value: uint64(math.MaxUint64)},
		{Key: "Name", Value: "Ada"},
		{Key: "Score", Value: 1.5},
		{Key: "Tags", Value: []any{"math", "engines"}},
	}
}

// sortedByKey returns a key-sorted copy of an Object, for comparisons where
// the source field order is not part of the contract.
func sortedByKey(o vcvalue.Object) vcvalue.Object {
	s := append(vcvalue.Object(nil), o...)
	sort.Slice(s, func(i, j int) bool { return s[i].Key < s[j].Key })
	return s
}

func TestRoundTrip(t *testing.T) {
	cipher := newCipher(t)
	aad := []byte("round-trip")

	ct, err := cipher.Encrypt(t.Context(), sampleRecord(), aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, ok := ct.(map[string]any); !ok {
		t.Fatalf("expected map-shaped ciphertext, got %T", ct)
	}

	got, err := cipher.Decrypt(t.Context(), ct, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !reflect.DeepEqual(got, wantRecord()) {
		t.Fatalf("round trip mismatch:\n got %#v\nwant %#v", got, wantRecord())
	}
}

// Empty composites seal to authenticated marker leaves (an empty container
// has no element ciphertexts to bind the AAD) and round-trip back to empty
// containers.
func TestEmptyCompositeRoundTrip(t *testing.T) {
	cipher := newCipher(t)
	aad := []byte("empty-composites")

	value := map[string]any{
		"tags": []any{},
		"meta": map[string]any{},
	}
	ct, err := cipher.Encrypt(t.Context(), value, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	m := ct.(map[string]any)
	if _, ok := m["tags"].(vcvalue.SealedEmptySeq); !ok {
		t.Fatalf("expected tags to be a SealedEmptySeq marker, got %#v", m["tags"])
	}
	if _, ok := m["meta"].(vcvalue.SealedEmptyMap); !ok {
		t.Fatalf("expected meta to be a SealedEmptyMap marker, got %#v", m["meta"])
	}

	got, err := cipher.Decrypt(t.Context(), ct, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	want := vcvalue.Object{
		{Key: "meta", Value: vcvalue.Object{}},
		{Key: "tags", Value: []any{}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
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
		{Key: "age", Value: uint64(36)},
		{Key: "name", Value: "Ada"},
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
	// no Decrypt call — and the sealed sibling is a marked Sealed leaf.
	m := ct.(map[string]any)
	if id, ok := m["id"].(vcvalue.Plain); !ok || id.V != int64(42) {
		t.Fatalf("expected id to be a readable Plain int64(42), got %#v", m["id"])
	}
	if _, ok := m["email"].(vcvalue.Sealed); !ok {
		t.Fatalf("expected email to be a Sealed leaf, got %#v", m["email"])
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
	ct.(map[string]any)["id"] = vcvalue.Plain{V: int64(999)}
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
	leaf := ct.(vcvalue.Sealed)
	leaf[len(leaf)/2] ^= 0x01
	if _, err := cipher.Decrypt(t.Context(), ct, nil); !errors.Is(err, vcencrypt.ErrAuthentication) {
		t.Fatalf("expected ErrAuthentication, got %v", err)
	}
}

// Garbage transport bytes (a ciphertext map key that is not valid UTF-8) are
// rejected by the guest's decoder as ErrEncoding, distinct from an auth error.
func TestGarbageTransportGivesEncodingError(t *testing.T) {
	cipher := newCipher(t)

	ct := map[string]any{
		string([]byte{0xff}): vcvalue.Sealed{1, 2, 3}, // invalid UTF-8 key
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
	m := ct.(map[string]any)
	if len(m) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(m))
	}

	renamed := map[string]any{"renamed": m["salary"], "bonus": m["bonus"]}
	if _, err := cipher.Decrypt(t.Context(), renamed, nil); !errors.Is(err, vcencrypt.ErrAuthentication) {
		t.Fatalf("expected rename to fail with ErrAuthentication, got %v", err)
	}

	swapped := map[string]any{"salary": m["bonus"], "bonus": m["salary"]}
	if _, err := cipher.Decrypt(t.Context(), swapped, nil); !errors.Is(err, vcencrypt.ErrAuthentication) {
		t.Fatalf("expected swap to fail with ErrAuthentication, got %v", err)
	}
}

// There is no whole-map seal: any subset of a record's entries decrypts on
// its own — the property per-column database reads rely on. The key binding
// still holds: a leaf lifted out of its map entry fails authentication.
func TestMapSubsetDecrypts(t *testing.T) {
	cipher := newCipher(t)

	ct, err := cipher.Encrypt(t.Context(), map[string]int64{"a": 1, "b": 2}, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	m := ct.(map[string]any)

	got, err := cipher.Decrypt(t.Context(), map[string]any{"b": m["b"]}, nil)
	if err != nil {
		t.Fatalf("Decrypt(subset): %v", err)
	}
	want := vcvalue.Object{{Key: "b", Value: int64(2)}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	if _, err := cipher.Decrypt(t.Context(), m["b"], nil); !errors.Is(err, vcencrypt.ErrAuthentication) {
		t.Fatalf("expected bare leaf to fail authentication, got %v", err)
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
	byKey := ct.(map[string]any)
	if p, ok := byKey["id"].(vcvalue.Plain); !ok || p.V != int64(42) {
		t.Fatalf("id should be a readable passthrough int64(42), got %#v", byKey["id"])
	}
	if p, ok := byKey["created_at"].(vcvalue.Plain); !ok || p.V != "2026-07-25T00:00:00Z" {
		t.Fatalf("created_at should be a readable passthrough string, got %#v", byKey["created_at"])
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
	// The fixture's expected value keeps Rust's write order; decryption
	// returns key-sorted fields (ciphertext maps are unordered), so compare
	// order-insensitively.
	if !reflect.DeepEqual(got, sortedByKey(want.(vcvalue.Object))) {
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

// A row batch-encrypted as part of a slice decrypts alone through
// DecryptElement under the collection's own aad — the workflow behind
// "insert many rows in one Encrypt call, SELECT one back".
func TestElementDecryptsBatchEncryptedRow(t *testing.T) {
	cipher := newCipher(t)
	aad := []byte("users")

	rows := []map[string]string{
		{"email": "ada@example.com"},
		{"email": "grace@example.com"},
	}
	ct, err := cipher.Encrypt(t.Context(), rows, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	row := ct.([]any)[1]

	got, err := cipher.DecryptElement(t.Context(), row, aad)
	if err != nil {
		t.Fatalf("DecryptElement: %v", err)
	}
	want := vcvalue.Object{{Key: "email", Value: "grace@example.com"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	// Plain Decrypt must keep refusing a lone element — the container shape
	// stays authenticated; DecryptElement is the sanctioned way in.
	if _, err := cipher.Decrypt(t.Context(), row, aad); !errors.Is(err, vcencrypt.ErrAuthentication) {
		t.Fatalf("Decrypt of a lone element: got %v, want ErrAuthentication", err)
	}
}

// A row inserted alone via EncryptElement interchanges with batch writes:
// collected into a slice it decrypts as a whole sequence, and it opens
// individually through DecryptElement.
func TestElementEncryptInterchangesWithBatch(t *testing.T) {
	cipher := newCipher(t)
	aad := []byte("users")

	ct1, err := cipher.EncryptElement(t.Context(), map[string]string{"email": "ada@example.com"}, aad)
	if err != nil {
		t.Fatalf("EncryptElement: %v", err)
	}
	ct2, err := cipher.EncryptElement(t.Context(), map[string]string{"email": "grace@example.com"}, aad)
	if err != nil {
		t.Fatalf("EncryptElement: %v", err)
	}

	got, err := cipher.Decrypt(t.Context(), []any{ct1, ct2}, aad)
	if err != nil {
		t.Fatalf("Decrypt of collected elements: %v", err)
	}
	want := []any{
		vcvalue.Object{{Key: "email", Value: "ada@example.com"}},
		vcvalue.Object{{Key: "email", Value: "grace@example.com"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// Element ciphertexts and bare (top-level) ciphertexts must not interchange
// in either direction: Element opts a value into collection semantics; it
// does not weaken shape authentication for values that never opted in.
func TestElementNotInterchangeableWithBareValues(t *testing.T) {
	cipher := newCipher(t)
	aad := []byte("users")

	bare, err := cipher.Encrypt(t.Context(), "x", aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := cipher.DecryptElement(t.Context(), bare, aad); !errors.Is(err, vcencrypt.ErrAuthentication) {
		t.Fatalf("DecryptElement of a bare ciphertext: got %v, want ErrAuthentication", err)
	}

	element, err := cipher.EncryptElement(t.Context(), "x", aad)
	if err != nil {
		t.Fatalf("EncryptElement: %v", err)
	}
	if _, err := cipher.Decrypt(t.Context(), element, aad); !errors.Is(err, vcencrypt.ErrAuthentication) {
		t.Fatalf("Decrypt of an element ciphertext: got %v, want ErrAuthentication", err)
	}
}

// TestSealedLeafWireSize pins the leaf layout the docs promise: one version
// byte, a 12-byte nonce, the ciphertext (one transport tag byte plus the
// string's bytes), and a 16-byte GCM tag. The Example used to pin these
// lengths in its output; the pin lives here now so the docs stay structural
// while a version- or framing-byte change still fails a named test.
func TestSealedLeafWireSize(t *testing.T) {
	const leafOverhead = 1 /* version */ + 12 /* nonce */ + 1 /* leaf tag */ + 16 /* GCM tag */

	cipher := newCipher(t)
	ct, err := cipher.Encrypt(t.Context(), map[string]any{
		"email": "ada@example.com",
		"name":  "Ada Lovelace",
	}, []byte("user:42"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	m := ct.(map[string]any)
	for field, plaintext := range map[string]string{
		"email": "ada@example.com",
		"name":  "Ada Lovelace",
	} {
		leaf := m[field].(vcvalue.Sealed)
		if got, want := len(leaf), len(plaintext)+leafOverhead; got != want {
			t.Fatalf("%s leaf: got %d bytes, want %d", field, got, want)
		}
	}
}

// TestContextCancellationFailsGuestCall verifies a caller can escape via
// context cancellation instead of queueing behind the client's serialized
// guest calls: with WithCloseOnContextDone set, a done context fails the
// call rather than running the guest to completion.
func TestContextCancellationFailsGuestCall(t *testing.T) {
	client := newClient(t)
	cipher, err := client.NewCipher(t.Context(), testKey)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cipher.Encrypt(cancelled, "value", []byte("aad")); err == nil {
		t.Fatal("an already-cancelled context must fail the guest call")
	}
}
