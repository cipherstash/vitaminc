package vcencrypt_test

import (
	"testing"
	"time"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// optional is a record whose optional fields are pointers, the Go side of
// Rust's Option<T>.
type optional struct {
	Born  *vcvalue.Date
	Age   *int32
	Score *float64
	Seen  *time.Time
	Price *vcvalue.Decimal
	ID    *vcvalue.UUID
}

// Through the real guest: a nil fixed-width field seals to a leaf of the
// same length as a present one (vitaminc#493), so the ciphertext does not
// show which optional values are absent, and it decrypts back as nil.
func TestANilFixedWidthFieldSealsAsLongAsAPresentOne(t *testing.T) {
	cipher := newCipher(t)
	aad := []byte("typed-null")
	born := vcvalue.Date{Year: 1815, Month: 12, Day: 10}
	age := int32(36)
	score := 1.5
	seen := time.Unix(1_700_000_000, 5).UTC()
	price := vcvalue.Decimal{Scale: 2, Coefficient: [12]byte{150}}
	id := vcvalue.UUID{0xAB}

	lengths := func(v optional) map[string]int {
		ct, err := cipher.Encrypt(t.Context(), v, aad)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		out := map[string]int{}
		for key, leaf := range ct.(map[string]any) {
			out[key] = len(leaf.(vcvalue.Sealed))
		}
		got, err := cipher.Decrypt(t.Context(), ct, aad)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if v.Age == nil {
			for _, f := range got.(vcvalue.Object) {
				if f.Value != nil {
					t.Fatalf("%s decrypted as %#v, want nil", f.Key, f.Value)
				}
			}
		}
		return out
	}
	present := lengths(optional{&born, &age, &score, &seen, &price, &id})
	absent := lengths(optional{})
	if len(present) != 6 {
		t.Fatalf("sealed %d fields", len(present))
	}
	for key, n := range present {
		if absent[key] != n {
			t.Fatalf("%s: absent seals to %d bytes, present to %d", key, absent[key], n)
		}
	}
}

// A bool and a string keep the plain null: a bool is already as short as
// one, and text is variable width.
func TestANilBoolOrStringSealsThePlainNull(t *testing.T) {
	cipher := newCipher(t)
	aad := []byte("plain-null")
	type rec struct {
		On   *bool
		Name *string
	}
	ct, err := cipher.Encrypt(t.Context(), rec{}, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	on := true
	present, err := cipher.Encrypt(t.Context(), rec{On: &on}, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if got, want := len(ct.(map[string]any)["On"].(vcvalue.Sealed)), len(present.(map[string]any)["On"].(vcvalue.Sealed)); got != want {
		t.Fatalf("bool: absent %d, present %d", got, want)
	}
	// A nil *string seals the plain null: as long as an empty string, and
	// shorter than any other.
	empty := ""
	withName, err := cipher.Encrypt(t.Context(), rec{Name: &empty}, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if got, want := len(ct.(map[string]any)["Name"].(vcvalue.Sealed)), len(withName.(map[string]any)["Name"].(vcvalue.Sealed)); got != want {
		t.Fatalf("string: absent %d, empty %d", got, want)
	}
}
