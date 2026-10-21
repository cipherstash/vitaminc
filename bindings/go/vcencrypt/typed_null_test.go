package vcencrypt_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// optional is a record with an optional field of every fixed-width type,
// as pointers, the Go side of Rust's Option<T>.
type optional struct {
	I8    *int8
	I16   *int16
	I32   *int32
	I64   *int64
	I128  *vcvalue.Int128
	U8    *uint8
	U16   *uint16
	U32   *uint32
	U64   *uint64
	U128  *vcvalue.Uint128
	F32   *float32
	F64   *float64
	Born  *vcvalue.Date
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
	var (
		i8    int8    = -1
		i16   int16   = -300
		i32   int32   = 36
		i64   int64   = 1 << 40
		i128          = vcvalue.Int128{1}
		u8    uint8   = 1
		u16   uint16  = 300
		u32   uint32  = 70_000
		u64   uint64  = 1 << 40
		u128          = vcvalue.Uint128{1}
		f32   float32 = 1.5
		f64           = 2.5
		born          = vcvalue.Date{Year: 1815, Month: 12, Day: 10}
		seen          = time.Unix(1_700_000_000, 5).UTC()
		price         = vcvalue.Decimal{Scale: 2, Coefficient: [12]byte{150}}
		id            = vcvalue.UUID{0xAB}
	)

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
		if v.I32 == nil {
			for _, f := range got.(vcvalue.Object) {
				if f.Value != nil {
					t.Fatalf("%s decrypted as %#v, want nil", f.Key, f.Value)
				}
			}
		}
		return out
	}
	present := lengths(optional{
		&i8, &i16, &i32, &i64, &i128, &u8, &u16, &u32, &u64, &u128, &f32, &f64,
		&born, &seen, &price, &id,
	})
	absent := lengths(optional{})
	if len(present) != 16 {
		t.Fatalf("sealed %d fields", len(present))
	}
	for key, n := range present {
		if absent[key] != n {
			t.Fatalf("%s: absent seals to %d bytes, present to %d", key, absent[key], n)
		}
	}
}

// A nil fixed-width pointer inside vcvalue.Plain is a typed null in the
// frame the guest reads, and the guest writes it back as the plain null:
// a passthrough is never sealed, so the padding would hide nothing there,
// and it reads as nil in the ciphertext and after a decrypt.
func TestANilFixedWidthPointerInAPassthroughIsThePlainNull(t *testing.T) {
	cipher := newCipher(t)
	aad := []byte("plain-typed-null")
	ct, err := cipher.Encrypt(t.Context(), map[string]any{
		"score": vcvalue.Plain{V: (*int32)(nil)},
		"email": "ada@example.com",
	}, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if score := ct.(map[string]any)["score"]; score != (vcvalue.Plain{V: nil}) {
		t.Fatalf("passthrough in the ciphertext: %#v", score)
	}
	got, err := cipher.Decrypt(t.Context(), ct, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	want := vcvalue.Object{
		{Key: "email", Value: "ada@example.com"},
		{Key: "score", Value: vcvalue.Plain{V: nil}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
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
