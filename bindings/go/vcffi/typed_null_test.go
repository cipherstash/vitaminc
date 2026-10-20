package vcffi

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// typedNullAnswers pins each FixedType's typed null: the cross-language
// bytes the Rust codec writes for the same type (vitaminc-aead's leaf
// tests), beside a value of the type, which must be as long.
var typedNullAnswers = []struct {
	t       vcvalue.FixedType
	hex     string
	present any
}{
	{vcvalue.TypeInt8, "150c", int8(-1)},
	{vcvalue.TypeInt16, "150e00", int16(-1)},
	{vcvalue.TypeInt32, "1504000000", int32(-1)},
	{vcvalue.TypeInt64, "1505" + zeros(7), int64(-1)},
	{vcvalue.TypeInt128, "1510" + zeros(15), vcvalue.Int128{1}},
	{vcvalue.TypeUint8, "150d", uint8(1)},
	{vcvalue.TypeUint16, "150f00", uint16(1)},
	{vcvalue.TypeUint32, "1506000000", uint32(1)},
	{vcvalue.TypeUint64, "1507" + zeros(7), uint64(1)},
	{vcvalue.TypeUint128, "1511" + zeros(15), vcvalue.Uint128{1}},
	{vcvalue.TypeFloat32, "1508000000", float32(1.5)},
	{vcvalue.TypeFloat64, "1509" + zeros(7), 1.5},
	{vcvalue.TypeDate, "1512000000", vcvalue.Date{Year: 1999, Month: 12, Day: 31}},
	{vcvalue.TypeTimestamp, "1513" + zeros(11), time.Unix(1_700_000_000, 5).UTC()},
	{vcvalue.TypeDecimal, "1514" + zeros(15), vcvalue.Decimal{Scale: 2, Coefficient: [12]byte{150}}},
	{vcvalue.TypeUUID, "15f305000b" + zeros(15), vcvalue.UUID{0xAB}},
}

func zeros(n int) string { return hex.EncodeToString(make([]byte, n)) }

func TestTypedNullKnownAnswers(t *testing.T) {
	for _, row := range typedNullAnswers {
		got, err := Marshal(vcvalue.TypedNull{Type: row.t})
		if err != nil {
			t.Fatalf("%v: %v", row.t, err)
		}
		if hex.EncodeToString(got) != row.hex {
			t.Fatalf("%v: got %x, want %s", row.t, got, row.hex)
		}
		present, err := Marshal(row.present)
		if err != nil {
			t.Fatalf("%v: %v", row.t, err)
		}
		// A frame gives bytes a length prefix; a typed null of a UUID has
		// none, because its sealed leaf has none.
		want := len(present)
		if row.t == vcvalue.TypeUUID {
			want -= 4
		}
		if len(got) != want {
			t.Fatalf("%v: typed null is %d bytes, a value %d", row.t, len(got), want)
		}
		// It reads back as nil, like every null, and writes back as one.
		v, err := Unmarshal(got)
		if err != nil || v != nil {
			t.Fatalf("%v: decoded %#v, %v", row.t, v, err)
		}
	}
	if len(typedNullAnswers) != int(vcvalue.TypeUUID) {
		t.Fatalf("pinned %d of %d types", len(typedNullAnswers), vcvalue.TypeUUID)
	}
}

func TestAnInvalidFixedTypeFailsTheEncode(t *testing.T) {
	for _, ft := range []vcvalue.FixedType{0, vcvalue.TypeUUID + 1, 255} {
		if _, err := Marshal(vcvalue.TypedNull{Type: ft}); !errors.Is(err, vcvalue.ErrInvalidFixedType) {
			t.Fatalf("%v: got %v", ft, err)
		}
	}
}

type selfEncoded int32

func (s selfEncoded) EncryptValue(enc Encoder) error {
	enc.String("custom")
	return nil
}

// A nil pointer to a fixed-width type is a typed null, the Go side of
// Rust's Option<T>; a nil with no fixed-width type to go by is the plain
// null.
func TestANilPointerIsATypedNullWhenItsTypeIsFixedWidth(t *testing.T) {
	type age int32
	cases := []struct {
		name string
		v    any
		want string
	}{
		{"*int8", (*int8)(nil), "150c"},
		{"*int", (*int)(nil), "1505" + zeros(7)},
		{"*uint", (*uint)(nil), "1507" + zeros(7)},
		{"*float32", (*float32)(nil), "1508000000"},
		{"*time.Time", (*time.Time)(nil), "1513" + zeros(11)},
		{"*vcvalue.Date", (*vcvalue.Date)(nil), "1512000000"},
		{"*vcvalue.Timestamp", (*vcvalue.Timestamp)(nil), "1513" + zeros(11)},
		{"*vcvalue.Decimal", (*vcvalue.Decimal)(nil), "1514" + zeros(15)},
		{"*vcvalue.UUID", (*vcvalue.UUID)(nil), "15f305000b" + zeros(15)},
		{"*vcvalue.Int128", (*vcvalue.Int128)(nil), "1510" + zeros(15)},
		{"named *age", (*age)(nil), "1504000000"},
		{"**int32", (**int32)(nil), "1504000000"},
		// No fixed width: the plain null.
		{"*bool", (*bool)(nil), "00"},
		{"*string", (*string)(nil), "00"},
		{"*[]byte", (*[]byte)(nil), "00"},
		{"*[16]byte", (*[16]byte)(nil), "00"},
		{"*struct", (*struct{ A int32 })(nil), "00"},
		{"*Encryptable", (*selfEncoded)(nil), "00"},
		{"nil", nil, "00"},
	}
	for _, c := range cases {
		got, err := Marshal(c.v)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if hex.EncodeToString(got) != c.want {
			t.Fatalf("%s: got %x, want %s", c.name, got, c.want)
		}
	}
}

func TestAStructsNilFieldsAreTypedNulls(t *testing.T) {
	type person struct {
		Name string
		Born *vcvalue.Date
		Age  *int32
		Tags []string
		Any  any
	}
	got, err := Marshal(person{Name: "Ada"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := Unmarshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range v.(vcvalue.Object) {
		if (f.Key == "Born" || f.Key == "Age" || f.Key == "Any") && f.Value != nil {
			t.Fatalf("%s decoded %#v", f.Key, f.Value)
		}
	}
	// Born and Age carry their padding; Any has no type to go by, and a nil
	// slice is an empty sequence, as it always was.
	if !bytes.Contains(got, []byte{tagTypedNull, tagDate, 0, 0, 0}) ||
		!bytes.Contains(got, []byte{tagTypedNull, tagInt32, 0, 0, 0}) {
		t.Fatalf("no typed nulls in %x", got)
	}
}

// The explicit channel, for an Encryptable that knows the type.
type maybeAge struct{ v *int32 }

func (m maybeAge) EncryptValue(enc Encoder) error {
	if m.v == nil {
		enc.TypedNull(vcvalue.TypeInt32)
	} else {
		enc.Int32(*m.v)
	}
	return nil
}

func TestTheTypedNullChannel(t *testing.T) {
	got, err := Marshal(maybeAge{})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != "1504000000" {
		t.Fatalf("got %x", got)
	}
	// It completes exactly one slot, like every terminal.
	enc := func(e Encoder) error {
		s := e.Seq()
		s.Elem().TypedNull(vcvalue.TypeUint8)
		s.Elem().Null()
		return s.End()
	}
	got, err = Marshal(encryptableFunc(enc))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != "f002000000150d00" {
		t.Fatalf("got %x", got)
	}
}

type encryptableFunc func(Encoder) error

func (f encryptableFunc) EncryptValue(e Encoder) error { return f(e) }

// Every absence has one encoding: the decoder refuses anything a writer
// does not write. The shared corpus pins the same refusals for every
// language; these are the Go-specific edges around them.
func TestATypedNullIsReadStrictly(t *testing.T) {
	refused := []string{
		"15", "1504", "15040000", "1504000001", "150400000000",
		"1500", "1502", "150a", "150b" + zeros(15), "1515040000",
		"15f3", "15f303", "15f30301", "15f3030304" + zeros(3), "15f3030409" + zeros(7),
		"15f3050104" + zeros(3), "15f3c8000a", "15f3c8000b" + zeros(15),
		"f0010000001502",
	}
	for _, h := range refused {
		raw, _ := hex.DecodeString(h)
		if _, err := Unmarshal(raw); err != ErrMalformed {
			t.Fatalf("%s: got %v, want ErrMalformed", h, err)
		}
	}
	accepted := []string{
		"15f3030004000000",                    // seconds over an int32
		"15f3030210" + zeros(15),              // microseconds over an int128
		"15f3c8ff09" + zeros(7),               // an unknown id, any parameter, over a float64
		"f0010000001506000000",                // inside an array
		"f2150c",                              // as passthrough
		"f101000000010000006115120000" + "00", // as an object value
	}
	for _, h := range accepted {
		raw, _ := hex.DecodeString(h)
		if _, err := Unmarshal(raw); err != nil {
			t.Fatalf("%s: %v", h, err)
		}
	}
}
