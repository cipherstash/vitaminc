package vcffi

import (
	"encoding/hex"
	"errors"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
	"reflect"
	"testing"
	"time"
)

func TestScalarHostEncoding(t *testing.T) {
	signed, err := vcvalue.ParseInt128("-170141183460469231731687303715884105728")
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := vcvalue.ParseUint128("340282366920938463463374607431768211455")
	if err != nil {
		t.Fatal(err)
	}
	decimal, err := vcvalue.ParseDecimal("1.50")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		value any
		wire  string
	}{
		{int8(-128), "0c80"}, {uint8(255), "0dff"}, {int16(-32768), "0e0080"}, {uint16(65535), "0fffff"},
		{signed, "1000000000000000000000000000000080"}, {unsigned, "11ffffffffffffffffffffffffffffffff"},
		{vcvalue.Date{Year: 1, Month: 1, Day: 1}, "1201000000"},
		{time.Unix(0, 123456789).UTC(), "13000000000000000015cd5b07"},
		{decimal, "1400000200960000000000000000000000"},
	}
	for _, tc := range cases {
		encoded, err := Marshal(tc.value)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(encoded) != tc.wire {
			t.Fatalf("%T: %x != %s", tc.value, encoded, tc.wire)
		}
		decoded, err := Unmarshal(encoded)
		if err != nil || !reflect.DeepEqual(decoded, tc.value) {
			t.Fatalf("%T: got %#v: %v", tc.value, decoded, err)
		}
		// The intercept also applies through pointers, fields and interfaces.
		nested := struct{ Value any }{Value: &tc.value}
		if _, err := Marshal(nested); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInvalidScalarHostEncoding(t *testing.T) {
	cases := []struct {
		value any
		err   error
	}{
		{vcvalue.Date{Year: 2023, Month: 2, Day: 29}, vcvalue.ErrInvalidDate},
		{vcvalue.Timestamp{Seconds: 0, Nanoseconds: 1000000000}, vcvalue.ErrInvalidTimestamp},
		{time.Date(262143, 1, 1, 0, 0, 0, 0, time.UTC), vcvalue.ErrInvalidTimestamp},
		{vcvalue.Decimal{Scale: 29}, vcvalue.ErrInvalidDecimal},
	}
	for _, tc := range cases {
		if _, err := Marshal(tc.value); !errors.Is(err, tc.err) {
			t.Fatalf("got %v, want %v", err, tc.err)
		}
	}
}
