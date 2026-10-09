package vcffi

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// rfc3339ish matches the corpus timestamp spelling, including leap seconds
// and ISO 8601 expanded years, which time.Parse cannot read.
var rfc3339ish = regexp.MustCompile(`^([+-]?\d{4,})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$`)

// expected builds the Go value a vector's kind and value fields describe,
// without the transport decoder, so a bug that decodes and encodes
// symmetrically wrong cannot pass.
func expected(kind string, raw json.RawMessage) (any, error) {
	var text string
	_ = json.Unmarshal(raw, &text)
	integer := func(bits int) (int64, error) { return strconv.ParseInt(text, 10, bits) }
	natural := func(bits int) (uint64, error) { return strconv.ParseUint(text, 10, bits) }
	switch kind {
	case "null", "undefined":
		return nil, nil
	case "bool":
		var v bool
		return v, json.Unmarshal(raw, &v)
	case "int8":
		v, err := integer(8)
		return int8(v), err
	case "uint8":
		v, err := natural(8)
		return uint8(v), err
	case "int16":
		v, err := integer(16)
		return int16(v), err
	case "uint16":
		v, err := natural(16)
		return uint16(v), err
	case "int32":
		v, err := integer(32)
		return int32(v), err
	case "uint32":
		v, err := natural(32)
		return uint32(v), err
	case "int64":
		return integer(64)
	case "uint64":
		return natural(64)
	case "int128":
		return vcvalue.ParseInt128(text)
	case "uint128":
		return vcvalue.ParseUint128(text)
	case "float32":
		var v float32
		return v, json.Unmarshal(raw, &v)
	case "float64":
		var v float64
		return v, json.Unmarshal(raw, &v)
	case "string":
		return text, nil
	case "bytes":
		return hex.DecodeString(text)
	case "date":
		t, err := time.Parse("2006-01-02", text)
		return vcvalue.Date{Year: t.Year(), Month: t.Month(), Day: t.Day()}, err
	case "timestamp":
		return timestamp(text)
	case "decimal":
		return vcvalue.ParseDecimal(text)
	case "array":
		if string(raw) == "[]" {
			return []any{}, nil
		}
	case "object":
		if string(raw) == "{}" {
			return vcvalue.Object{}, nil
		}
	}
	return nil, fmt.Errorf("teach expected() the %s vector %s", kind, raw)
}

func timestamp(text string) (any, error) {
	m := rfc3339ish.FindStringSubmatch(text)
	if m == nil {
		return nil, fmt.Errorf("unparseable timestamp %q", text)
	}
	n := make([]int, 6)
	for i := range n {
		v, err := strconv.Atoi(m[i+1])
		if err != nil {
			return nil, err
		}
		n[i] = v
	}
	nanos, _ := strconv.Atoi((m[7] + "000000000")[:9])
	if n[5] == 60 {
		// chrono's leap second: second 59 with nanoseconds >= 1e9.
		t := time.Date(n[0], time.Month(n[1]), n[2], n[3], n[4], 59, 0, time.UTC)
		return vcvalue.Timestamp{Seconds: t.Unix(), Nanoseconds: uint32(1000000000 + nanos)}, nil
	}
	return time.Date(n[0], time.Month(n[1]), n[2], n[3], n[4], n[5], nanos, time.UTC), nil
}

func sameValue(got, want any) bool {
	if want, ok := want.(time.Time); ok {
		got, ok := got.(time.Time)
		return ok && got.Equal(want)
	}
	return reflect.DeepEqual(got, want)
}

func TestSharedValueConformance(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/value-conformance.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			Name, Kind, Transport string
			Value                 json.RawMessage
			GoReencode            string `json:"go_reencode"`
		}
		Malformed []struct{ Name, Transport string }
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, row := range corpus.Vectors {
		t.Run(row.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(row.Transport)
			if err != nil {
				t.Fatal(err)
			}
			value, err := Unmarshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			expect, err := expected(row.Kind, row.Value)
			if err != nil {
				t.Fatal(err)
			}
			if !sameValue(value, expect) {
				t.Fatalf("decoded %#v, want %#v", value, expect)
			}
			want := row.Transport
			if row.GoReencode != "" {
				want = row.GoReencode
			}
			// Encode the decoded value and, independently, the expected one.
			for _, v := range []any{value, expect} {
				encoded, err := Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(encoded) != want {
					t.Fatalf("got %x, want %s (%#v)", encoded, want, v)
				}
			}
		})
	}
	for _, row := range corpus.Malformed {
		t.Run(row.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(row.Transport)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Unmarshal(raw); err != ErrMalformed {
				t.Fatalf("got %v, want ErrMalformed", err)
			}
		})
	}
}
