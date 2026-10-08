package vcffi

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestSharedValueConformance(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/value-conformance.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			Name, Transport string
			GoReencode      string `json:"go_reencode"`
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
			encoded, err := Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			want := row.Transport
			if row.GoReencode != "" {
				want = row.GoReencode
			}
			if hex.EncodeToString(encoded) != want {
				t.Fatalf("got %x, want %s (%#v)", encoded, want, value)
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
