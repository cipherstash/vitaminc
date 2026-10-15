package vcencrypt_test

import (
	"encoding/hex"
	"encoding/json"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"os"
	"testing"
)

func TestScalarCorpusThroughWasm(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/value-conformance.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			Name, Transport string
			GoReencode      string `json:"go_reencode"`
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	cipher := newCipher(t)
	for _, row := range corpus.Vectors {
		t.Run(row.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(row.Transport)
			if err != nil {
				t.Fatal(err)
			}
			value, err := vcffi.Unmarshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := cipher.Encrypt(t.Context(), value, []byte("shared-corpus"))
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := cipher.Decrypt(t.Context(), sealed, []byte("shared-corpus"))
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := vcffi.Marshal(decoded)
			if err != nil {
				t.Fatal(err)
			}
			want := row.Transport
			if row.GoReencode != "" {
				want = row.GoReencode
			}
			if hex.EncodeToString(encoded) != want {
				t.Fatalf("got %x, want %s", encoded, want)
			}
		})
	}
}
