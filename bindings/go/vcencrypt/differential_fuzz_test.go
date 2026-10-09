package vcencrypt

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/tetratelabs/wazero/api"
)

// Differential fuzzing: the same bytes go to Go's decoder (vcffi) and to the
// Rust decoder inside the embedded guest, and the two must agree. Each side's
// own fuzz targets prove it is consistent with itself; only a differential
// target finds the bugs where both are self-consistent but disagree, such as
// one side quieting a signaling NaN the other keeps.
//
// The guest has no decode-only export, and a test-only one would ship in the
// production module. Instead the targets lean on the order its transform
// calls work in: vc_encrypt and vc_decrypt decode their input BEFORE looking
// up the cipher handle. Called with a handle that was never issued, they
// answer ErrEncoding when Rust rejects the bytes and ErrBadHandle when it
// accepts them, without touching AES. TestUnissuedHandleReportsDecoding pins
// that order; everything below depends on it.

// unissuedHandle is never a live session: the guest numbers handles from 1,
// because a zero high half of a packed result means "error".
const unissuedHandle = 0

// maxDifferentialInput bounds an input so one large, slow guest call cannot
// dominate a fuzzing run. Decoder bugs show up in small inputs.
const maxDifferentialInput = 4 << 10

var differentialAAD = []byte("vcencrypt differential fuzzing")

// differentialGuest opens one guest instance and cipher for a fuzz target.
// Go runs the code before f.Fuzz once in every fuzzing worker process, so
// each worker reuses one instance across its iterations.
func differentialGuest(f *testing.F) (*Client, *Cipher) {
	ctx := context.Background()
	client, err := NewClient(ctx)
	if err != nil {
		f.Fatalf("NewClient: %v", err)
	}
	f.Cleanup(func() { _ = client.Close(ctx) })
	cipher, err := client.NewCipher(ctx, bytes.Repeat([]byte{0x2a}, KeySize))
	if err != nil {
		f.Fatalf("NewCipher: %v", err)
	}
	return client, cipher
}

// rustAccepts reports whether the guest's decoder accepts data as the input
// of fn (vc_encrypt for a value tree, vc_decrypt for a ciphertext tree).
func rustAccepts(c *Client, fn api.Function, data []byte) (bool, error) {
	_, err := c.call(context.Background(), fn, unissuedHandle, differentialAAD, data)
	switch {
	case errors.Is(err, ErrBadHandle):
		return true, nil
	case errors.Is(err, ErrEncoding):
		return false, nil
	case err == nil:
		return false, errors.New("guest succeeded under an unissued handle")
	default:
		return false, err
	}
}

// rustReencode decrypts a ciphertext tree under a live cipher and returns the
// guest's transport encoding of the result.
func rustReencode(c *Client, cipher *Cipher, ct []byte) ([]byte, error) {
	return c.call(context.Background(), c.decrypt, cipher.handle, differentialAAD, ct)
}

// corpusTransports returns the transport bytes of every valid and malformed
// vector in the shared value corpus.
func corpusTransports(f *testing.F) [][]byte {
	data, err := os.ReadFile("../../../testdata/value-conformance.json")
	if err != nil {
		f.Fatal(err)
	}
	var corpus struct{ Vectors, Malformed []struct{ Transport string } }
	if err := json.Unmarshal(data, &corpus); err != nil {
		f.Fatal(err)
	}
	var out [][]byte
	for _, row := range append(corpus.Vectors, corpus.Malformed...) {
		raw, err := hex.DecodeString(row.Transport)
		if err != nil {
			f.Fatal(err)
		}
		out = append(out, raw)
	}
	return out
}

// sameModuloUndefined fails unless goOut is rustOut with some Undefined tags
// (0x01) turned into Null (0x00): Go projects Undefined to nil by design,
// and both are one-byte tags, so the lengths must match.
func sameModuloUndefined(t *testing.T, data, rustOut, goOut []byte) {
	t.Helper()
	if len(goOut) != len(rustOut) {
		t.Fatalf("input %x: Rust re-encodes as %x, Go as %x", data, rustOut, goOut)
	}
	for i := range rustOut {
		if rustOut[i] != goOut[i] && (rustOut[i] != 0x01 || goOut[i] != 0x00) {
			t.Fatalf("input %x: Rust re-encodes as %x, Go as %x (byte %d)", data, rustOut, goOut, i)
		}
	}
}

func FuzzDifferentialValue(f *testing.F) {
	client, cipher := differentialGuest(f)
	for _, raw := range corpusTransports(f) {
		f.Add(raw)
		f.Add(append([]byte{0xF0, 1, 0, 0, 0}, raw...)) // in an array
		f.Add(append([]byte{0xF2}, raw...))             // as passthrough
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxDifferentialInput {
			return
		}
		goValue, goErr := vcffi.Unmarshal(data)
		rustOK, err := rustAccepts(client, client.encrypt, data)
		if err != nil {
			t.Fatalf("input %x: guest decode failed abnormally: %v", data, err)
		}
		if rustOK != (goErr == nil) {
			t.Fatalf("input %x: Rust accepts=%v, Go accepts=%v (Go error: %v)", data, rustOK, goErr == nil, goErr)
		}
		if !rustOK {
			return
		}

		// Both accept: compare what each makes of the bytes. Rust's view comes
		// from decrypting a ciphertext that is a single passthrough node
		// (ctPassthrough, 0x05) carrying the input: the guest decodes the
		// value and re-encodes it as a Value passthrough (0xF2), with no AES
		// and none of the cipher's rules about what may be sealed (encrypting
		// would refuse, by design, a container holding only passthrough
		// values).
		wrapped := append([]byte{0x05}, data...)
		rustOut, err := rustReencode(client, cipher, wrapped)
		if errors.Is(err, ErrEncoding) {
			// The wrapper adds a level of nesting, so an input at the depth
			// limit can be refused only when wrapped. Go must agree.
			if _, goErr := vcffi.UnmarshalCipherText(vcffi.VCValueLeaves(), wrapped); goErr == nil {
				t.Fatalf("input %x: Rust rejects it as a passthrough node, Go accepts", data)
			}
			return
		}
		if err != nil {
			t.Fatalf("input %x: guest re-encode failed: %v", data, err)
		}
		// Rust has no Undefined projection, so its re-encoding is exact.
		if !bytes.Equal(rustOut, append([]byte{0xF2}, data...)) {
			t.Fatalf("input %x: Rust re-encodes the passthrough as %x", data, rustOut)
		}
		rustOut = rustOut[1:]
		goOut, err := vcffi.Marshal(goValue)
		if err != nil {
			t.Fatalf("input %x: Go decoded %#v but cannot re-encode it: %v", data, goValue, err)
		}
		sameModuloUndefined(t, data, rustOut, goOut)
	})
}

func FuzzDifferentialCipherText(f *testing.F) {
	client, cipher := differentialGuest(f)
	ctx := context.Background()
	for _, raw := range corpusTransports(f) {
		f.Add(append([]byte{0x05}, raw...)) // as a clear passthrough node
		// Real ciphertext of each valid vector, so the fuzzer starts from
		// well-formed sealed leaves of every kind.
		if ct, err := client.call(ctx, client.encrypt, cipher.handle, differentialAAD, raw); err == nil {
			f.Add(ct)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxDifferentialInput {
			return
		}
		_, goErr := vcffi.UnmarshalCipherText(vcffi.VCValueLeaves(), data)
		rustOK, err := rustAccepts(client, client.decrypt, data)
		if err != nil {
			t.Fatalf("input %x: guest decode failed abnormally: %v", data, err)
		}
		// Fuzzed seals never authenticate, so there is no plaintext to
		// compare: acceptance is the whole check.
		if rustOK != (goErr == nil) {
			t.Fatalf("input %x: Rust accepts=%v, Go accepts=%v (Go error: %v)", data, rustOK, goErr == nil, goErr)
		}
	})
}

// TestUnissuedHandleReportsDecoding pins the call order the differential
// targets read Rust's verdict from: decode first, handle lookup second. If
// the guest ever looked the handle up first, every input would come back
// ErrBadHandle and read as accepted, so the targets would compare nothing.
func TestUnissuedHandleReportsDecoding(t *testing.T) {
	c := newRawClient(t)
	valid := []byte{0x00}              // Null
	malformed := []byte{0x0A, 9, 0, 0} // truncated String
	for _, tc := range []struct {
		name string
		fn   api.Function
		data []byte
		want error
	}{
		{"encrypt valid", c.encrypt, valid, ErrBadHandle},
		{"encrypt malformed", c.encrypt, malformed, ErrEncoding},
		{"decrypt valid", c.decrypt, []byte{0x05, 0x00}, ErrBadHandle}, // passthrough Null
		{"decrypt malformed", c.decrypt, malformed, ErrEncoding},
	} {
		_, err := c.call(context.Background(), tc.fn, unissuedHandle, differentialAAD, tc.data)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

// BenchmarkDifferential measures the two tiers' cost per input: the
// accept/reject check every input pays, and the re-encode only accepted
// inputs pay. It sizes the nightly fuzz time.
func BenchmarkDifferential(b *testing.B) {
	ctx := context.Background()
	client, err := NewClient(ctx)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = client.Close(ctx) }()
	cipher, err := client.NewCipher(ctx, bytes.Repeat([]byte{0x2a}, KeySize))
	if err != nil {
		b.Fatal(err)
	}
	// An object of a few mixed scalars: a typical small accepted input.
	data, err := vcffi.Marshal(map[string]any{"a": int64(7), "b": "hello", "c": []any{true, 1.5}})
	if err != nil {
		b.Fatal(err)
	}

	b.Run("accept-check", func(b *testing.B) {
		for b.Loop() {
			if ok, err := rustAccepts(client, client.encrypt, data); !ok || err != nil {
				b.Fatal(ok, err)
			}
		}
	})
	b.Run("re-encode", func(b *testing.B) {
		wrapped := append([]byte{0x05}, data...)
		for b.Loop() {
			if _, err := rustReencode(client, cipher, wrapped); err != nil {
				b.Fatal(err)
			}
		}
	})
}
