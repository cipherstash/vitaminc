package vcencrypt

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
)

// These tests drive the raw vc_* exports with hostile (ptr, len) pairs the
// public API never produces, pinning the guest's fail-closed behaviour:
// invalid input must come back as a status code, never a trap. A trap would
// poison the shared instance for every open cipher handle, so each test ends
// by proving the instance still round-trips.

func newRawClient(t *testing.T) *Client {
	t.Helper()
	client, err := NewClient(context.Background())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	return client
}

// assertAlive proves the instance was not poisoned by earlier hostile calls.
func assertAlive(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	cipher, err := c.NewCipher(ctx, bytes.Repeat([]byte{0x2a}, KeySize))
	if err != nil {
		t.Fatalf("instance poisoned: NewCipher: %v", err)
	}
	defer func() { _ = cipher.Close(ctx) }()
	aad := []byte("liveness")
	ct, err := cipher.Encrypt(ctx, "still alive", aad)
	if err != nil {
		t.Fatalf("instance poisoned: Encrypt: %v", err)
	}
	got, err := cipher.Decrypt(ctx, ct, aad)
	if err != nil {
		t.Fatalf("instance poisoned: Decrypt: %v", err)
	}
	if got != "still alive" {
		t.Fatalf("round trip after hostile calls: got %v", got)
	}
}

func TestGuestRejectsHostilePointerLengthPairs(t *testing.T) {
	ctx := context.Background()
	c := newRawClient(t)

	// A null pointer with a nonzero length must fail closed, not read as an
	// empty input.
	res, err := c.cipherInit.Call(ctx, 0, uint64(KeySize))
	if err != nil {
		t.Fatalf("cipher init with null pointer trapped: %v", err)
	}
	if _, cerr := packedResult(res[0]); !errors.Is(cerr, ErrEncoding) {
		t.Fatalf("null key pointer: got %v, want ErrEncoding", cerr)
	}

	buf, err := c.allocWrite(ctx, bytes.Repeat([]byte{0x2a}, KeySize))
	if err != nil {
		t.Fatalf("allocWrite: %v", err)
	}
	defer c.free(ctx, buf)

	// Lengths reaching past linear memory (and past isize::MAX) must be
	// rejected before any read happens.
	for _, hostileLen := range []uint64{0x7FFF_FFF0, 0xFFFF_FFFF} {
		res, err := c.cipherInit.Call(ctx, uint64(buf.ptr), hostileLen)
		if err != nil {
			t.Fatalf("cipher init with len %#x trapped: %v", hostileLen, err)
		}
		if _, cerr := packedResult(res[0]); !errors.Is(cerr, ErrEncoding) {
			t.Fatalf("hostile len %#x: got %v, want ErrEncoding", hostileLen, cerr)
		}
	}

	// A wrong key length is an encoding error at the boundary, distinguishable
	// from an internal crypto failure.
	res, err = c.cipherInit.Call(ctx, uint64(buf.ptr), 16)
	if err != nil {
		t.Fatalf("cipher init with short key trapped: %v", err)
	}
	if _, cerr := packedResult(res[0]); !errors.Is(cerr, ErrEncoding) {
		t.Fatalf("short key: got %v, want ErrEncoding", cerr)
	}

	assertAlive(t, c)
}

func TestGuestAllocFailureReturnsNullNotTrap(t *testing.T) {
	ctx := context.Background()
	c := newRawClient(t)

	// An impossible allocation (over isize::MAX on wasm32) must return null —
	// the documented contract allocWrite's guard is written against — rather
	// than aborting and killing the instance.
	res, err := c.alloc.Call(ctx, 0xFFFF_FFFF)
	if err != nil {
		t.Fatalf("vc_alloc trapped: %v", err)
	}
	if res[0] != 0 {
		t.Fatalf("vc_alloc(0xFFFFFFFF): got %#x, want null", res[0])
	}

	// A reasonable allocation still succeeds afterwards.
	buf, err := c.allocWrite(ctx, make([]byte, 64))
	if err != nil {
		t.Fatalf("alloc after failed alloc: %v", err)
	}
	c.free(ctx, buf)

	assertAlive(t, c)
}

func TestGuestDeallocRefusesUnknownAndMismatchedFrees(t *testing.T) {
	ctx := context.Background()
	c := newRawClient(t)

	// A pointer the guest never handed out: no-op, no trap.
	if _, err := c.dealloc.Call(ctx, 0x1000, 16); err != nil {
		t.Fatalf("dealloc of unknown pointer trapped: %v", err)
	}

	buf, err := c.allocWrite(ctx, []byte("sixteen bytes!!!"))
	if err != nil {
		t.Fatalf("allocWrite: %v", err)
	}
	// A mismatched length: refused (the buffer stays live), no trap and no
	// heap corruption from freeing with the wrong layout.
	if _, err := c.dealloc.Call(ctx, uint64(buf.ptr), uint64(buf.len)*2); err != nil {
		t.Fatalf("dealloc with wrong length trapped: %v", err)
	}
	// The correct free still works, and a double-free is a no-op.
	c.free(ctx, buf)
	if _, err := c.dealloc.Call(ctx, uint64(buf.ptr), uint64(buf.len)); err != nil {
		t.Fatalf("double free trapped: %v", err)
	}

	assertAlive(t, c)
}

func TestGuestRejectsNullAadWithNonzeroLength(t *testing.T) {
	ctx := context.Background()
	c := newRawClient(t)
	cipher, err := c.NewCipher(ctx, bytes.Repeat([]byte{0x2a}, KeySize))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	defer func() { _ = cipher.Close(ctx) }()

	encoded, err := vcffi.Marshal("attack at dawn")
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	valBuf, err := c.allocWrite(ctx, encoded)
	if err != nil {
		t.Fatalf("allocWrite: %v", err)
	}
	defer c.free(ctx, valBuf)

	// A null AAD pointer with a nonzero claimed length must fail closed:
	// sealing under a silently empty AAD would drop the context binding.
	res, err := c.encrypt.Call(ctx,
		uint64(cipher.handle),
		uint64(valBuf.ptr), uint64(valBuf.len),
		0, 7,
	)
	if err != nil {
		t.Fatalf("vc_encrypt with null aad trapped: %v", err)
	}
	if _, cerr := packedResult(res[0]); !errors.Is(cerr, ErrEncoding) {
		t.Fatalf("null aad with nonzero len: got %v, want ErrEncoding", cerr)
	}

	assertAlive(t, c)
}
