package vitaminc

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"sync"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed wasm/vitaminc_guest.wasm
var guestWasm []byte

// ErrUnspecified is returned for any cryptographic failure. No detail is
// available by design.
var ErrUnspecified = errors.New("vitaminc: encryption operation failed")

// KeySize is the required key length in bytes (AES-256-GCM).
const KeySize = 32

// Client wraps one instance of the wasm guest. It is safe for concurrent
// use; calls are serialized internally (wasm instances are
// single-threaded).
type Client struct {
	runtime wazero.Runtime

	mu      sync.Mutex
	module  api.Module
	alloc   api.Function
	dealloc api.Function
	encrypt api.Function
	decrypt api.Function
}

// NewClient instantiates the embedded guest module.
func NewClient(ctx context.Context) (*Client, error) {
	runtime := wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)

	module, err := runtime.Instantiate(ctx, guestWasm)
	if err != nil {
		_ = runtime.Close(ctx)
		return nil, fmt.Errorf("vitaminc: instantiating guest: %w", err)
	}

	c := &Client{
		runtime: runtime,
		module:  module,
		alloc:   module.ExportedFunction("vc_alloc"),
		dealloc: module.ExportedFunction("vc_dealloc"),
		encrypt: module.ExportedFunction("vc_encrypt"),
		decrypt: module.ExportedFunction("vc_decrypt"),
	}
	if c.alloc == nil || c.dealloc == nil || c.encrypt == nil || c.decrypt == nil {
		_ = runtime.Close(ctx)
		return nil, errors.New("vitaminc: guest is missing required exports")
	}
	return c, nil
}

// Close releases the wasm runtime and all guest memory.
func (c *Client) Close(ctx context.Context) error {
	return c.runtime.Close(ctx)
}

// Encrypt seals v with the 32-byte key. v is encoded through the vcvalue
// currency: builtins, slices, maps and structs are handled by reflection,
// and any type implementing vcvalue.Encryptable controls its own encoding.
// aad is authenticated but not encrypted; the same aad must be presented to
// Decrypt.
func (c *Client) Encrypt(ctx context.Context, key []byte, v any, aad []byte) (vcvalue.CipherText, error) {
	encoded, err := vcvalue.Marshal(v)
	if err != nil {
		return vcvalue.CipherText{}, err
	}
	out, err := c.call(ctx, c.encrypt, key, aad, encoded)
	if err != nil {
		return vcvalue.CipherText{}, err
	}
	return vcvalue.UnmarshalCipherText(out)
}

// Decrypt opens a ciphertext produced by Encrypt (in any language) with the
// same key and aad. The plaintext is returned in vcvalue's decode shape (Go
// natives plus vcvalue.Object for maps).
func (c *Client) Decrypt(ctx context.Context, key []byte, ct vcvalue.CipherText, aad []byte) (any, error) {
	encoded, err := ct.MarshalTransport()
	if err != nil {
		return nil, err
	}
	out, err := c.call(ctx, c.decrypt, key, aad, encoded)
	if err != nil {
		return nil, err
	}
	return vcvalue.Unmarshal(out)
}

// guestBuf is a host-owned allocation inside guest linear memory.
type guestBuf struct {
	ptr uint32
	len uint32
}

func (c *Client) allocWrite(ctx context.Context, data []byte) (guestBuf, error) {
	res, err := c.alloc.Call(ctx, uint64(len(data)))
	if err != nil {
		return guestBuf{}, fmt.Errorf("vitaminc: guest alloc: %w", err)
	}
	buf := guestBuf{ptr: uint32(res[0]), len: uint32(len(data))}
	if buf.ptr == 0 {
		return guestBuf{}, errors.New("vitaminc: guest allocation failed")
	}
	if len(data) > 0 && !c.module.Memory().Write(buf.ptr, data) {
		return guestBuf{}, errors.New("vitaminc: guest memory write out of range")
	}
	return buf, nil
}

// free zeroizes and releases a guest buffer (vc_dealloc wipes).
func (c *Client) free(ctx context.Context, buf guestBuf) {
	if buf.ptr != 0 {
		_, _ = c.dealloc.Call(ctx, uint64(buf.ptr), uint64(buf.len))
	}
}

func (c *Client) call(ctx context.Context, fn api.Function, key, aad, payload []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("vitaminc: key must be %d bytes", KeySize)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var bufs []guestBuf
	defer func() {
		for _, b := range bufs {
			c.free(ctx, b)
		}
	}()

	stage := func(data []byte) (guestBuf, error) {
		buf, err := c.allocWrite(ctx, data)
		if err == nil {
			bufs = append(bufs, buf)
		}
		return buf, err
	}

	keyBuf, err := stage(key)
	if err != nil {
		return nil, err
	}
	aadBuf, err := stage(aad)
	if err != nil {
		return nil, err
	}
	payloadBuf, err := stage(payload)
	if err != nil {
		return nil, err
	}

	res, err := fn.Call(ctx,
		uint64(keyBuf.ptr), uint64(keyBuf.len),
		uint64(aadBuf.ptr), uint64(aadBuf.len),
		uint64(payloadBuf.ptr), uint64(payloadBuf.len),
	)
	if err != nil {
		return nil, fmt.Errorf("vitaminc: guest call: %w", err)
	}
	packed := res[0]
	if packed == 0 {
		return nil, ErrUnspecified
	}

	outBuf := guestBuf{ptr: uint32(packed >> 32), len: uint32(packed & 0xFFFFFFFF)}
	bufs = append(bufs, outBuf)
	out, ok := c.module.Memory().Read(outBuf.ptr, outBuf.len)
	if !ok {
		return nil, errors.New("vitaminc: guest returned an out-of-range buffer")
	}
	// Copy out before the deferred free wipes the guest-side buffer.
	result := make([]byte, len(out))
	copy(result, out)
	return result, nil
}
