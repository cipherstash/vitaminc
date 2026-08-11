package vcencrypt

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

// KeySize is the required key length in bytes (AES-256-GCM).
const KeySize = 32

// Distinguishable failure kinds surfaced across the boundary. Decryption
// still reveals nothing about the plaintext — these only separate an
// authentication failure from a malformed input or a stale handle.
var (
	// ErrAuthentication is an AEAD open failure: wrong key, wrong AAD, or a
	// tampered ciphertext. They are deliberately indistinguishable from one
	// another.
	ErrAuthentication = errors.New("vcencrypt: authentication failed")
	// ErrEncoding is a malformed transport payload (a bad ciphertext or value
	// tree handed to the guest).
	ErrEncoding = errors.New("vcencrypt: malformed transport encoding")
	// ErrBadHandle is an unknown cipher handle — never issued, or used after
	// Close.
	ErrBadHandle = errors.New("vcencrypt: unknown or freed cipher handle")
	// ErrInternal is a guest panic or any other unexpected internal failure.
	ErrInternal = errors.New("vcencrypt: internal guest failure")
)

// Guest status codes (see guest/src/abi.rs). Kept in lockstep with the Rust
// STATUS_* constants.
const (
	statusAuth      = 1
	statusEncoding  = 2
	statusBadHandle = 3
	statusInternal  = 4
)

func statusError(status uint32) error {
	switch status {
	case statusAuth:
		return ErrAuthentication
	case statusEncoding:
		return ErrEncoding
	case statusBadHandle:
		return ErrBadHandle
	default:
		return ErrInternal
	}
}

// A single shared compilation cache means only the first NewClient in a
// process compiles the guest module; later Clients reuse the cached machine
// code. The cache is safe for concurrent use across runtimes; each Client
// still owns its own runtime and instance and serializes calls with a mutex.
var (
	cacheOnce   sync.Once
	sharedCache wazero.CompilationCache
)

func compilationCache() wazero.CompilationCache {
	cacheOnce.Do(func() { sharedCache = wazero.NewCompilationCache() })
	return sharedCache
}

// Client wraps one instance of the wasm guest. It is safe for concurrent use;
// calls are serialized internally (wasm instances are single-threaded).
// Ciphers created from it share the instance and that serialization.
type Client struct {
	runtime wazero.Runtime

	mu             sync.Mutex
	module         api.Module
	alloc          api.Function
	dealloc        api.Function
	cipherInit     api.Function
	cipherFree     api.Function
	encrypt        api.Function
	decrypt        api.Function
	encryptElement api.Function
	decryptElement api.Function
}

// NewClient instantiates the embedded guest module, reusing a process-wide
// compilation cache so only the first client pays the compile cost.
func NewClient(ctx context.Context) (*Client, error) {
	config := wazero.NewRuntimeConfig().WithCompilationCache(compilationCache())
	runtime := wazero.NewRuntimeWithConfig(ctx, config)
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)

	module, err := runtime.Instantiate(ctx, guestWasm)
	if err != nil {
		_ = runtime.Close(ctx)
		return nil, fmt.Errorf("vcencrypt: instantiating guest: %w", err)
	}

	c := &Client{
		runtime:        runtime,
		module:         module,
		alloc:          module.ExportedFunction("vc_alloc"),
		dealloc:        module.ExportedFunction("vc_dealloc"),
		cipherInit:     module.ExportedFunction("vc_cipher_init"),
		cipherFree:     module.ExportedFunction("vc_cipher_free"),
		encrypt:        module.ExportedFunction("vc_encrypt"),
		decrypt:        module.ExportedFunction("vc_decrypt"),
		encryptElement: module.ExportedFunction("vc_encrypt_element"),
		decryptElement: module.ExportedFunction("vc_decrypt_element"),
	}
	if c.alloc == nil || c.dealloc == nil || c.cipherInit == nil ||
		c.cipherFree == nil || c.encrypt == nil || c.decrypt == nil ||
		c.encryptElement == nil || c.decryptElement == nil {
		_ = runtime.Close(ctx)
		return nil, errors.New("vcencrypt: guest is missing required exports")
	}
	return c, nil
}

// Close releases the wasm runtime and all guest memory (including any cipher
// sessions still open).
func (c *Client) Close(ctx context.Context) error {
	return c.runtime.Close(ctx)
}

// Cipher is a handle to a key schedule living inside the guest. Create one
// with NewCipher and release it with Close. All of its methods run on the
// owning Client's serialized instance.
type Cipher struct {
	client *Client
	handle uint32
}

// NewCipher loads a 32-byte key into the guest and returns a handle to the
// resulting cipher. The key material is copied into the guest, where it is
// zeroized immediately after the key schedule is built; the Go-side copy this
// method makes is wiped before returning. (Neither wipe can cover copies the
// Go runtime or the caller may hold — treat process memory as sensitive.)
func (c *Client) NewCipher(ctx context.Context, key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("vcencrypt: key must be %d bytes", KeySize)
	}
	// Own a copy so we can wipe it; the caller's slice is theirs to manage.
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	defer wipe(keyCopy)

	c.mu.Lock()
	defer c.mu.Unlock()

	keyBuf, err := c.allocWrite(ctx, keyCopy)
	if err != nil {
		return nil, err
	}
	defer c.free(ctx, keyBuf)

	res, err := c.cipherInit.Call(ctx, uint64(keyBuf.ptr), uint64(keyBuf.len))
	if err != nil {
		return nil, fmt.Errorf("vcencrypt: cipher init: %w", err)
	}
	handle, cerr := handleResult(res[0])
	if cerr != nil {
		return nil, cerr
	}
	return &Cipher{client: c, handle: handle}, nil
}

// Encrypt seals v under this cipher. v is encoded through the vcvalue
// model: builtins, slices, maps and structs are handled by reflection, a
// type implementing vcvalue.Encryptable controls its own encoding, and a
// vcvalue.Plain marks a field to travel in the clear (passthrough). aad is
// authenticated but not encrypted; the same aad must be presented to Decrypt.
//
// The ciphertext comes back as ordinary Go values mirroring the plaintext's
// structure: vcvalue.Sealed leaves where fields were encrypted, vcvalue.Plain
// where they passed through, map[string]any for records (directly bindable as
// database named parameters), []any for sequences.
func (cph *Cipher) Encrypt(ctx context.Context, v any, aad []byte) (any, error) {
	encoded, err := vcvalue.Marshal(v)
	if err != nil {
		return nil, err
	}
	out, err := cph.client.call(ctx, cph.client.encrypt, cph.handle, aad, encoded)
	if err != nil {
		return nil, err
	}
	return vcvalue.UnmarshalCipherText(out)
}

// Decrypt opens a ciphertext produced by Encrypt (in any language) with the
// same cipher and aad. ct takes the same dynamic shape Encrypt returns —
// e.g. a map[string]any of vcvalue.Sealed leaves loaded back from database
// columns; any subset of a record's entries decrypts. The plaintext is
// returned in vcvalue's decode shape (Go natives, vcvalue.Object for maps,
// and vcvalue.Plain for passthrough fields).
func (cph *Cipher) Decrypt(ctx context.Context, ct any, aad []byte) (any, error) {
	encoded, err := vcvalue.MarshalCipherText(ct)
	if err != nil {
		return nil, err
	}
	out, err := cph.client.call(ctx, cph.client.decrypt, cph.handle, aad, encoded)
	if err != nil {
		return nil, err
	}
	return vcvalue.Unmarshal(out)
}

// EncryptElement seals v as a *sequence element* of the logical collection
// identified by aad — byte-identical to what Encrypt of a whole slice binds
// per element. Use it to insert a single row into a collection whose other
// rows were (or will be) written by batch-encrypting a slice under the same
// aad: rows from both paths interchange freely.
func (cph *Cipher) EncryptElement(ctx context.Context, v any, aad []byte) (any, error) {
	encoded, err := vcvalue.Marshal(v)
	if err != nil {
		return nil, err
	}
	out, err := cph.client.call(ctx, cph.client.encryptElement, cph.handle, aad, encoded)
	if err != nil {
		return nil, err
	}
	return vcvalue.UnmarshalCipherText(out)
}

// DecryptElement opens a ciphertext that was sealed as a sequence element —
// a single row of a collection encrypted with Encrypt of a slice (or with
// EncryptElement) under the same aad. Sequence elements are authenticated
// against a derivation of the collection's aad, not the bare aad, so Decrypt
// cannot open a lone row; DecryptElement performs that derivation internally.
// As with element order, *which* element (and how many) is a caller
// obligation, not an authenticated fact.
func (cph *Cipher) DecryptElement(ctx context.Context, ct any, aad []byte) (any, error) {
	encoded, err := vcvalue.MarshalCipherText(ct)
	if err != nil {
		return nil, err
	}
	out, err := cph.client.call(ctx, cph.client.decryptElement, cph.handle, aad, encoded)
	if err != nil {
		return nil, err
	}
	return vcvalue.Unmarshal(out)
}

// Close frees the cipher's key schedule inside the guest. Using the Cipher
// afterwards returns ErrBadHandle. Close is idempotent-safe to call once;
// double Close frees an unknown handle (a no-op in the guest).
func (cph *Cipher) Close(ctx context.Context) error {
	cph.client.mu.Lock()
	defer cph.client.mu.Unlock()
	_, err := cph.client.cipherFree.Call(ctx, uint64(cph.handle))
	if err != nil {
		return fmt.Errorf("vcencrypt: cipher free: %w", err)
	}
	return nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// guestBuf is a host-owned allocation inside guest linear memory.
type guestBuf struct {
	ptr uint32
	len uint32
}

func (c *Client) allocWrite(ctx context.Context, data []byte) (guestBuf, error) {
	res, err := c.alloc.Call(ctx, uint64(len(data)))
	if err != nil {
		return guestBuf{}, fmt.Errorf("vcencrypt: guest alloc: %w", err)
	}
	buf := guestBuf{ptr: uint32(res[0]), len: uint32(len(data))}
	if buf.ptr == 0 {
		return guestBuf{}, errors.New("vcencrypt: guest allocation failed")
	}
	if len(data) > 0 && !c.module.Memory().Write(buf.ptr, data) {
		return guestBuf{}, errors.New("vcencrypt: guest memory write out of range")
	}
	return buf, nil
}

// free zeroizes and releases a guest buffer (vc_dealloc wipes).
func (c *Client) free(ctx context.Context, buf guestBuf) {
	if buf.ptr != 0 {
		_, _ = c.dealloc.Call(ctx, uint64(buf.ptr), uint64(buf.len))
	}
}

// handleResult decodes a vc_cipher_init result: high 32 bits are the handle
// on success, or an error status in the low 32 bits.
func handleResult(packed uint64) (uint32, error) {
	if packed>>32 == 0 {
		return 0, statusError(uint32(packed))
	}
	return uint32(packed >> 32), nil
}

// call runs an encrypt/decrypt guest function under handle, staging aad and
// payload into guest memory and copying the output back out.
func (c *Client) call(ctx context.Context, fn api.Function, handle uint32, aad, payload []byte) ([]byte, error) {
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

	payloadBuf, err := stage(payload)
	if err != nil {
		return nil, err
	}
	aadBuf, err := stage(aad)
	if err != nil {
		return nil, err
	}

	res, err := fn.Call(ctx,
		uint64(handle),
		uint64(payloadBuf.ptr), uint64(payloadBuf.len),
		uint64(aadBuf.ptr), uint64(aadBuf.len),
	)
	if err != nil {
		return nil, fmt.Errorf("vcencrypt: guest call: %w", err)
	}
	packed := res[0]
	if packed>>32 == 0 {
		return nil, statusError(uint32(packed))
	}

	outBuf := guestBuf{ptr: uint32(packed >> 32), len: uint32(packed & 0xFFFFFFFF)}
	bufs = append(bufs, outBuf)
	out, ok := c.module.Memory().Read(outBuf.ptr, outBuf.len)
	if !ok {
		return nil, errors.New("vcencrypt: guest returned an out-of-range buffer")
	}
	// Copy out before the deferred free wipes the guest-side buffer.
	result := make([]byte, len(out))
	copy(result, out)
	return result, nil
}
