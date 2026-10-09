package vcencrypt

import (
	"bytes"
	"context"
	"encoding/binary"
	"math/rand"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// wasiProbe is a hand-assembled WebAssembly module. It forwards WASI's
// random_get and clock_time_get so the test can inspect guestModuleConfig
// without calling ZeroKMS or changing the real guest. Its WAT equivalent is:
//
//	(module
//	  (import "wasi_snapshot_preview1" "random_get"
//	    (func $random_get (param i32 i32) (result i32)))
//	  (import "wasi_snapshot_preview1" "clock_time_get"
//	    (func $clock_time_get (param i32 i64 i32) (result i32)))
//	  (memory (export "memory") 1)
//	  (func (export "random_get") (param i32 i32) (result i32)
//	    local.get 0 local.get 1 call $random_get)
//	  (func (export "clock_time_get") (param i32 i64 i32) (result i32)
//	    local.get 0 local.get 1 local.get 2 call $clock_time_get))
var wasiProbe = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0e, 0x02, 0x60,
	0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x60, 0x03, 0x7f, 0x7e, 0x7f, 0x01, 0x7f,
	0x02, 0x4d, 0x02, 0x16, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73, 0x6e, 0x61,
	0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69, 0x65,
	0x77, 0x31, 0x0a, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x65,
	0x74, 0x00, 0x00, 0x16, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73, 0x6e, 0x61,
	0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69, 0x65,
	0x77, 0x31, 0x0e, 0x63, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x74, 0x69, 0x6d,
	0x65, 0x5f, 0x67, 0x65, 0x74, 0x00, 0x01, 0x03, 0x03, 0x02, 0x00, 0x01,
	0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x28, 0x03, 0x06, 0x6d, 0x65, 0x6d,
	0x6f, 0x72, 0x79, 0x02, 0x00, 0x0a, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d,
	0x5f, 0x67, 0x65, 0x74, 0x00, 0x02, 0x0e, 0x63, 0x6c, 0x6f, 0x63, 0x6b,
	0x5f, 0x74, 0x69, 0x6d, 0x65, 0x5f, 0x67, 0x65, 0x74, 0x00, 0x03, 0x0a,
	0x15, 0x02, 0x08, 0x00, 0x20, 0x00, 0x20, 0x01, 0x10, 0x00, 0x0b, 0x0a,
	0x00, 0x20, 0x00, 0x20, 0x01, 0x20, 0x02, 0x10, 0x01, 0x0b,
}

// probe instantiates wasiProbe with the same module configuration as NewClient.
func probe(t *testing.T, ctx context.Context) (wazero.Runtime, func(n uint32) []byte, func(id uint64) time.Duration) {
	t.Helper()
	rt := wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, rt)
	mod, err := rt.InstantiateWithConfig(ctx, wasiProbe, guestModuleConfig())
	if err != nil {
		t.Fatalf("instantiating probe: %v", err)
	}
	randomGet := mod.ExportedFunction("random_get")
	clockTimeGet := mod.ExportedFunction("clock_time_get")
	random := func(n uint32) []byte {
		if res, err := randomGet.Call(ctx, 0, uint64(n)); err != nil || res[0] != 0 {
			t.Fatalf("random_get: errno %v err %v", res, err)
		}
		out, ok := mod.Memory().Read(0, n)
		if !ok {
			t.Fatal("reading probe memory")
		}
		return bytes.Clone(out)
	}
	// clock_time_get(id, precision, out_ptr) writes u64 nanoseconds.
	clock := func(id uint64) time.Duration {
		if res, err := clockTimeGet.Call(ctx, id, 1, 64); err != nil || res[0] != 0 {
			t.Fatalf("clock_time_get: errno %v err %v", res, err)
		}
		raw, ok := mod.Memory().Read(64, 8)
		if !ok {
			t.Fatal("reading probe memory")
		}
		return time.Duration(binary.LittleEndian.Uint64(raw))
	}
	return rt, random, clock
}

// TestGuestModuleConfigUsesHostRandomAndClocks checks that the guest uses
// the host's CSPRNG and clocks instead of wazero's deterministic defaults.
// A fixed seed would give every Client the same AES-GCM nonce sequence
// when callers reuse a key across clients.
func TestGuestModuleConfigUsesHostRandomAndClocks(t *testing.T) {
	ctx := context.Background()
	firstRuntime, randomFirst, clockFirst := probe(t, ctx)
	defer firstRuntime.Close(ctx)
	secondRuntime, randomSecond, _ := probe(t, ctx)
	defer secondRuntime.Close(ctx)

	const n = 32
	first, second := randomFirst(n), randomSecond(n)
	if bytes.Equal(first, second) {
		t.Fatalf("two fresh instances drew identical random bytes: %x", first)
	}
	// wazero's default is math/rand seeded with 42; neither instance may
	// start on that stream.
	wazeroDefaultStream := make([]byte, n)
	if _, err := rand.New(rand.NewSource(42)).Read(wazeroDefaultStream); err != nil {
		t.Fatalf("reading wazero's default random stream: %v", err)
	}
	for _, got := range [][]byte{first, second} {
		if bytes.Equal(got, wazeroDefaultStream) {
			t.Fatalf("random_get is wazero's fixed-seed default: %x", got)
		}
	}
	// WASI clock ID 0 is wall time. Its value should be close to the host clock.
	beforeWall := time.Now()
	wall := time.Unix(0, int64(clockFirst(0)))
	afterWall := time.Now()
	if wall.Before(beforeWall.Add(-time.Minute)) || wall.After(afterWall.Add(time.Minute)) {
		t.Fatalf("wall clock returned %v, outside host interval %v to %v", wall, beforeWall, afterWall)
	}

	// The fake clock advances 1ms per read regardless of elapsed time, so
	// two reads around a sleep are 1ms apart on it and the whole sleep
	// apart on the host's. The floor is half the sleep, not all of it: on
	// Windows the sleep timer and the monotonic source are different
	// clocks, and a sleep can return a fraction of a millisecond before
	// the monotonic clock says the interval has passed. Half still leaves
	// an order of magnitude between the two answers.
	const sleep = 20 * time.Millisecond
	before := clockFirst(1)
	time.Sleep(sleep)
	if elapsed := clockFirst(1) - before; elapsed < sleep/2 {
		t.Fatalf("monotonic clock advanced %v across a %v sleep: not the host clock", elapsed, sleep)
	}
}

// Keep the guest's entropy dependency visible: if its getrandom backend
// changes, the host configuration and nonce safety need another review.
func TestGuestImportsWASIRandomGet(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)
	compiled, err := rt.CompileModule(ctx, guestWasm)
	if err != nil {
		t.Fatalf("compiling embedded guest: %v", err)
	}
	defer compiled.Close(ctx)
	for _, fn := range compiled.ImportedFunctions() {
		module, name, ok := fn.Import()
		if ok && module == "wasi_snapshot_preview1" && name == "random_get" {
			return
		}
	}
	t.Fatal("guest no longer imports wasi_snapshot_preview1:random_get")
}
