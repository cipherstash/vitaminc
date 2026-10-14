package vcencrypt

import (
	"context"
	"slices"
	"testing"

	"github.com/tetratelabs/wazero"
)

// TestGuestWASIImports fails when a guest rebuild adds or drops a WASI
// import. wazero's defaults for host services are deterministic (fixed-seed
// random_get, fake clocks), so any change here needs a check that
// guestModuleConfig still supplies real host sources for what the guest uses.
func TestGuestWASIImports(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)
	compiled, err := rt.CompileModule(ctx, guestWasm)
	if err != nil {
		t.Fatalf("compiling embedded guest: %v", err)
	}
	defer compiled.Close(ctx)

	var got []string
	for _, fn := range compiled.ImportedFunctions() {
		module, name, _ := fn.Import()
		got = append(got, module+":"+name)
	}
	slices.Sort(got)
	want := []string{
		"wasi_snapshot_preview1:environ_get",
		"wasi_snapshot_preview1:environ_sizes_get",
		"wasi_snapshot_preview1:fd_write",
		"wasi_snapshot_preview1:proc_exit",
		"wasi_snapshot_preview1:random_get",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("guest imports changed; review guestModuleConfig, then update this list.\n got %q\nwant %q", got, want)
	}
}
