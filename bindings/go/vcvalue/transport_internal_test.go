package vcvalue

import "testing"

// eagerCap is the guard against the summed-reservation hazard: nested
// containers each claiming a huge count would otherwise multiply their
// pre-allocations before any element fails to parse. A round trip can never
// observe the clamp (append grows past the initial capacity regardless), so
// the constant and the min behaviour are pinned here directly — the same
// reasoning as the Rust codec's eager_capacity mutant pin.
func TestEagerCapClampsHostileCounts(t *testing.T) {
	if maxEagerCapacity != 1024 {
		t.Fatalf("maxEagerCapacity: got %d, want 1024", maxEagerCapacity)
	}
	if got := eagerCap(0); got != 0 {
		t.Fatalf("eagerCap(0): got %d, want 0", got)
	}
	if got := eagerCap(maxEagerCapacity - 1); got != maxEagerCapacity-1 {
		t.Fatalf("eagerCap(max-1): got %d, want %d", got, maxEagerCapacity-1)
	}
	if got := eagerCap(maxEagerCapacity); got != maxEagerCapacity {
		t.Fatalf("eagerCap(max): got %d, want %d", got, maxEagerCapacity)
	}
	if got := eagerCap(1 << 30); got != maxEagerCapacity {
		t.Fatalf("eagerCap(1<<30): got %d, want %d", got, maxEagerCapacity)
	}
}
