package vcvalue

import "testing"

// White-box pin for eagerCap, mirroring the Rust transport codec's
// eager_capacity test: the clamp is a capacity hint invisible to round-trip
// tests, so assert the function directly — identity below the threshold,
// flat at maxEagerCapacity above it.
func TestEagerCapClampsOnlyAboveThreshold(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, 0},
		{5, 5},
		{maxEagerCapacity, maxEagerCapacity},
		{maxEagerCapacity + 1, maxEagerCapacity},
		{1 << 30, maxEagerCapacity},
	}
	for _, c := range cases {
		if got := eagerCap(c.in); got != c.want {
			t.Fatalf("eagerCap(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}
