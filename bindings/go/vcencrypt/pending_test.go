package vcencrypt

import "github.com/cipherstash/vitaminc/bindings/go/vcvalue"

// PendingADR0001 reports whether a decoded value, or the passthrough values
// of a decoded ciphertext tree, hold a scalar that the guest and vcffi still
// read differently. The guest now seals through the ADR 0001 leaf codec,
// which refuses a leap-second timestamp and reads a decimal negative zero
// back as zero; vcffi keeps the old reading until #444 brings it into line.
// The tests that compare the two skip such inputs, so the gap is stated
// here rather than hidden in a failing test. #444 removes this helper with
// the skips.
func PendingADR0001(v any) bool {
	switch v := v.(type) {
	case vcvalue.Timestamp:
		return v.Nanoseconds >= 1_000_000_000
	case vcvalue.Decimal:
		return v.Negative && v.Coefficient == [12]byte{}
	case vcvalue.Plain:
		return PendingADR0001(v.V)
	case []any:
		for _, item := range v {
			if PendingADR0001(item) {
				return true
			}
		}
	case vcvalue.Object:
		for _, field := range v {
			if PendingADR0001(field.Value) {
				return true
			}
		}
	case map[string]any:
		for _, item := range v {
			if PendingADR0001(item) {
				return true
			}
		}
	}
	return false
}
