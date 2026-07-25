package vcvalue

import (
	"database/sql/driver"
	"fmt"
	"math"
)

// Sealed is one encrypted leaf: nonce || ciphertext || tag — the only frozen
// byte format in the model. It is a named type so sealed bytes can never be
// confused with a plaintext []byte value in the dynamic ciphertext shape.
//
// Sealed implements driver.Valuer and sql.Scanner, so it stores into and
// loads from a BLOB/BYTEA column with no conversion.
type Sealed []byte

// Value implements driver.Valuer: a Sealed binds as raw bytes.
func (s Sealed) Value() (driver.Value, error) {
	return []byte(s), nil
}

// Scan implements sql.Scanner: a BLOB/BYTEA column loads as a Sealed.
func (s *Sealed) Scan(src any) error {
	switch b := src.(type) {
	case nil:
		*s = nil
	case []byte:
		*s = append(Sealed(nil), b...)
	default:
		return fmt.Errorf("vcvalue: cannot scan %T into Sealed", src)
	}
	return nil
}

// SealedNone is the authenticated absent marker: a sealed empty plaintext
// whose tag still binds the AAD, so an absence cannot be forged.
//
// The value model has no "absent" of its own — a missing field is Null — so
// nothing on this side of the boundary produces a SealedNone. It exists
// because the container it mirrors does: a Rust cipher driven directly can
// seal an Option::None, and such a ciphertext must survive the round trip
// rather than being rejected or silently flattened into a Sealed.
type SealedNone []byte

// Value implements driver.Valuer for passthrough fields, so a map-shaped
// ciphertext binds directly as database named parameters. Only scalar
// natives convert; a container passthrough has no single-column form.
func (p Plain) Value() (driver.Value, error) {
	switch v := p.V.(type) {
	case nil, bool, int64, float64, string, []byte:
		return v, nil
	case int32:
		return int64(v), nil
	case uint32:
		return int64(v), nil
	case float32:
		return float64(v), nil
	case uint64:
		if v > math.MaxInt64 {
			return nil, fmt.Errorf("vcvalue: passthrough uint64 %d overflows the driver's int64", v)
		}
		return int64(v), nil
	default:
		return nil, fmt.Errorf("vcvalue: passthrough %T has no single-column driver representation", p.V)
	}
}
