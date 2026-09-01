package vcffi

import (
	"encoding/binary"
	"math"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// Unmarshal decodes value transport bytes into Go natives:
//
//   - Null and Undefined → nil (Go has no undefined analog);
//   - Bool               → bool;
//   - Int32              → int32;
//   - Int64              → int64;
//   - UInt32             → uint32;
//   - UInt64             → uint64;
//   - Float32            → float32;
//   - Float64            → float64;
//   - String             → string;
//   - Bytes              → []byte;
//   - Array              → []any;
//   - vcvalue.Object             → vcvalue.Object (ordered []Field);
//   - Passthrough        → vcvalue.Plain{V: <decoded value>} (the clear-field marker).
//
// Go maps exactly in both directions — the 32-bit tags decode to int32 /
// uint32 / float32, not widened to 64-bit — unlike JavaScript, which widens
// every numeric tag to a JS number on decode.
//
// This self-describing shape is deliberately spike-scoped. A reflection-based
// unmarshal into caller structs (the mirror of Encode) is future work.
func Unmarshal(buf []byte) (any, error) {
	r := &reader{buf: buf}
	v, err := decodeValue(r, 0)
	if err != nil {
		return nil, err
	}
	if !r.finished() {
		return nil, ErrMalformed
	}
	return v, nil
}

func decodeValue(r *reader, depth int) (any, error) {
	if depth > maxDepth {
		return nil, ErrMalformed
	}
	tag, err := r.byteTag()
	if err != nil {
		return nil, err
	}
	switch tag {
	case tagNull, tagUndefined:
		return nil, nil
	case tagFalse:
		return false, nil
	case tagTrue:
		return true, nil
	case tagInt32:
		s, err := r.take(4)
		if err != nil {
			return nil, err
		}
		return int32(binary.LittleEndian.Uint32(s)), nil
	case tagInt64:
		s, err := r.take(8)
		if err != nil {
			return nil, err
		}
		return int64(binary.LittleEndian.Uint64(s)), nil
	case tagUint32:
		s, err := r.take(4)
		if err != nil {
			return nil, err
		}
		return binary.LittleEndian.Uint32(s), nil
	case tagUint64:
		s, err := r.take(8)
		if err != nil {
			return nil, err
		}
		return binary.LittleEndian.Uint64(s), nil
	case tagFloat32:
		s, err := r.take(4)
		if err != nil {
			return nil, err
		}
		return math.Float32frombits(binary.LittleEndian.Uint32(s)), nil
	case tagFloat64:
		s, err := r.take(8)
		if err != nil {
			return nil, err
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(s)), nil
	case tagString:
		return r.str()
	case tagBytes:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		s, err := r.take(n)
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(s))
		copy(out, s)
		return out, nil
	case tagArray:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		items := make([]any, 0, eagerCap(n))
		for range n {
			item, err := decodeValue(r, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return items, nil
	case tagObject:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		fields := make(vcvalue.Object, 0, eagerCap(n))
		// Duplicate keys are rejected as on the ciphertext decode path (and
		// both Rust decoders): an vcvalue.Object with duplicates cannot survive a
		// re-encode through a Go map without silently dropping an entry.
		seen := make(map[string]struct{}, eagerCap(n))
		for range n {
			key, err := r.str()
			if err != nil {
				return nil, err
			}
			if _, dup := seen[key]; dup {
				return nil, ErrMalformed
			}
			seen[key] = struct{}{}
			value, err := decodeValue(r, depth+1)
			if err != nil {
				return nil, err
			}
			fields = append(fields, vcvalue.Field{Key: key, Value: value})
		}
		return fields, nil
	case tagPassthrough:
		// A passthrough value surfaces as vcvalue.Plain{V: <decoded value>}, the
		// mirror of the Encoder's vcvalue.Plain opt-in, so a caller can tell the
		// field travelled in the clear.
		inner, err := decodeValue(r, depth+1)
		if err != nil {
			return nil, err
		}
		return vcvalue.Plain{V: inner}, nil
	default:
		return nil, ErrMalformed
	}
}
