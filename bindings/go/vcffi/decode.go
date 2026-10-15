package vcffi

import (
	"encoding/binary"
	"math"
	"math/big"
	"time"

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
//   - Passthrough        → vcvalue.Plain{V: <decoded value>} (the clear-field marker);
//   - the 0xF3 envelope  → time.Time for a timestamp in seconds, milliseconds
//     or microseconds, vcvalue.UUID for a UUID, and vcvalue.Tagged for a
//     logical id this build does not know, which re-encodes unchanged.
//
// Go maps exactly in both directions — the 32-bit tags decode to int32 /
// uint32 / float32, not widened to 64-bit. JavaScript decodes integer tags
// as BigInt and widens Float32 to a number.
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
	return decodeTagged(r, tag, depth)
}

// decodeTagged decodes the node whose tag has just been read.
func decodeTagged(r *reader, tag byte, depth int) (any, error) {
	switch tag {
	case tagInt8, tagUint8, tagInt16, tagUint16, tagInt128, tagUint128, tagDate, tagTimestamp, tagDecimal:
		return decodeScalar(r, tag)
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
	case tagEnvelope:
		return decodeEnvelope(r)
	default:
		return nil, ErrMalformed
	}
}

// physicalTag reports whether tag is a physical scalar: one the envelope
// may carry. The logical shorthand tags (Undefined, Date, Timestamp,
// Decimal) and the containers are not.
func physicalTag(tag byte) bool {
	switch tag {
	case tagNull, tagFalse, tagTrue, tagInt32, tagInt64, tagUint32, tagUint64, tagFloat32, tagFloat64,
		tagString, tagBytes, tagInt8, tagUint8, tagInt16, tagUint16, tagInt128, tagUint128:
		return true
	}
	return false
}

// decodeEnvelope reads the 0xF3 envelope after its tag: a logical id, a
// parameter, and a physical scalar. There is one encoding per value, so an
// envelope over a type with a shorthand tag, an id of zero, or a known id
// with a parameter it cannot take is malformed (ADR 0001 section 3).
func decodeEnvelope(r *reader) (any, error) {
	id, err := r.byteTag()
	if err != nil {
		return nil, err
	}
	param, err := r.byteTag()
	if err != nil {
		return nil, err
	}
	tag, err := r.byteTag()
	if err != nil {
		return nil, err
	}
	if !physicalTag(tag) {
		return nil, ErrMalformed
	}
	physical, err := decodeTagged(r, tag, maxDepth)
	if err != nil {
		return nil, err
	}
	switch id {
	case 0, logicalUndefined, logicalDate, logicalDecimal:
		return nil, ErrMalformed
	case logicalTimestamp:
		return envelopeTimestamp(param, physical)
	case logicalUUID:
		b, ok := physical.([]byte)
		if param != 0 || !ok || len(b) != 16 {
			return nil, ErrMalformed
		}
		var u vcvalue.UUID
		copy(u[:], b)
		return u, nil
	default:
		return vcvalue.Tagged{ID: id, Param: param, V: physical}, nil
	}
}

// envelopeTimestamp is a count of seconds, milliseconds or microseconds
// since the epoch as a time.Time, in chrono's range. The nanosecond unit has
// the shorthand Timestamp tag and is refused in the envelope.
func envelopeTimestamp(unit byte, physical any) (any, error) {
	var per int64
	switch unit {
	case unitSeconds:
		per = 1_000_000_000
	case unitMillis:
		per = 1_000_000
	case unitMicros:
		per = 1_000
	default:
		return nil, ErrMalformed
	}
	count, ok := integerOf(physical)
	if !ok {
		return nil, ErrMalformed
	}
	nanos := new(big.Int).Mul(count, big.NewInt(per))
	seconds, sub := new(big.Int).DivMod(nanos, big.NewInt(1_000_000_000), new(big.Int))
	if !seconds.IsInt64() {
		return nil, ErrMalformed
	}
	t := vcvalue.Timestamp{Seconds: seconds.Int64(), Nanoseconds: uint32(sub.Int64())}
	if t.Validate() != nil {
		return nil, ErrMalformed
	}
	return time.Unix(t.Seconds, int64(t.Nanoseconds)).UTC(), nil
}

// integerOf is the value of a decoded int of any width.
func integerOf(v any) (*big.Int, bool) {
	switch x := v.(type) {
	case int8:
		return big.NewInt(int64(x)), true
	case int16:
		return big.NewInt(int64(x)), true
	case int32:
		return big.NewInt(int64(x)), true
	case int64:
		return big.NewInt(x), true
	case uint8:
		return new(big.Int).SetUint64(uint64(x)), true
	case uint16:
		return new(big.Int).SetUint64(uint64(x)), true
	case uint32:
		return new(big.Int).SetUint64(uint64(x)), true
	case uint64:
		return new(big.Int).SetUint64(x), true
	case vcvalue.Int128:
		value, ok := new(big.Int).SetString(x.String(), 10)
		return value, ok
	case vcvalue.Uint128:
		value, ok := new(big.Int).SetString(x.String(), 10)
		return value, ok
	}
	return nil, false
}
