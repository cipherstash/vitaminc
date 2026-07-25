package vcvalue

import (
	"encoding/binary"
	"math"
)

// Object is the decode result for a map-mode value: an ordered list of
// fields mirroring the wire order. Decoding uses this (rather than a Go map)
// so entry order is preserved and results compare deterministically. Encode
// takes any/struct/map instead — this type is decode-only.
type Object []Field

// Field is one entry of a decoded Object.
type Field struct {
	Key   string
	Value any
}

// Unmarshal decodes value transport bytes into Go natives:
//
//   - Null and Undefined → nil (Go has no undefined analog);
//   - Bool               → bool;
//   - Number             → float64;
//   - Int                → int64;
//   - UInt               → uint64;
//   - String             → string;
//   - Bytes              → []byte;
//   - Array              → []any;
//   - Object             → Object (ordered []Field).
//
// This self-describing shape is deliberately spike-scoped. A reflection-based
// Unmarshal into caller structs (the mirror of Encode) is future work.
func Unmarshal(buf []byte) (any, error) {
	r := &reader{buf: buf}
	v, err := decodeValue(r, 0)
	if err != nil {
		return nil, err
	}
	if !r.finished() {
		return nil, errMalformed
	}
	return v, nil
}

func decodeValue(r *reader, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errMalformed
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
	case tagNumber:
		s, err := r.take(8)
		if err != nil {
			return nil, err
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(s)), nil
	case tagInt64:
		s, err := r.take(8)
		if err != nil {
			return nil, err
		}
		return int64(binary.LittleEndian.Uint64(s)), nil
	case tagUint64:
		s, err := r.take(8)
		if err != nil {
			return nil, err
		}
		return binary.LittleEndian.Uint64(s), nil
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
		items := make([]any, 0, n)
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
		fields := make(Object, 0, n)
		for range n {
			key, err := r.str()
			if err != nil {
				return nil, err
			}
			value, err := decodeValue(r, depth+1)
			if err != nil {
				return nil, err
			}
			fields = append(fields, Field{Key: key, Value: value})
		}
		return fields, nil
	default:
		return nil, errMalformed
	}
}
