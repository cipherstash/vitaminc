package vitaminc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
)

// Value is the Go projection of vitaminc's FfiValue: a self-describing
// tree of encryptable values. The concrete types below are the only
// implementations.
//
// Number and Int are distinct on purpose: an Int encrypted from Go
// round-trips as an integer in every language (surfacing as BigInt in
// JavaScript beyond 2^53-1), while Number is an IEEE-754 double.
type Value interface {
	isValue()
}

type (
	// Null is the cross-language null (Go nil, JS null, Python None).
	Null struct{}
	// Undefined is JavaScript's undefined. Go code should not normally
	// encrypt it, but it can arrive in values encrypted from JS.
	Undefined struct{}
	Bool      bool
	Number    float64
	Int       int64
	String    string
	Bytes     []byte
	Array     []Value
	// Object is an ordered list of string-keyed fields. Keys travel in
	// the clear inside the ciphertext (bound into each value's AAD);
	// values are sealed.
	Object []Field
)

// Field is one entry of an Object.
type Field struct {
	Key   string
	Value Value
}

func (Null) isValue()      {}
func (Undefined) isValue() {}
func (Bool) isValue()      {}
func (Number) isValue()    {}
func (Int) isValue()       {}
func (String) isValue()    {}
func (Bytes) isValue()     {}
func (Array) isValue()     {}
func (Object) isValue()    {}

// Transport tags. The scalar tags mirror vitaminc-aead-value's frozen
// sealed-leaf tag table so the two can't drift apart on meaning; the
// ARRAY/OBJECT framing tags are transport-local. The transport encoding
// itself is NOT a storage format — see the guest crate's codec docs.
const (
	tagNull      = 0x00
	tagUndefined = 0x01
	tagFalse     = 0x02
	tagTrue      = 0x03
	tagNumber    = 0x04
	tagString    = 0x05
	tagBytes     = 0x06
	tagInt64     = 0x07
	tagArray     = 0x10
	tagObject    = 0x11
)

// maxDepth mirrors the guest codec's recursion bound.
const maxDepth = 128

var errMalformed = errors.New("vitaminc: malformed transport bytes")

func appendLen(out []byte, n int) ([]byte, error) {
	if n < 0 || n > math.MaxUint32 {
		return nil, fmt.Errorf("vitaminc: length %d out of range", n)
	}
	return binary.LittleEndian.AppendUint32(out, uint32(n)), nil
}

func appendChunk(out, chunk []byte) ([]byte, error) {
	out, err := appendLen(out, len(chunk))
	if err != nil {
		return nil, err
	}
	return append(out, chunk...), nil
}

func encodeValue(out []byte, v Value, depth int) ([]byte, error) {
	if depth > maxDepth {
		return nil, errors.New("vitaminc: value is nested too deeply")
	}
	switch v := v.(type) {
	case Null:
		return append(out, tagNull), nil
	case Undefined:
		return append(out, tagUndefined), nil
	case Bool:
		if v {
			return append(out, tagTrue), nil
		}
		return append(out, tagFalse), nil
	case Number:
		out = append(out, tagNumber)
		return binary.LittleEndian.AppendUint64(out, math.Float64bits(float64(v))), nil
	case Int:
		out = append(out, tagInt64)
		return binary.LittleEndian.AppendUint64(out, uint64(v)), nil
	case String:
		if !utf8.ValidString(string(v)) {
			return nil, errors.New("vitaminc: string is not valid UTF-8")
		}
		out = append(out, tagString)
		return appendChunk(out, []byte(v))
	case Bytes:
		out = append(out, tagBytes)
		return appendChunk(out, v)
	case Array:
		out = append(out, tagArray)
		out, err := appendLen(out, len(v))
		if err != nil {
			return nil, err
		}
		for _, item := range v {
			if out, err = encodeValue(out, item, depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	case Object:
		out = append(out, tagObject)
		out, err := appendLen(out, len(v))
		if err != nil {
			return nil, err
		}
		for _, field := range v {
			if !utf8.ValidString(field.Key) {
				return nil, errors.New("vitaminc: object key is not valid UTF-8")
			}
			if out, err = appendChunk(out, []byte(field.Key)); err != nil {
				return nil, err
			}
			if out, err = encodeValue(out, field.Value, depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("vitaminc: unsupported value type %T", v)
	}
}

type reader struct {
	buf []byte
	pos int
}

func (r *reader) byteTag() (byte, error) {
	if r.pos >= len(r.buf) {
		return 0, errMalformed
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || n > len(r.buf)-r.pos {
		return nil, errMalformed
	}
	s := r.buf[r.pos : r.pos+n]
	r.pos += n
	return s, nil
}

func (r *reader) u32() (int, error) {
	s, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return int(binary.LittleEndian.Uint32(s)), nil
}

// count reads a u32 item count, rejecting counts that exceed the bytes
// remaining (every item costs at least one byte) so hostile input cannot
// drive a huge preallocation.
func (r *reader) count() (int, error) {
	n, err := r.u32()
	if err != nil {
		return 0, err
	}
	if n > len(r.buf)-r.pos {
		return 0, errMalformed
	}
	return n, nil
}

func (r *reader) finished() bool {
	return r.pos == len(r.buf)
}

func (r *reader) str() (string, error) {
	n, err := r.count()
	if err != nil {
		return "", err
	}
	s, err := r.take(n)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(s) {
		return "", errMalformed
	}
	return string(s), nil
}

func decodeValue(r *reader, depth int) (Value, error) {
	if depth > maxDepth {
		return nil, errMalformed
	}
	tag, err := r.byteTag()
	if err != nil {
		return nil, err
	}
	switch tag {
	case tagNull:
		return Null{}, nil
	case tagUndefined:
		return Undefined{}, nil
	case tagFalse:
		return Bool(false), nil
	case tagTrue:
		return Bool(true), nil
	case tagNumber:
		s, err := r.take(8)
		if err != nil {
			return nil, err
		}
		return Number(math.Float64frombits(binary.LittleEndian.Uint64(s))), nil
	case tagInt64:
		s, err := r.take(8)
		if err != nil {
			return nil, err
		}
		return Int(int64(binary.LittleEndian.Uint64(s))), nil
	case tagString:
		s, err := r.str()
		if err != nil {
			return nil, err
		}
		return String(s), nil
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
		return Bytes(out), nil
	case tagArray:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		items := make(Array, 0, n)
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
