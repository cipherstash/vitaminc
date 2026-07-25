package vcvalue

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

// Transport framing tags. The scalar tags mirror vitaminc-aead-value's
// frozen sealed-leaf tag table so the two tables can't drift apart on
// meaning; the ARRAY/OBJECT container tags are transport-local (the sealed
// format has no container tags — container shape rides on the ciphertext
// tree). See the package doc: this transport encoding is NOT a storage
// format.
const (
	tagNull      = 0x00
	tagUndefined = 0x01
	tagFalse     = 0x02
	tagTrue      = 0x03
	tagInt32     = 0x04
	tagInt64     = 0x05
	tagUint32    = 0x06
	tagUint64    = 0x07
	tagFloat32   = 0x08
	tagFloat64   = 0x09
	tagString    = 0x0A
	tagBytes     = 0x0B
	tagArray     = 0x10
	tagObject    = 0x11
	// tagPassthrough wraps one value node that travels in the clear
	// (unencrypted, unauthenticated). Transport-local, like array/object.
	tagPassthrough = 0x12
)

// maxUint32 bounds every length/count written or read (all are u32 LE).
const maxUint32 = 1<<32 - 1

// maxDepth mirrors the Rust transport codec's recursion bound, keeping a
// hostile nesting depth from overflowing the stack.
const maxDepth = 128

var errMalformed = errors.New("vcvalue: malformed transport bytes")

func appendLen(out []byte, n int) ([]byte, error) {
	if n < 0 || n > maxUint32 {
		return nil, fmt.Errorf("vcvalue: length %d out of range", n)
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

// reader is a cursor over a transport buffer, tracking bytes consumed so a
// decode can insist the whole buffer was used.
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

// str reads a length-prefixed, UTF-8-validated string.
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
