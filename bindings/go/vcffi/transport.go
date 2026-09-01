package vcffi

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
// Typed uint64, not an untyped constant: an untyped 1<<32-1 compared against
// an int fails to compile on 32-bit GOARCH (constant overflows int), and the
// guard is load-bearing there — an oversized count coerced to a negative int
// would slip past the remaining-bytes check and panic in make instead of
// returning ErrMalformed. Comparisons convert the int operand to uint64
// (always lossless for non-negative values, which the n < 0 guards ensure).
const maxUint32 = uint64(1<<32 - 1)

// maxDepth mirrors the Rust transport codec's recursion bound, keeping a
// hostile nesting depth from overflowing the stack.
const maxDepth = 128

// maxEagerCapacity clamps the up-front reservation of a count-driven
// allocation. The reader's count guard bounds a single reservation against
// the bytes remaining, but not the sum of live reservations: a container
// nesting level costs 5-9 wire bytes while a reserved slot costs many times
// that, and up to maxDepth ancestor reservations are live at once — so ~1 MB
// of hostile bytes could otherwise pin gigabytes. Mirrors the Rust codecs'
// MAX_EAGER_CAPACITY. Slices still grow past the clamp on append; only the
// initial reservation is bounded.
const maxEagerCapacity = 1024

func eagerCap(n int) int {
	// n < 0 is unreachable on 64-bit (u32 counts are non-negative in a 64-bit
	// int) but load-bearing on 32-bit GOARCH, where a hostile prefix >= 2^31
	// coerces negative and min() would pass it through to make().
	if n < 0 {
		return 0
	}
	return min(n, maxEagerCapacity)
}

// ErrMalformed is returned (sometimes wrapped) by the decoders for any
// transport buffer that does not parse: truncated, over-deep, hostile
// counts, duplicate keys, unknown tags. Deliberately unspecific — the
// decoders treat their input as hostile and do not distinguish *how* it is
// malformed.
var ErrMalformed = errors.New("vcffi: malformed transport bytes")

func appendLen(out []byte, n int) ([]byte, error) {
	if n < 0 || uint64(n) > maxUint32 {
		return nil, fmt.Errorf("vcffi: length %d out of range", n)
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
		return 0, ErrMalformed
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || n > len(r.buf)-r.pos {
		return nil, ErrMalformed
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
// drive a huge preallocation. The n < 0 guard matches take/appendLen: on
// 32-bit GOARCH a prefix >= 2^31 coerces to a negative int, which would slip
// past the remaining-bytes check and panic in make.
func (r *reader) count() (int, error) {
	n, err := r.u32()
	if err != nil {
		return 0, err
	}
	if n < 0 || n > len(r.buf)-r.pos {
		return 0, ErrMalformed
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
		return "", ErrMalformed
	}
	return string(s), nil
}
