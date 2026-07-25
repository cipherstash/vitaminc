package vcvalue

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"unicode/utf8"
)

// Encryptable is the extension point for user types: a type implements it to
// control how it is sealed, the way a Rust type implements `Encrypt`. Because
// Go has no orphan impls, this interface (rather than reflection) is how a
// type opts into a bespoke encoding. Encode and Marshal consult it before
// falling back to reflection.
type Encryptable interface {
	// EncryptValue records this value into enc. Implementations write
	// exactly one value: one terminal channel (String, Int, …) or one
	// container (Seq, Map). Returning an error aborts the whole encode.
	EncryptValue(enc Encoder) error
}

// encState is the buffer and first-error shared by an Encoder and every
// sub-encoder it hands out. Errors accumulate: once one is recorded, further
// channel calls are no-ops, so consumer code can chain writes without
// checking after every call and still surface the first failure from
// End/Marshal.
type encState struct {
	buf []byte
	err error
}

func (s *encState) fail(err error) {
	if s.err == nil {
		s.err = err
	}
}

// Encoder records a single value in transport form. It mirrors the Rust
// Cipher channels — it is a recorder that writes the transport bytes, not a
// live cipher handle. Exactly one channel must be used per Encoder: a
// terminal (Null, Undefined, Bool, Number, Int, UInt, String, Bytes) or a
// container (Seq, Map).
//
// Encoder is passed and stored by value; all instances handed out for one
// encode share the same underlying buffer and first-error via a pointer, so
// copying an Encoder is cheap and safe.
type Encoder struct {
	st    *encState
	depth int
}

func (e Encoder) push(b ...byte) {
	e.st.buf = append(e.st.buf, b...)
}

// Null records the cross-language null (Go nil, JS null, Python None).
func (e Encoder) Null() {
	if e.st.err == nil {
		e.push(tagNull)
	}
}

// Undefined records JavaScript's undefined. Go has no analog, so Go code
// rarely writes it; the channel exists so a value round-tripped from JS can
// be re-encoded. On decode, Undefined collapses to nil like Null.
func (e Encoder) Undefined() {
	if e.st.err == nil {
		e.push(tagUndefined)
	}
}

// Bool records a boolean.
func (e Encoder) Bool(b bool) {
	if e.st.err != nil {
		return
	}
	if b {
		e.push(tagTrue)
	} else {
		e.push(tagFalse)
	}
}

// Number records an IEEE-754 double. Distinct from Int/UInt: it round-trips
// as a float in every language.
func (e Encoder) Number(f float64) {
	if e.st.err != nil {
		return
	}
	e.push(tagNumber)
	e.st.buf = binary.LittleEndian.AppendUint64(e.st.buf, math.Float64bits(f))
}

// Int records a signed 64-bit integer. Kept distinct from Number so
// integer-typed languages round-trip integers as integers.
func (e Encoder) Int(i int64) {
	if e.st.err != nil {
		return
	}
	e.push(tagInt64)
	e.st.buf = binary.LittleEndian.AppendUint64(e.st.buf, uint64(i))
}

// UInt records an unsigned 64-bit integer. Values above math.MaxInt64 are
// representable here and nowhere else in the model.
func (e Encoder) UInt(u uint64) {
	if e.st.err != nil {
		return
	}
	e.push(tagUint64)
	e.st.buf = binary.LittleEndian.AppendUint64(e.st.buf, u)
}

// String records a UTF-8 string. Invalid UTF-8 fails the encode.
func (e Encoder) String(s string) {
	if e.st.err != nil {
		return
	}
	if !utf8.ValidString(s) {
		e.st.fail(errors.New("vcvalue: string is not valid UTF-8"))
		return
	}
	e.push(tagString)
	if buf, err := appendChunk(e.st.buf, []byte(s)); err != nil {
		e.st.fail(err)
	} else {
		e.st.buf = buf
	}
}

// Bytes records raw binary data.
func (e Encoder) Bytes(b []byte) {
	if e.st.err != nil {
		return
	}
	e.push(tagBytes)
	if buf, err := appendChunk(e.st.buf, b); err != nil {
		e.st.fail(err)
	} else {
		e.st.buf = buf
	}
}

// Seq begins a sequence. Call Elem once per element and End when done.
func (e Encoder) Seq() *SeqEncoder {
	s := &SeqEncoder{st: e.st, depth: e.depth + 1}
	if e.st.err != nil {
		return s
	}
	if e.depth+1 > maxDepth {
		e.st.fail(errors.New("vcvalue: value is nested too deeply"))
		return s
	}
	e.push(tagArray)
	s.lenOff = len(e.st.buf)
	e.push(0, 0, 0, 0) // length back-patched by End
	return s
}

// Map begins a string-keyed map. Call Field once per entry and End when
// done. Keys preserve insertion order and are UTF-8 validated.
func (e Encoder) Map() *MapEncoder {
	m := &MapEncoder{st: e.st, depth: e.depth + 1}
	if e.st.err != nil {
		return m
	}
	if e.depth+1 > maxDepth {
		e.st.fail(errors.New("vcvalue: value is nested too deeply"))
		return m
	}
	e.push(tagObject)
	m.lenOff = len(e.st.buf)
	e.push(0, 0, 0, 0) // length back-patched by End
	return m
}

// SeqEncoder records the elements of a sequence. The element count is
// back-patched into the reserved length slot at End.
type SeqEncoder struct {
	st     *encState
	depth  int
	lenOff int
	count  int
}

// Elem returns an Encoder for the next element. Write the element fully
// (one channel) before calling Elem again.
func (s *SeqEncoder) Elem() Encoder {
	if s.st.err == nil {
		s.count++
	}
	return Encoder{st: s.st, depth: s.depth}
}

// End finalizes the sequence, writing its element count, and returns the
// first error recorded during the whole encode (if any).
func (s *SeqEncoder) End() error {
	return patchLen(s.st, s.lenOff, s.count)
}

// MapEncoder records the entries of a map. The entry count is back-patched
// into the reserved length slot at End.
type MapEncoder struct {
	st     *encState
	depth  int
	lenOff int
	count  int
}

// Field writes an entry key and returns an Encoder for its value. Write the
// value fully (one channel) before calling Field again. Keys are UTF-8
// validated; insertion order is preserved on the wire.
func (m *MapEncoder) Field(key string) Encoder {
	if m.st.err == nil {
		if !utf8.ValidString(key) {
			m.st.fail(errors.New("vcvalue: object key is not valid UTF-8"))
		} else if buf, err := appendChunk(m.st.buf, []byte(key)); err != nil {
			m.st.fail(err)
		} else {
			m.st.buf = buf
			m.count++
		}
	}
	return Encoder{st: m.st, depth: m.depth}
}

// End finalizes the map, writing its entry count, and returns the first
// error recorded during the whole encode (if any).
func (m *MapEncoder) End() error {
	return patchLen(m.st, m.lenOff, m.count)
}

func patchLen(st *encState, off, count int) error {
	if st.err != nil {
		return st.err
	}
	if count < 0 || count > maxUint32 {
		st.fail(fmt.Errorf("vcvalue: item count %d out of range", count))
		return st.err
	}
	binary.LittleEndian.PutUint32(st.buf[off:off+4], uint32(count))
	return nil
}

// Marshal encodes v into the value transport form the guest expects. It is
// the encode counterpart of Unmarshal and the path Client.Encrypt uses.
func Marshal(v any) ([]byte, error) {
	st := &encState{}
	if err := Encode(Encoder{st: st}, v); err != nil {
		return nil, err
	}
	return st.buf, nil
}

// Encode records v into enc following encoding/json-style rules, but
// consulting the Encryptable interface first:
//
//   - a value implementing Encryptable uses its EncryptValue;
//   - nil                        → Null;
//   - bool                       → Bool;
//   - int/int8/16/32/64          → Int;
//   - uint8/16/32                → Int (they always fit int64);
//   - uint64 (and uint/uintptr)  → UInt;
//   - float32/float64            → Number;
//   - string                     → String;
//   - []byte                     → Bytes;
//   - slices/arrays              → Seq;
//   - map[string]T               → Map, keys SORTED for determinism;
//   - structs                    → Map by field name, honoring `vc:"name"`
//     tags (`vc:"-"` skips a field), in declaration order;
//   - pointers                   → dereferenced (nil pointer → Null).
//
// Map keys are sorted because Go map iteration order is randomized;
// sorting makes the encrypted structure deterministic. Struct fields keep
// declaration order.
//
// Encode returns the first error recorded while writing enc, so it composes:
// an Encryptable can delegate a sub-value with vcvalue.Encode(m.Field(k), x).
func Encode(enc Encoder, v any) error {
	encodeAny(enc, v)
	return enc.st.err
}

func encodeAny(enc Encoder, v any) {
	if enc.st.err != nil {
		return
	}
	if v == nil {
		enc.Null()
		return
	}
	if e, ok := v.(Encryptable); ok {
		if err := e.EncryptValue(enc); err != nil {
			enc.st.fail(err)
		}
		return
	}
	if b, ok := v.([]byte); ok {
		enc.Bytes(b)
		return
	}
	encodeReflect(enc, reflect.ValueOf(v))
}

func encodeReflect(enc Encoder, rv reflect.Value) {
	if enc.st.err != nil {
		return
	}
	if !rv.IsValid() {
		enc.Null()
		return
	}
	// Re-check Encryptable for values reached through reflection (struct
	// fields, slice elements, map values).
	if rv.CanInterface() {
		if e, ok := rv.Interface().(Encryptable); ok {
			if err := e.EncryptValue(enc); err != nil {
				enc.st.fail(err)
			}
			return
		}
	}

	switch rv.Kind() {
	case reflect.Bool:
		enc.Bool(rv.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		enc.Int(rv.Int())
	case reflect.Uint8, reflect.Uint16, reflect.Uint32:
		enc.Int(int64(rv.Uint()))
	case reflect.Uint, reflect.Uint64, reflect.Uintptr:
		// uint64 keeps its unsigned identity; platform-width uint/uintptr
		// stay Int when they fit int64 and become UInt only when they must.
		u := rv.Uint()
		if rv.Kind() == reflect.Uint64 || u > math.MaxInt64 {
			enc.UInt(u)
		} else {
			enc.Int(int64(u))
		}
	case reflect.Float32, reflect.Float64:
		enc.Number(rv.Float())
	case reflect.String:
		enc.String(rv.String())
	case reflect.Slice:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			enc.Bytes(rv.Bytes())
			return
		}
		encodeSeq(enc, rv)
	case reflect.Array:
		encodeSeq(enc, rv)
	case reflect.Map:
		encodeMap(enc, rv)
	case reflect.Struct:
		encodeStruct(enc, rv)
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			enc.Null()
			return
		}
		encodeReflect(enc, rv.Elem())
	default:
		enc.st.fail(fmt.Errorf("vcvalue: cannot encode value of kind %s", rv.Kind()))
	}
}

func encodeSeq(enc Encoder, rv reflect.Value) {
	s := enc.Seq()
	for i := 0; i < rv.Len(); i++ {
		encodeReflect(s.Elem(), rv.Index(i))
	}
	_ = s.End()
}

func encodeMap(enc Encoder, rv reflect.Value) {
	if rv.Type().Key().Kind() != reflect.String {
		enc.st.fail(fmt.Errorf("vcvalue: map keys must be strings, got %s", rv.Type().Key()))
		return
	}
	keys := rv.MapKeys()
	// Sort keys: Go map iteration is randomized; sorting makes the encrypted
	// structure deterministic across encodes of an equal map.
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	m := enc.Map()
	for _, k := range keys {
		encodeReflect(m.Field(k.String()), rv.MapIndex(k))
	}
	_ = m.End()
}

func encodeStruct(enc Encoder, rv reflect.Value) {
	t := rv.Type()
	m := enc.Map()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue // unexported
		}
		name := f.Name
		if tag, ok := f.Tag.Lookup("vc"); ok {
			if tag == "-" {
				continue
			}
			if tag != "" {
				name = tag
			}
		}
		encodeReflect(m.Field(name), rv.Field(i))
	}
	_ = m.End()
}
