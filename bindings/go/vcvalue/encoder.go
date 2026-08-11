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

// Plain marks a value that must travel through the cipher **unencrypted and
// unauthenticated** — the reflection-encode opt-in for passthrough. Wrap a
// non-secret value (Plain{V: id}) and Encode/Marshal records it via the
// Encoder's Passthrough channel instead of sealing it. Passthrough never
// happens implicitly: only an explicit Plain (or a direct
// enc.Passthrough() call) produces it.
//
// A decoded passthrough field surfaces back as Plain{V: <decoded value>},
// so the marking round-trips and a caller can tell which fields were in the
// clear. See the package docs — non-sensitive fields only.
type Plain struct {
	V any
}

// encState is the buffer and first-error shared by an Encoder and every
// sub-encoder it hands out. Errors accumulate: once one is recorded, further
// channel calls are no-ops, so consumer code can chain writes without
// checking after every call and still surface the first failure from
// End/Marshal.
type encState struct {
	buf []byte
	err error
	// nodes counts completed value nodes (terminals, and containers at their
	// End). MapEncoder.Field and SeqEncoder.Elem record it to verify their
	// "write exactly one value before the next entry" contract at encode
	// time — without this, a skipped value shifts the wire (the next key
	// parses as the missing value) and only surfaces as an opaque
	// errMalformed at decode.
	nodes int
}

func (s *encState) fail(err error) {
	if s.err == nil {
		s.err = err
	}
}

// Encoder records a single value in transport form. It mirrors the Rust
// Cipher channels — it is a recorder that writes the transport bytes, not a
// live cipher handle. Exactly one channel must be used per Encoder: a
// terminal (Null, Undefined, Bool, Int32, Int64, UInt32, UInt64, Float32,
// Float64, String, Bytes) or a container (Seq, Map).
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
		e.st.nodes++
	}
}

// Undefined records JavaScript's undefined. Go has no analog, so Go code
// rarely writes it; the channel exists so a value round-tripped from JS can
// be re-encoded. On decode, Undefined collapses to nil like Null.
func (e Encoder) Undefined() {
	if e.st.err == nil {
		e.push(tagUndefined)
		e.st.nodes++
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
	e.st.nodes++
}

// Float64 records an IEEE-754 double. Distinct from the integer channels: it
// round-trips as a 64-bit float in every language. Round-trips by raw bit
// pattern, so NaN payloads and -0.0 survive.
func (e Encoder) Float64(f float64) {
	if e.st.err != nil {
		return
	}
	e.push(tagFloat64)
	e.st.buf = binary.LittleEndian.AppendUint64(e.st.buf, math.Float64bits(f))
	e.st.nodes++
}

// Float32 records an IEEE-754 single. For schema fidelity with float4 at the
// EQL layer; round-trips by raw bit pattern.
func (e Encoder) Float32(f float32) {
	if e.st.err != nil {
		return
	}
	e.push(tagFloat32)
	e.st.buf = binary.LittleEndian.AppendUint32(e.st.buf, math.Float32bits(f))
	e.st.nodes++
}

// Int32 records a signed 32-bit integer. For schema fidelity with int4 at
// the EQL layer; kept distinct from Int64.
func (e Encoder) Int32(i int32) {
	if e.st.err != nil {
		return
	}
	e.push(tagInt32)
	e.st.buf = binary.LittleEndian.AppendUint32(e.st.buf, uint32(i))
	e.st.nodes++
}

// Int64 records a signed 64-bit integer. Kept distinct from Float64 so
// integer-typed languages round-trip integers as integers.
func (e Encoder) Int64(i int64) {
	if e.st.err != nil {
		return
	}
	e.push(tagInt64)
	e.st.buf = binary.LittleEndian.AppendUint64(e.st.buf, uint64(i))
	e.st.nodes++
}

// UInt32 records an unsigned 32-bit integer. For schema fidelity with the
// EQL layer.
func (e Encoder) UInt32(u uint32) {
	if e.st.err != nil {
		return
	}
	e.push(tagUint32)
	e.st.buf = binary.LittleEndian.AppendUint32(e.st.buf, u)
	e.st.nodes++
}

// UInt64 records an unsigned 64-bit integer. Values above math.MaxInt64 are
// representable here and nowhere else in the model.
func (e Encoder) UInt64(u uint64) {
	if e.st.err != nil {
		return
	}
	e.push(tagUint64)
	e.st.buf = binary.LittleEndian.AppendUint64(e.st.buf, u)
	e.st.nodes++
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
		e.st.nodes++
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
		e.st.nodes++
	}
}

// Passthrough marks the next value as passthrough (unencrypted,
// unauthenticated) and returns an Encoder for it — the same channel set, so
// the wrapped value is written exactly as any other:
//
//	m.Field("id").Passthrough().Int64(42)   // a passthrough map entry
//	enc.Passthrough().String("v")           // a passthrough root value
//	s.Elem().Passthrough().Bool(true)       // a passthrough sequence element
//
// Write exactly one value (terminal or container) through the returned
// Encoder. Non-sensitive data only — the wrapped value is not sealed.
func (e Encoder) Passthrough() Encoder {
	if e.st.err == nil {
		if e.depth+1 > maxDepth {
			e.st.fail(errors.New("vcvalue: value is nested too deeply"))
		} else {
			e.push(tagPassthrough)
		}
	}
	return Encoder{st: e.st, depth: e.depth + 1}
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
	// mark is st.nodes as of the last Elem call — the next Elem (or End)
	// verifies at least one value node completed since, so a skipped element
	// fails here at encode time instead of as errMalformed at decode.
	mark int
}

// Elem returns an Encoder for the next element. Write the element fully
// (one channel) before calling Elem again.
func (s *SeqEncoder) Elem() Encoder {
	if s.st.err == nil {
		if s.count > 0 && s.st.nodes == s.mark {
			s.st.fail(errors.New("vcvalue: previous sequence element was never written"))
		} else {
			s.mark = s.st.nodes
			s.count++
		}
	}
	return Encoder{st: s.st, depth: s.depth}
}

// End finalizes the sequence, writing its element count, and returns the
// first error recorded during the whole encode (if any).
func (s *SeqEncoder) End() error {
	if s.st.err == nil && s.count > 0 && s.st.nodes == s.mark {
		s.st.fail(errors.New("vcvalue: last sequence element was never written"))
	}
	err := patchLen(s.st, s.lenOff, s.count)
	if err == nil {
		// The sequence itself is one completed value node for any enclosing
		// container's contract check.
		s.st.nodes++
	}
	return err
}

// MapEncoder records the entries of a map. The entry count is back-patched
// into the reserved length slot at End.
type MapEncoder struct {
	st     *encState
	depth  int
	lenOff int
	count  int
	// mark mirrors SeqEncoder.mark: st.nodes as of the last Field call, so a
	// key whose value was never written fails at encode time — otherwise the
	// wire shifts and the next key parses as the missing value, surfacing
	// only as an opaque errMalformed at decode.
	mark int
}

// Field writes an entry key and returns an Encoder for its value. Write the
// value fully (one channel) before calling Field again. Keys are UTF-8
// validated; insertion order is preserved on the wire.
func (m *MapEncoder) Field(key string) Encoder {
	if m.st.err == nil {
		if m.count > 0 && m.st.nodes == m.mark {
			m.st.fail(fmt.Errorf("vcvalue: value for the entry before %q was never written", key))
		} else if !utf8.ValidString(key) {
			m.st.fail(errors.New("vcvalue: object key is not valid UTF-8"))
		} else if buf, err := appendChunk(m.st.buf, []byte(key)); err != nil {
			m.st.fail(err)
		} else {
			m.st.buf = buf
			m.mark = m.st.nodes
			m.count++
		}
	}
	return Encoder{st: m.st, depth: m.depth}
}

// End finalizes the map, writing its entry count, and returns the first
// error recorded during the whole encode (if any).
func (m *MapEncoder) End() error {
	if m.st.err == nil && m.count > 0 && m.st.nodes == m.mark {
		m.st.fail(errors.New("vcvalue: value for the last map entry was never written"))
	}
	err := patchLen(m.st, m.lenOff, m.count)
	if err == nil {
		// The map itself is one completed value node for any enclosing
		// container's contract check.
		m.st.nodes++
	}
	return err
}

func patchLen(st *encState, off, count int) error {
	if st.err != nil {
		return st.err
	}
	if count < 0 || uint64(count) > maxUint32 {
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
//   - int8/int16/int32           → Int32;
//   - int/int64                  → Int64;
//   - uint8/uint16/uint32        → UInt32;
//   - uint/uint64/uintptr        → UInt64;
//   - float32                    → Float32;
//   - float64                    → Float64;
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
	if interceptMarkers(enc, v) {
		return
	}
	if b, ok := v.([]byte); ok {
		enc.Bytes(b)
		return
	}
	encodeReflect(enc, reflect.ValueOf(v))
}

// interceptMarkers handles the marker types both dispatchers (encodeAny for
// interface values, encodeReflect for values reached through reflection)
// must special-case before any reflection sees them. Returns true when v was
// fully handled.
//
//   - Plain is the explicit passthrough opt-in; checked before Encryptable
//     and the struct arm so it is never mistaken for a plain struct.
//   - Object is decode-only in spirit, but a decrypt-then-re-encrypt flow
//     legitimately feeds it back in; without interception the reflect slice
//     arm would encode it as a SEQ of {Key,Value} structs, silently changing
//     the record's structure.
//   - Encryptable hands control to the user type — except a typed nil
//     pointer, which still satisfies the assertion but would dereference nil
//     in typical implementations; it encodes as Null like every other nil.
func interceptMarkers(enc Encoder, v any) bool {
	switch x := v.(type) {
	case Plain:
		encodeAny(enc.Passthrough(), x.V)
		return true
	case Object:
		encodeObject(enc, x)
		return true
	}
	if e, ok := v.(Encryptable); ok {
		if ev := reflect.ValueOf(e); ev.Kind() == reflect.Pointer && ev.IsNil() {
			enc.Null()
			return true
		}
		if err := e.EncryptValue(enc); err != nil {
			enc.st.fail(err)
		}
		return true
	}
	return false
}

// encodeObject re-encodes a decoded Object with object framing, preserving
// its field order (Object exists precisely to preserve wire order).
func encodeObject(enc Encoder, o Object) {
	m := enc.Map()
	for _, f := range o {
		encodeAny(m.Field(f.Key), f.Value)
	}
	_ = m.End()
}

func encodeReflect(enc Encoder, rv reflect.Value) {
	if enc.st.err != nil {
		return
	}
	if !rv.IsValid() {
		enc.Null()
		return
	}
	// Re-check the explicit markers for values reached through reflection
	// (struct fields, slice elements, map values). Plain is itself a struct,
	// so it must be intercepted before the reflect.Struct arm below.
	if rv.CanInterface() && interceptMarkers(enc, rv.Interface()) {
		return
	}

	switch rv.Kind() {
	case reflect.Bool:
		enc.Bool(rv.Bool())
	case reflect.Int8, reflect.Int16, reflect.Int32:
		// Narrower signed kinds map to the 32-bit tag (schema fidelity with
		// int4); int/int64 keep 64-bit width.
		enc.Int32(int32(rv.Int()))
	case reflect.Int, reflect.Int64:
		enc.Int64(rv.Int())
	case reflect.Uint8, reflect.Uint16, reflect.Uint32:
		enc.UInt32(uint32(rv.Uint()))
	case reflect.Uint, reflect.Uint64, reflect.Uintptr:
		// Every unsigned word-or-wider kind keeps its unsigned identity as
		// UInt64 (no fit-check: a bare uint always maps to UINT64 now).
		enc.UInt64(rv.Uint())
	case reflect.Float32:
		enc.Float32(float32(rv.Float()))
	case reflect.Float64:
		enc.Float64(rv.Float())
	case reflect.String:
		enc.String(rv.String())
	case reflect.Slice:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			enc.Bytes(rv.Bytes())
			return
		}
		encodeSeq(enc, rv)
	case reflect.Array:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			// Byte arrays are one Bytes leaf, matching the slice arm above
			// and Rust's single-leaf [u8; N] — element-wise encoding would
			// seal N separate leaves and produce a ciphertext shape no other
			// producer emits.
			b := make([]byte, rv.Len())
			reflect.Copy(reflect.ValueOf(b), rv)
			enc.Bytes(b)
			return
		}
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
		// Charge the dereference against the shared depth budget: it writes
		// no container framing, so without this a pointer cycle (x = &x)
		// would recurse to stack overflow instead of failing cleanly.
		if enc.depth+1 > maxDepth {
			enc.st.fail(errors.New("vcvalue: value is nested too deeply"))
			return
		}
		encodeReflect(Encoder{st: enc.st, depth: enc.depth + 1}, rv.Elem())
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
	encoded, unexported := 0, 0
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			unexported++
			continue
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
		encoded++
	}
	// A struct whose every field is unexported (time.Time is the canonical
	// case) would seal as an empty map and the payload would be gone with no
	// error at either end — the exact hazard the NAPI layer's
	// ensure_plain_object guards. An all-`vc:"-"` struct is left alone: the
	// caller asked for the empty encoding explicitly.
	if encoded == 0 && unexported > 0 {
		enc.st.fail(fmt.Errorf(
			"vcvalue: struct %s has no exported fields to encode — implement Encryptable to control its sealing", t))
		return
	}
	_ = m.End()
}
