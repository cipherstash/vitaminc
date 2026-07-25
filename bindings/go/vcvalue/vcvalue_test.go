package vcvalue_test

import (
	"math"
	"reflect"
	"testing"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// marshalUnmarshal is the round trip every case below shares: encode v to
// transport bytes, decode back to the natives shape.
func marshalUnmarshal(t *testing.T, v any) any {
	t.Helper()
	buf, err := vcvalue.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal(%#v): %v", v, err)
	}
	got, err := vcvalue.Unmarshal(buf)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return got
}

func TestReflectNatives(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want any
	}{
		{"nil", nil, nil},
		{"bool", true, true},
		{"int", 42, int64(42)},                 // int → Int64
		{"int8", int8(-5), int32(-5)},          // narrow signed → Int32
		{"int16", int16(-300), int32(-300)},    // narrow signed → Int32
		{"int32", int32(-9), int32(-9)},        // Int32, exact width
		{"int64", int64(-9), int64(-9)},        // Int64
		{"uint8", uint8(7), uint32(7)},         // narrow unsigned → UInt32
		{"uint16", uint16(300), uint32(300)},   // narrow unsigned → UInt32
		{"uint32", uint32(7), uint32(7)},       // UInt32, exact width
		{"uint", uint(7), uint64(7)},           // bare uint → UInt64 (no fit-check)
		{"uint64-small", uint64(7), uint64(7)}, // uint64 → UInt64
		{"uint64-max", uint64(math.MaxUint64), uint64(math.MaxUint64)},
		{"float32", float32(1.5), float32(1.5)}, // Float32, exact width
		{"float", 1.5, 1.5},                     // float64 → Float64
		{"string", "hi", "hi"},
		{"bytes", []byte{1, 2, 3}, []byte{1, 2, 3}},
		{"slice", []int{1, 2}, []any{int64(1), int64(2)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := marshalUnmarshal(t, c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %#v, want %#v", got, c.want)
			}
		})
	}
}

func TestReflectStructTags(t *testing.T) {
	type inner struct {
		A int64 `vc:"a"`
	}
	type outer struct {
		Name    string `vc:"name"`
		Skipped string `vc:"-"`
		hidden  string //nolint:unused // unexported, must be skipped
		Nested  inner
	}
	got := marshalUnmarshal(t, outer{Name: "x", Skipped: "no", hidden: "no", Nested: inner{A: 1}})
	want := vcvalue.Object{
		{Key: "name", Value: "x"},
		{Key: "Nested", Value: vcvalue.Object{{Key: "a", Value: int64(1)}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestReflectMapSortsKeys(t *testing.T) {
	// Map iteration is randomized; the encoder must sort keys so the
	// structure is deterministic. Decode preserves that sorted order.
	got := marshalUnmarshal(t, map[string]int64{"c": 3, "a": 1, "b": 2})
	want := vcvalue.Object{
		{Key: "a", Value: int64(1)},
		{Key: "b", Value: int64(2)},
		{Key: "c", Value: int64(3)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestReflectPointerDeref(t *testing.T) {
	n := int64(5)
	if got := marshalUnmarshal(t, &n); !reflect.DeepEqual(got, int64(5)) {
		t.Fatalf("got %#v, want int64(5)", got)
	}
	var nilPtr *int64
	if got := marshalUnmarshal(t, nilPtr); got != nil {
		t.Fatalf("nil pointer should decode as nil, got %#v", got)
	}
}

// point uses the Encryptable extension point.
type point struct{ X, Y int64 }

func (p point) EncryptValue(enc vcvalue.Encoder) error {
	m := enc.Map()
	m.Field("x").Int64(p.X)
	m.Field("y").Int64(p.Y)
	return m.End()
}

func TestEncryptableImpl(t *testing.T) {
	got := marshalUnmarshal(t, point{X: 1, Y: 2})
	want := vcvalue.Object{{Key: "x", Value: int64(1)}, {Key: "y", Value: int64(2)}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// TestEncryptableNested confirms an Encryptable is honored when reached
// through reflection (as a struct field), not only at the top level.
func TestEncryptableNested(t *testing.T) {
	type shape struct {
		Origin point
	}
	got := marshalUnmarshal(t, shape{Origin: point{X: 3, Y: 4}})
	want := vcvalue.Object{
		{Key: "Origin", Value: vcvalue.Object{
			{Key: "x", Value: int64(3)},
			{Key: "y", Value: int64(4)},
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestEncoderChannels(t *testing.T) {
	// Drive the raw Encoder channels directly, including a nested Seq.
	buf, err := vcvalue.Marshal(seqBuilder{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := vcvalue.Unmarshal(buf)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want := []any{
		nil, true,
		float64(1.5), float32(0.5),
		int32(-1), int64(-1),
		uint32(math.MaxUint32), uint64(math.MaxUint64),
		"s", []byte{9},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

type seqBuilder struct{}

func (seqBuilder) EncryptValue(enc vcvalue.Encoder) error {
	s := enc.Seq()
	s.Elem().Null()
	s.Elem().Bool(true)
	s.Elem().Float64(1.5)
	s.Elem().Float32(0.5)
	s.Elem().Int32(-1)
	s.Elem().Int64(-1)
	s.Elem().UInt32(math.MaxUint32)
	s.Elem().UInt64(math.MaxUint64)
	s.Elem().String("s")
	s.Elem().Bytes([]byte{9})
	return s.End()
}

func TestInvalidUTF8StringRejected(t *testing.T) {
	if _, err := vcvalue.Marshal(string([]byte{0xff})); err == nil {
		t.Fatal("expected invalid UTF-8 string to be rejected")
	}
}

func TestUnmarshalRejectsGarbage(t *testing.T) {
	if _, err := vcvalue.Unmarshal([]byte{0x7f}); err == nil {
		t.Fatal("unknown tag must be rejected")
	}
	// Trailing bytes after a complete value.
	if _, err := vcvalue.Unmarshal([]byte{0x00, 0x00}); err == nil {
		t.Fatal("trailing bytes must be rejected")
	}
}

// TestPlainPassthroughRoundTrip: the reflection opt-in marker Plain seals a
// value as passthrough, and it decodes back as Plain{V:...} — the marking
// round-trips so a caller can tell the field travelled in the clear.
func TestPlainPassthroughRoundTrip(t *testing.T) {
	got := marshalUnmarshal(t, map[string]any{
		"id":    vcvalue.Plain{V: int64(42)},
		"email": "ada@example.com",
	})
	want := vcvalue.Object{
		{Key: "email", Value: "ada@example.com"},
		{Key: "id", Value: vcvalue.Plain{V: int64(42)}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// A Plain wrapping a whole subtree makes the entire subtree passthrough.
func TestPlainPassthroughSubtree(t *testing.T) {
	got := marshalUnmarshal(t, vcvalue.Plain{V: []any{int64(1), "two", true}})
	want := vcvalue.Plain{V: []any{int64(1), "two", true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// The raw Encoder.Passthrough() channel, at root/seq/map positions.
type passthroughBuilder struct{}

func (passthroughBuilder) EncryptValue(enc vcvalue.Encoder) error {
	s := enc.Seq()
	s.Elem().Passthrough().Int64(7) // passthrough sequence element
	s.Elem().String("sealed")
	return s.End()
}

func TestEncoderPassthroughChannel(t *testing.T) {
	got := marshalUnmarshal(t, passthroughBuilder{})
	want := []any{vcvalue.Plain{V: int64(7)}, "sealed"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestUnmarshalRejectsTruncatedPassthrough(t *testing.T) {
	// A passthrough marker (0x12) with no value node behind it.
	if _, err := vcvalue.Unmarshal([]byte{0x12}); err == nil {
		t.Fatal("truncated passthrough node must be rejected")
	}
}

func TestUnmarshalRejectsPassthroughDepthBomb(t *testing.T) {
	// Nesting exclusively through passthrough markers must hit the depth bound.
	bytes := make([]byte, 0, 200)
	for range 130 { // > maxDepth (128)
		bytes = append(bytes, 0x12)
	}
	bytes = append(bytes, 0x00) // NULL
	if _, err := vcvalue.Unmarshal(bytes); err == nil {
		t.Fatal("over-deep passthrough nesting must be rejected")
	}
}

// A KindPassthrough ciphertext node carries its readable value across the
// transport and back.
func TestCipherTextPassthroughTransportRoundTrip(t *testing.T) {
	ct := vcvalue.CipherText{
		Kind: vcvalue.KindMap,
		Fields: []vcvalue.CipherTextField{
			{Key: "id", Node: vcvalue.CipherText{Kind: vcvalue.KindPassthrough, Passthrough: int64(42)}},
			{Key: "email", Node: vcvalue.CipherText{Kind: vcvalue.KindSingle, Leaf: []byte{9, 9, 9}}},
		},
	}
	buf, err := ct.MarshalTransport()
	if err != nil {
		t.Fatalf("MarshalTransport: %v", err)
	}
	got, err := vcvalue.UnmarshalCipherText(buf)
	if err != nil {
		t.Fatalf("UnmarshalCipherText: %v", err)
	}
	if !reflect.DeepEqual(got, ct) {
		t.Fatalf("got %#v, want %#v", got, ct)
	}
}

func TestCipherTextTransportRoundTrip(t *testing.T) {
	ct := vcvalue.CipherText{
		Kind: vcvalue.KindMap,
		Fields: []vcvalue.CipherTextField{
			{Key: "a", Node: vcvalue.CipherText{Kind: vcvalue.KindSingle, Leaf: []byte{9, 9, 9}}},
			{Key: "b", Node: vcvalue.CipherText{Kind: vcvalue.KindSeq, Items: []vcvalue.CipherText{
				{Kind: vcvalue.KindSingle, Leaf: []byte{1}},
				{Kind: vcvalue.KindNone, Leaf: []byte{2}},
			}}},
		},
	}
	buf, err := ct.MarshalTransport()
	if err != nil {
		t.Fatalf("MarshalTransport: %v", err)
	}
	got, err := vcvalue.UnmarshalCipherText(buf)
	if err != nil {
		t.Fatalf("UnmarshalCipherText: %v", err)
	}
	if !reflect.DeepEqual(got, ct) {
		t.Fatalf("got %#v, want %#v", got, ct)
	}
}
