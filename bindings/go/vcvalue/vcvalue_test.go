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
		{"int", 42, int64(42)},
		{"int64", int64(-9), int64(-9)},
		{"uint32", uint32(7), int64(7)},        // fits int64 → Int
		{"uint64-small", uint64(7), uint64(7)}, // static uint64 → UInt
		{"uint64-max", uint64(math.MaxUint64), uint64(math.MaxUint64)},
		{"float", 1.5, 1.5},
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
	m.Field("x").Int(p.X)
	m.Field("y").Int(p.Y)
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
	want := []any{nil, true, 1.5, int64(-1), uint64(math.MaxUint64), "s", []byte{9}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

type seqBuilder struct{}

func (seqBuilder) EncryptValue(enc vcvalue.Encoder) error {
	s := enc.Seq()
	s.Elem().Null()
	s.Elem().Bool(true)
	s.Elem().Number(1.5)
	s.Elem().Int(-1)
	s.Elem().UInt(math.MaxUint64)
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
