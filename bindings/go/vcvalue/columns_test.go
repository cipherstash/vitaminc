package vcvalue

import (
	"bytes"
	"reflect"
	"testing"
)

func mapCT(fields ...CipherTextField) CipherText {
	return CipherText{Kind: KindMap, Fields: fields}
}

func TestColumnsFlattensMixedFields(t *testing.T) {
	ct := mapCT(
		CipherTextField{Key: "id", Node: CipherText{Kind: KindPassthrough, Passthrough: int64(42)}},
		CipherTextField{Key: "email", Node: CipherText{Kind: KindSingle, Leaf: []byte{1, 2, 3}}},
	)
	cols, err := ct.Columns()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"id":    int64(42),
		"email": []byte{1, 2, 3},
	}
	if !reflect.DeepEqual(cols, want) {
		t.Fatalf("cols = %#v, want %#v", cols, want)
	}
}

func TestColumnsRejectsNonMapRoot(t *testing.T) {
	if _, err := (CipherText{Kind: KindSingle, Leaf: []byte{1}}).Columns(); err == nil {
		t.Fatal("expected error for non-map root")
	}
}

func TestColumnsRejectsNestedContainers(t *testing.T) {
	for _, kind := range []CipherTextKind{KindSeq, KindMap, KindNone} {
		ct := mapCT(CipherTextField{Key: "nested", Node: CipherText{Kind: kind}})
		if _, err := ct.Columns(); err == nil {
			t.Fatalf("expected error for nested kind %#02x", byte(kind))
		}
	}
}

func TestSealedColumnsSortsKeysAndRoundTrips(t *testing.T) {
	leaves := map[string][]byte{
		"name":  {9, 9},
		"email": {1, 2, 3},
	}
	ct := SealedColumns(leaves)
	if ct.Kind != KindMap || len(ct.Fields) != 2 {
		t.Fatalf("shape = %#v", ct)
	}
	if ct.Fields[0].Key != "email" || ct.Fields[1].Key != "name" {
		t.Fatalf("keys not sorted: %q, %q", ct.Fields[0].Key, ct.Fields[1].Key)
	}
	if !bytes.Equal(ct.Fields[0].Node.Leaf, leaves["email"]) {
		t.Fatal("leaf bytes not carried through")
	}

	// Sealed leaves survive a Columns round trip.
	cols, err := ct.Columns()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cols["name"].([]byte), leaves["name"]) {
		t.Fatalf("round trip lost name leaf: %#v", cols)
	}
}
