package vcvalue

import (
	"fmt"
	"sort"
)

// Columns flattens a map-shaped ciphertext into named columns, ready to bind
// as parameters in a database layer (database/sql, sqlx NamedExec, an ORM):
// passthrough fields surface as their decoded native values, sealed fields
// as their opaque leaf bytes ([]byte). The conversion is purely mechanical —
// every entry of a map ciphertext already carries its field name, so no
// schema knowledge is involved.
//
// Only flat fields convert. A field that is itself a sequence or map (or an
// authenticated-absent None) has no single-column representation — how to
// flatten one is schema policy, so Columns returns an error rather than
// guessing.
func (ct CipherText) Columns() (map[string]any, error) {
	if ct.Kind != KindMap {
		return nil, fmt.Errorf("vcvalue: Columns needs a map-shaped ciphertext, got kind %#02x", byte(ct.Kind))
	}
	cols := make(map[string]any, len(ct.Fields))
	for _, f := range ct.Fields {
		switch f.Node.Kind {
		case KindPassthrough:
			cols[f.Key] = f.Node.Passthrough
		case KindSingle:
			cols[f.Key] = f.Node.Leaf
		default:
			return nil, fmt.Errorf("vcvalue: field %q (kind %#02x) has no single-column representation", f.Key, byte(f.Node.Kind))
		}
	}
	return cols, nil
}

// SealedColumns is the read-path inverse of [CipherText.Columns]: it rebuilds
// the decryptable map node around sealed leaf bytes loaded back from storage,
// keyed by the exact field names they were sealed under. The name is
// authenticated into each leaf's AAD, so a renamed column fails decryption
// rather than decrypting into the wrong field. Any subset of a record's
// sealed fields decrypts — there is no whole-map seal.
//
// Keys are sorted for deterministic output; entry order is not authenticated.
func SealedColumns(leaves map[string][]byte) CipherText {
	keys := make([]string, 0, len(leaves))
	for k := range leaves {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ct := CipherText{Kind: KindMap, Fields: make([]CipherTextField, 0, len(keys))}
	for _, k := range keys {
		ct.Fields = append(ct.Fields, CipherTextField{
			Key:  k,
			Node: CipherText{Kind: KindSingle, Leaf: leaves[k]},
		})
	}
	return ct
}
