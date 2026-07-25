package vcvalue

import (
	"errors"
	"fmt"
	"sort"
)

// A ciphertext is made of ordinary Go values — the same dynamic shape as
// decoded plaintext — with marker types distinguishing what is sealed from
// what travels in the clear:
//
//   - Sealed: one encrypted leaf (nonce || ciphertext || tag)
//   - SealedNone: the authenticated absent marker
//   - Plain{V: ...}: a passthrough field, readable without the key
//   - []any: a sequence of ciphertext nodes
//   - map[string]any: a record of named nodes. Keys travel in the clear but
//     each is cryptographically bound to its sealed value — renaming or
//     swapping keys fails decryption. Entry order is not authenticated
//     (encoding sorts keys for determinism), and there is no whole-map seal:
//     any subset of entries decrypts independently.
//
// There is deliberately no dedicated tree type and no conversion step: a
// map-shaped ciphertext binds directly as database named parameters (Sealed
// and Plain implement driver.Valuer), and leaves loaded back from columns go
// into a map[string]any for decryption. Only the Sealed leaf bytes are a
// frozen format; the transport encoding crossing the FFI boundary is an
// implementation detail.

// Ciphertext node tags in the transport encoding (mirrors the Rust codec).
const (
	ctSingle      byte = 0x01
	ctNone        byte = 0x02
	ctSeq         byte = 0x03
	ctMap         byte = 0x04
	ctPassthrough byte = 0x05
)

// MarshalCipherText encodes a ciphertext value into transport bytes. Bare
// plaintext values are rejected — a passthrough must be marked with Plain, so
// a value can never end up travelling unencrypted by accident.
func MarshalCipherText(v any) ([]byte, error) {
	return encodeCipherText(nil, v, 0)
}

// UnmarshalCipherText decodes a transport-encoded ciphertext into the dynamic
// shape above, requiring the whole buffer to be consumed.
func UnmarshalCipherText(buf []byte) (any, error) {
	r := &reader{buf: buf}
	ct, err := decodeCipherText(r, 0)
	if err != nil {
		return nil, err
	}
	if !r.finished() {
		return nil, errMalformed
	}
	return ct, nil
}

func encodeCipherText(out []byte, v any, depth int) ([]byte, error) {
	if depth > maxDepth {
		return nil, errors.New("vcvalue: ciphertext is nested too deeply")
	}
	switch n := v.(type) {
	case Sealed:
		out = append(out, ctSingle)
		return appendChunk(out, n)
	case SealedNone:
		out = append(out, ctNone)
		return appendChunk(out, n)
	case []any:
		out = append(out, ctSeq)
		out, err := appendLen(out, len(n))
		if err != nil {
			return nil, err
		}
		for _, item := range n {
			if out, err = encodeCipherText(out, item, depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	case map[string]any:
		out = append(out, ctMap)
		out, err := appendLen(out, len(n))
		if err != nil {
			return nil, err
		}
		keys := make([]string, 0, len(n))
		for k := range n {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if out, err = appendChunk(out, []byte(k)); err != nil {
				return nil, err
			}
			if out, err = encodeCipherText(out, n[k], depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	case Plain:
		out = append(out, ctPassthrough)
		// Encode the plaintext payload as one value node, sharing the
		// recursion budget with the surrounding ciphertext (depth+1),
		// mirroring the Rust CT_PASSTHROUGH framing.
		st := &encState{buf: out}
		encodeAny(Encoder{st: st, depth: depth + 1}, n.V)
		if st.err != nil {
			return nil, st.err
		}
		return st.buf, nil
	default:
		return nil, fmt.Errorf("vcvalue: %T is not a ciphertext node — wrap passthrough values in Plain", v)
	}
}

func decodeCipherText(r *reader, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errMalformed
	}
	tag, err := r.byteTag()
	if err != nil {
		return nil, err
	}
	switch tag {
	case ctSingle, ctNone:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		s, err := r.take(n)
		if err != nil {
			return nil, err
		}
		leaf := make([]byte, len(s))
		copy(leaf, s)
		if tag == ctNone {
			return SealedNone(leaf), nil
		}
		return Sealed(leaf), nil
	case ctSeq:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		items := make([]any, 0, n)
		for range n {
			item, err := decodeCipherText(r, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return items, nil
	case ctMap:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		fields := make(map[string]any, n)
		for range n {
			key, err := r.str()
			if err != nil {
				return nil, err
			}
			if _, dup := fields[key]; dup {
				return nil, errMalformed
			}
			node, err := decodeCipherText(r, depth+1)
			if err != nil {
				return nil, err
			}
			fields[key] = node
		}
		return fields, nil
	case ctPassthrough:
		// One embedded plaintext value node, decoded one level deeper.
		v, err := decodeValue(r, depth+1)
		if err != nil {
			return nil, err
		}
		return Plain{V: v}, nil
	default:
		return nil, errMalformed
	}
}
