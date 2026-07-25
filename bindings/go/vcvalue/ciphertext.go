package vcvalue

import "errors"

// CipherText is the Go projection of vitaminc's generic ciphertext
// container. The container shape has no canonical byte representation — only
// the sealed leaf bytes (inside Leaf) are a frozen format. The transport
// encoding used to cross the FFI boundary is an implementation detail;
// durable cross-language storage is the EQL layer's job.
type CipherText struct {
	Kind   CipherTextKind
	Leaf   []byte // Single, None
	Items  []CipherText
	Fields []CipherTextField
	// Passthrough holds the decoded plaintext value (in the Unmarshal decode
	// shape — Go natives plus Object) for a KindPassthrough node: a field that
	// travelled in the clear, readable without the key.
	Passthrough any
}

// CipherTextField is one entry of a map-mode ciphertext. The key travels in
// the clear but is cryptographically bound to its sealed value: renaming or
// swapping keys makes decryption fail.
type CipherTextField struct {
	Key  string
	Node CipherText
}

// CipherTextKind identifies a ciphertext node's shape.
type CipherTextKind byte

const (
	// KindSingle is a sealed leaf value.
	KindSingle CipherTextKind = 0x01
	// KindNone is a sealed "no value" marker (Option::None) — still
	// authenticated, so its absence can't be forged.
	KindNone CipherTextKind = 0x02
	// KindSeq is a sequence of nodes.
	KindSeq CipherTextKind = 0x03
	// KindMap is a map of clear keys to nodes.
	KindMap CipherTextKind = 0x04
	// KindPassthrough is a value that travelled in the clear beside the
	// sealed nodes — unencrypted and unauthenticated. Its readable value is
	// in the Passthrough field.
	KindPassthrough CipherTextKind = 0x05
)

// MarshalTransport encodes the ciphertext tree into transport bytes.
func (ct CipherText) MarshalTransport() ([]byte, error) {
	return encodeCipherText(nil, &ct, 0)
}

// UnmarshalCipherText decodes a transport-encoded ciphertext tree, requiring
// the whole buffer to be consumed.
func UnmarshalCipherText(buf []byte) (CipherText, error) {
	r := &reader{buf: buf}
	ct, err := decodeCipherText(r, 0)
	if err != nil {
		return CipherText{}, err
	}
	if !r.finished() {
		return CipherText{}, errMalformed
	}
	return ct, nil
}

func encodeCipherText(out []byte, ct *CipherText, depth int) ([]byte, error) {
	if depth > maxDepth {
		return nil, errors.New("vcvalue: ciphertext is nested too deeply")
	}
	switch ct.Kind {
	case KindSingle, KindNone:
		out = append(out, byte(ct.Kind))
		return appendChunk(out, ct.Leaf)
	case KindSeq:
		out = append(out, byte(ct.Kind))
		out, err := appendLen(out, len(ct.Items))
		if err != nil {
			return nil, err
		}
		for i := range ct.Items {
			if out, err = encodeCipherText(out, &ct.Items[i], depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	case KindMap:
		out = append(out, byte(ct.Kind))
		out, err := appendLen(out, len(ct.Fields))
		if err != nil {
			return nil, err
		}
		for i := range ct.Fields {
			if out, err = appendChunk(out, []byte(ct.Fields[i].Key)); err != nil {
				return nil, err
			}
			if out, err = encodeCipherText(out, &ct.Fields[i].Node, depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	case KindPassthrough:
		out = append(out, byte(ct.Kind))
		// Encode the plaintext payload as one value node, sharing the
		// recursion budget with the surrounding ciphertext (depth+1), mirroring
		// the Rust CT_PASSTHROUGH framing.
		st := &encState{buf: out}
		encodeAny(Encoder{st: st, depth: depth + 1}, ct.Passthrough)
		if st.err != nil {
			return nil, st.err
		}
		return st.buf, nil
	default:
		return nil, errors.New("vcvalue: unknown ciphertext kind")
	}
}

func decodeCipherText(r *reader, depth int) (CipherText, error) {
	if depth > maxDepth {
		return CipherText{}, errMalformed
	}
	tag, err := r.byteTag()
	if err != nil {
		return CipherText{}, err
	}
	switch CipherTextKind(tag) {
	case KindSingle, KindNone:
		n, err := r.count()
		if err != nil {
			return CipherText{}, err
		}
		s, err := r.take(n)
		if err != nil {
			return CipherText{}, err
		}
		leaf := make([]byte, len(s))
		copy(leaf, s)
		return CipherText{Kind: CipherTextKind(tag), Leaf: leaf}, nil
	case KindSeq:
		n, err := r.count()
		if err != nil {
			return CipherText{}, err
		}
		items := make([]CipherText, 0, n)
		for range n {
			item, err := decodeCipherText(r, depth+1)
			if err != nil {
				return CipherText{}, err
			}
			items = append(items, item)
		}
		return CipherText{Kind: KindSeq, Items: items}, nil
	case KindMap:
		n, err := r.count()
		if err != nil {
			return CipherText{}, err
		}
		fields := make([]CipherTextField, 0, n)
		for range n {
			key, err := r.str()
			if err != nil {
				return CipherText{}, err
			}
			node, err := decodeCipherText(r, depth+1)
			if err != nil {
				return CipherText{}, err
			}
			fields = append(fields, CipherTextField{Key: key, Node: node})
		}
		return CipherText{Kind: KindMap, Fields: fields}, nil
	case KindPassthrough:
		// One embedded plaintext value node, decoded one level deeper.
		v, err := decodeValue(r, depth+1)
		if err != nil {
			return CipherText{}, err
		}
		return CipherText{Kind: KindPassthrough, Passthrough: v}, nil
	default:
		return CipherText{}, errMalformed
	}
}
