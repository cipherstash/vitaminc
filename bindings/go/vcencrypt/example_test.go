package vcencrypt_test

import (
	"bytes"
	"context"
	"fmt"

	"github.com/cipherstash/vitaminc/bindings/go/vcencrypt"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// Example encrypts a user record where the non-secret fields (id, created_at)
// travel in the clear via vcvalue.Plain while email and name are sealed, then
// shows the structured ciphertext — passthrough values readable without the
// key, sealed fields as opaque leaves — and finally decrypts it.
func Example() {
	ctx := context.Background()
	client, err := vcencrypt.NewClient(ctx)
	if err != nil {
		panic(err)
	}
	defer func() { _ = client.Close(ctx) }()

	key := bytes.Repeat([]byte{0x2a}, vcencrypt.KeySize)
	cipher, err := client.NewCipher(ctx, key)
	if err != nil {
		panic(err)
	}
	defer func() { _ = cipher.Close(ctx) }()

	aad := []byte("user:42")
	record := map[string]any{
		"id":         vcvalue.Plain{V: int64(42)},
		"created_at": vcvalue.Plain{V: "2026-07-25"},
		"email":      "ada@example.com",
		"name":       "Ada Lovelace",
	}

	ct, err := cipher.Encrypt(ctx, record, aad)
	if err != nil {
		panic(err)
	}

	// The structured ciphertext, field by field (keys are sorted on encode).
	fmt.Println("ciphertext:")
	for _, f := range ct.Fields {
		switch f.Node.Kind {
		case vcvalue.KindPassthrough:
			fmt.Printf("  %-11s passthrough = %v\n", f.Key, f.Node.Passthrough)
		case vcvalue.KindSingle:
			fmt.Printf("  %-11s sealed (%d-byte leaf)\n", f.Key, len(f.Node.Leaf))
		}
	}

	got, err := cipher.Decrypt(ctx, ct, aad)
	if err != nil {
		panic(err)
	}

	fmt.Println("decrypted:")
	for _, f := range got.(vcvalue.Object) {
		if p, ok := f.Value.(vcvalue.Plain); ok {
			fmt.Printf("  %-11s %v (in the clear)\n", f.Key, p.V)
		} else {
			fmt.Printf("  %-11s %v\n", f.Key, f.Value)
		}
	}

	// Output:
	// ciphertext:
	//   created_at  passthrough = 2026-07-25
	//   email       sealed (44-byte leaf)
	//   id          passthrough = 42
	//   name        sealed (41-byte leaf)
	// decrypted:
	//   created_at  2026-07-25 (in the clear)
	//   email       ada@example.com
	//   id          42 (in the clear)
	//   name        Ada Lovelace
}
