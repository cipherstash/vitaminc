// Command userrecord is a runnable walk-through of the vcencrypt README:
// a user record with mixed passthrough/sealed fields, the structured
// ciphertext it produces, per-column storage, single-column decryption,
// and a slice of records.
//
//	cd bindings/go/vcencrypt && go run ./examples/userrecord
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"

	"github.com/cipherstash/vitaminc/bindings/go/vcencrypt"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// User controls its own sealing via vcvalue.Encryptable: id and created_at
// travel in the clear (readable and indexable without the key), email and
// name are sealed.
type User struct {
	ID        int64
	CreatedAt string
	Email     string
	Name      string
}

func (u User) EncryptValue(enc vcvalue.Encoder) error {
	m := enc.Map()
	m.Field("id").Passthrough().Int64(u.ID)
	m.Field("created_at").Passthrough().String(u.CreatedAt)
	m.Field("email").String(u.Email)
	m.Field("name").String(u.Name)
	return m.End()
}

// rowAad binds a ciphertext to its row identity. Sealed leaves from two rows
// are otherwise interchangeable (same key, same field name), so without this
// an attacker with database write access could swap user 1's email into
// user 2's row undetected.
func rowAad(id int64) []byte {
	return fmt.Appendf(nil, "users:%d", id)
}

func main() {
	ctx := context.Background()

	client, err := vcencrypt.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close(ctx)

	// Demonstration only: vitaminc-encrypt binds a single static key by
	// design. Never hard-code keys outside an example.
	key := bytes.Repeat([]byte{0x2a}, vcencrypt.KeySize)
	cipher, err := client.NewCipher(ctx, key)
	if err != nil {
		log.Fatal(err)
	}
	defer cipher.Close(ctx)

	ada := User{ID: 42, CreatedAt: "2026-07-25", Email: "ada@example.com", Name: "Ada Lovelace"}

	// --- Encrypt one record: the ciphertext is a tree, not a blob. --------
	ct, err := cipher.Encrypt(ctx, ada, rowAad(ada.ID))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("structured ciphertext:")
	columns := map[string][]byte{} // sealed leaves, as a database would hold them
	for _, f := range ct.Fields {
		switch f.Node.Kind {
		case vcvalue.KindPassthrough:
			fmt.Printf("  %-11s passthrough  %v\n", f.Key, f.Node.Passthrough)
		case vcvalue.KindSingle:
			fmt.Printf("  %-11s sealed leaf  %d bytes (nonce||ct||tag)\n", f.Key, len(f.Node.Leaf))
			columns[f.Key] = f.Node.Leaf
		}
	}

	// --- Read back one column: rebuild a one-entry map around the leaf. ---
	one := vcvalue.CipherText{
		Kind:   vcvalue.KindMap,
		Fields: []vcvalue.CipherTextField{{Key: "email", Node: vcvalue.CipherText{Kind: vcvalue.KindSingle, Leaf: columns["email"]}}},
	}
	got, err := cipher.Decrypt(ctx, one, rowAad(ada.ID))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nsingle-column decrypt: email = %v\n", got.(vcvalue.Object)[0].Value)

	// The same leaf under the wrong row identity fails authentication.
	if _, err := cipher.Decrypt(ctx, one, rowAad(7)); err != nil {
		fmt.Printf("wrong row AAD:         %v\n", err)
	}

	// --- A slice of records: one KindMap per user inside a KindSeq. -------
	users := []User{ada, {ID: 43, CreatedAt: "2026-07-25", Email: "grace@example.com", Name: "Grace Hopper"}}
	seqCt, err := cipher.Encrypt(ctx, users, []byte("users:list"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nslice of %d users -> %d ciphertext trees:\n", len(users), len(seqCt.Items))
	for i, row := range seqCt.Items {
		sealed := 0
		for _, f := range row.Fields {
			if f.Node.Kind == vcvalue.KindSingle {
				sealed++
			}
		}
		fmt.Printf("  row %d: %d fields, %d sealed\n", i, len(row.Fields), sealed)
	}

	decrypted, err := cipher.Decrypt(ctx, seqCt, []byte("users:list"))
	if err != nil {
		log.Fatal(err)
	}
	for _, row := range decrypted.([]any) {
		obj := row.(vcvalue.Object)
		fmt.Printf("  decrypted: %v %v\n", obj[0].Value.(vcvalue.Plain).V, obj[2].Value)
	}
}
