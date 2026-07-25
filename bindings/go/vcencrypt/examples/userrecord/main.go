// Command userrecord is a runnable walk-through of the vcencrypt README,
// storing the results in a real database via sqlx: a slice of user records
// with mixed passthrough/sealed fields is encrypted in ONE call (the
// collection itself is encryptable, the Go analog of Rust's
// `impl Encrypt for Vec<T>`), each resulting row binds directly as named
// parameters, and reads decrypt one column or a whole record.
//
//	cd bindings/go/vcencrypt/examples && go run ./userrecord
//
// The sqlite driver is pure Go, so the whole example still runs with
// CGO_ENABLED=0 — same as the binding itself.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"

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

// userRow is the scan destination for whole-row SELECTs. Passthrough fields
// map to native columns; sealed fields scan straight into vcvalue.Sealed
// (it implements sql.Scanner). Column names must equal the sealed field
// names — the name is authenticated into each leaf's AAD, so a mis-mapped
// column fails decryption instead of decrypting into the wrong field.
type userRow struct {
	ID        int64          `db:"id"`
	CreatedAt string         `db:"created_at"`
	Email     vcvalue.Sealed `db:"email"`
	Name      vcvalue.Sealed `db:"name"`
}

const schema = `CREATE TABLE users (
	id         INTEGER PRIMARY KEY,
	created_at TEXT NOT NULL,
	email      BLOB NOT NULL,
	name       BLOB NOT NULL
)`

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

	db := sqlx.MustConnect("sqlite", ":memory:")
	defer db.Close()
	db.MustExec(schema)

	// The AAD is shared by everything sealed in one Encrypt call. Batch
	// encryption binds it to the collection; a caller that instead needs
	// each row bound to its own identity encrypts row-by-row with a
	// per-row AAD (e.g. "users:42").
	aad := []byte("users")

	// --- Write path: ONE Encrypt call seals the whole slice. --------------
	users := []User{
		{ID: 42, CreatedAt: "2026-07-25", Email: "ada@example.com", Name: "Ada Lovelace"},
		{ID: 43, CreatedAt: "2026-07-25", Email: "grace@example.com", Name: "Grace Hopper"},
	}
	ct, err := cipher.Encrypt(ctx, users, aad)
	if err != nil {
		log.Fatal(err)
	}

	// The ciphertext mirrors the plaintext's structure: a []any of rows,
	// each already a map of named parameters — passthrough fields as Plain
	// (native values to the driver), sealed fields as Sealed leaf bytes.
	for _, row := range ct.([]any) {
		if _, err := db.NamedExecContext(ctx, `INSERT INTO users (id, created_at, email, name)
			VALUES (:id, :created_at, :email, :name)`, row.(map[string]any)); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Printf("inserted %d users from one Encrypt call\n", len(users))

	// Passthrough columns are plain SQL — no key, no cipher.
	var count int
	if err := db.GetContext(ctx, &count, `SELECT COUNT(*) FROM users WHERE created_at = ?`, "2026-07-25"); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("WHERE on passthrough column: %d rows created 2026-07-25\n", count)

	// --- Read path, one column: scan the leaf, decrypt it under its name. -
	var leaf vcvalue.Sealed
	if err := db.GetContext(ctx, &leaf, `SELECT email FROM users WHERE id = ?`, 42); err != nil {
		log.Fatal(err)
	}
	got, err := cipher.Decrypt(ctx, map[string]any{"email": leaf}, aad)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("single-column decrypt:  email = %v\n", got.(vcvalue.Object)[0].Value)

	// The same leaf under the wrong AAD fails authentication.
	if _, err := cipher.Decrypt(ctx, map[string]any{"email": leaf}, []byte("other")); err != nil {
		fmt.Printf("wrong AAD:              %v\n", err)
	}

	// --- Read path, whole record: natives straight from SQL, sealed
	// columns through one decrypt. ------------------------------------------
	var row userRow
	if err := db.GetContext(ctx, &row, `SELECT id, created_at, email, name FROM users WHERE id = ?`, 43); err != nil {
		log.Fatal(err)
	}
	obj, err := cipher.Decrypt(ctx, map[string]any{"email": row.Email, "name": row.Name}, aad)
	if err != nil {
		log.Fatal(err)
	}
	u := User{ID: row.ID, CreatedAt: row.CreatedAt}
	for _, f := range obj.(vcvalue.Object) {
		switch f.Key {
		case "email":
			u.Email = f.Value.(string)
		case "name":
			u.Name = f.Value.(string)
		}
	}
	fmt.Printf("whole-record read:      %+v\n", u)
}
