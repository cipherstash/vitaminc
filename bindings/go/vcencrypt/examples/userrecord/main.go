// Command userrecord is a runnable walk-through of the vcencrypt README,
// storing the results in a real database via sqlx: a user record with mixed
// passthrough/sealed fields, per-column storage (passthrough fields as
// native columns, sealed leaves as BLOBs), single-column decryption, and a
// slice of records.
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

// userRow is the scan destination for whole-row SELECTs: passthrough fields
// map to native columns, sealed fields to BLOB columns holding leaf bytes.
// Column names must equal the sealed field names — the name is authenticated
// into each leaf's AAD, so a mis-mapped column fails decryption instead of
// decrypting into the wrong field.
type userRow struct {
	ID        int64  `db:"id"`
	CreatedAt string `db:"created_at"`
	Email     []byte `db:"email"`
	Name      []byte `db:"name"`
}

const schema = `CREATE TABLE users (
	id         INTEGER PRIMARY KEY,
	created_at TEXT NOT NULL,
	email      BLOB NOT NULL,
	name       BLOB NOT NULL
)`

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

	db := sqlx.MustConnect("sqlite", ":memory:")
	defer db.Close()
	db.MustExec(schema)

	// --- Write path: encrypt each record, walk the tree into a row. -------
	users := []User{
		{ID: 42, CreatedAt: "2026-07-25", Email: "ada@example.com", Name: "Ada Lovelace"},
		{ID: 43, CreatedAt: "2026-07-25", Email: "grace@example.com", Name: "Grace Hopper"},
	}
	for _, u := range users {
		ct, err := cipher.Encrypt(ctx, u, rowAad(u.ID))
		if err != nil {
			log.Fatal(err)
		}
		// Columns flattens the tree into sqlx-bindable named parameters:
		// passthrough fields as native values, sealed fields as leaf bytes.
		cols, err := ct.Columns()
		if err != nil {
			log.Fatal(err)
		}
		if _, err := db.NamedExecContext(ctx, `INSERT INTO users (id, created_at, email, name)
			VALUES (:id, :created_at, :email, :name)`, cols); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Printf("inserted %d users (email/name stored as sealed BLOBs)\n", len(users))

	// Passthrough columns are plain SQL — no key, no cipher.
	var count int
	if err := db.GetContext(ctx, &count, `SELECT COUNT(*) FROM users WHERE created_at = ?`, "2026-07-25"); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("WHERE on passthrough column: %d rows created 2026-07-25\n", count)

	// --- Read path, one column: SELECT the leaf, rebuild, decrypt. --------
	var leaf []byte
	if err := db.GetContext(ctx, &leaf, `SELECT email FROM users WHERE id = ?`, 42); err != nil {
		log.Fatal(err)
	}
	got, err := cipher.Decrypt(ctx, vcvalue.SealedColumns(map[string][]byte{"email": leaf}), rowAad(42))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("single-column decrypt:  email = %v\n", got.(vcvalue.Object)[0].Value)

	// The same leaf under the wrong row identity fails authentication.
	if _, err := cipher.Decrypt(ctx, vcvalue.SealedColumns(map[string][]byte{"email": leaf}), rowAad(7)); err != nil {
		fmt.Printf("wrong row AAD:          %v\n", err)
	}

	// --- Read path, whole record: natives straight from SQL, sealed
	// columns through one decrypt. ------------------------------------------
	var row userRow
	if err := db.GetContext(ctx, &row, `SELECT id, created_at, email, name FROM users WHERE id = ?`, 43); err != nil {
		log.Fatal(err)
	}
	obj, err := cipher.Decrypt(ctx, vcvalue.SealedColumns(map[string][]byte{"email": row.Email, "name": row.Name}), rowAad(row.ID))
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
