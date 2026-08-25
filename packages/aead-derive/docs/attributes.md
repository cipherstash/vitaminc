# Attributes

All options live under `#[aead(...)]`. Anything else — a misspelling included —
is a compile error rather than a silently dropped setting, because a dropped
option is one the author believes is in effect.

| Attribute | Applies to | Effect |
|---|---|---|
| `crate = "path"` | container | Name the path to `vitaminc_aead` in the generated code |
| `rename = "name"` | field | Store the field under `name` instead of its own name |
| `passthrough` | field | Store the field **in the clear**, unencrypted and unauthenticated |
| `aad` | field | Store the field **in the clear**, bound into every encrypted field's AAD |

## `#[aead(crate = "...")]`

Points the generated code at a re-export of `vitaminc_aead`, for callers who
depend on it through an umbrella crate rather than directly:

```ignore
#[derive(Encrypt, Decrypt)]
#[aead(crate = "::vitaminc::aead")]
struct User {
    name: String,
}
```

Every path the expansion emits is redirected, so the deriving crate needs no
direct dependency on `vitaminc_aead` at all.

## `#[aead(rename = "...")]`

Changes the map key a field is stored under:

```ignore
#[derive(Encrypt, Decrypt)]
struct User {
    #[aead(rename = "n")]
    name: String,
}
// ciphertext: Map { "n": … }
```

Field names are part of the ciphertext contract — each key is bound into the
AAD its value is sealed against — so renaming a field in Rust breaks
compatibility with data already stored under the old name. `rename` is how you
keep the old wire key while changing the Rust one.

Two fields cannot share a key; the collision is a compile error rather than a
value silently overwriting another. `rename` on a newtype is a compile error
too: a newtype is transparent, so its value is not stored under a key at all
and there is nothing to rename.

## `#[aead(passthrough)]`

Stores a field as a cleartext map entry, so it can be an ordinary database
column that other queries select, filter, and update without holding the key:

```ignore
#[derive(Encrypt, Decrypt)]
struct Row {
    #[aead(passthrough)]
    tenant: String,   // a plain column
    ssn: String,      // encrypted
}
```

### ⚠️ The field gives up all protection

That independence is bought by giving up everything, and the trade is total:

- The value is **not encrypted** — anyone who can read the stored ciphertext
  can read it.
- The value is **not authenticated**. No tag covers it, and unlike an encrypted
  entry's key, nothing binds its key either. It can be edited, retargeted at
  another key, added, or removed, and every encrypted field beside it still
  decrypts. Treat what comes back as untrusted input — it is exactly as
  trustworthy as the column it was read from.
- Deleting the entry is caught only by the ordinary missing-field rule, and is
  not distinguished from a value that was never written.

So: non-sensitive, non-security-deciding data only. Never a field the program
then trusts to make an authorization choice.

A cleartext field that must be tamper-evident wants [`aad`](#aeadaad) instead —
but read the coupling it introduces first. `passthrough` exists precisely to
avoid that coupling.

### Requirements

A passthrough field's type must be `Any + Send + 'static`: the value travels
through the cipher type-erased and is downcast on the way out. That rules out
borrowed types such as `&'a str`.

Two shapes are rejected at compile time:

- **Every field passthrough.** Nothing would be encrypted, so the ciphertext
  would carry no tag at all — neither the associated data nor the entry keys
  would be authenticated. `MapCipher::end` refuses to seal such a container, so
  the derive refuses to emit one.
- **`passthrough` on a newtype.** A newtype is transparent and opens no map, so
  there is no entry to store in the clear; honouring the attribute would mean
  the whole value travelled unencrypted.

## `#[aead(aad)]`

Stores a field in the clear like `passthrough`, and additionally binds its bytes
into the associated data every encrypted field is sealed against. Editing the
cleartext therefore stops those fields opening.

The case it is for is searchable encrypted metadata: an index term derived from
a value and stored beside it, so a query can use the term without the key.

```ignore
#[derive(Encrypt, Decrypt)]
struct Row {
    #[aead(aad)]
    ore_term: Vec<u8>,   // clear, so a query can read it
    ssn: String,         // encrypted, and bound to the term above
}
```

Substituting `ore_term` in storage, deleting it, or transposing it with another
`aad` field all make `ssn` fail to decrypt. The context is a labelled
`PAE(domain, key, bytes, …)` over the `aad` fields in **declaration** order, so
permuting the stored map cannot change it, and each value is bound to its own
key.

### ⚠️ The field is still cleartext, and now everything depends on it

`aad` makes the field *tamper-evident*, not confidential or trustworthy on its
own:

- It is **not encrypted** — anyone who can read the ciphertext can read it.
- Nothing detects a change to it *in isolation*; what happens is that the
  encrypted fields stop decrypting. That is a loud failure, not a silent one,
  but it is the only signal.

And the coupling runs both ways. **Anything that rewrites the field
independently breaks decryption of every encrypted field beside it.** A column
some other process updates on its own is a `passthrough` field, never an `aad`
one. `aad` fits a value *derived from* the encrypted data and rewritten only
when that data is — which is exactly what an index term is.

### Consequences

- **Adding or removing an `aad` field is wire-breaking.** The derivation carries
  its own domain label, so a ciphertext written with context cannot be read
  without it, or the reverse. Existing data does not decode after the change.
- **The decode becomes order-dependent.** An encrypted entry cannot be opened
  until every `aad` field has been read, and `MapAccess` cannot skip ahead to
  fetch one. The derive writes cleartext entries first, so its own ciphertexts
  are fine; a map reordered in storage fails to decrypt. That is a denial of
  service, not a forgery — entry order was never authenticated.

### Requirements

An `aad` field's type must be `AsRef<[u8]>`, which supplies the bytes that go
into the context, as well as the `Any + Send + 'static` that storing it in the
clear requires. `Vec<u8>`, `String`, and byte-array newtypes qualify; an integer
does not — give it a byte encoding you are willing to commit to.

`aad` and `passthrough` on one field is a compile error: `aad` already stores
the value in the clear. `aad` on a newtype is rejected for the same reason
`passthrough` is, with the addition that a newtype has no sibling field for the
value to be bound to. A struct whose fields are *all* cleartext is rejected
whichever attribute is used — an `aad` field needs at least one encrypted field
to bind.
