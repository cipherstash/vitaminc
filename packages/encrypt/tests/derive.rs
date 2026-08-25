//! End-to-end tests for `#[derive(Encrypt)]` / `#[derive(Decrypt)]` against the
//! real AES-256-GCM cipher.
//!
//! The derive macros only generate calls into the `Cipher`/`Decipher` protocol,
//! so what needs proving here is the wire contract they commit to: a derived
//! struct is a map keyed by field name, its ciphertext is interchangeable with
//! the equivalent `HashMap`, its fields are individually key-bound, and its
//! decode is strict about missing, unknown, and duplicate keys.

use std::collections::HashMap;

use vitaminc_aead::{Decrypt, Encrypt};
use vitaminc_encrypt::{Aes256Cipher, Key};

fn cipher() -> Aes256Cipher {
    Aes256Cipher::new(&Key::from([42u8; 32])).expect("failed to create cipher")
}

#[derive(Encrypt, Decrypt, Debug, PartialEq)]
struct User {
    name: String,
    age: u32,
}

#[derive(Encrypt, Decrypt, Debug, PartialEq)]
struct Renamed {
    #[aead(rename = "n")]
    name: String,
}

#[derive(Encrypt, Decrypt, Debug, PartialEq)]
struct Newtype(String);

#[derive(Encrypt, Decrypt, Debug, PartialEq)]
struct Pair(String, u32);

#[derive(Encrypt, Decrypt, Debug, PartialEq)]
struct Unit;

#[derive(Encrypt, Decrypt, Debug, PartialEq)]
struct Nested {
    user: User,
    tags: Vec<String>,
    note: Option<String>,
}

#[derive(Encrypt, Decrypt, Debug, PartialEq)]
struct Generic<T> {
    value: T,
    label: String,
}

#[test]
fn roundtrip_named_struct() {
    let cipher = cipher();
    let plaintext = User {
        name: "alice".to_string(),
        age: 42,
    };

    let ciphertext = User {
        name: "alice".to_string(),
        age: 42,
    }
    .encrypt(&cipher)
    .expect("encryption failed");

    let decrypted: User = cipher.decrypt(ciphertext).expect("decryption failed");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn roundtrip_newtype_is_transparent() {
    let cipher = cipher();

    // A newtype adds nothing to the ciphertext, so a `Newtype` ciphertext
    // decrypts as its inner `String` and vice versa. This is the property that
    // makes wrapping an existing type a non-breaking change.
    let ciphertext = Newtype("hello".to_string())
        .encrypt(&cipher)
        .expect("encryption failed");
    let as_inner: String = cipher.decrypt(ciphertext).expect("decryption failed");
    assert_eq!(as_inner, "hello");

    let ciphertext = "hello".encrypt(&cipher).expect("encryption failed");
    let as_newtype: Newtype = cipher.decrypt(ciphertext).expect("decryption failed");
    assert_eq!(as_newtype, Newtype("hello".to_string()));
}

#[test]
fn roundtrip_tuple_struct() {
    let cipher = cipher();
    let ciphertext = Pair("alice".to_string(), 42)
        .encrypt(&cipher)
        .expect("encryption failed");
    let decrypted: Pair = cipher.decrypt(ciphertext).expect("decryption failed");
    assert_eq!(decrypted, Pair("alice".to_string(), 42));
}

#[test]
fn roundtrip_unit_struct() {
    let cipher = cipher();
    let ciphertext = Unit.encrypt(&cipher).expect("encryption failed");
    let decrypted: Unit = cipher.decrypt(ciphertext).expect("decryption failed");
    assert_eq!(decrypted, Unit);
}

#[test]
fn roundtrip_nested_struct() {
    let cipher = cipher();
    let plaintext = Nested {
        user: User {
            name: "alice".to_string(),
            age: 42,
        },
        tags: vec!["a".to_string(), "b".to_string()],
        note: None,
    };
    let ciphertext = Nested {
        user: User {
            name: "alice".to_string(),
            age: 42,
        },
        tags: vec!["a".to_string(), "b".to_string()],
        note: None,
    }
    .encrypt(&cipher)
    .expect("encryption failed");

    let decrypted: Nested = cipher.decrypt(ciphertext).expect("decryption failed");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn roundtrip_generic_struct() {
    let cipher = cipher();
    let ciphertext = Generic {
        value: 7u32,
        label: "seven".to_string(),
    }
    .encrypt(&cipher)
    .expect("encryption failed");

    let decrypted: Generic<u32> = cipher.decrypt(ciphertext).expect("decryption failed");
    assert_eq!(
        decrypted,
        Generic {
            value: 7u32,
            label: "seven".to_string(),
        }
    );
}

#[test]
fn derived_struct_is_wire_compatible_with_hashmap() {
    let cipher = cipher();

    // Same keys, same per-entry AAD binding: a derived struct's ciphertext is
    // exactly the map its fields describe. Downstream storage that treats
    // records as maps therefore needs no separate encoding for derived types.
    let mut map: HashMap<String, String> = HashMap::new();
    map.insert("name".to_string(), "alice".to_string());
    let ciphertext = map.encrypt(&cipher).expect("encryption failed");

    let decrypted: OneField = cipher.decrypt(ciphertext).expect("decryption failed");
    assert_eq!(decrypted.name, "alice");

    let ciphertext = OneField {
        name: "alice".to_string(),
    }
    .encrypt(&cipher)
    .expect("encryption failed");
    let back: HashMap<String, String> = cipher.decrypt(ciphertext).expect("decryption failed");
    assert_eq!(back.get("name").map(String::as_str), Some("alice"));
}

#[derive(Encrypt, Decrypt, Debug, PartialEq)]
struct OneField {
    name: String,
}

#[test]
fn rename_changes_the_wire_key() {
    let cipher = cipher();

    let ciphertext = Renamed {
        name: "alice".to_string(),
    }
    .encrypt(&cipher)
    .expect("encryption failed");

    // Stored under "n", not "name" — so the un-renamed struct cannot read it.
    let back: HashMap<String, String> = cipher.decrypt(ciphertext).expect("decryption failed");
    assert_eq!(back.get("n").map(String::as_str), Some("alice"));

    let ciphertext = Renamed {
        name: "alice".to_string(),
    }
    .encrypt(&cipher)
    .expect("encryption failed");
    assert!(cipher.decrypt::<OneField>(ciphertext).is_err());
}

#[test]
fn missing_field_is_rejected() {
    let cipher = cipher();

    // `User` needs both `name` and `age`; a map carrying only one is refused
    // rather than defaulted, because an absent entry is an unverified one.
    let mut map: HashMap<String, String> = HashMap::new();
    map.insert("name".to_string(), "alice".to_string());
    let ciphertext = map.encrypt(&cipher).expect("encryption failed");

    assert!(cipher.decrypt::<User>(ciphertext).is_err());
}

#[test]
fn unknown_field_is_rejected() {
    let cipher = cipher();

    let mut map: HashMap<String, String> = HashMap::new();
    map.insert("name".to_string(), "alice".to_string());
    map.insert("nickname".to_string(), "al".to_string());
    let ciphertext = map.encrypt(&cipher).expect("encryption failed");

    assert!(cipher.decrypt::<OneField>(ciphertext).is_err());
}

#[test]
fn field_order_does_not_matter() {
    let cipher = cipher();

    // `HashMap` iteration order is arbitrary, so encrypting the same two
    // entries repeatedly exercises both orderings; every one must decode.
    for _ in 0..16 {
        let mut map: HashMap<String, String> = HashMap::new();
        map.insert("first".to_string(), "a".to_string());
        map.insert("second".to_string(), "b".to_string());
        let ciphertext = map.encrypt(&cipher).expect("encryption failed");

        let decrypted: TwoStrings = cipher.decrypt(ciphertext).expect("decryption failed");
        assert_eq!(decrypted.first, "a");
        assert_eq!(decrypted.second, "b");
    }
}

#[derive(Encrypt, Decrypt, Debug, PartialEq)]
struct TwoStrings {
    first: String,
    second: String,
}

#[test]
fn field_values_are_bound_to_their_key() {
    let cipher = cipher();

    // Both fields are `String`s of equal length, so nothing but the AAD
    // binding distinguishes them. Swapping the two entries in the stored
    // ciphertext must therefore fail to decrypt, not silently transpose them.
    let ciphertext = TwoStrings {
        first: "aaa".to_string(),
        second: "bbb".to_string(),
    }
    .encrypt(&cipher)
    .expect("encryption failed");

    let swapped = match ciphertext {
        vitaminc_aead::CipherText::Map(entries) => {
            let mut entries = entries;
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            let (_, first) = entries.remove(0);
            let (_, second) = entries.remove(0);
            vitaminc_aead::CipherText::Map(vec![
                ("first".to_string(), second),
                ("second".to_string(), first),
            ])
        }
        other => panic!("expected a Map ciphertext, got {other:?}"),
    };

    assert!(cipher.decrypt::<TwoStrings>(swapped).is_err());
}

#[test]
fn wrong_aad_fails() {
    let cipher = cipher();

    let ciphertext = User {
        name: "alice".to_string(),
        age: 42,
    }
    .encrypt_with_aad(&cipher, "tenant:1".as_bytes())
    .expect("encryption failed");

    assert!(cipher
        .decrypt_with_aad::<User, _>(ciphertext, "tenant:2".as_bytes())
        .is_err());
}

/// A database row: two columns stored in the clear so other queries can read
/// and write them independently, one encrypted column alongside.
#[derive(Encrypt, Decrypt, Debug, PartialEq)]
struct Row {
    #[aead(passthrough)]
    id: i64,
    #[aead(passthrough)]
    tenant: String,
    ssn: String,
}

fn a_row() -> Row {
    Row {
        id: 7,
        tenant: "acme".to_string(),
        ssn: "123-45-6789".to_string(),
    }
}

/// Replace the payload stored under `key`, leaving the rest of the map alone —
/// what an `UPDATE` touching a single column does to the stored value.
fn rewrite_entry(
    ciphertext: vitaminc_encrypt::AesCipherText,
    key: &str,
    payload: vitaminc_encrypt::AesCipherText,
) -> vitaminc_encrypt::AesCipherText {
    match ciphertext {
        vitaminc_aead::CipherText::Map(entries) => {
            let mut payload = Some(payload);
            vitaminc_aead::CipherText::Map(
                entries
                    .into_iter()
                    .map(|(k, v)| match k == key {
                        true => (k, payload.take().expect("key appears more than once")),
                        false => (k, v),
                    })
                    .collect(),
            )
        }
        other => panic!("expected a Map ciphertext, got {other:?}"),
    }
}

#[test]
fn roundtrip_mixed_passthrough_and_encrypted() {
    let cipher = cipher();

    let ciphertext = a_row().encrypt(&cipher).expect("encryption failed");
    let decrypted: Row = cipher.decrypt(ciphertext).expect("decryption failed");

    assert_eq!(decrypted, a_row());
}

/// The whole point of passthrough: the value is readable straight out of the
/// stored ciphertext with no key at all, so it can be an ordinary column.
#[test]
fn a_passthrough_column_is_readable_without_the_key() {
    let cipher = cipher();
    let ciphertext = a_row().encrypt(&cipher).expect("encryption failed");

    let entries = match &ciphertext {
        vitaminc_aead::CipherText::Map(entries) => entries,
        other => panic!("expected a Map ciphertext, got {other:?}"),
    };

    let tenant = entries
        .iter()
        .find(|(k, _)| k == "tenant")
        .map(|(_, v)| v)
        .expect("tenant entry missing");
    match tenant {
        vitaminc_aead::CipherText::Passthrough(value) => {
            let value = value.downcast_ref::<String>().expect("wrong payload type");
            assert_eq!(value, "acme");
        }
        other => panic!("expected a Passthrough node, got {other:?}"),
    }

    // The encrypted column is *not* readable the same way.
    let ssn = entries
        .iter()
        .find(|(k, _)| k == "ssn")
        .map(|(_, v)| v)
        .expect("ssn entry missing");
    assert!(matches!(ssn, vitaminc_aead::CipherText::Single(_)));
}

/// A passthrough column carries no tag and its key is bound into nothing, so
/// an independent write to it — the `UPDATE tenant = …` this shape exists to
/// allow — leaves the row decryptable and simply reads back the new value.
///
/// Stated the other way, which is the security-relevant reading: a passthrough
/// column is attacker-modifiable, and nothing about the ciphertext detects it.
#[test]
fn rewriting_a_passthrough_column_is_undetectable_by_design() {
    let cipher = cipher();
    let ciphertext = a_row().encrypt(&cipher).expect("encryption failed");

    let rewritten = rewrite_entry(
        ciphertext,
        "tenant",
        vitaminc_aead::CipherText::Passthrough(Box::new("evilcorp".to_string())),
    );

    let decrypted: Row = cipher.decrypt(rewritten).expect("decryption failed");
    assert_eq!(decrypted.tenant, "evilcorp");
    // The encrypted column is untouched by the substitution.
    assert_eq!(decrypted.ssn, "123-45-6789");
}

/// Passthrough entries must not weaken the entries around them: the encrypted
/// column keeps its per-key AAD binding.
#[test]
fn an_encrypted_column_still_fails_when_tampered() {
    let cipher = cipher();

    let ciphertext = a_row().encrypt(&cipher).expect("encryption failed");
    let other = Row {
        ssn: "999-99-9999".to_string(),
        ..a_row()
    }
    .encrypt(&cipher)
    .expect("encryption failed");

    // Lift the encrypted `ssn` node out of the second ciphertext and graft it
    // onto the first — a value sealed under the same key and the same AAD.
    let grafted_ssn = match other {
        vitaminc_aead::CipherText::Map(entries) => entries
            .into_iter()
            .find(|(k, _)| k == "ssn")
            .map(|(_, v)| v)
            .expect("ssn entry missing"),
        other => panic!("expected a Map ciphertext, got {other:?}"),
    };

    let grafted = rewrite_entry(ciphertext, "ssn", grafted_ssn);

    // The graft *does* decrypt — same key, same AAD — which is exactly why the
    // encrypted column must not be relied on to authenticate the row as a
    // whole. What it proves is narrower: the entry is bound to its own key.
    let decrypted: Row = cipher.decrypt(grafted).expect("decryption failed");
    assert_eq!(decrypted.ssn, "999-99-9999");

    // Moving that same node onto a different key breaks the binding.
    let ciphertext = a_row().encrypt(&cipher).expect("encryption failed");
    let moved = match ciphertext {
        vitaminc_aead::CipherText::Map(entries) => vitaminc_aead::CipherText::Map(
            entries
                .into_iter()
                .map(|(k, v)| match k.as_str() {
                    "ssn" => ("tenant".to_string(), v),
                    _ => (k, v),
                })
                .collect(),
        ),
        other => panic!("expected a Map ciphertext, got {other:?}"),
    };
    assert!(cipher.decrypt::<Row>(moved).is_err());
}

/// The downcast is the only check a passthrough read performs. It catches a
/// payload of the wrong type — a type confusion, not a tamper — rather than
/// handing the struct a field it cannot hold.
#[test]
fn a_passthrough_payload_of_the_wrong_type_is_rejected() {
    let cipher = cipher();
    let ciphertext = a_row().encrypt(&cipher).expect("encryption failed");

    let confused = rewrite_entry(
        ciphertext,
        "tenant",
        vitaminc_aead::CipherText::Passthrough(Box::new(42u8)),
    );

    assert!(cipher.decrypt::<Row>(confused).is_err());
}

/// Deleting a passthrough entry cannot be detected cryptographically, so the
/// decode falls back on the same strictness every other field gets: a missing
/// field is a rejection, not a default.
#[test]
fn a_deleted_passthrough_column_is_rejected_as_a_missing_field() {
    let cipher = cipher();
    let ciphertext = a_row().encrypt(&cipher).expect("encryption failed");

    let truncated = match ciphertext {
        vitaminc_aead::CipherText::Map(entries) => vitaminc_aead::CipherText::Map(
            entries.into_iter().filter(|(k, _)| k != "tenant").collect(),
        ),
        other => panic!("expected a Map ciphertext, got {other:?}"),
    };

    assert!(cipher.decrypt::<Row>(truncated).is_err());
}

/// An encrypted entry must not be readable through the passthrough path: that
/// would hand back a payload whose tag was never checked.
#[test]
fn an_encrypted_entry_cannot_be_read_as_a_passthrough() {
    let cipher = cipher();
    let ciphertext = a_row().encrypt(&cipher).expect("encryption failed");

    // `ssn` is sealed; relabel it as the `tenant` key, which `Row` decodes
    // through `next_passthrough`.
    let swapped = match ciphertext {
        vitaminc_aead::CipherText::Map(entries) => vitaminc_aead::CipherText::Map(
            entries
                .into_iter()
                .filter(|(k, _)| k != "tenant")
                .map(|(k, v)| match k.as_str() {
                    "ssn" => ("tenant".to_string(), v),
                    _ => (k, v),
                })
                .collect(),
        ),
        other => panic!("expected a Map ciphertext, got {other:?}"),
    };

    assert!(cipher.decrypt::<Row>(swapped).is_err());
}
