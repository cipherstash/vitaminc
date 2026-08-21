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
