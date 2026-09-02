//! Contract tests for the key/value split on `MapAccess`.
//!
//! `next_key` hands out a key and leaves the value undecrypted so the caller
//! can choose the type to decrypt it into — that is what makes a derived
//! struct with heterogeneous fields decodable. The split also opens two ways
//! to misuse it, both of which leave a stored value's AAD binding unverified,
//! and both of which the implementation must refuse rather than tolerate.

use std::collections::HashMap;

use vitaminc_aead::{Decipher, DecipherVisitor, Encrypt, MapAccess, Unspecified};
use vitaminc_encrypt::Aes256Cipher;

mod common;
use common::cipher;

fn two_entry_ciphertext(cipher: &Aes256Cipher) -> vitaminc_encrypt::AesCipherText {
    let mut map: HashMap<String, String> = HashMap::new();
    map.insert("first".to_string(), "a".to_string());
    map.insert("second".to_string(), "b".to_string());
    map.encrypt(cipher).expect("encryption failed")
}

/// Reads every key then every value — i.e. calls `next_key` twice in a row.
struct SkipsAValue;

impl<'c> DecipherVisitor<'c> for SkipsAValue {
    type Value = ();

    fn visit_map<A: MapAccess<'c>>(self, mut map: A) -> Result<Self::Value, Unspecified> {
        map.next_key().map_err(|_| Unspecified)?;
        // Second key without consuming the first value: the skipped entry
        // would never have its AAD binding checked.
        map.next_key().map_err(|_| Unspecified)?;
        Ok(())
    }
}

/// Asks for a value before any key has been read.
struct ValueWithoutKey;

impl<'c> DecipherVisitor<'c> for ValueWithoutKey {
    type Value = ();

    fn visit_map<A: MapAccess<'c>>(self, mut map: A) -> Result<Self::Value, Unspecified> {
        map.next_value::<String>().map_err(|_| Unspecified)?;
        Ok(())
    }
}

/// The well-behaved sequence: key, value, key, value, then exhaustion.
struct ReadsEveryEntry;

impl<'c> DecipherVisitor<'c> for ReadsEveryEntry {
    type Value = Vec<(String, String)>;

    fn visit_map<A: MapAccess<'c>>(self, mut map: A) -> Result<Self::Value, Unspecified> {
        let mut entries = Vec::new();
        while let Some(key) = map.next_key().map_err(|_| Unspecified)? {
            let value = map.next_value::<String>().map_err(|_| Unspecified)?;
            entries.push((key, value));
        }
        Ok(entries)
    }
}

#[test]
fn skipping_a_value_is_rejected() {
    let cipher = cipher();
    let ciphertext = two_entry_ciphertext(&cipher);

    let result = cipher
        .decipher(ciphertext)
        .decrypt_map(SkipsAValue, "".as_bytes());
    assert!(result.is_err());
}

#[test]
fn value_without_a_key_is_rejected() {
    let cipher = cipher();
    let ciphertext = two_entry_ciphertext(&cipher);

    let result = cipher
        .decipher(ciphertext)
        .decrypt_map(ValueWithoutKey, "".as_bytes());
    assert!(result.is_err());
}

#[test]
fn key_then_value_reads_every_entry() {
    let cipher = cipher();
    let ciphertext = two_entry_ciphertext(&cipher);

    let mut entries = cipher
        .decipher(ciphertext)
        .decrypt_map(ReadsEveryEntry, "".as_bytes())
        .expect("decryption failed");
    entries.sort();

    assert_eq!(
        entries,
        vec![
            ("first".to_string(), "a".to_string()),
            ("second".to_string(), "b".to_string()),
        ]
    );
}

#[test]
fn next_entry_still_works_over_the_split() {
    // `HashMap`'s own `Decrypt` impl goes through the defaulted `next_entry`,
    // so a passing roundtrip proves the default composes with the split.
    let cipher = cipher();
    let ciphertext = two_entry_ciphertext(&cipher);

    let decrypted: HashMap<String, String> = cipher.decrypt(ciphertext).expect("decryption failed");
    assert_eq!(decrypted.get("first").map(String::as_str), Some("a"));
    assert_eq!(decrypted.get("second").map(String::as_str), Some("b"));
}
