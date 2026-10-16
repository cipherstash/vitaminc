//! `Aes256Cipher` as the sink-based `Cipher` of ADR 0001, driven through
//! `vitaminc_aead::encrypt` and `decrypt`: scalars, nested containers,
//! empty containers and passthrough round-trip through real AES-256-GCM,
//! and a wrong AAD or key fails at the cipher.

use std::collections::BTreeMap;

use vitaminc_aead::{
    decrypt, encrypt, CipherText, Decrypt, DecryptError, Encrypt, EncryptError, MapSink, Sink,
    Unencryptable,
};
use vitaminc_encrypt::{Aes256Cipher, Key};
use vitaminc_protected::{Controlled, Protected};

fn cipher() -> Aes256Cipher {
    Aes256Cipher::new(&Key::from([42u8; 32])).expect("cipher")
}

#[derive(Debug, Clone, PartialEq, Encrypt, Decrypt)]
struct Record {
    #[aead(passthrough)]
    id: u64,
    name: String,
    scores: Vec<u32>,
    labels: BTreeMap<String, String>,
    nickname: Option<String>,
}

fn record() -> Record {
    Record {
        id: 7,
        name: "Ada".into(),
        scores: vec![1, 2, 3],
        labels: BTreeMap::from([("role".to_string(), "founder".to_string())]),
        nickname: None,
    }
}

mod given_a_scalar {
    use super::*;

    #[test]
    fn round_trips_through_aes() {
        let cipher = cipher();
        let node = encrypt("hello".to_string(), &cipher, "ctx").expect("encrypt");
        assert!(
            matches!(node, CipherText::Single(_)),
            "a scalar seals as one leaf"
        );
        let got: String = decrypt(&cipher, node, "ctx").expect("decrypt");
        assert_eq!(got, "hello");
    }

    #[test]
    fn returns_a_cipher_error_under_the_wrong_aad() {
        let cipher = cipher();
        let node = encrypt(42u32, &cipher, "right").expect("encrypt");
        let err = decrypt::<u32, _, _>(&cipher, node, "wrong").expect_err("wrong AAD");
        assert!(matches!(err, DecryptError::Cipher(_)), "got {err:?}");
    }

    #[test]
    fn returns_a_cipher_error_under_the_wrong_key() {
        let node = encrypt(42u32, &cipher(), "ctx").expect("encrypt");
        let other = Aes256Cipher::new(&Key::from([1u8; 32])).expect("cipher");
        let err = decrypt::<u32, _, _>(&other, node, "ctx").expect_err("wrong key");
        assert!(matches!(err, DecryptError::Cipher(_)), "got {err:?}");
    }
}

mod given_a_nested_record {
    use super::*;

    #[test]
    fn round_trips_with_its_passthrough_in_the_clear() {
        let cipher = cipher();
        let node = encrypt(record(), &cipher, "users").expect("encrypt");
        let CipherText::Map(entries) = &node else {
            panic!("a struct seals as a map");
        };
        assert!(
            entries
                .iter()
                .any(|(key, node)| key == "id" && matches!(node, CipherText::Passthrough(_))),
            "the passthrough field is a cleartext entry"
        );
        let got: Record = decrypt(&cipher, node, "users").expect("decrypt");
        assert_eq!(got, record());
    }

    #[test]
    fn seals_empty_containers_as_authenticated_markers() {
        let cipher = cipher();
        let empty = Record {
            scores: Vec::new(),
            labels: BTreeMap::new(),
            ..record()
        };
        let node = encrypt(empty.clone(), &cipher, "users").expect("encrypt");
        let CipherText::Map(entries) = &node else {
            panic!("a struct seals as a map");
        };
        let shapes: BTreeMap<&str, &str> = entries
            .iter()
            .map(|(key, node)| {
                let shape = match node {
                    CipherText::EmptySequence(_) => "empty-seq",
                    CipherText::EmptyMap(_) => "empty-map",
                    _ => "other",
                };
                (key.as_str(), shape)
            })
            .collect();
        assert_eq!(shapes["scores"], "empty-seq");
        assert_eq!(shapes["labels"], "empty-map");
        let got: Record = decrypt(&cipher, node, "users").expect("decrypt");
        assert_eq!(got, empty);
    }

    #[test]
    fn refuses_a_map_with_nothing_sealed() {
        // The derive refuses this shape at compile time, so the source is
        // written by hand: a map whose only entry is a passthrough.
        struct OnlyPlain;
        impl Encrypt for OnlyPlain {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let mut map = sink.map(Some(1))?;
                map.entry("id")?.passthrough(7u64)?;
                map.end()
            }
        }
        let err = encrypt(OnlyPlain, &cipher(), "ctx").expect_err("nothing sealed");
        assert!(
            matches!(
                err,
                EncryptError::Shape(ref refusal)
                    if refusal.reason() == Unencryptable::MapHasNothingSealed
            ),
            "got {err:?}"
        );
    }
}

mod given_protected_bytes {
    use super::*;

    #[test]
    fn round_trips_without_leaving_the_wrapper() {
        let cipher = cipher();
        let secret = Protected::new(vec![0xDEu8, 0xAD, 0xBE, 0xEF]);
        let node = encrypt(secret, &cipher, "blob").expect("encrypt");
        let got: Protected<Vec<u8>> = decrypt(&cipher, node, "blob").expect("decrypt");
        assert_eq!(got.risky_unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }
}
