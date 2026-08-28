//! End-to-end tests for `Passthrough` against the real AES-256-GCM cipher: a
//! struct mixing encrypted and passthrough fields round-trips, the passthrough
//! fields are readable in the stored ciphertext without a key, and a
//! passthrough payload of the wrong type fails to decrypt cleanly.

use vitaminc_aead::{
    Cipher, Decipher, DecipherVisitor, Decrypt, Encrypt, IntoAad, MapAccess, MapCipher,
    Passthrough, Unspecified,
};
use vitaminc_encrypt::{Aes256Cipher, AesCipherText, Key};

fn cipher() -> Aes256Cipher {
    Aes256Cipher::new(&Key::from([42u8; 32])).expect("failed to create cipher")
}

#[derive(Debug, PartialEq)]
struct User {
    id: u32,       // passthrough
    email: String, // encrypted
}

impl Encrypt for User {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher
            .encrypt_map(aad)
            .encrypt_entry("id", Passthrough(self.id))?
            .encrypt_entry("email", self.email)?
            .end()
    }
}

impl<'c> Decrypt<'c> for User {
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        struct UserVisitor;
        impl<'c> DecipherVisitor<'c> for UserVisitor {
            type Value = User;

            fn visit_map<M: MapAccess<'c>>(self, mut map: M) -> Result<User, Unspecified> {
                let (k, Passthrough(id)) = map
                    .next_entry::<Passthrough<u32>>()
                    .map_err(|_| Unspecified)?
                    .ok_or(Unspecified)?;
                if k != "id" {
                    return Err(Unspecified);
                }
                let (k, email) = map
                    .next_entry::<String>()
                    .map_err(|_| Unspecified)?
                    .ok_or(Unspecified)?;
                if k != "email" {
                    return Err(Unspecified);
                }
                Ok(User { id, email })
            }
        }
        decipher.decrypt_map(UserVisitor, aad)
    }
}

#[test]
fn mixed_struct_round_trips() {
    let cipher = cipher();
    let user = User {
        id: 7,
        email: "alice@example.com".into(),
    };

    let ciphertext = user
        .encrypt_with_aad(&cipher, "users")
        .expect("encryption failed");
    let got: User = cipher
        .decrypt_with_aad(ciphertext, "users")
        .expect("decryption failed");

    assert_eq!(
        got,
        User {
            id: 7,
            email: "alice@example.com".into()
        }
    );
}

#[test]
fn passthrough_field_is_readable_in_the_stored_ciphertext() {
    let cipher = cipher();
    let user = User {
        id: 7,
        email: "alice@example.com".into(),
    };

    let ciphertext = user.encrypt(&cipher).expect("encryption failed");
    let AesCipherText::Map(entries) = ciphertext else {
        panic!("a struct encrypts to a map");
    };
    let (key, value) = &entries[0];
    assert_eq!(key, "id");
    let AesCipherText::Passthrough(boxed) = value else {
        panic!("the passthrough field must be a passthrough node");
    };
    assert_eq!(boxed.downcast_ref::<u32>(), Some(&7));
}

#[test]
fn vec_of_mixed_structs_round_trips() {
    let cipher = cipher();
    let users = vec![
        User {
            id: 1,
            email: "a@example.com".into(),
        },
        User {
            id: 2,
            email: "b@example.com".into(),
        },
    ];

    let ciphertext = users
        .encrypt_with_aad(&cipher, "users")
        .expect("encryption failed");
    let got: Vec<User> = cipher
        .decrypt_with_aad(ciphertext, "users")
        .expect("decryption failed");

    assert_eq!(got.len(), 2);
    assert_eq!(got[0].id, 1);
    assert_eq!(got[1].email, "b@example.com");
}

#[test]
fn top_level_passthrough_round_trips() {
    let cipher = cipher();
    let ciphertext = Passthrough(String::from("display"))
        .encrypt(&cipher)
        .expect("encryption failed");
    let got: Passthrough<String> = cipher.decrypt(ciphertext).expect("decryption failed");
    assert_eq!(got.into_inner(), "display");
}

#[test]
fn wrong_payload_type_fails_to_decrypt() {
    let cipher = cipher();
    let ciphertext = Passthrough(7u32)
        .encrypt(&cipher)
        .expect("encryption failed");
    let got: Result<Passthrough<String>, _> = cipher.decrypt(ciphertext);
    assert!(got.is_err());
}

#[test]
fn passthrough_is_not_authenticated() {
    // Documented caveat, pinned: altering a passthrough node in the stored
    // ciphertext is not detected.
    let cipher = cipher();
    let user = User {
        id: 7,
        email: "alice@example.com".into(),
    };
    let ciphertext = user.encrypt(&cipher).expect("encryption failed");
    let AesCipherText::Map(mut entries) = ciphertext else {
        panic!("a struct encrypts to a map");
    };
    entries[0].1 = AesCipherText::Passthrough(Box::new(99u32));
    let tampered = AesCipherText::Map(entries);

    let got: User = cipher
        .decrypt(tampered)
        .expect("tampered passthrough still decrypts");
    assert_eq!(got.id, 99);
}
