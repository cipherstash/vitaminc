//! End-to-end checks, against the real AES-256-GCM cipher, for the byte-leaf
//! `Protected` seams (`Encrypt::encrypt_protected` /
//! `Decrypt::decrypt_protected`) and the transparency they give newtypes that
//! derive `Encrypt` around `Protected<[u8; N]>` / `Protected<Vec<u8>>`.

use vitaminc_aead::Encrypt;
use vitaminc_encrypt::{Aes256Cipher, Key};
use vitaminc_protected::{Controlled, Protected};

fn cipher() -> Aes256Cipher {
    Aes256Cipher::new(&Key::from([42u8; 32])).expect("failed to create cipher")
}

#[test]
fn vec_u8_is_a_byte_leaf_that_roundtrips() {
    let cipher = cipher();
    let ct = vec![1u8, 2, 3]
        .encrypt_with_aad(&cipher, "ctx")
        .expect("encrypt");
    let out: Vec<u8> = cipher.decrypt_with_aad(ct, "ctx").expect("decrypt");
    assert_eq!(out, vec![1, 2, 3]);
}

// A `Vec<u8>` ciphertext is the same wire shape as the other byte leaves —
// it reads back as `[u8; N]` and (for valid UTF-8) as `String`.
#[test]
fn vec_u8_shares_the_byte_leaf_wire_shape() {
    let cipher = cipher();
    let ct = b"hi".to_vec().encrypt(&cipher).expect("encrypt");
    let arr: [u8; 2] = cipher.decrypt(ct).expect("decrypt as array");
    assert_eq!(arr, *b"hi");
    let ct = b"hi".to_vec().encrypt(&cipher).expect("encrypt");
    let s: String = cipher.decrypt(ct).expect("decrypt as string");
    assert_eq!(s, "hi");
}

#[test]
fn protected_vec_u8_roundtrips_wrapped() {
    let cipher = cipher();
    let ct = Protected::new(vec![7u8, 8, 9])
        .encrypt_with_aad(&cipher, "ctx")
        .expect("encrypt");
    let out: Protected<Vec<u8>> = cipher.decrypt_with_aad(ct, "ctx").expect("decrypt");
    assert_eq!(out.risky_ref(), &[7, 8, 9]);
}

#[test]
fn protected_array_roundtrips_wrapped() {
    let cipher = cipher();
    let ct = Protected::new([4u8; 16])
        .encrypt_with_aad(&cipher, "ctx")
        .expect("encrypt");
    let out: Protected<[u8; 16]> = cipher.decrypt_with_aad(ct, "ctx").expect("decrypt");
    assert_eq!(out.risky_ref(), &[4u8; 16]);
}

#[test]
fn protected_array_rejects_a_length_mismatch() {
    let cipher = cipher();
    let ct = Protected::new([4u8; 16]).encrypt(&cipher).expect("encrypt");
    assert!(cipher.decrypt::<Protected<[u8; 15]>>(ct).is_err());
    let ct = Protected::new([4u8; 16]).encrypt(&cipher).expect("encrypt");
    assert!(cipher.decrypt::<[u8; 17]>(ct).is_err());
}

// The wrapped and bare forms are interchangeable on the wire: the seam
// changes how the plaintext travels, not what is sealed.
#[test]
fn wrapped_and_bare_byte_leaves_are_interchangeable() {
    let cipher = cipher();

    let from_wrapped = Protected::new([1u8, 2, 3, 4])
        .encrypt_with_aad(&cipher, "ctx")
        .expect("encrypt");
    let bare: [u8; 4] = cipher
        .decrypt_with_aad(from_wrapped, "ctx")
        .expect("decrypt");
    assert_eq!(bare, [1, 2, 3, 4]);

    let from_bare = [1u8, 2, 3, 4]
        .encrypt_with_aad(&cipher, "ctx")
        .expect("encrypt");
    let wrapped: Protected<[u8; 4]> = cipher.decrypt_with_aad(from_bare, "ctx").expect("decrypt");
    assert_eq!(wrapped.risky_ref(), &[1, 2, 3, 4]);
}

// The shape `Key` and the FFI tagged leaves take: a derived newtype around a
// wrapped byte payload. Transparent, so the payload decrypts as plain bytes.
#[derive(Encrypt)]
struct Secret(Protected<[u8; 32]>);

#[derive(Encrypt)]
struct Blob(Protected<Vec<u8>>);

#[test]
fn derived_newtype_around_protected_array_is_transparent() {
    let cipher = cipher();
    let ct = Secret(Protected::new([0xABu8; 32]))
        .encrypt_with_aad(&cipher, "wrap")
        .expect("encrypt");
    let out: Protected<[u8; 32]> = cipher.decrypt_with_aad(ct, "wrap").expect("decrypt");
    assert_eq!(out.risky_ref(), &[0xABu8; 32]);
}

#[test]
fn derived_newtype_around_protected_vec_is_transparent() {
    let cipher = cipher();
    let ct = Blob(Protected::new(vec![1u8, 2, 3]))
        .encrypt_with_aad(&cipher, "wrap")
        .expect("encrypt");
    let out: Vec<u8> = cipher.decrypt_with_aad(ct, "wrap").expect("decrypt");
    assert_eq!(out, vec![1, 2, 3]);
}

// `Key` itself: its derived `Encrypt` seals the raw 32 bytes, so a wrapped
// key reads back as the array it was built from.
#[test]
fn key_encrypts_as_its_raw_bytes() {
    let cipher = cipher();
    let ct = Key::from([0x5Au8; 32])
        .encrypt_with_aad(&cipher, "kek")
        .expect("encrypt");
    let out: Protected<[u8; 32]> = cipher.decrypt_with_aad(ct, "kek").expect("decrypt");
    assert_eq!(out.risky_ref(), &[0x5Au8; 32]);
}
