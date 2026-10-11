//! Real AES-256-GCM: the spike's guest code against today's.

mod common;

use common::valid;
use vitaminc_aead_value::Value;
use vitaminc_encrypt::{Aes256Cipher, AesCipherText, Encrypt, Key};
use vitaminc_plaintext_spike::hosts::go_guest::{spike, today, GuestError};
use vitaminc_plaintext_spike::Tagged;
use vitaminc_protected::Controlled;

const AAD: &[u8] = b"\x01\x00\x00\x00spike";

fn cipher() -> Aes256Cipher {
    Aes256Cipher::new(&Key::from([7u8; 32])).unwrap()
}

#[test]
fn spike_and_today_interoperate_both_ways() {
    let cipher = cipher();
    for v in valid() {
        let new_ct = spike::encrypt(&cipher, AAD, &v.bytes).expect(&v.name);
        let old_ct = today::encrypt(&cipher, AAD, &v.bytes).expect(&v.name);

        assert_eq!(today::decrypt(&cipher, AAD, &new_ct).expect(&v.name), v.bytes, "new to old: {}", v.name);
        assert_eq!(spike::decrypt(&cipher, AAD, &old_ct).expect(&v.name).risky_ref(), &v.bytes[..], "old to new: {}", v.name);
        assert_eq!(spike::decrypt(&cipher, AAD, &new_ct).expect(&v.name).risky_ref(), &v.bytes[..], "new to new: {}", v.name);
    }
}

#[test]
fn wrong_aad_fails_on_the_spike_path() {
    let cipher = cipher();
    for v in valid() {
        let ct = spike::encrypt(&cipher, AAD, &v.bytes).unwrap();
        let wrong = spike::decrypt(&cipher, b"\x01\x00\x00\x00other", &ct);
        // A passthrough-only value authenticates nothing, by design.
        if wrong.is_ok() {
            assert!(v.bytes.first() == Some(&0xF2), "{} decrypted under the wrong AAD", v.name);
        } else {
            assert_eq!(wrong.err(), Some(GuestError::Auth), "{}", v.name);
        }
    }
}

#[test]
fn the_scalar_example_from_the_trace() {
    let cipher = cipher();
    let leaf_len = |ct: AesCipherText| match ct {
        AesCipherText::Single(leaf) => leaf.as_ref().len(),
        _ => panic!("expected a single leaf"),
    };
    // Go's uint32(34): 1 + 12 + 5 + 16. JS's 34n (Int8): 1 + 12 + 2 + 16.
    assert_eq!(leaf_len(Tagged(34u32).encrypt(&cipher).unwrap()), 34);
    assert_eq!(leaf_len(Tagged(34i8).encrypt(&cipher).unwrap()), 31);

    // And today's `Decrypt for Value` reads the spike's leaf back.
    let value: Value = cipher.decrypt(Tagged(34u32).encrypt(&cipher).unwrap()).unwrap();
    assert!(matches!(value, Value::UInt32(34)));
}
