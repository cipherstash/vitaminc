use vitaminc_aead::{Context, Encrypt};
use vitaminc_encrypt::{Aes256Cipher, Key};
use vitaminc_protected::{Controlled, Protected};

fn cipher() -> Aes256Cipher {
    Aes256Cipher::new(&Key::from([7; 32])).expect("cipher")
}

#[test]
fn primitive_128_bit_integers_seal_as_untagged_little_endian_bytes() {
    let cipher = cipher();
    let signed: Vec<u8> = cipher
        .decrypt(i128::MIN.encrypt(&cipher).expect("encrypt"))
        .expect("bytes");
    assert_eq!(signed, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80]);
    let unsigned: Vec<u8> = cipher
        .decrypt(
            0x0F0E0D0C0B0A09080706050403020100u128
                .encrypt(&cipher)
                .expect("encrypt"),
        )
        .expect("bytes");
    assert_eq!(
        unsigned,
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
}

#[test]
fn primitive_128_bit_boundaries_roundtrip_bare_and_protected() {
    let cipher = cipher();
    for value in [i128::MIN, -1, 0, 1, i128::MAX] {
        let ct = value.encrypt(&cipher).expect("encrypt");
        assert_eq!(cipher.decrypt::<i128>(ct).expect("decrypt"), value);
        let ct = Protected::new(value)
            .encrypt(&cipher)
            .expect("encrypt protected");
        let decoded: Protected<i128> = cipher.decrypt(ct).expect("decrypt protected");
        assert_eq!(*decoded.risky_ref(), value);
    }
    for value in [0, 1, i128::MAX as u128 + 1, u128::MAX] {
        let ct = value.encrypt(&cipher).expect("encrypt");
        assert_eq!(cipher.decrypt::<u128>(ct).expect("decrypt"), value);
        let ct = Protected::new(value)
            .encrypt(&cipher)
            .expect("encrypt protected");
        let decoded: Protected<u128> = cipher.decrypt(ct).expect("decrypt protected");
        assert_eq!(*decoded.risky_ref(), value);
    }
}

#[test]
fn primitive_128_bit_decryption_checks_width_and_authentication() {
    let cipher = cipher();
    for width in [0, 15, 17] {
        let ct = vec![0u8; width].encrypt(&cipher).expect("encrypt bytes");
        assert!(cipher.decrypt::<i128>(ct).is_err());
        let ct = vec![0u8; width].encrypt(&cipher).expect("encrypt bytes");
        assert!(cipher.decrypt::<Protected<u128>>(ct).is_err());
    }
    let ct = 42i128
        .encrypt_with_aad(&cipher, Context::from_encoded(b"right"))
        .expect("encrypt");
    assert!(cipher
        .decrypt_with_aad::<i128, _>(ct, Context::from_encoded(b"wrong"))
        .is_err());
    let ct = 42u128
        .encrypt_with_aad(&cipher, Context::from_encoded(b"right"))
        .expect("encrypt");
    assert!(cipher
        .decrypt_with_aad::<Protected<u128>, _>(ct, Context::from_encoded(b"wrong"))
        .is_err());
}
