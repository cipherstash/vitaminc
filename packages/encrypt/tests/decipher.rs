//! `Decipher::and_then_ok` on the AES decipher: the fallible bind that lets a
//! `Decrypt` impl decode as one type and validate its way into another.

use vitaminc_aead::{Decipher, Unspecified};
use vitaminc_encrypt::AesDecipher;

#[test]
fn and_then_ok_applies_a_successful_conversion() {
    let out: Result<u32, Unspecified> =
        <AesDecipher<'_> as Decipher<'_>>::and_then_ok(Ok::<&str, Unspecified>("42"), |s| {
            s.parse().map_err(|_| Unspecified)
        });
    assert_eq!(out, Ok(42));
}

#[test]
fn and_then_ok_reports_a_failed_conversion_as_unspecified() {
    let out: Result<u32, Unspecified> =
        <AesDecipher<'_> as Decipher<'_>>::and_then_ok(Ok::<&str, Unspecified>("x"), |s| {
            s.parse().map_err(|_| Unspecified)
        });
    assert_eq!(out, Err(Unspecified));
}

#[test]
fn and_then_ok_does_not_run_the_conversion_on_a_failed_decrypt() {
    let mut ran = false;
    let out: Result<u32, Unspecified> =
        <AesDecipher<'_> as Decipher<'_>>::and_then_ok(Err::<&str, _>(Unspecified), |_| {
            ran = true;
            Ok(1)
        });
    assert_eq!(out, Err(Unspecified));
    assert!(!ran);
}
