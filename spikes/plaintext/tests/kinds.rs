//! Physical kinds plus logical types: a timestamp is an int with a unit,
//! and the logical layer is open.

mod common;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use vitaminc_aead_value::canonical::{domain, EqualityInput};
use vitaminc_aead_value::tags;
use vitaminc_encrypt::{Aes256Cipher, Key};
use vitaminc_plaintext_spike::scalar::LOGICAL;
use vitaminc_plaintext_spike::{
    decrypt_as, decrypt_into, describe, encrypt, encrypt_with_terms, to_frame, DecodeError, DecryptError, EncryptError,
    Frame, FrameWriter, Int, Logical, Physical, Plaintext, Raw, TermError, TimeUnit, Uuid,
};
use vitaminc_protected::Controlled;

fn cipher() -> Aes256Cipher {
    Aes256Cipher::new(&Key::from([7u8; 32])).unwrap()
}

fn term<P: Plaintext>(p: P) -> Result<EqualityInput, TermError> {
    let (_, mut terms) = encrypt_with_terms(p, &cipher(), ()).unwrap();
    terms.remove(0).input
}

#[test]
fn todays_tags_read_as_physical_plus_logical() {
    let date = NaiveDate::from_ymd_opt(2024, 2, 29).unwrap();
    let frame = to_frame(date).unwrap();
    // Still today's tag, so today's readers still read it.
    assert_eq!(frame.risky_ref()[0], tags::DATE);
    assert_eq!(describe(Frame::parse(frame.risky_ref()).unwrap()).unwrap(), "date i32 19782");
    assert_eq!(describe(Decimal::new(123, 2)).unwrap(), "decimal(2) i128 123");
    assert_eq!(describe(common::ts()).unwrap(), "timestamp(ns) i128 1700000000123456789");

    let sample = common::encode(common::sample());
    assert_eq!(
        describe(Frame::parse(&sample).unwrap()).unwrap(),
        r#"{"name": "Ada", "age": u32 34, "scores": [i8 -1, f64 2.5, null], "joined": date i32 19782, "#.to_owned()
            + r#""note": passthrough "public", "blob": 0x010203, "seen": timestamp(ns) i128 1700000000123456789, "#
            + r#""active": true}"#
    );
}

#[test]
fn a_timestamp_is_an_int_with_a_unit() {
    let cipher = cipher();
    // What a JS Date says: milliseconds, with no conversion.
    let js = Raw(Some(Logical::Timestamp(TimeUnit::Millis)), Physical::Int(Int::I64(1_700_000_000_123)));
    let instant = DateTime::from_timestamp_millis(1_700_000_000_123).unwrap();

    // No shorthand tag for milliseconds, so it travels in the envelope.
    assert_eq!(to_frame(js).unwrap().risky_ref()[..4], [LOGICAL, 3, 1, tags::INT64]);

    // Typed Rust reads it as a DateTime, whatever the unit.
    let ct = encrypt(js, &cipher, ()).unwrap();
    assert_eq!(decrypt_as::<DateTime<Utc>, _, _>(&cipher, ct, ()).unwrap(), instant);

    // The index folds the unit away: same instant, same term.
    let (from_js, from_rust) = (term(js).unwrap(), term(instant).unwrap());
    assert_eq!(from_js.domain, domain::TIMESTAMP);
    assert_eq!(from_js.domain, from_rust.domain);
    assert_eq!(from_js.bytes.risky_ref(), from_rust.bytes.risky_ref());

    // But it's not the integer it's stored as.
    assert_eq!(term(1_700_000_000_123i64).unwrap().domain, domain::INTEGER);
}

#[test]
fn a_new_logical_type_travels_in_the_envelope() {
    let cipher = cipher();
    let id = Uuid([0xAB; 16]);
    assert_eq!(to_frame(&id).unwrap().risky_ref()[..5], [LOGICAL, 5, 0, tags::BYTES, 16]);
    let ct = encrypt(&id, &cipher, ()).unwrap();
    assert_eq!(decrypt_as::<Uuid, _, _>(&cipher, ct, ()).unwrap(), id);
}

#[test]
fn an_unknown_logical_type_passes_through_structural_sinks() {
    let cipher = cipher();
    // Logical id 127, parameter 9: nothing this build knows.
    let bytes = [LOGICAL, 0x7F, 9, tags::UINT32, 34, 0, 0, 0];
    let frame = Frame::parse(&bytes).unwrap();
    assert_eq!(describe(frame).unwrap(), "logical(127, 9) u32 34");

    // Encrypt and decrypt keep the annotation, byte for byte.
    let ct = encrypt(frame, &cipher, ()).unwrap();
    let mut out = Vec::new();
    decrypt_into(&cipher, ct, (), FrameWriter::new(&mut out)).unwrap();
    assert_eq!(out, bytes);

    // A typed target doesn't take it as a plain u32.
    let ct = encrypt(frame, &cipher, ()).unwrap();
    assert!(matches!(
        decrypt_as::<u32, _, _>(&cipher, ct, ()),
        Err(DecryptError::Sink(DecodeError::Expected("u32")))
    ));
}

#[test]
fn index_sinks_opt_in_to_logical_types() {
    // Unknown: no term, and it says why, rather than indexing the u32.
    let unknown = Frame::parse(&[LOGICAL, 0x7F, 9, tags::UINT32, 34, 0, 0, 0]).unwrap();
    assert!(matches!(term(unknown), Err(TermError::NoDomain(Logical::Unknown(_)))));
    // Known to this crate, but this index hasn't chosen a domain for it.
    assert!(matches!(term(&Uuid([0; 16])), Err(TermError::NoDomain(Logical::Uuid))));
    // A date and the day count it's stored as don't collide.
    let date = NaiveDate::from_ymd_opt(2024, 2, 29).unwrap();
    assert_eq!(term(date).unwrap().domain, domain::DATE);
    assert_eq!(term(19782i32).unwrap().domain, domain::INTEGER);
}

#[test]
fn a_value_must_fit_its_logical_type() {
    let cipher = cipher();
    let shape = |r| matches!(r, Err(EncryptError::Shape(_)));
    assert!(shape(encrypt(Raw(Some(Logical::Uuid), Physical::Bytes(&[1, 2, 3])), &cipher, ())));
    assert!(shape(encrypt(Raw(Some(Logical::Date), Physical::Text("2024-02-29")), &cipher, ())));
    let too_big = Raw(Some(Logical::Decimal { scale: 2 }), Physical::Int(Int::U128(u128::MAX)));
    assert!(shape(encrypt(too_big, &cipher, ())));
    assert!(to_frame(too_big).is_err());

    // Known ids take only their own parameters.
    assert_eq!(Logical::from_wire(4, 29), None);
    assert_eq!(Logical::from_wire(3, 4), None);
    // One encoding per value: no envelope where today's tag would do.
    assert!(Frame::parse(&[LOGICAL, 2, 0, tags::INT32, 0x46, 0x4D, 0, 0]).is_err());
}

#[test]
fn leap_seconds_and_negative_zero_have_no_int_form() {
    let cipher = cipher();
    let leap = NaiveDate::from_ymd_opt(2016, 12, 31)
        .unwrap()
        .and_hms_nano_opt(23, 59, 59, 1_500_000_000)
        .unwrap()
        .and_utc();
    assert!(matches!(encrypt(leap, &cipher, ()), Err(EncryptError::Source(_))));

    // Negative zero becomes zero: equal, and the equality term never told
    // them apart anyway.
    let mut negative_zero = Decimal::new(0, 2);
    negative_zero.set_sign_negative(true);
    assert_eq!(describe(negative_zero).unwrap(), "decimal(2) i128 0");
    let ct = encrypt(negative_zero, &cipher, ()).unwrap();
    let back = decrypt_as::<Decimal, _, _>(&cipher, ct, ()).unwrap();
    assert_eq!((back, back.scale(), back.is_sign_negative()), (Decimal::ZERO, 2, false));
}

#[test]
fn integer_width_is_a_hint() {
    let cipher = cipher();
    let ct = encrypt(34i8, &cipher, ()).unwrap();
    assert_eq!(decrypt_as::<u32, _, _>(&cipher, ct, ()).unwrap(), 34);
    let ct = encrypt(-1i8, &cipher, ()).unwrap();
    assert!(decrypt_as::<u32, _, _>(&cipher, ct, ()).is_err());
    let ct = encrypt(300u32, &cipher, ()).unwrap();
    assert!(decrypt_as::<i8, _, _>(&cipher, ct, ()).is_err());
    // Equality never saw the width.
    let (a, b) = (term(34i8).unwrap(), term(34u64).unwrap());
    assert_eq!(a.bytes.risky_ref(), b.bytes.risky_ref());
}
