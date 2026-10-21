//! The canonical encodings promised by ADR 0002, for adapters whose vendor
//! returns something else: ECDSA signatures as DER `SEQUENCE { INTEGER r,
//! INTEGER s }` and public keys as DER `SubjectPublicKeyInfo`.
//!
//! Azure returns ECDSA signatures as raw `r || s` and public keys as JWK
//! fields; Vault returns PEM, except for `ed25519` keys, whose public key
//! it returns as the raw 32 bytes in base64. AWS and GCP already return the canonical
//! forms (GCP when asked for DER), so they do not use this module.

use der::asn1::{BitStringRef, UintRef};
use der::{Decode, Encode, Sequence};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncodingError {
    #[error(
        "ECDSA signature is {received} bytes, expected {expected} (two {field_len}-byte integers)"
    )]
    EcdsaSignatureLength {
        expected: usize,
        received: usize,
        field_len: usize,
    },
    #[error("DER encoding failed: {0}")]
    Der(#[from] der::Error),
    #[error("PEM decoding failed: {0}")]
    Pem(#[from] pem_rfc7468::Error),
    #[error("PEM label was {0:?}, expected \"PUBLIC KEY\"")]
    PemLabel(String),
    #[error("unknown elliptic curve for an EC public key")]
    UnknownCurve,
    #[error("a public-key component is empty")]
    EmptyComponent,
    #[error("an Ed25519 public key is {0} bytes, expected 32")]
    Ed25519PublicKeyLength(usize),
}

/// The named curve of an EC public key, for [`ec_spki`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurve {
    P256,
    P384,
    P521,
}

impl EcCurve {
    fn oid(self) -> const_oid::ObjectIdentifier {
        match self {
            Self::P256 => const_oid::db::rfc5912::SECP_256_R_1,
            Self::P384 => const_oid::db::rfc5912::SECP_384_R_1,
            Self::P521 => const_oid::db::rfc5912::SECP_521_R_1,
        }
    }

    /// Byte length of one coordinate on this curve.
    pub const fn field_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }
}

#[derive(Sequence)]
struct EcdsaSigValue<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

/// Convert a raw `r || s` ECDSA signature (both fixed-width, big-endian,
/// `field_len` bytes each — the JWS/IEEE P1363 form Azure returns) into
/// DER `SEQUENCE { INTEGER r, INTEGER s }`.
pub fn ecdsa_raw_to_der(raw: &[u8], field_len: usize) -> Result<Vec<u8>, EncodingError> {
    if raw.len() != 2 * field_len {
        return Err(EncodingError::EcdsaSignatureLength {
            expected: 2 * field_len,
            received: raw.len(),
            field_len,
        });
    }
    let (r, s) = raw.split_at(field_len);
    let value = EcdsaSigValue {
        r: UintRef::new(strip_leading_zeros(r))?,
        s: UintRef::new(strip_leading_zeros(s))?,
    };
    Ok(value.to_der()?)
}

/// The inverse of [`ecdsa_raw_to_der`]: DER `SEQUENCE { INTEGER r, INTEGER
/// s }` into fixed-width `r || s` of `2 * field_len` bytes, for vendors
/// whose verify call wants the raw form.
pub fn ecdsa_der_to_raw(der: &[u8], field_len: usize) -> Result<Vec<u8>, EncodingError> {
    let value = EcdsaSigValue::from_der(der)?;
    let mut out = vec![0u8; 2 * field_len];
    left_pad_into(&mut out[..field_len], value.r.as_bytes())?;
    left_pad_into(&mut out[field_len..], value.s.as_bytes())?;
    Ok(out)
}

#[derive(Sequence)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    public_exponent: UintRef<'a>,
}

/// DER `SubjectPublicKeyInfo` for an RSA public key given its big-endian
/// modulus `n` and exponent `e` (the JWK `n`/`e` fields, base64url-decoded).
pub fn rsa_spki(n: &[u8], e: &[u8]) -> Result<Vec<u8>, EncodingError> {
    if n.is_empty() || e.is_empty() {
        return Err(EncodingError::EmptyComponent);
    }
    let key = RsaPublicKey {
        modulus: UintRef::new(strip_leading_zeros(n))?,
        public_exponent: UintRef::new(strip_leading_zeros(e))?,
    };
    let key_der = key.to_der()?;
    let spki = SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            oid: const_oid::db::rfc5912::RSA_ENCRYPTION,
            parameters: Some(der::asn1::Null),
        },
        subject_public_key: BitStringRef::from_bytes(&key_der)?,
    };
    Ok(spki.to_der()?)
}

/// DER `SubjectPublicKeyInfo` for an EC public key given its curve and
/// big-endian affine coordinates (the JWK `x`/`y` fields, base64url-decoded).
/// Coordinates shorter than the field width are left-padded.
pub fn ec_spki(curve: EcCurve, x: &[u8], y: &[u8]) -> Result<Vec<u8>, EncodingError> {
    if x.is_empty() || y.is_empty() {
        return Err(EncodingError::EmptyComponent);
    }
    let field_len = curve.field_len();
    let mut point = vec![0u8; 1 + 2 * field_len];
    point[0] = 0x04;
    left_pad_into(&mut point[1..1 + field_len], x)?;
    left_pad_into(&mut point[1 + field_len..], y)?;
    let spki = SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            oid: const_oid::db::rfc5912::ID_EC_PUBLIC_KEY,
            parameters: Some(curve.oid()),
        },
        subject_public_key: BitStringRef::from_bytes(&point)?,
    };
    Ok(spki.to_der()?)
}

/// The length in bytes of an Ed25519 public key (RFC 8032), which is also
/// the length of the `subjectPublicKey` in its SPKI (RFC 8410).
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// DER `SubjectPublicKeyInfo` for an Ed25519 public key given its raw
/// 32-byte encoding, as Vault's public-key export returns for `ed25519`
/// keys. RFC 8410: the algorithm is `id-Ed25519` with no parameters.
pub fn ed25519_spki(raw: &[u8]) -> Result<Vec<u8>, EncodingError> {
    if raw.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(EncodingError::Ed25519PublicKeyLength(raw.len()));
    }
    let spki = SubjectPublicKeyInfo::<der::asn1::AnyRef<'_>, _> {
        algorithm: AlgorithmIdentifier {
            oid: const_oid::db::rfc8410::ID_ED_25519,
            parameters: None,
        },
        subject_public_key: BitStringRef::from_bytes(raw)?,
    };
    Ok(spki.to_der()?)
}

/// Decode a PEM `PUBLIC KEY` block (RFC 7468) into its DER
/// `SubjectPublicKeyInfo` bytes, as Vault's public-key export returns.
pub fn pem_public_key_to_der(pem: &str) -> Result<Vec<u8>, EncodingError> {
    let (label, der) = pem_rfc7468::decode_vec(pem.as_bytes())?;
    if label != "PUBLIC KEY" {
        return Err(EncodingError::PemLabel(label.to_owned()));
    }
    Ok(der)
}

/// Drop leading zero bytes, keeping one byte for an all-zero value. An
/// empty slice stays empty and is rejected further down as an invalid
/// INTEGER, not a panic.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|b| *b != 0) {
        Some(first_nonzero) => &bytes[first_nonzero..],
        None => &bytes[bytes.len().saturating_sub(1)..],
    }
}

fn left_pad_into(out: &mut [u8], value: &[u8]) -> Result<(), EncodingError> {
    let value = strip_leading_zeros(value);
    if value.len() > out.len() {
        return Err(EncodingError::EcdsaSignatureLength {
            expected: out.len(),
            received: value.len(),
            field_len: out.len(),
        });
    }
    let pad = out.len() - value.len();
    out[..pad].fill(0);
    out[pad..].copy_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_raw_and_der_round_trip_with_high_bit_set() {
        // r has its high bit set, so DER needs a leading 0x00 in the INTEGER.
        let mut raw = vec![0u8; 64];
        raw[0] = 0x80;
        raw[31] = 0x01;
        raw[63] = 0x02;

        let der = ecdsa_raw_to_der(&raw, 32).unwrap();
        assert_eq!(der[0], 0x30);
        assert_eq!(&der[2..5], &[0x02, 0x21, 0x00]);

        assert_eq!(ecdsa_der_to_raw(&der, 32).unwrap(), raw);
    }

    #[test]
    fn ecdsa_raw_to_der_strips_leading_zeros_from_short_values() {
        let mut raw = vec![0u8; 64];
        raw[31] = 0x05;
        raw[63] = 0x07;

        let der = ecdsa_raw_to_der(&raw, 32).unwrap();
        assert_eq!(der, [0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07]);
    }

    #[test]
    fn ecdsa_raw_to_der_rejects_the_wrong_length() {
        let err = ecdsa_raw_to_der(&[0u8; 63], 32).unwrap_err();
        assert!(matches!(
            err,
            EncodingError::EcdsaSignatureLength {
                expected: 64,
                received: 63,
                ..
            }
        ));
    }

    #[test]
    fn empty_and_all_zero_inputs_are_errors_not_panics() {
        assert!(matches!(
            rsa_spki(&[], &[0x01, 0x00, 0x01]),
            Err(EncodingError::EmptyComponent)
        ));
        assert!(matches!(
            ec_spki(EcCurve::P256, &[], &[0x02]),
            Err(EncodingError::EmptyComponent)
        ));
        assert!(
            ecdsa_raw_to_der(&[0u8; 64], 32).is_ok(),
            "all-zero r and s still encode"
        );
    }

    #[test]
    fn rsa_spki_matches_a_known_encoding() {
        // Tiny (non-real) modulus so the expected bytes are readable.
        let n = [0x00, 0xC3, 0x5B];
        let e = [0x01, 0x00, 0x01];
        let spki = rsa_spki(&n, &e).unwrap();
        let expected = [
            0x30, 0x1E, // SEQUENCE
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05,
            0x00, // rsaEncryption, NULL
            0x03, 0x0D, 0x00, // BIT STRING, 0 unused bits
            0x30, 0x0A, 0x02, 0x03, 0x00, 0xC3, 0x5B, 0x02, 0x03, 0x01, 0x00, 0x01,
        ];
        assert_eq!(spki, expected);
    }

    #[test]
    fn ec_spki_carries_the_named_curve_and_uncompressed_point() {
        let x = [0x11u8; 32];
        let y = [0x22u8; 32];
        let spki = ec_spki(EcCurve::P256, &x, &y).unwrap();
        let parsed = spki::SubjectPublicKeyInfoRef::from_der(&spki).unwrap();
        assert_eq!(
            parsed.algorithm.oid,
            const_oid::db::rfc5912::ID_EC_PUBLIC_KEY
        );
        let point = parsed.subject_public_key.raw_bytes();
        assert_eq!(point[0], 0x04);
        assert_eq!(&point[1..33], &x);
        assert_eq!(&point[33..], &y);
    }

    #[test]
    fn ec_spki_left_pads_short_coordinates() {
        let spki = ec_spki(EcCurve::P256, &[0x01], &[0x02]).unwrap();
        let parsed = spki::SubjectPublicKeyInfoRef::from_der(&spki).unwrap();
        let point = parsed.subject_public_key.raw_bytes();
        assert_eq!(point.len(), 65);
        assert_eq!(point[32], 0x01);
        assert_eq!(point[64], 0x02);
    }

    #[test]
    fn ed25519_spki_matches_the_rfc_8410_example() {
        // RFC 8410 section 10.1: the example Ed25519 public key, as PEM
        // `MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=`.
        let raw = [
            0x19, 0xBF, 0x44, 0x09, 0x69, 0x84, 0xCD, 0xFE, 0x85, 0x41, 0xBA, 0xC1, 0x67, 0xDC,
            0x3B, 0x96, 0xC8, 0x50, 0x86, 0xAA, 0x30, 0xB6, 0xB6, 0xCB, 0x0C, 0x5C, 0x38, 0xAD,
            0x70, 0x31, 0x66, 0xE1,
        ];
        let mut expected = vec![
            0x30, 0x2A, // SEQUENCE
            0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, // id-Ed25519, no parameters
            0x03, 0x21, 0x00, // BIT STRING, 0 unused bits
        ];
        expected.extend_from_slice(&raw);

        assert_eq!(ed25519_spki(&raw).unwrap(), expected);
    }

    #[test]
    fn ed25519_spki_rejects_a_key_of_the_wrong_length() {
        assert!(matches!(
            ed25519_spki(&[0u8; 31]),
            Err(EncodingError::Ed25519PublicKeyLength(31))
        ));
        assert!(matches!(
            ed25519_spki(&[]),
            Err(EncodingError::Ed25519PublicKeyLength(0))
        ));
    }

    #[test]
    fn pem_public_key_round_trips_and_rejects_other_labels() {
        let spki = ec_spki(EcCurve::P256, &[0x01], &[0x02]).unwrap();
        let pem =
            pem_rfc7468::encode_string("PUBLIC KEY", pem_rfc7468::LineEnding::LF, &spki).unwrap();
        assert_eq!(pem_public_key_to_der(&pem).unwrap(), spki);

        let wrong =
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &spki).unwrap();
        assert!(matches!(
            pem_public_key_to_der(&wrong),
            Err(EncodingError::PemLabel(_))
        ));
    }
}
