//! The canonical encodings promised by ADR 0001, for adapters whose vendor
//! returns something else: ECDSA signatures as DER `SEQUENCE { INTEGER r,
//! INTEGER s }` and public keys as DER `SubjectPublicKeyInfo`.
//!
//! Azure returns ECDSA signatures as raw `r || s` and public keys as JWK
//! fields; Vault returns PEM. AWS and GCP already return the canonical
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

/// Decode a PEM `PUBLIC KEY` block (RFC 7468) into its DER
/// `SubjectPublicKeyInfo` bytes, as Vault's public-key export returns.
pub fn pem_public_key_to_der(pem: &str) -> Result<Vec<u8>, EncodingError> {
    let (label, der) = pem_rfc7468::decode_vec(pem.as_bytes())?;
    if label != "PUBLIC KEY" {
        return Err(EncodingError::PemLabel(label.to_owned()));
    }
    Ok(der)
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_nonzero = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    &bytes[first_nonzero.min(bytes.len().saturating_sub(1))..]
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
