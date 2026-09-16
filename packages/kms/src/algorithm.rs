/// The signature scheme a signing-key adapter is constructed with.
///
/// One crate-level enum rather than each vendor's own type, so a consumer
/// that moves between backends keeps the same configuration value. Every
/// member takes a pre-computed digest of the named hash, which is what the
/// [`Sign`](crate::Sign) trait accepts; Ed25519 is absent because pure
/// Ed25519 signs the message itself and has no pre-hashed mode on the
/// vendors that offer it.
///
/// Each adapter maps a member to its vendor's identifier and rejects, at
/// construction, any member the vendor or the bound key cannot serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// ECDSA over P-256 with SHA-256. Signatures are DER-encoded (ADR 0001).
    EcdsaP256Sha256,
    /// ECDSA over P-384 with SHA-384. Signatures are DER-encoded (ADR 0001).
    EcdsaP384Sha384,
    /// ECDSA over P-521 with SHA-512. Signatures are DER-encoded (ADR 0001).
    EcdsaP521Sha512,
    /// RSASSA-PSS with SHA-256 (MGF1-SHA-256, salt length = digest length).
    RsaPssSha256,
    /// RSASSA-PSS with SHA-384 (MGF1-SHA-384, salt length = digest length).
    RsaPssSha384,
    /// RSASSA-PSS with SHA-512 (MGF1-SHA-512, salt length = digest length).
    RsaPssSha512,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RsaPkcs1Sha256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RsaPkcs1Sha384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RsaPkcs1Sha512,
}

/// The caller's digest is the wrong length for the algorithm a signing key
/// was constructed with. Every adapter raises this before any network call,
/// since no vendor hashes on the caller's behalf through these traits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the digest is {received} bytes, but {algorithm:?} signs a {expected}-byte digest")]
pub struct DigestLengthError {
    pub algorithm: SignatureAlgorithm,
    pub expected: usize,
    pub received: usize,
}

impl SignatureAlgorithm {
    /// Check a caller's digest length against [`digest_len`](Self::digest_len).
    pub const fn check_digest_len(self, received: usize) -> Result<(), DigestLengthError> {
        let expected = self.digest_len();
        if received == expected {
            Ok(())
        } else {
            Err(DigestLengthError {
                algorithm: self,
                expected,
                received,
            })
        }
    }

    /// Length in bytes of the digest this algorithm signs. Adapters check
    /// the caller's digest against it before making a network call.
    pub const fn digest_len(self) -> usize {
        match self {
            Self::EcdsaP256Sha256 | Self::RsaPssSha256 | Self::RsaPkcs1Sha256 => 32,
            Self::EcdsaP384Sha384 | Self::RsaPssSha384 | Self::RsaPkcs1Sha384 => 48,
            Self::EcdsaP521Sha512 | Self::RsaPssSha512 | Self::RsaPkcs1Sha512 => 64,
        }
    }

    /// Whether this is an ECDSA scheme, whose signatures must be DER
    /// `SEQUENCE { INTEGER r, INTEGER s }` at the trait boundary.
    pub const fn is_ecdsa(self) -> bool {
        matches!(
            self,
            Self::EcdsaP256Sha256 | Self::EcdsaP384Sha384 | Self::EcdsaP521Sha512
        )
    }

    /// For ECDSA schemes, the byte length of one coordinate (and of `r` and
    /// `s`) on the curve. `None` for RSA.
    pub const fn ecdsa_field_len(self) -> Option<usize> {
        match self {
            Self::EcdsaP256Sha256 => Some(32),
            Self::EcdsaP384Sha384 => Some(48),
            Self::EcdsaP521Sha512 => Some(66),
            _ => None,
        }
    }
}
