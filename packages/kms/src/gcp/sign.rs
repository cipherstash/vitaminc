use super::integrity::{self, CallError};
use crate::algorithm::SignatureAlgorithm;
use crate::sign::{GetPublicKey, Sign, Verify};
use google_cloud_kms_v1::client::KeyManagementService;
use google_cloud_kms_v1::model::crypto_key_version::CryptoKeyVersionAlgorithm;
use google_cloud_kms_v1::model::public_key::PublicKeyFormat;
use google_cloud_kms_v1::model::Digest;
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::hazmat::PrehashVerifier;
use sha2::{Sha256, Sha512};
use thiserror::Error;
use vitaminc_protected::{Controlled, Protected};

/// Errors from [`GcpSigningKey`].
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Gcp(#[from] google_cloud_kms_v1::Error),
    /// Two consecutive responses failed the same CRC32C check: the
    /// first was discarded and retried, and the retry failed the same way.
    #[error("Google Cloud KMS responses failed their {0} integrity check twice")]
    Integrity(&'static str),
    /// Google Cloud KMS has no key algorithm for this scheme, so no key
    /// version could serve it: there is no P-521 curve, and no RSA-PSS or
    /// RSA-PKCS#1 with SHA-384.
    #[error("Google Cloud KMS cannot sign with {0:?}")]
    UnsupportedAlgorithm(SignatureAlgorithm),
    /// The bound key version exists but signs with something else. Its
    /// algorithm is fixed at creation, so this cannot be fixed by
    /// retrying — the caller wants a different key version, or a different
    /// [`SignatureAlgorithm`].
    #[error("the bound key version signs with {version}, not {requested:?}")]
    AlgorithmMismatch {
        requested: SignatureAlgorithm,
        version: String,
    },
    /// The public key Google Cloud KMS returned is not a DER
    /// `SubjectPublicKeyInfo` this adapter can verify against.
    #[error("Google Cloud KMS returned a public key that could not be parsed: {0}")]
    MalformedPublicKey(#[from] spki::Error),
    /// The digest handed to [`Sign`]/[`Verify`] cannot be one this key
    /// signs. Checked before any network call.
    #[error(transparent)]
    DigestLength(#[from] crate::DigestLengthError),
}

impl From<CallError> for Error {
    fn from(error: CallError) -> Self {
        match error {
            CallError::Gcp(error) => Self::Gcp(error),
            CallError::Integrity(field) => Self::Integrity(field),
        }
    }
}

/// Google Cloud KMS-backed signing key, bound to one `CryptoKeyVersion`
/// resource name and one [`SignatureAlgorithm`].
///
/// [`Sign`] is `cryptoKeyVersions.asymmetricSign` over a pre-computed
/// digest. [`GetPublicKey`] and [`Verify`] need no network call at all:
/// construction fetches the public key once, and **verification is local**,
/// because Google Cloud KMS is the one surveyed backend with no
/// server-side asymmetric verify. The digest a caller passes to [`Verify`]
/// is consumed as-is, exactly as [`Sign`] would have sent it.
///
/// Construction is therefore `async`, and it fails when the bound key
/// version's own algorithm is not the one requested — Google Cloud KMS
/// fixes a version's algorithm at creation, so the check belongs at
/// construction rather than on every call.
///
/// Signatures cross the trait boundary in the canonical encodings of
/// ADR 0001: DER for ECDSA (which is what Google Cloud KMS already
/// returns) and raw signature bytes for RSA. Public keys are DER
/// `SubjectPublicKeyInfo`.
pub struct GcpSigningKey {
    client: KeyManagementService,
    crypto_key_version_name: String,
    algorithm: SignatureAlgorithm,
    hash: Hash,
    public_key_der: Vec<u8>,
    verifier: Verifier,
}

impl GcpSigningKey {
    /// `crypto_key_version_name` is the full resource name of the
    /// `CryptoKeyVersion` this instance is bound to
    /// (`projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}/cryptoKeyVersions/{v}`),
    /// whose `CryptoKey` purpose must be `ASYMMETRIC_SIGN`.
    ///
    /// Makes one `getPublicKey` call, checks the version's algorithm
    /// against `algorithm`, and keeps the DER `SubjectPublicKeyInfo` for
    /// [`GetPublicKey`] and [`Verify`].
    pub async fn new(
        client: KeyManagementService,
        crypto_key_version_name: impl Into<String>,
        algorithm: SignatureAlgorithm,
    ) -> Result<Self, Error> {
        let crypto_key_version_name = crypto_key_version_name.into();
        let hash = Hash::for_algorithm(algorithm).ok_or(Error::UnsupportedAlgorithm(algorithm))?;

        let response = integrity::checked_call(|| {
            client
                .get_public_key()
                .set_name(crypto_key_version_name.clone())
                .set_public_key_format(PublicKeyFormat::Der)
                .send()
        })
        .await?;

        if scheme_of(&response.algorithm) != Some(algorithm) {
            return Err(Error::AlgorithmMismatch {
                requested: algorithm,
                version: format!("{:?}", response.algorithm),
            });
        }

        // `check_integrity` already rejected a response without one.
        let public_key_der = response
            .public_key
            .ok_or(Error::Integrity("publicKey"))?
            .data
            .to_vec();
        let verifier = Verifier::new(algorithm, &public_key_der)?;

        Ok(Self {
            client,
            crypto_key_version_name,
            algorithm,
            hash,
            public_key_der,
            verifier,
        })
    }

    /// The signing algorithm this instance is bound to.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn checked_digest(&self, digest: &Protected<Vec<u8>>) -> Result<Vec<u8>, Error> {
        let digest = digest.clone().risky_unwrap();
        self.algorithm.check_digest_len(digest.len())?;
        Ok(digest)
    }
}

impl Sign for GcpSigningKey {
    type Error = Error;

    async fn sign(&self, digest: &Protected<Vec<u8>>) -> Result<Vec<u8>, Self::Error> {
        let digest = self.checked_digest(digest)?;
        let checksum = integrity::crc32c(&digest);
        let field = self.hash.digest_field(digest);

        let response = integrity::checked_call(|| {
            self.client
                .asymmetric_sign()
                .set_name(self.crypto_key_version_name.clone())
                .set_digest(field.clone())
                .set_digest_crc32c(checksum)
                .send()
        })
        .await?;

        Ok(response.signature.to_vec())
    }
}

impl Verify for GcpSigningKey {
    type Error = Error;

    /// Verified locally against the public key fetched at construction —
    /// Google Cloud KMS has no asymmetric verify call. A signature that is
    /// malformed, or is over different bytes, is `Ok(false)`; `Self::Error`
    /// stays reserved for a digest of the wrong length.
    async fn verify(
        &self,
        digest: &Protected<Vec<u8>>,
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        let digest = self.checked_digest(digest)?;

        Ok(self.verifier.verify(&digest, signature))
    }
}

impl GetPublicKey for GcpSigningKey {
    type Error = Error;

    /// The DER `SubjectPublicKeyInfo` fetched at construction. No network
    /// call: a key version's public half never changes.
    async fn get_public_key(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(self.public_key_der.clone())
    }
}

/// The hash a [`SignatureAlgorithm`] signs over, and the `Digest` field
/// that names it in an `asymmetricSign` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    /// `None` where Google Cloud KMS has no matching key algorithm at all.
    fn for_algorithm(algorithm: SignatureAlgorithm) -> Option<Self> {
        match algorithm {
            SignatureAlgorithm::EcdsaP256Sha256
            | SignatureAlgorithm::RsaPssSha256
            | SignatureAlgorithm::RsaPkcs1Sha256 => Some(Self::Sha256),
            SignatureAlgorithm::EcdsaP384Sha384 => Some(Self::Sha384),
            SignatureAlgorithm::RsaPssSha512 | SignatureAlgorithm::RsaPkcs1Sha512 => {
                Some(Self::Sha512)
            }
            // No P-521 curve, and no PSS/PKCS#1 pairing with SHA-384.
            SignatureAlgorithm::EcdsaP521Sha512
            | SignatureAlgorithm::RsaPssSha384
            | SignatureAlgorithm::RsaPkcs1Sha384 => None,
        }
    }

    fn digest_field(self, digest: Vec<u8>) -> Digest {
        match self {
            Self::Sha256 => Digest::new().set_sha256(digest),
            Self::Sha384 => Digest::new().set_sha384(digest),
            Self::Sha512 => Digest::new().set_sha512(digest),
        }
    }
}

/// The crate-level scheme a Google Cloud KMS key algorithm implements, for
/// the algorithms this adapter supports. `None` covers both algorithms
/// with no crate-level equivalent (Ed25519, secp256k1, the post-quantum
/// families, the raw PKCS#1 variants that sign data rather than a digest)
/// and every non-signing purpose.
fn scheme_of(algorithm: &CryptoKeyVersionAlgorithm) -> Option<SignatureAlgorithm> {
    match algorithm {
        CryptoKeyVersionAlgorithm::EcSignP256Sha256 => Some(SignatureAlgorithm::EcdsaP256Sha256),
        CryptoKeyVersionAlgorithm::EcSignP384Sha384 => Some(SignatureAlgorithm::EcdsaP384Sha384),
        CryptoKeyVersionAlgorithm::RsaSignPss2048Sha256
        | CryptoKeyVersionAlgorithm::RsaSignPss3072Sha256
        | CryptoKeyVersionAlgorithm::RsaSignPss4096Sha256 => Some(SignatureAlgorithm::RsaPssSha256),
        CryptoKeyVersionAlgorithm::RsaSignPss4096Sha512 => Some(SignatureAlgorithm::RsaPssSha512),
        CryptoKeyVersionAlgorithm::RsaSignPkcs12048Sha256
        | CryptoKeyVersionAlgorithm::RsaSignPkcs13072Sha256
        | CryptoKeyVersionAlgorithm::RsaSignPkcs14096Sha256 => {
            Some(SignatureAlgorithm::RsaPkcs1Sha256)
        }
        CryptoKeyVersionAlgorithm::RsaSignPkcs14096Sha512 => {
            Some(SignatureAlgorithm::RsaPkcs1Sha512)
        }
        _ => None,
    }
}

/// The local half of the signing adapter: one parsed public key, already
/// specialised to the scheme it verifies.
enum Verifier {
    EcdsaP256(Box<p256::ecdsa::VerifyingKey>),
    EcdsaP384(Box<p384::ecdsa::VerifyingKey>),
    RsaPssSha256(Box<rsa::pss::VerifyingKey<Sha256>>),
    RsaPssSha512(Box<rsa::pss::VerifyingKey<Sha512>>),
    RsaPkcs1Sha256(Box<rsa::pkcs1v15::VerifyingKey<Sha256>>),
    RsaPkcs1Sha512(Box<rsa::pkcs1v15::VerifyingKey<Sha512>>),
}

impl Verifier {
    fn new(algorithm: SignatureAlgorithm, public_key_der: &[u8]) -> Result<Self, Error> {
        // RSA-PSS with salt length = digest length, and PKCS#1 v1.5 with
        // the hash's DigestInfo prefix, are what Google Cloud KMS
        // produces; `VerifyingKey::new` is exactly those defaults.
        let rsa = || rsa::RsaPublicKey::from_public_key_der(public_key_der);

        Ok(match algorithm {
            SignatureAlgorithm::EcdsaP256Sha256 => Self::EcdsaP256(Box::new(
                p256::ecdsa::VerifyingKey::from_public_key_der(public_key_der)?,
            )),
            SignatureAlgorithm::EcdsaP384Sha384 => Self::EcdsaP384(Box::new(
                p384::ecdsa::VerifyingKey::from_public_key_der(public_key_der)?,
            )),
            SignatureAlgorithm::RsaPssSha256 => {
                Self::RsaPssSha256(Box::new(rsa::pss::VerifyingKey::new(rsa()?)))
            }
            SignatureAlgorithm::RsaPssSha512 => {
                Self::RsaPssSha512(Box::new(rsa::pss::VerifyingKey::new(rsa()?)))
            }
            SignatureAlgorithm::RsaPkcs1Sha256 => {
                Self::RsaPkcs1Sha256(Box::new(rsa::pkcs1v15::VerifyingKey::new(rsa()?)))
            }
            SignatureAlgorithm::RsaPkcs1Sha512 => {
                Self::RsaPkcs1Sha512(Box::new(rsa::pkcs1v15::VerifyingKey::new(rsa()?)))
            }
            other => return Err(Error::UnsupportedAlgorithm(other)),
        })
    }

    fn verify(&self, digest: &[u8], signature: &[u8]) -> bool {
        match self {
            Self::EcdsaP256(key) => {
                verify_prehash::<p256::ecdsa::DerSignature, _>(&**key, digest, signature)
            }
            Self::EcdsaP384(key) => {
                verify_prehash::<p384::ecdsa::DerSignature, _>(&**key, digest, signature)
            }
            Self::RsaPssSha256(key) => {
                verify_prehash::<rsa::pss::Signature, _>(&**key, digest, signature)
            }
            Self::RsaPssSha512(key) => {
                verify_prehash::<rsa::pss::Signature, _>(&**key, digest, signature)
            }
            Self::RsaPkcs1Sha256(key) => {
                verify_prehash::<rsa::pkcs1v15::Signature, _>(&**key, digest, signature)
            }
            Self::RsaPkcs1Sha512(key) => {
                verify_prehash::<rsa::pkcs1v15::Signature, _>(&**key, digest, signature)
            }
        }
    }
}

/// Decodes the signature and checks it against the digest as given. A
/// signature that will not decode is a failed verification, not an error:
/// the caller asked whether these bytes verify, and they do not.
fn verify_prehash<S, K>(key: &K, digest: &[u8], signature: &[u8]) -> bool
where
    S: for<'a> TryFrom<&'a [u8]>,
    K: PrehashVerifier<S>,
{
    S::try_from(signature).is_ok_and(|signature| key.verify_prehash(digest, &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcp::integrity::crc32c;
    use crate::gcp::test_support::{ok, MockKms};
    use google_cloud_kms_v1::model::{AsymmetricSignResponse, ChecksummedData, PublicKey};
    use p256::elliptic_curve::Generate;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::signature::hazmat::{PrehashSigner, RandomizedPrehashSigner};
    use rsa::signature::SignatureEncoding;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, LazyLock};
    use vitaminc_random::SafeRand;

    const VERSION: &str = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";

    /// A P-256 key pair, generated once for the whole test module.
    static P256_KEY: LazyLock<p256::ecdsa::SigningKey> = LazyLock::new(|| {
        let mut rng = SafeRand::from_entropy().unwrap();
        p256::ecdsa::SigningKey::generate_from_rng(&mut rng)
    });

    /// An RSA key pair. 2048 bits, generated once: key generation is slow
    /// in a debug build and nothing here depends on the modulus size.
    static RSA_KEY: LazyLock<rsa::RsaPrivateKey> = LazyLock::new(|| {
        let mut rng = SafeRand::from_entropy().unwrap();
        rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap()
    });

    fn p256_public_key_der() -> Vec<u8> {
        P256_KEY
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    fn rsa_public_key_der() -> Vec<u8> {
        RSA_KEY
            .to_public_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    fn digest(message: &[u8]) -> Protected<Vec<u8>> {
        use sha2::Digest as _;

        Protected::new(Sha256::digest(message).to_vec())
    }

    fn public_key_response(der: Vec<u8>, algorithm: CryptoKeyVersionAlgorithm) -> PublicKey {
        PublicKey::new()
            .set_name(VERSION)
            .set_algorithm(algorithm)
            .set_public_key_format(PublicKeyFormat::Der)
            .set_public_key(
                ChecksummedData::new()
                    .set_crc32c_checksum(crc32c(&der))
                    .set_data(der),
            )
    }

    fn sign_response(signature: Vec<u8>) -> AsymmetricSignResponse {
        AsymmetricSignResponse::new()
            .set_name(VERSION)
            .set_signature_crc32c(crc32c(&signature))
            .set_signature(signature)
            .set_verified_digest_crc32c(true)
    }

    /// A stub that serves one `getPublicKey` and nothing else.
    fn stub_with_public_key(der: Vec<u8>, algorithm: CryptoKeyVersionAlgorithm) -> MockKms {
        let mut stub = MockKms::new();
        stub.expect_get_public_key()
            .times(1)
            .returning(move |req, _| {
                assert_eq!(req.name, VERSION);
                assert_eq!(req.public_key_format, PublicKeyFormat::Der);
                ok(public_key_response(der.clone(), algorithm.clone()))
            });
        stub
    }

    async fn p256_signing_key(stub: MockKms) -> GcpSigningKey {
        GcpSigningKey::new(
            KeyManagementService::from_stub(stub),
            VERSION,
            SignatureAlgorithm::EcdsaP256Sha256,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn construction_fetches_the_der_public_key_once_and_keeps_it() {
        let der = p256_public_key_der();
        let stub = stub_with_public_key(der.clone(), CryptoKeyVersionAlgorithm::EcSignP256Sha256);

        let key = p256_signing_key(stub).await;

        // Two reads, still one call: `getPublicKey` happens at
        // construction, never per call.
        assert_eq!(key.get_public_key().await.unwrap(), der);
        assert_eq!(key.get_public_key().await.unwrap(), der);
        assert_eq!(key.algorithm(), SignatureAlgorithm::EcdsaP256Sha256);
    }

    #[tokio::test]
    async fn an_algorithm_google_cloud_kms_cannot_serve_fails_before_any_call() {
        // A stub with no expectations panics on any call.
        let stub = MockKms::new();

        let Err(error) = GcpSigningKey::new(
            KeyManagementService::from_stub(stub),
            VERSION,
            SignatureAlgorithm::EcdsaP521Sha512,
        )
        .await
        else {
            panic!("expected an unsupported-algorithm error");
        };

        assert!(matches!(
            error,
            Error::UnsupportedAlgorithm(SignatureAlgorithm::EcdsaP521Sha512)
        ));
    }

    #[tokio::test]
    async fn every_unsupported_pairing_is_refused() {
        for algorithm in [
            SignatureAlgorithm::EcdsaP521Sha512,
            SignatureAlgorithm::RsaPssSha384,
            SignatureAlgorithm::RsaPkcs1Sha384,
        ] {
            let Err(error) = GcpSigningKey::new(
                KeyManagementService::from_stub(MockKms::new()),
                VERSION,
                algorithm,
            )
            .await
            else {
                panic!("expected an unsupported-algorithm error");
            };

            assert!(matches!(error, Error::UnsupportedAlgorithm(_)));
        }
    }

    #[tokio::test]
    async fn a_key_version_signing_with_something_else_is_refused() {
        let stub = stub_with_public_key(
            p256_public_key_der(),
            CryptoKeyVersionAlgorithm::EcSignP384Sha384,
        );

        let Err(error) = GcpSigningKey::new(
            KeyManagementService::from_stub(stub),
            VERSION,
            SignatureAlgorithm::EcdsaP256Sha256,
        )
        .await
        else {
            panic!("expected a construction error");
        };

        assert!(matches!(
            error,
            Error::AlgorithmMismatch {
                requested: SignatureAlgorithm::EcdsaP256Sha256,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn a_key_version_with_an_unmappable_algorithm_is_refused() {
        let stub = stub_with_public_key(
            p256_public_key_der(),
            CryptoKeyVersionAlgorithm::EcSignEd25519,
        );

        let Err(error) = GcpSigningKey::new(
            KeyManagementService::from_stub(stub),
            VERSION,
            SignatureAlgorithm::EcdsaP256Sha256,
        )
        .await
        else {
            panic!("expected a construction error");
        };

        assert!(matches!(error, Error::AlgorithmMismatch { .. }));
    }

    #[tokio::test]
    async fn a_mangled_public_key_checksum_is_retried_then_fatal() {
        let der = p256_public_key_der();
        let mut stub = MockKms::new();
        stub.expect_get_public_key()
            .times(2)
            .returning(move |_, _| {
                ok(
                    public_key_response(der.clone(), CryptoKeyVersionAlgorithm::EcSignP256Sha256)
                        .set_public_key(ChecksummedData::new().set_data(der.clone())),
                )
            });

        let Err(error) = GcpSigningKey::new(
            KeyManagementService::from_stub(stub),
            VERSION,
            SignatureAlgorithm::EcdsaP256Sha256,
        )
        .await
        else {
            panic!("expected a construction error");
        };

        assert!(matches!(
            error,
            Error::Integrity("publicKey.crc32cChecksum")
        ));
    }

    #[tokio::test]
    async fn sign_sends_the_digest_in_the_field_the_hash_names() {
        let mut stub = stub_with_public_key(
            p256_public_key_der(),
            CryptoKeyVersionAlgorithm::EcSignP256Sha256,
        );
        stub.expect_asymmetric_sign().times(1).returning(|req, _| {
            assert_eq!(req.name, VERSION);
            assert!(req.data.is_empty(), "digest signing never sends `data`");

            let digest = req.digest.as_ref().expect("a digest field");
            let sha256 = digest.sha256().expect("the sha256 variant");
            assert_eq!(sha256.len(), 32);
            assert_eq!(req.digest_crc32c, Some(crc32c(sha256)));

            ok(sign_response(vec![9u8; 70]))
        });

        let key = p256_signing_key(stub).await;

        let signature = key.sign(&digest(b"sign me")).await.unwrap();

        assert_eq!(signature, vec![9u8; 70]);
    }

    #[tokio::test]
    async fn a_digest_of_the_wrong_length_never_reaches_the_backend() {
        let stub = stub_with_public_key(
            p256_public_key_der(),
            CryptoKeyVersionAlgorithm::EcSignP256Sha256,
        );
        let key = p256_signing_key(stub).await;

        let error = key.sign(&Protected::new(vec![0u8; 48])).await.unwrap_err();

        assert!(matches!(
            error,
            Error::DigestLength(crate::DigestLengthError {
                expected: 32,
                received: 48,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn a_mangled_signature_checksum_is_discarded_and_the_call_retried_once() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);

        let mut stub = stub_with_public_key(
            p256_public_key_der(),
            CryptoKeyVersionAlgorithm::EcSignP256Sha256,
        );
        stub.expect_asymmetric_sign()
            .times(2)
            .returning(move |_, _| {
                let response = sign_response(vec![9u8; 70]);
                if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                    return ok(response.set_signature_crc32c(0));
                }
                ok(response)
            });

        let key = p256_signing_key(stub).await;

        assert_eq!(key.sign(&digest(b"sign me")).await.unwrap(), vec![9u8; 70]);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_persistently_mangled_signature_is_an_integrity_error() {
        let mut stub = stub_with_public_key(
            p256_public_key_der(),
            CryptoKeyVersionAlgorithm::EcSignP256Sha256,
        );
        stub.expect_asymmetric_sign()
            .times(2)
            .returning(|_, _| ok(sign_response(vec![9u8; 70]).set_verified_digest_crc32c(false)));

        let key = p256_signing_key(stub).await;

        let error = key.sign(&digest(b"sign me")).await.unwrap_err();

        assert!(matches!(error, Error::Integrity("verifiedDigestCrc32c")));
    }

    #[tokio::test]
    async fn ecdsa_signatures_verify_locally_against_the_stored_public_key() {
        let stub = stub_with_public_key(
            p256_public_key_der(),
            CryptoKeyVersionAlgorithm::EcSignP256Sha256,
        );
        let key = p256_signing_key(stub).await;

        let signed = digest(b"sign me");
        // What Google Cloud KMS returns: a DER-encoded ECDSA signature
        // over the same digest.
        let signature: p256::ecdsa::DerSignature = P256_KEY
            .sign_prehash(&signed.clone().risky_unwrap())
            .unwrap();

        assert!(key.verify(&signed, signature.as_bytes()).await.unwrap());
        assert!(!key
            .verify(&digest(b"a different message"), signature.as_bytes())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn a_tampered_or_malformed_signature_is_false_not_an_error() {
        let stub = stub_with_public_key(
            p256_public_key_der(),
            CryptoKeyVersionAlgorithm::EcSignP256Sha256,
        );
        let key = p256_signing_key(stub).await;

        let signed = digest(b"sign me");
        let signature: p256::ecdsa::DerSignature = P256_KEY
            .sign_prehash(&signed.clone().risky_unwrap())
            .unwrap();

        let mut tampered = signature.as_bytes().to_vec();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert!(!key.verify(&signed, &tampered).await.unwrap());

        assert!(!key.verify(&signed, b"not a signature").await.unwrap());
        assert!(!key.verify(&signed, &[]).await.unwrap());
    }

    #[tokio::test]
    async fn rsa_pss_signatures_verify_locally() {
        let stub = stub_with_public_key(
            rsa_public_key_der(),
            CryptoKeyVersionAlgorithm::RsaSignPss2048Sha256,
        );
        let key = GcpSigningKey::new(
            KeyManagementService::from_stub(stub),
            VERSION,
            SignatureAlgorithm::RsaPssSha256,
        )
        .await
        .unwrap();

        let signed = digest(b"sign me");
        let signing_key = rsa::pss::SigningKey::<Sha256>::new(RSA_KEY.clone());
        // Google Cloud KMS salts with the digest length, which is what
        // `SigningKey::new` does too.
        let signature: rsa::pss::Signature = signing_key
            .sign_prehash_with_rng(
                &mut SafeRand::from_entropy().unwrap(),
                &signed.clone().risky_unwrap(),
            )
            .unwrap();
        let signature = signature.to_vec();

        assert!(key.verify(&signed, &signature).await.unwrap());

        let mut tampered = signature.clone();
        tampered[0] ^= 0x01;
        assert!(!key.verify(&signed, &tampered).await.unwrap());
    }

    #[tokio::test]
    async fn rsa_pkcs1_signatures_verify_locally() {
        let stub = stub_with_public_key(
            rsa_public_key_der(),
            CryptoKeyVersionAlgorithm::RsaSignPkcs12048Sha256,
        );
        let key = GcpSigningKey::new(
            KeyManagementService::from_stub(stub),
            VERSION,
            SignatureAlgorithm::RsaPkcs1Sha256,
        )
        .await
        .unwrap();

        let signed = digest(b"sign me");
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(RSA_KEY.clone());
        let signature: rsa::pkcs1v15::Signature = signing_key
            .sign_prehash(&signed.clone().risky_unwrap())
            .unwrap();

        assert!(key.verify(&signed, &signature.to_vec()).await.unwrap());
        assert!(!key.verify(&signed, &[0u8; 256]).await.unwrap());
    }

    #[test]
    fn every_google_cloud_kms_signing_algorithm_maps_to_one_scheme() {
        for (gcp, scheme) in [
            (
                CryptoKeyVersionAlgorithm::EcSignP256Sha256,
                SignatureAlgorithm::EcdsaP256Sha256,
            ),
            (
                CryptoKeyVersionAlgorithm::EcSignP384Sha384,
                SignatureAlgorithm::EcdsaP384Sha384,
            ),
            (
                CryptoKeyVersionAlgorithm::RsaSignPss3072Sha256,
                SignatureAlgorithm::RsaPssSha256,
            ),
            (
                CryptoKeyVersionAlgorithm::RsaSignPss4096Sha512,
                SignatureAlgorithm::RsaPssSha512,
            ),
            (
                CryptoKeyVersionAlgorithm::RsaSignPkcs14096Sha256,
                SignatureAlgorithm::RsaPkcs1Sha256,
            ),
            (
                CryptoKeyVersionAlgorithm::RsaSignPkcs14096Sha512,
                SignatureAlgorithm::RsaPkcs1Sha512,
            ),
        ] {
            assert_eq!(scheme_of(&gcp), Some(scheme));
        }

        for unsupported in [
            CryptoKeyVersionAlgorithm::EcSignEd25519,
            CryptoKeyVersionAlgorithm::EcSignSecp256K1Sha256,
            CryptoKeyVersionAlgorithm::RsaSignRawPkcs12048,
            CryptoKeyVersionAlgorithm::HmacSha256,
            CryptoKeyVersionAlgorithm::GoogleSymmetricEncryption,
        ] {
            assert_eq!(scheme_of(&unsupported), None);
        }
    }

    #[test]
    fn each_hash_names_its_own_digest_field() {
        assert!(Hash::Sha256.digest_field(vec![0; 32]).sha256().is_some());
        assert!(Hash::Sha384.digest_field(vec![0; 48]).sha384().is_some());
        assert!(Hash::Sha512.digest_field(vec![0; 64]).sha512().is_some());
    }
}
