use super::integrity::{self, CallError, SignedData};
use crate::sign::{GetPublicKey, SignMessage, VerifyMessage};
use ed25519_dalek::pkcs8::DecodePublicKey;
use google_cloud_kms_v1::client::KeyManagementService;
use google_cloud_kms_v1::model::crypto_key_version::CryptoKeyVersionAlgorithm;
use google_cloud_kms_v1::model::public_key::PublicKeyFormat;
use thiserror::Error;
use vitaminc_protected::{Controlled, Protected};

/// Errors from [`GcpEd25519Key`].
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Gcp(#[from] google_cloud_kms_v1::Error),
    /// Two consecutive responses failed the same CRC32C check: the
    /// first was discarded and retried, and the retry failed the same way.
    #[error("Google Cloud KMS responses failed their {0} integrity check twice")]
    Integrity(&'static str),
    /// The bound key version exists but is not `EC_SIGN_ED25519`. Its
    /// algorithm is fixed at creation, so this cannot be fixed by
    /// retrying: the caller wants a different key version, or
    /// [`GcpSigningKey`](super::GcpSigningKey) for a digest scheme.
    #[error("the bound key version signs with {0}, not EC_SIGN_ED25519")]
    AlgorithmMismatch(String),
    /// The public key Google Cloud KMS returned is not a DER
    /// `SubjectPublicKeyInfo` for an Ed25519 key.
    #[error("Google Cloud KMS returned a public key that could not be parsed: {0}")]
    MalformedPublicKey(#[from] spki::Error),
}

impl From<CallError> for Error {
    fn from(error: CallError) -> Self {
        match error {
            CallError::Gcp(error) => Self::Gcp(error),
            CallError::Integrity(field) => Self::Integrity(field),
        }
    }
}

/// Google Cloud KMS-backed Ed25519 key, bound to one `EC_SIGN_ED25519`
/// `CryptoKeyVersion` resource name.
///
/// [`SignMessage`] is `cryptoKeyVersions.asymmetricSign` with the whole
/// message in `data`, not a `digest`: Google Cloud KMS signs only pure
/// Ed25519 (RFC 8032), which hashes inside the signature. That is why this
/// is its own type and not a
/// [`SignatureAlgorithm`](crate::SignatureAlgorithm) of
/// [`GcpSigningKey`](super::GcpSigningKey): it does not implement
/// [`Sign`](crate::Sign), so a digest cannot go to it by mistake. The
/// request carries `dataCrc32c`, and the response must confirm it with
/// `verifiedDataCrc32c`.
///
/// As with [`GcpSigningKey`](super::GcpSigningKey), construction fetches
/// the public key once, and [`VerifyMessage`] is **local**, because Google
/// Cloud KMS has no server-side asymmetric verify. Local verification uses
/// `ed25519-dalek`'s strict verifier, which also refuses the weak-key and
/// malleable signature forms that RFC 8032 permits. A key that Google
/// Cloud KMS holds never makes those forms.
///
/// Signatures cross the trait boundary as the raw 64 bytes, and the public
/// key as DER `SubjectPublicKeyInfo` (ADR 0002).
///
/// A digest key does not take a message either. Neither of these compiles:
///
/// ```compile_fail
/// fn signs_a_digest<K: vitaminc_kms::Sign>() {}
/// signs_a_digest::<vitaminc_kms::gcp::GcpEd25519Key>();
/// ```
///
/// ```compile_fail
/// fn signs_a_message<K: vitaminc_kms::SignMessage>() {}
/// signs_a_message::<vitaminc_kms::gcp::GcpSigningKey>();
/// ```
pub struct GcpEd25519Key {
    client: KeyManagementService,
    crypto_key_version_name: String,
    public_key_der: Vec<u8>,
    verifying_key: ed25519_dalek::VerifyingKey,
}

impl GcpEd25519Key {
    /// `crypto_key_version_name` is the full resource name of the
    /// `CryptoKeyVersion` this instance is bound to
    /// (`projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}/cryptoKeyVersions/{v}`),
    /// whose algorithm must be `EC_SIGN_ED25519`.
    ///
    /// Makes one `getPublicKey` call, checks the version's algorithm, and
    /// keeps the DER `SubjectPublicKeyInfo` for [`GetPublicKey`] and
    /// [`VerifyMessage`].
    pub async fn new(
        client: KeyManagementService,
        crypto_key_version_name: impl Into<String>,
    ) -> Result<Self, Error> {
        let crypto_key_version_name = crypto_key_version_name.into();

        let response = integrity::checked_call(|| {
            client
                .get_public_key()
                .set_name(crypto_key_version_name.clone())
                .set_public_key_format(PublicKeyFormat::Der)
                .send()
        })
        .await?;

        if response.algorithm != CryptoKeyVersionAlgorithm::EcSignEd25519 {
            return Err(Error::AlgorithmMismatch(format!(
                "{:?}",
                response.algorithm
            )));
        }

        // `check_integrity` already rejected a response without one.
        let public_key_der = response
            .public_key
            .ok_or(Error::Integrity("publicKey"))?
            .data
            .to_vec();
        let verifying_key = ed25519_dalek::VerifyingKey::from_public_key_der(&public_key_der)?;

        Ok(Self {
            client,
            crypto_key_version_name,
            public_key_der,
            verifying_key,
        })
    }
}

impl SignMessage for GcpEd25519Key {
    type Error = Error;

    async fn sign_message(&self, message: &Protected<Vec<u8>>) -> Result<Vec<u8>, Self::Error> {
        let message = message.risky_ref();
        let checksum = integrity::crc32c(message);

        let response = integrity::checked_call(|| {
            let send = self
                .client
                .asymmetric_sign()
                .set_name(self.crypto_key_version_name.clone())
                .set_data(message.to_vec())
                .set_data_crc32c(checksum)
                .send();
            async move { send.await.map(SignedData) }
        })
        .await?;

        Ok(response.0.signature.to_vec())
    }
}

impl VerifyMessage for GcpEd25519Key {
    type Error = Error;

    /// Verified locally against the public key fetched at construction.
    /// A signature that is malformed, or is over different bytes, is
    /// `Ok(false)`. Nothing here can fail, so this never returns an error.
    async fn verify_message(
        &self,
        message: &Protected<Vec<u8>>,
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
            return Ok(false);
        };

        Ok(self
            .verifying_key
            .verify_strict(message.risky_ref(), &signature)
            .is_ok())
    }
}

impl GetPublicKey for GcpEd25519Key {
    type Error = Error;

    /// The DER `SubjectPublicKeyInfo` fetched at construction. No network
    /// call: a key version's public half never changes.
    async fn get_public_key(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(self.public_key_der.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcp::integrity::crc32c;
    use crate::gcp::test_support::{ok, MockKms};
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::Signer;
    use google_cloud_kms_v1::model::{AsymmetricSignResponse, ChecksummedData, PublicKey};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, LazyLock};

    const VERSION: &str = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";

    const MESSAGE: &[u8] = b"a whole message, not a digest";

    /// A fixed Ed25519 key pair. Ed25519 signing is deterministic, so a
    /// fixed seed gives the same test vectors on every run.
    static SIGNING_KEY: LazyLock<ed25519_dalek::SigningKey> =
        LazyLock::new(|| ed25519_dalek::SigningKey::from_bytes(&[0x5Au8; 32]));

    fn public_key_der() -> Vec<u8> {
        SIGNING_KEY
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    fn message() -> Protected<Vec<u8>> {
        Protected::new(MESSAGE.to_vec())
    }

    /// What Google Cloud KMS returns: the raw 64-byte signature over the
    /// message.
    fn signature_over(message: &[u8]) -> Vec<u8> {
        SIGNING_KEY.sign(message).to_bytes().to_vec()
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
            .set_verified_data_crc32c(true)
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

    fn ed25519_stub() -> MockKms {
        stub_with_public_key(public_key_der(), CryptoKeyVersionAlgorithm::EcSignEd25519)
    }

    async fn ed25519_key(stub: MockKms) -> GcpEd25519Key {
        GcpEd25519Key::new(KeyManagementService::from_stub(stub), VERSION)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn construction_fetches_the_der_public_key_once_and_keeps_it() {
        let key = ed25519_key(ed25519_stub()).await;

        // Two reads, still one call.
        assert_eq!(key.get_public_key().await.unwrap(), public_key_der());
        assert_eq!(key.get_public_key().await.unwrap(), public_key_der());
    }

    #[tokio::test]
    async fn a_key_version_that_is_not_ed25519_is_refused() {
        let stub = stub_with_public_key(
            public_key_der(),
            CryptoKeyVersionAlgorithm::EcSignP256Sha256,
        );

        let Err(error) = GcpEd25519Key::new(KeyManagementService::from_stub(stub), VERSION).await
        else {
            panic!("expected a construction error");
        };

        assert!(matches!(error, Error::AlgorithmMismatch(_)));
    }

    // The SPKI builder lives behind `canonical-encoding`, which `gcp` does
    // not enable; `--all-features` runs this.
    #[cfg(feature = "canonical-encoding")]
    #[tokio::test]
    async fn a_public_key_that_is_not_ed25519_is_refused() {
        // An SPKI for a P-256 key, labelled as an Ed25519 version.
        let p256 = crate::encoding::ec_spki(crate::encoding::EcCurve::P256, &[0x01], &[0x02]);
        let stub = stub_with_public_key(p256.unwrap(), CryptoKeyVersionAlgorithm::EcSignEd25519);

        let Err(error) = GcpEd25519Key::new(KeyManagementService::from_stub(stub), VERSION).await
        else {
            panic!("expected a construction error");
        };

        assert!(matches!(error, Error::MalformedPublicKey(_)));
    }

    #[tokio::test]
    async fn a_mangled_public_key_checksum_is_retried_then_fatal() {
        let der = public_key_der();
        let mut stub = MockKms::new();
        stub.expect_get_public_key()
            .times(2)
            .returning(move |_, _| {
                ok(
                    public_key_response(der.clone(), CryptoKeyVersionAlgorithm::EcSignEd25519)
                        .set_public_key(ChecksummedData::new().set_data(der.clone())),
                )
            });

        let Err(error) = GcpEd25519Key::new(KeyManagementService::from_stub(stub), VERSION).await
        else {
            panic!("expected a construction error");
        };

        assert!(matches!(
            error,
            Error::Integrity("publicKey.crc32cChecksum")
        ));
    }

    #[tokio::test]
    async fn sign_sends_the_message_in_data_with_its_checksum() {
        let mut stub = ed25519_stub();
        stub.expect_asymmetric_sign().times(1).returning(|req, _| {
            assert_eq!(req.name, VERSION);
            assert!(req.digest.is_none(), "Ed25519 signing never sends a digest");
            assert_eq!(req.digest_crc32c, None);
            assert_eq!(&req.data[..], MESSAGE);
            assert_eq!(req.data_crc32c, Some(crc32c(MESSAGE)));

            ok(sign_response(signature_over(&req.data)))
        });

        let key = ed25519_key(stub).await;

        let signature = key.sign_message(&message()).await.unwrap();

        assert_eq!(signature, signature_over(MESSAGE));
        assert!(key.verify_message(&message(), &signature).await.unwrap());
    }

    #[tokio::test]
    async fn a_mangled_signature_checksum_is_discarded_and_the_call_retried_once() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);

        let mut stub = ed25519_stub();
        stub.expect_asymmetric_sign()
            .times(2)
            .returning(move |_, _| {
                let response = sign_response(signature_over(MESSAGE));
                if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                    return ok(response.set_signature_crc32c(0));
                }
                ok(response)
            });

        let key = ed25519_key(stub).await;

        assert_eq!(
            key.sign_message(&message()).await.unwrap(),
            signature_over(MESSAGE)
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_persistently_unverified_data_checksum_is_an_integrity_error() {
        let mut stub = ed25519_stub();
        stub.expect_asymmetric_sign().times(2).returning(|_, _| {
            ok(sign_response(signature_over(MESSAGE)).set_verified_data_crc32c(false))
        });

        let key = ed25519_key(stub).await;

        assert!(matches!(
            key.sign_message(&message()).await.unwrap_err(),
            Error::Integrity("verifiedDataCrc32c")
        ));
    }

    /// The digest flag is what a digest request gets back. A data request
    /// that only has that flag set has not had its data checked, so it
    /// does not pass.
    #[tokio::test]
    async fn the_digest_flag_does_not_stand_in_for_the_data_flag() {
        let mut stub = ed25519_stub();
        stub.expect_asymmetric_sign().times(2).returning(|_, _| {
            ok(sign_response(signature_over(MESSAGE))
                .set_verified_data_crc32c(false)
                .set_verified_digest_crc32c(true))
        });

        let key = ed25519_key(stub).await;

        assert!(matches!(
            key.sign_message(&message()).await.unwrap_err(),
            Error::Integrity("verifiedDataCrc32c")
        ));
    }

    #[tokio::test]
    async fn a_persistently_mangled_signature_is_an_integrity_error() {
        let mut stub = ed25519_stub();
        stub.expect_asymmetric_sign()
            .times(2)
            .returning(|_, _| ok(sign_response(signature_over(MESSAGE)).set_signature_crc32c(0)));

        let key = ed25519_key(stub).await;

        assert!(matches!(
            key.sign_message(&message()).await.unwrap_err(),
            Error::Integrity("signatureCrc32c")
        ));
    }

    #[tokio::test]
    async fn signatures_verify_locally_against_the_stored_public_key() {
        let key = ed25519_key(ed25519_stub()).await;
        let signature = signature_over(MESSAGE);

        assert!(key.verify_message(&message(), &signature).await.unwrap());
        assert!(!key
            .verify_message(&Protected::new(b"a different message".to_vec()), &signature)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn a_tampered_message_does_not_verify() {
        let key = ed25519_key(ed25519_stub()).await;
        let signature = signature_over(MESSAGE);

        let mut tampered = MESSAGE.to_vec();
        tampered[0] ^= 0x01;

        assert!(!key
            .verify_message(&Protected::new(tampered), &signature)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn a_tampered_or_malformed_signature_is_false_not_an_error() {
        let key = ed25519_key(ed25519_stub()).await;

        let mut tampered = signature_over(MESSAGE);
        tampered[0] ^= 0x01;
        assert!(!key.verify_message(&message(), &tampered).await.unwrap());

        assert!(!key
            .verify_message(&message(), b"not a signature")
            .await
            .unwrap());
        assert!(!key.verify_message(&message(), &[]).await.unwrap());
        assert!(!key.verify_message(&message(), &[0u8; 64]).await.unwrap());
        assert!(!key.verify_message(&message(), &[0u8; 65]).await.unwrap());
    }
}
