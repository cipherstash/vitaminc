//! [`AwsSigningKey`]: the signing-key adapter over an AWS KMS asymmetric
//! sign/verify key.

use crate::algorithm::SignatureAlgorithm;
use crate::sign::{GetPublicKey, Sign, Verify};
use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
use aws_sdk_kms::{primitives::Blob, Client};
use thiserror::Error;
use vitaminc_protected::{Controlled, Protected};

/// Errors from [`AwsSigningKey`].
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    AwsSdk(#[from] aws_sdk_kms::Error),
    /// The caller's digest is not the length the configured algorithm's
    /// hash produces. Caught before the call goes out: AWS would either
    /// reject it or, worse for a `RAW` mix-up, sign the wrong bytes.
    #[error("expected a {expected}-byte digest, got {received} bytes")]
    DigestLength { expected: usize, received: usize },
    /// AWS KMS returned a successful `Sign` response with no `Signature`
    /// field — should not happen, but the SDK models the field as optional.
    #[error("AWS KMS returned no signature")]
    MissingSignature,
    /// AWS KMS returned a successful `GetPublicKey` response with no
    /// `PublicKey` field — should not happen, but the SDK models the field
    /// as optional.
    #[error("AWS KMS returned no public key")]
    MissingPublicKey,
}

/// The crate's algorithm enum mapped onto AWS's `SigningAlgorithmSpec`.
/// Total: every member of [`SignatureAlgorithm`] has an AWS equivalent, so
/// there is nothing for the constructor to reject.
fn signing_algorithm_spec(algorithm: SignatureAlgorithm) -> SigningAlgorithmSpec {
    match algorithm {
        SignatureAlgorithm::EcdsaP256Sha256 => SigningAlgorithmSpec::EcdsaSha256,
        SignatureAlgorithm::EcdsaP384Sha384 => SigningAlgorithmSpec::EcdsaSha384,
        SignatureAlgorithm::EcdsaP521Sha512 => SigningAlgorithmSpec::EcdsaSha512,
        SignatureAlgorithm::RsaPssSha256 => SigningAlgorithmSpec::RsassaPssSha256,
        SignatureAlgorithm::RsaPssSha384 => SigningAlgorithmSpec::RsassaPssSha384,
        SignatureAlgorithm::RsaPssSha512 => SigningAlgorithmSpec::RsassaPssSha512,
        SignatureAlgorithm::RsaPkcs1Sha256 => SigningAlgorithmSpec::RsassaPkcs1V15Sha256,
        SignatureAlgorithm::RsaPkcs1Sha384 => SigningAlgorithmSpec::RsassaPkcs1V15Sha384,
        SignatureAlgorithm::RsaPkcs1Sha512 => SigningAlgorithmSpec::RsassaPkcs1V15Sha512,
    }
}

/// A signing key: an adapter over an AWS KMS backend key whose purpose is
/// signing (`KeyUsage=SIGN_VERIFY`). The algorithm is fixed at
/// construction, so a caller cannot sign one digest under two schemes by
/// accident, and the expected digest length is known before any call.
///
/// Both [`sign`](Sign::sign) and [`verify`](Verify::verify) send
/// `MessageType=DIGEST` — the crate's traits take a pre-computed digest,
/// and `RAW` over an already-hashed input would hash it twice and break
/// verification silently.
///
/// Encodings need no conversion here: AWS returns ECDSA signatures as DER
/// and public keys as DER `SubjectPublicKeyInfo`, which is exactly what
/// ADR 0001 makes canonical, so the bytes pass straight through.
///
/// ```no_run
/// # use aws_sdk_kms::Client;
/// # use vitaminc_kms::{AwsSigningKey, GetPublicKey, SignatureAlgorithm, Sign, Verify};
/// # use vitaminc_protected::Protected;
/// # async fn example(client: Client, sha256_of_message: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
/// let key = AwsSigningKey::new(
///     client,
///     "arn:aws:kms:...",
///     SignatureAlgorithm::EcdsaP256Sha256,
/// );
/// let digest = Protected::new(sha256_of_message);
///
/// let signature = key.sign(&digest).await?;
/// assert!(key.verify(&digest, &signature).await?);
///
/// let spki_der = key.get_public_key().await?;
/// # Ok(())
/// # }
/// ```
pub struct AwsSigningKey {
    client: Client,
    key_id: String,
    algorithm: SignatureAlgorithm,
}

impl AwsSigningKey {
    /// `key_id` is the AWS KMS key ARN/ID/alias this instance is bound to,
    /// and `algorithm` the scheme every call uses — both settled here, as
    /// in every adapter in this crate. Whether the bound key can actually
    /// serve `algorithm` is a fact only AWS holds, so a mismatch surfaces
    /// on the first call as `InvalidKeyUsageException`.
    pub fn new(client: Client, key_id: impl Into<String>, algorithm: SignatureAlgorithm) -> Self {
        Self {
            client,
            key_id: key_id.into(),
            algorithm,
        }
    }

    /// The configured scheme.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    // `aws_sdk_kms::Error` is large and we re-export it as-is through our
    // own `Error`, so shrinking it would mean boxing a public variant. Not
    // worth a breaking change for an error on a network round-trip.
    #[allow(clippy::result_large_err)]
    fn checked_digest(&self, digest: &Protected<Vec<u8>>) -> Result<Vec<u8>, Error> {
        let bytes = digest.clone().risky_unwrap();
        let expected = self.algorithm.digest_len();
        if bytes.len() != expected {
            return Err(Error::DigestLength {
                expected,
                received: bytes.len(),
            });
        }
        Ok(bytes)
    }
}

impl Sign for AwsSigningKey {
    type Error = Error;

    async fn sign(&self, digest: &Protected<Vec<u8>>) -> Result<Vec<u8>, Self::Error> {
        let message = self.checked_digest(digest)?;

        let response = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(message))
            .message_type(MessageType::Digest)
            .signing_algorithm(signing_algorithm_spec(self.algorithm))
            .send()
            .await
            .map_err(aws_sdk_kms::Error::from)?;

        let signature = response.signature.ok_or(Error::MissingSignature)?;
        Ok(signature.into_inner())
    }
}

impl Verify for AwsSigningKey {
    type Error = Error;

    /// AWS never returns `SignatureValid=false` — a signature that does not
    /// check out raises `KMSInvalidSignatureException` instead. That one
    /// exception is the expected "did not verify" path and becomes
    /// `Ok(false)`; every other exception is a genuine infrastructure
    /// failure and stays an `Err`.
    async fn verify(
        &self,
        digest: &Protected<Vec<u8>>,
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        let message = self.checked_digest(digest)?;

        let result = self
            .client
            .verify()
            .key_id(&self.key_id)
            .message(Blob::new(message))
            .message_type(MessageType::Digest)
            .signature(Blob::new(signature.to_vec()))
            .signing_algorithm(signing_algorithm_spec(self.algorithm))
            .send()
            .await;

        match result {
            Ok(response) => Ok(response.signature_valid),
            Err(error) => match aws_sdk_kms::Error::from(error) {
                aws_sdk_kms::Error::KmsInvalidSignatureException(_) => Ok(false),
                other => Err(Error::AwsSdk(other)),
            },
        }
    }
}

impl GetPublicKey for AwsSigningKey {
    type Error = Error;

    /// Returns the DER `SubjectPublicKeyInfo` bytes as AWS gives them —
    /// already the canonical form of ADR 0001.
    async fn get_public_key(&self) -> Result<Vec<u8>, Self::Error> {
        let response = self
            .client
            .get_public_key()
            .key_id(&self.key_id)
            .send()
            .await
            .map_err(aws_sdk_kms::Error::from)?;

        let public_key = response.public_key.ok_or(Error::MissingPublicKey)?;
        Ok(public_key.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_kms::operation::get_public_key::GetPublicKeyOutput;
    use aws_sdk_kms::operation::sign::SignOutput;
    use aws_sdk_kms::operation::verify::{VerifyError, VerifyOutput};
    use aws_sdk_kms::types::error::KmsInvalidSignatureException;
    use aws_smithy_mocks::{mock, mock_client, RuleMode};

    const TEST_KEY_ID: &str = "arn:aws:kms:us-east-1:111122223333:key/test-signing-key";

    fn digest() -> Protected<Vec<u8>> {
        Protected::new(vec![1u8; 32])
    }

    fn signing_key(client: Client) -> AwsSigningKey {
        AwsSigningKey::new(client, TEST_KEY_ID, SignatureAlgorithm::EcdsaP256Sha256)
    }

    #[tokio::test]
    async fn sign_returns_the_der_signature_unchanged() {
        let sign_rule = mock!(Client::sign).then_output(|| {
            SignOutput::builder()
                .signature(Blob::new(vec![0x30, 0x06]))
                .build()
        });
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&sign_rule]);
        let key = signing_key(client);

        let signature = key.sign(&digest()).await.unwrap();

        assert_eq!(signature, vec![0x30, 0x06]);
        assert_eq!(sign_rule.num_calls(), 1);
    }

    #[tokio::test]
    async fn a_response_with_no_signature_is_an_error() {
        let sign_rule = mock!(Client::sign).then_output(|| SignOutput::builder().build());
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&sign_rule]);
        let key = signing_key(client);

        let error = key.sign(&digest()).await.unwrap_err();

        assert!(matches!(error, Error::MissingSignature));
    }

    /// The digest length is checked before the call, so a caller that
    /// passes a raw message (or a digest of the wrong hash) never spends a
    /// network round trip — or, worse, gets a signature over the wrong
    /// thing.
    #[tokio::test]
    async fn a_wrong_length_digest_is_rejected_before_any_call() {
        let sign_rule = mock!(Client::sign).then_output(|| {
            SignOutput::builder()
                .signature(Blob::new(vec![0x30]))
                .build()
        });
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&sign_rule]);
        let key = signing_key(client);

        let error = key.sign(&Protected::new(vec![1u8; 48])).await.unwrap_err();

        assert!(matches!(
            error,
            Error::DigestLength {
                expected: 32,
                received: 48
            }
        ));
        assert_eq!(sign_rule.num_calls(), 0);
    }

    #[tokio::test]
    async fn verify_returns_true_for_a_good_signature() {
        let verify_rule = mock!(Client::verify)
            .then_output(|| VerifyOutput::builder().signature_valid(true).build());
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&verify_rule]);
        let key = signing_key(client);

        assert!(key.verify(&digest(), &[0x30, 0x06]).await.unwrap());
        assert_eq!(verify_rule.num_calls(), 1);
    }

    /// AWS throws rather than returning `false`; the trait promises
    /// `Ok(false)`, so the adapter absorbs exactly that one exception.
    #[tokio::test]
    async fn an_invalid_signature_exception_becomes_ok_false() {
        let verify_rule = mock!(Client::verify).then_error(|| {
            VerifyError::KmsInvalidSignatureException(
                KmsInvalidSignatureException::builder().build(),
            )
        });
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&verify_rule]);
        let key = signing_key(client);

        assert!(!key.verify(&digest(), &[0x30, 0x06]).await.unwrap());
    }

    /// Every other failure is infrastructure, and must stay an `Err`.
    #[tokio::test]
    async fn any_other_exception_stays_an_error() {
        use aws_sdk_kms::types::error::NotFoundException;

        let verify_rule = mock!(Client::verify)
            .then_error(|| VerifyError::NotFoundException(NotFoundException::builder().build()));
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&verify_rule]);
        let key = signing_key(client);

        let error = key.verify(&digest(), &[0x30, 0x06]).await.unwrap_err();

        assert!(matches!(error, Error::AwsSdk(_)));
    }

    #[tokio::test]
    async fn verify_also_rejects_a_wrong_length_digest_before_any_call() {
        let verify_rule = mock!(Client::verify)
            .then_output(|| VerifyOutput::builder().signature_valid(true).build());
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&verify_rule]);
        let key = signing_key(client);

        let error = key
            .verify(&Protected::new(vec![1u8; 20]), &[0x30, 0x06])
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            Error::DigestLength {
                expected: 32,
                received: 20
            }
        ));
        assert_eq!(verify_rule.num_calls(), 0);
    }

    /// AWS already returns DER `SubjectPublicKeyInfo`, the canonical form
    /// of ADR 0001, so the adapter passes the bytes straight through.
    #[tokio::test]
    async fn get_public_key_returns_the_der_bytes_unchanged() {
        let public_key_rule = mock!(Client::get_public_key).then_output(|| {
            GetPublicKeyOutput::builder()
                .public_key(Blob::new(vec![0x30, 0x59, 0x30, 0x13]))
                .build()
        });
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&public_key_rule]);
        let key = signing_key(client);

        let public_key = key.get_public_key().await.unwrap();

        assert_eq!(public_key, vec![0x30, 0x59, 0x30, 0x13]);
    }

    #[tokio::test]
    async fn a_response_with_no_public_key_is_an_error() {
        let public_key_rule =
            mock!(Client::get_public_key).then_output(|| GetPublicKeyOutput::builder().build());
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&public_key_rule]);
        let key = signing_key(client);

        let error = key.get_public_key().await.unwrap_err();

        assert!(matches!(error, Error::MissingPublicKey));
    }

    #[test]
    fn every_algorithm_maps_to_its_aws_spec() {
        use aws_sdk_kms::types::SigningAlgorithmSpec;

        let pairs = [
            (
                SignatureAlgorithm::EcdsaP256Sha256,
                SigningAlgorithmSpec::EcdsaSha256,
            ),
            (
                SignatureAlgorithm::EcdsaP384Sha384,
                SigningAlgorithmSpec::EcdsaSha384,
            ),
            (
                SignatureAlgorithm::EcdsaP521Sha512,
                SigningAlgorithmSpec::EcdsaSha512,
            ),
            (
                SignatureAlgorithm::RsaPssSha256,
                SigningAlgorithmSpec::RsassaPssSha256,
            ),
            (
                SignatureAlgorithm::RsaPssSha384,
                SigningAlgorithmSpec::RsassaPssSha384,
            ),
            (
                SignatureAlgorithm::RsaPssSha512,
                SigningAlgorithmSpec::RsassaPssSha512,
            ),
            (
                SignatureAlgorithm::RsaPkcs1Sha256,
                SigningAlgorithmSpec::RsassaPkcs1V15Sha256,
            ),
            (
                SignatureAlgorithm::RsaPkcs1Sha384,
                SigningAlgorithmSpec::RsassaPkcs1V15Sha384,
            ),
            (
                SignatureAlgorithm::RsaPkcs1Sha512,
                SigningAlgorithmSpec::RsassaPkcs1V15Sha512,
            ),
        ];

        for (algorithm, spec) in pairs {
            assert_eq!(signing_algorithm_spec(algorithm), spec);
        }
    }

    /// Against LocalStack on `localhost:4566` — see the crate README for
    /// how to bring it up.
    mod localstack {
        use super::*;
        use crate::aws::testing::localstack_client;
        use aws_sdk_kms::types::{KeySpec, KeyUsageType};

        /// A P-256 sign/verify key, to match
        /// [`SignatureAlgorithm::EcdsaP256Sha256`].
        async fn p256_signing_key(client: &Client) -> String {
            let key = client
                .create_key()
                .key_usage(KeyUsageType::SignVerify)
                .key_spec(KeySpec::EccNistP256)
                .send()
                .await
                .expect("LocalStack CreateKey");

            key.key_metadata().unwrap().key_id().to_owned()
        }

        #[tokio::test]
        async fn sign_then_verify_round_trip() {
            let client = localstack_client();
            let key_id = p256_signing_key(&client).await;
            let key = signing_key_bound_to(client, key_id);

            let signature = key.sign(&digest()).await.unwrap();

            assert!(key.verify(&digest(), &signature).await.unwrap());
        }

        #[tokio::test]
        async fn a_signature_over_a_different_digest_verifies_as_false() {
            let client = localstack_client();
            let key_id = p256_signing_key(&client).await;
            let key = signing_key_bound_to(client, key_id);

            let signature = key.sign(&digest()).await.unwrap();
            let other = Protected::new(vec![2u8; 32]);

            assert!(!key.verify(&other, &signature).await.unwrap());
        }

        /// DER `SubjectPublicKeyInfo` always opens with the `SEQUENCE` tag,
        /// `0x30` — the canonical form of ADR 0001, which AWS already
        /// returns, so the adapter converts nothing.
        #[tokio::test]
        async fn get_public_key_returns_der_subject_public_key_info() {
            let client = localstack_client();
            let key_id = p256_signing_key(&client).await;
            let key = signing_key_bound_to(client, key_id);

            let public_key = key.get_public_key().await.unwrap();

            assert_eq!(public_key.first(), Some(&0x30));
        }

        fn signing_key_bound_to(client: Client, key_id: String) -> AwsSigningKey {
            AwsSigningKey::new(client, key_id, SignatureAlgorithm::EcdsaP256Sha256)
        }
    }
}
