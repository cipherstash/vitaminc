//! [`AwsMacKey`]: the MAC-key adapter over an AWS KMS HMAC key.
//!
//! The older [`AwsKmsHmac`](super::AwsKmsHmac) covers the same `GenerateMac`
//! operation behind the streaming `Update`/`AsyncFixedOutput` traits. This
//! module is the capability-trait adapter: one type per key purpose, bound
//! to one backend key, and with `VerifyMac` as well.

use crate::mac::{GenerateMac, VerifyMac};
use aws_sdk_kms::{primitives::Blob, Client};
use private::ValidMacSize;
use thiserror::Error;
use vitaminc_protected::{Controlled, Protected};

/// Errors from [`AwsMacKey`].
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    AwsSdk(#[from] aws_sdk_kms::Error),
    /// AWS KMS returned a successful `GenerateMac` response with no `Mac`
    /// field — should not happen, but the SDK models the field as optional,
    /// so this is handled rather than unwrapped.
    #[error("AWS KMS returned no MAC")]
    MissingMac,
    /// AWS KMS returned a MAC of an unexpected length. Guards the
    /// `Vec<u8>` -> `[u8; N]` conversion so a malformed or truncated
    /// response surfaces as an error rather than a panic.
    #[error("AWS KMS returned a {received}-byte MAC, expected {expected}")]
    UnexpectedMacLength { expected: usize, received: usize },
}

/// A MAC key: an adapter over an AWS KMS backend key whose purpose is MAC
/// (`KeyUsage=GENERATE_VERIFY_MAC`). `N` is the tag length in bytes, and it
/// picks the `MacAlgorithm` sent to AWS:
///
/// | `N` | algorithm |
/// |---|---|
/// | 28 | `HMAC_SHA_224` |
/// | 32 | `HMAC_SHA_256` |
/// | 48 | `HMAC_SHA_384` |
/// | 64 | `HMAC_SHA_512` |
///
/// Any other `N` does not compile: the mapping lives in a sealed trait with
/// exactly those four impls, so an unsupported tag length is a build error
/// and not a runtime `InvalidKeyUsageException`. `N` must also agree with
/// the bound key's `KeySpec`, which only AWS can check.
///
/// ```no_run
/// # use aws_sdk_kms::Client;
/// # use vitaminc_kms::aws::AwsMacKey;
/// # use vitaminc_kms::{GenerateMac, VerifyMac};
/// # use vitaminc_protected::Protected;
/// # async fn example(client: Client) -> Result<(), Box<dyn std::error::Error>> {
/// let key = AwsMacKey::<32>::new(client, "arn:aws:kms:...");
/// let message = Protected::new(b"payload".to_vec());
///
/// let mac = key.generate_mac(&message).await?;
/// assert!(key.verify_mac(&message, &mac).await?);
/// # Ok(())
/// # }
/// ```
///
/// A tag length AWS has no HMAC algorithm for does not build:
///
/// ```compile_fail
/// # use aws_sdk_kms::Client;
/// # use vitaminc_kms::aws::AwsMacKey;
/// # fn example(client: Client) {
/// let key = AwsMacKey::<31>::new(client, "arn:aws:kms:...");
/// # }
/// ```
pub struct AwsMacKey<const N: usize> {
    client: Client,
    key_id: String,
}

impl<const N: usize> AwsMacKey<N>
where
    Self: ValidMacSize<N>,
{
    /// `key_id` is the AWS KMS key ARN/ID/alias this instance is bound to —
    /// construction-time key binding, as in every adapter in this crate.
    /// The `client` is the caller's: credentials, region and endpoint are
    /// settled before it gets here.
    pub fn new(client: Client, key_id: impl Into<String>) -> Self {
        Self {
            client,
            key_id: key_id.into(),
        }
    }
}

impl<const N: usize> GenerateMac<N> for AwsMacKey<N>
where
    Self: ValidMacSize<N>,
{
    type Error = Error;

    async fn generate_mac(&self, message: &Protected<Vec<u8>>) -> Result<[u8; N], Self::Error> {
        let response = self
            .client
            .generate_mac()
            .key_id(&self.key_id)
            .mac_algorithm(Self::spec())
            .message(Blob::new(message.clone().risky_unwrap()))
            .send()
            .await
            .map_err(aws_sdk_kms::Error::from)?;

        let mac = response.mac.ok_or(Error::MissingMac)?.into_inner();
        let received = mac.len();
        mac.try_into().map_err(|_| Error::UnexpectedMacLength {
            expected: N,
            received,
        })
    }
}

impl<const N: usize> VerifyMac<N> for AwsMacKey<N>
where
    Self: ValidMacSize<N>,
{
    type Error = Error;

    /// AWS never returns `MacValid=false` — a tag that does not match
    /// raises `KMSInvalidMacException` instead. That one exception is the
    /// expected "did not verify" path and becomes `Ok(false)`; every other
    /// exception is a genuine infrastructure failure and stays an `Err`.
    async fn verify_mac(
        &self,
        message: &Protected<Vec<u8>>,
        mac: &[u8; N],
    ) -> Result<bool, Self::Error> {
        let result = self
            .client
            .verify_mac()
            .key_id(&self.key_id)
            .mac_algorithm(Self::spec())
            .message(Blob::new(message.clone().risky_unwrap()))
            .mac(Blob::new(mac.to_vec()))
            .send()
            .await;

        match result {
            Ok(response) => Ok(response.mac_valid),
            Err(error) => match aws_sdk_kms::Error::from(error) {
                aws_sdk_kms::Error::KmsInvalidMacException(_) => Ok(false),
                other => Err(Error::AwsSdk(other)),
            },
        }
    }
}

/// Seals the `N` -> `MacAlgorithmSpec` mapping: the trait cannot be named
/// outside this module, so the four impls below are the only valid tag
/// lengths and no downstream crate can add a fifth.
mod private {
    use aws_sdk_kms::types::MacAlgorithmSpec;

    pub trait ValidMacSize<const N: usize> {
        fn spec() -> MacAlgorithmSpec;
    }

    impl ValidMacSize<28> for super::AwsMacKey<28> {
        fn spec() -> MacAlgorithmSpec {
            MacAlgorithmSpec::HmacSha224
        }
    }

    impl ValidMacSize<32> for super::AwsMacKey<32> {
        fn spec() -> MacAlgorithmSpec {
            MacAlgorithmSpec::HmacSha256
        }
    }

    impl ValidMacSize<48> for super::AwsMacKey<48> {
        fn spec() -> MacAlgorithmSpec {
            MacAlgorithmSpec::HmacSha384
        }
    }

    impl ValidMacSize<64> for super::AwsMacKey<64> {
        fn spec() -> MacAlgorithmSpec {
            MacAlgorithmSpec::HmacSha512
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_kms::operation::generate_mac::GenerateMacOutput;
    use aws_sdk_kms::operation::verify_mac::{VerifyMacError, VerifyMacOutput};
    use aws_sdk_kms::types::error::KmsInvalidMacException;
    use aws_smithy_mocks::{mock, mock_client, RuleMode};

    const TEST_KEY_ID: &str = "arn:aws:kms:us-east-1:111122223333:key/test-hmac-key";

    fn message() -> Protected<Vec<u8>> {
        Protected::new(b"the message".to_vec())
    }

    #[tokio::test]
    async fn generate_mac_returns_the_tag_as_a_fixed_size_array() {
        let generate_rule = mock!(Client::generate_mac).then_output(|| {
            GenerateMacOutput::builder()
                .mac(Blob::new(vec![3u8; 32]))
                .build()
        });
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&generate_rule]);
        let key = AwsMacKey::<32>::new(client, TEST_KEY_ID);

        let mac = key.generate_mac(&message()).await.unwrap();

        assert_eq!(mac, [3u8; 32]);
        assert_eq!(generate_rule.num_calls(), 1);
    }

    #[tokio::test]
    async fn a_mac_of_the_wrong_length_is_an_error_not_a_panic() {
        let generate_rule = mock!(Client::generate_mac).then_output(|| {
            GenerateMacOutput::builder()
                .mac(Blob::new(vec![3u8; 31]))
                .build()
        });
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&generate_rule]);
        let key = AwsMacKey::<32>::new(client, TEST_KEY_ID);

        let error = key.generate_mac(&message()).await.unwrap_err();

        assert!(matches!(
            error,
            Error::UnexpectedMacLength {
                expected: 32,
                received: 31
            }
        ));
    }

    #[tokio::test]
    async fn a_response_with_no_mac_is_an_error() {
        let generate_rule =
            mock!(Client::generate_mac).then_output(|| GenerateMacOutput::builder().build());
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&generate_rule]);
        let key = AwsMacKey::<32>::new(client, TEST_KEY_ID);

        let error = key.generate_mac(&message()).await.unwrap_err();

        assert!(matches!(error, Error::MissingMac));
    }

    #[tokio::test]
    async fn verify_mac_returns_true_for_a_good_tag() {
        let verify_rule = mock!(Client::verify_mac)
            .then_output(|| VerifyMacOutput::builder().mac_valid(true).build());
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&verify_rule]);
        let key = AwsMacKey::<32>::new(client, TEST_KEY_ID);

        assert!(key.verify_mac(&message(), &[3u8; 32]).await.unwrap());
        assert_eq!(verify_rule.num_calls(), 1);
    }

    /// AWS throws rather than returning `false`; the trait promises
    /// `Ok(false)`, so the adapter absorbs exactly that one exception.
    #[tokio::test]
    async fn an_invalid_mac_exception_becomes_ok_false() {
        let verify_rule = mock!(Client::verify_mac).then_error(|| {
            VerifyMacError::KmsInvalidMacException(KmsInvalidMacException::builder().build())
        });
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&verify_rule]);
        let key = AwsMacKey::<32>::new(client, TEST_KEY_ID);

        assert!(!key.verify_mac(&message(), &[9u8; 32]).await.unwrap());
    }

    /// Every other failure is infrastructure, and must stay an `Err`.
    #[tokio::test]
    async fn any_other_exception_stays_an_error() {
        use aws_sdk_kms::types::error::NotFoundException;

        let verify_rule = mock!(Client::verify_mac)
            .then_error(|| VerifyMacError::NotFoundException(NotFoundException::builder().build()));
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&verify_rule]);
        let key = AwsMacKey::<32>::new(client, TEST_KEY_ID);

        let error = key.verify_mac(&message(), &[9u8; 32]).await.unwrap_err();

        assert!(matches!(error, Error::AwsSdk(_)));
    }

    /// Against LocalStack on `localhost:4566` — see the crate README for
    /// how to bring it up.
    mod localstack {
        use super::*;
        use crate::aws::testing::localstack_client;
        use aws_sdk_kms::types::{KeySpec, KeyUsageType};

        async fn hmac_key(client: &Client) -> String {
            let key = client
                .create_key()
                .key_usage(KeyUsageType::GenerateVerifyMac)
                .key_spec(KeySpec::Hmac256)
                .send()
                .await
                .expect("LocalStack CreateKey");

            key.key_metadata().unwrap().key_id().to_owned()
        }

        #[tokio::test]
        async fn generate_then_verify_round_trip() {
            let client = localstack_client();
            let key_id = hmac_key(&client).await;
            let key = AwsMacKey::<32>::new(client, key_id);

            let mac = key.generate_mac(&message()).await.unwrap();

            assert!(key.verify_mac(&message(), &mac).await.unwrap());
        }

        #[tokio::test]
        async fn a_tampered_tag_verifies_as_false_not_as_an_error() {
            let client = localstack_client();
            let key_id = hmac_key(&client).await;
            let key = AwsMacKey::<32>::new(client, key_id);

            let mut mac = key.generate_mac(&message()).await.unwrap();
            mac[0] ^= 0xff;

            assert!(!key.verify_mac(&message(), &mac).await.unwrap());
        }

        #[tokio::test]
        async fn a_tag_over_a_different_message_verifies_as_false() {
            let client = localstack_client();
            let key_id = hmac_key(&client).await;
            let key = AwsMacKey::<32>::new(client, key_id);

            let mac = key.generate_mac(&message()).await.unwrap();
            let other = Protected::new(b"a different message".to_vec());

            assert!(!key.verify_mac(&other, &mac).await.unwrap());
        }
    }
}
