use crate::crypt::{DecryptWithKey, EncryptWithKey};
use crate::data_key::{
    dedup_retrieve, fan_out_generate, BatchGenerateDataKey, BatchRetrieveDataKey, GenerateDataKey,
    GeneratedDataKey, KeyIsolation, KeyReconstruction, RetrieveDataKey,
};
use crate::key_id::KeyId;
use crate::pooled::PooledDataKeySource;
use aws_sdk_kms::{primitives::Blob, Client};
use thiserror::Error;
use vitaminc_protected::{Controlled, Protected};

/// Errors from an AWS KMS-backed Group 2 adapter.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    AwsSdk(#[from] aws_sdk_kms::Error),
    /// AWS KMS returned a response with no plaintext field — should not
    /// happen for a successful `GenerateDataKey`/`Decrypt` call, but the
    /// SDK models the field as optional, so this is handled rather than
    /// unwrapped.
    #[error("AWS KMS returned no plaintext")]
    MissingPlaintext,
    /// AWS KMS returned a response with no ciphertext blob field — should
    /// not happen for a successful `GenerateDataKey` call.
    #[error("AWS KMS returned no ciphertext blob")]
    MissingCiphertextBlob,
    /// AWS KMS returned key material of an unexpected length. Guards the
    /// `Vec<u8>` -> `[u8; N]` conversion so a malformed/truncated response
    /// surfaces as an error rather than a panic.
    #[error("AWS KMS returned {received} bytes of key material, expected {expected}")]
    UnexpectedKeyLength { expected: usize, received: usize },
}

// `aws_sdk_kms::Error` is large and we re-export it as-is through our own
// `Error`, so shrinking it would mean boxing a public variant. Not worth a
// breaking change for an error on a network round-trip.
#[allow(clippy::result_large_err)]
fn into_sized<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], Error> {
    crate::data_key::into_sized(bytes, |expected, received| Error::UnexpectedKeyLength {
        expected,
        received,
    })
}

/// AWS KMS-backed data key source with per-value key isolation
/// (`KeyIsolation::PerValue`) — one distinct key per item, via
/// [`fan_out_generate`]. AWS KMS has no native batch primitive for
/// `GenerateDataKey`/`Decrypt` (one operation per network call); this is
/// the N-round-trips option that preserves the same per-value isolation
/// property ZeroKMS already provides. See CIP-4030.
pub struct AwsDataKeySource<const N: usize> {
    client: Client,
    key_id: String,
}

impl<const N: usize> AwsDataKeySource<N> {
    /// `key_id` is the AWS KMS key ARN/ID/alias this instance is bound to
    /// — construction-time key binding, per CIP-3986's convention.
    pub fn new(client: Client, key_id: impl Into<String>) -> Self {
        Self {
            client,
            key_id: key_id.into(),
        }
    }
}

impl<const N: usize> GenerateDataKey<N> for AwsDataKeySource<N> {
    type Error = Error;

    async fn generate_data_key(&self) -> Result<GeneratedDataKey<N>, Self::Error> {
        let response = self
            .client
            .generate_data_key()
            .key_id(&self.key_id)
            .number_of_bytes(N as i32)
            .send()
            .await
            .map_err(aws_sdk_kms::Error::from)?;

        let plaintext = response.plaintext.ok_or(Error::MissingPlaintext)?;
        let ciphertext_blob = response
            .ciphertext_blob
            .ok_or(Error::MissingCiphertextBlob)?;

        Ok(GeneratedDataKey {
            plaintext: Protected::new(into_sized(plaintext.into_inner())?),
            key_id: KeyId::new(ciphertext_blob.into_inner()),
        })
    }
}

impl<const N: usize> RetrieveDataKey<N> for AwsDataKeySource<N> {
    type Error = Error;

    /// AWS KMS reconstructs a data key from server-side material alone —
    /// the `CiphertextBlob` plus IAM/key-policy authorization is
    /// sufficient, unlike ZeroKMS's client+server scheme.
    const RECONSTRUCTION: KeyReconstruction = KeyReconstruction::ServerOnly;

    async fn retrieve_data_key(&self, key_id: &KeyId) -> Result<Protected<[u8; N]>, Self::Error> {
        let response = self
            .client
            .decrypt()
            .ciphertext_blob(Blob::new(key_id.as_bytes().to_vec()))
            .key_id(&self.key_id)
            .send()
            .await
            .map_err(aws_sdk_kms::Error::from)?;

        let plaintext = response.plaintext.ok_or(Error::MissingPlaintext)?;
        Ok(Protected::new(into_sized(plaintext.into_inner())?))
    }
}

/// Direct encryption under the bound symmetric key — the `Encrypt`
/// operation, not envelope encryption. No encryption context is sent, so
/// the ciphertext is decryptable by [`DecryptWithKey`] below (and by any
/// other caller authorized on the same backend key) with no extra state to
/// carry alongside it.
///
/// AWS caps the plaintext at 4096 bytes for a `SYMMETRIC_DEFAULT` key. The
/// adapter does not pre-check that: the limit is a property of the backend
/// key's spec, not of the adapter, so it is surfaced as the SDK's own
/// error rather than duplicated (and risked going stale) here.
impl<const N: usize> EncryptWithKey for AwsDataKeySource<N> {
    type Error = Error;

    async fn encrypt(&self, plaintext: Protected<Vec<u8>>) -> Result<Vec<u8>, Self::Error> {
        let response = self
            .client
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(Blob::new(plaintext.risky_unwrap()))
            .send()
            .await
            .map_err(aws_sdk_kms::Error::from)?;

        let ciphertext_blob = response
            .ciphertext_blob
            .ok_or(Error::MissingCiphertextBlob)?;
        Ok(ciphertext_blob.into_inner())
    }
}

/// The inverse of the [`EncryptWithKey`] impl above. The `ciphertext` is
/// the AWS `CiphertextBlob` passed straight through — this adapter adds no
/// framing of its own, so a blob produced by any `Encrypt` call under the
/// same backend key decrypts here.
impl<const N: usize> DecryptWithKey for AwsDataKeySource<N> {
    type Error = Error;

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Protected<Vec<u8>>, Self::Error> {
        let response = self
            .client
            .decrypt()
            .ciphertext_blob(Blob::new(ciphertext.to_vec()))
            .key_id(&self.key_id)
            .send()
            .await
            .map_err(aws_sdk_kms::Error::from)?;

        let plaintext = response.plaintext.ok_or(Error::MissingPlaintext)?;
        Ok(Protected::new(plaintext.into_inner()))
    }
}

impl<const N: usize> BatchGenerateDataKey<N> for AwsDataKeySource<N> {
    const ISOLATION: KeyIsolation = KeyIsolation::PerValue;

    async fn generate_data_keys(
        &self,
        count: usize,
    ) -> Result<Vec<GeneratedDataKey<N>>, Self::Error> {
        fan_out_generate(self, count).await
    }
}

impl<const N: usize> BatchRetrieveDataKey<N> for AwsDataKeySource<N> {
    async fn retrieve_data_keys(
        &self,
        key_ids: &[KeyId],
    ) -> Result<Vec<Protected<[u8; N]>>, Self::Error> {
        dedup_retrieve(self, key_ids).await
    }
}

/// [`AwsDataKeySource`] with pooled key isolation (`KeyIsolation::Pooled`):
/// one key shared across the whole batch, one round trip per batch. Build
/// it as `PooledDataKeySource::new(AwsDataKeySource::new(client, key_id))`.
/// See [`PooledDataKeySource`] for the trade-off; opt in deliberately.
pub type AwsPooledDataKeySource<const N: usize> = PooledDataKeySource<AwsDataKeySource<N>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypt::{DecryptWithKey, EncryptWithKey};
    use aws_sdk_kms::operation::decrypt::DecryptOutput;
    use aws_sdk_kms::operation::encrypt::EncryptOutput;
    use aws_sdk_kms::operation::generate_data_key::GenerateDataKeyOutput;
    use aws_smithy_mocks::{mock, mock_client, RuleMode};
    use vitaminc_protected::Controlled;

    const TEST_KEY_ID: &str = "arn:aws:kms:us-east-1:111122223333:key/test-key";

    fn fixed_plaintext() -> [u8; 32] {
        [7u8; 32]
    }

    fn fixed_ciphertext_blob() -> Vec<u8> {
        vec![9u8; 64]
    }

    #[tokio::test]
    async fn generate_then_retrieve_round_trips() {
        let generate_rule = mock!(Client::generate_data_key).then_output(|| {
            GenerateDataKeyOutput::builder()
                .plaintext(Blob::new(fixed_plaintext().to_vec()))
                .ciphertext_blob(Blob::new(fixed_ciphertext_blob()))
                .key_id(TEST_KEY_ID)
                .build()
        });
        let decrypt_rule = mock!(Client::decrypt).then_output(|| {
            DecryptOutput::builder()
                .plaintext(Blob::new(fixed_plaintext().to_vec()))
                .key_id(TEST_KEY_ID)
                .build()
        });
        let client = mock_client!(
            aws_sdk_kms,
            RuleMode::MatchAny,
            &[&generate_rule, &decrypt_rule]
        );

        let source = AwsDataKeySource::<32>::new(client, TEST_KEY_ID);

        let generated = source.generate_data_key().await.unwrap();
        assert_eq!(generated.key_id.as_bytes(), fixed_ciphertext_blob());

        let retrieved = source.retrieve_data_key(&generated.key_id).await.unwrap();
        assert_eq!(retrieved.risky_unwrap(), fixed_plaintext());

        assert_eq!(generate_rule.num_calls(), 1);
        assert_eq!(decrypt_rule.num_calls(), 1);
    }

    #[tokio::test]
    async fn per_value_batch_generate_makes_one_call_per_item() {
        let generate_rule = mock!(Client::generate_data_key).then_output(|| {
            GenerateDataKeyOutput::builder()
                .plaintext(Blob::new(fixed_plaintext().to_vec()))
                .ciphertext_blob(Blob::new(fixed_ciphertext_blob()))
                .key_id(TEST_KEY_ID)
                .build()
        });
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&generate_rule]);
        let source = AwsDataKeySource::<32>::new(client, TEST_KEY_ID);

        let keys = source.generate_data_keys(3).await.unwrap();

        assert_eq!(keys.len(), 3);
        assert_eq!(generate_rule.num_calls(), 3);
        assert_eq!(AwsDataKeySource::<32>::ISOLATION, KeyIsolation::PerValue);
    }

    #[tokio::test]
    async fn pooled_batch_generate_makes_one_call_for_the_whole_batch() {
        let generate_rule = mock!(Client::generate_data_key).then_output(|| {
            GenerateDataKeyOutput::builder()
                .plaintext(Blob::new(fixed_plaintext().to_vec()))
                .ciphertext_blob(Blob::new(fixed_ciphertext_blob()))
                .key_id(TEST_KEY_ID)
                .build()
        });
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&generate_rule]);
        let source: AwsPooledDataKeySource<32> =
            PooledDataKeySource::new(AwsDataKeySource::new(client, TEST_KEY_ID));

        let keys = source.generate_data_keys(5).await.unwrap();

        assert_eq!(keys.len(), 5);
        assert_eq!(generate_rule.num_calls(), 1);
        assert_eq!(
            <AwsPooledDataKeySource<32> as BatchGenerateDataKey<32>>::ISOLATION,
            KeyIsolation::Pooled
        );
    }

    #[tokio::test]
    async fn encrypt_then_decrypt_round_trips_the_ciphertext_blob() {
        let plaintext = b"a short secret".to_vec();
        let encrypt_rule = mock!(Client::encrypt).then_output(|| {
            EncryptOutput::builder()
                .ciphertext_blob(Blob::new(fixed_ciphertext_blob()))
                .key_id(TEST_KEY_ID)
                .build()
        });
        let decrypt_rule = mock!(Client::decrypt).then_output(|| {
            DecryptOutput::builder()
                .plaintext(Blob::new(b"a short secret".to_vec()))
                .key_id(TEST_KEY_ID)
                .build()
        });
        let client = mock_client!(
            aws_sdk_kms,
            RuleMode::MatchAny,
            &[&encrypt_rule, &decrypt_rule]
        );
        let source = AwsDataKeySource::<32>::new(client, TEST_KEY_ID);

        let ciphertext = source
            .encrypt(Protected::new(plaintext.clone()))
            .await
            .unwrap();
        assert_eq!(ciphertext, fixed_ciphertext_blob());

        let recovered = source.decrypt(&ciphertext).await.unwrap();
        assert_eq!(recovered.risky_unwrap(), plaintext);

        assert_eq!(encrypt_rule.num_calls(), 1);
        assert_eq!(decrypt_rule.num_calls(), 1);
    }

    #[tokio::test]
    async fn encrypt_without_a_ciphertext_blob_is_an_error() {
        let encrypt_rule = mock!(Client::encrypt)
            .then_output(|| EncryptOutput::builder().key_id(TEST_KEY_ID).build());
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&encrypt_rule]);
        let source = AwsDataKeySource::<32>::new(client, TEST_KEY_ID);

        let error = source
            .encrypt(Protected::new(vec![1, 2, 3]))
            .await
            .unwrap_err();

        assert!(matches!(error, Error::MissingCiphertextBlob));
    }

    #[tokio::test]
    async fn decrypt_without_a_plaintext_is_an_error() {
        let decrypt_rule = mock!(Client::decrypt)
            .then_output(|| DecryptOutput::builder().key_id(TEST_KEY_ID).build());
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&decrypt_rule]);
        let source = AwsDataKeySource::<32>::new(client, TEST_KEY_ID);

        let error = source.decrypt(&fixed_ciphertext_blob()).await.unwrap_err();

        assert!(matches!(error, Error::MissingPlaintext));
    }

    /// Against LocalStack on `localhost:4566` — see the crate README for
    /// how to bring it up.
    mod localstack {
        use super::*;
        use crate::aws::testing::localstack_client;
        use aws_sdk_kms::types::{KeySpec, KeyUsageType};

        async fn encrypt_decrypt_key(client: &Client) -> String {
            let key = client
                .create_key()
                .key_usage(KeyUsageType::EncryptDecrypt)
                .key_spec(KeySpec::SymmetricDefault)
                .send()
                .await
                .expect("LocalStack CreateKey");

            key.key_metadata().unwrap().key_id().to_owned()
        }

        #[tokio::test]
        async fn data_key_generate_and_retrieve_round_trip() {
            let client = localstack_client();
            let key_id = encrypt_decrypt_key(&client).await;
            let source = AwsDataKeySource::<32>::new(client, key_id);

            let generated = source.generate_data_key().await.unwrap();
            let retrieved = source.retrieve_data_key(&generated.key_id).await.unwrap();

            assert_eq!(retrieved.risky_unwrap(), generated.plaintext.risky_unwrap());
        }

        #[tokio::test]
        async fn direct_encrypt_and_decrypt_round_trip() {
            let client = localstack_client();
            let key_id = encrypt_decrypt_key(&client).await;
            let source = AwsDataKeySource::<32>::new(client, key_id);
            let plaintext = b"small enough to encrypt directly".to_vec();

            let ciphertext = source
                .encrypt(Protected::new(plaintext.clone()))
                .await
                .unwrap();
            assert_ne!(ciphertext, plaintext);

            let recovered = source.decrypt(&ciphertext).await.unwrap();

            assert_eq!(recovered.risky_unwrap(), plaintext);
        }
    }
}
