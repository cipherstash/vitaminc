use crate::data_key::{
    dedup_retrieve, fan_out_generate, pooled_key_generate, BatchGenerateDataKey,
    BatchRetrieveDataKey, GenerateDataKey, GeneratedDataKey, KeyIsolation, KeyReconstruction,
    RetrieveDataKey,
};
use crate::key_id::KeyId;
use aws_sdk_kms::{primitives::Blob, Client};
use thiserror::Error;
use vitaminc_protected::Protected;

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

fn into_sized<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], Error> {
    let received = bytes.len();
    bytes
        .try_into()
        .map_err(|_| Error::UnexpectedKeyLength { expected: N, received })
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
        let ciphertext_blob = response.ciphertext_blob.ok_or(Error::MissingCiphertextBlob)?;

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

impl<const N: usize> BatchGenerateDataKey<N> for AwsDataKeySource<N> {
    const ISOLATION: KeyIsolation = KeyIsolation::PerValue;

    async fn generate_data_keys(&self, count: usize) -> Result<Vec<GeneratedDataKey<N>>, Self::Error> {
        fan_out_generate(self, count).await
    }
}

impl<const N: usize> BatchRetrieveDataKey<N> for AwsDataKeySource<N> {
    async fn retrieve_data_keys(&self, key_ids: &[KeyId]) -> Result<Vec<Protected<[u8; N]>>, Self::Error> {
        dedup_retrieve(self, key_ids).await
    }
}

/// AWS KMS-backed data key source with pooled key isolation
/// (`KeyIsolation::Pooled`) — one key shared across the whole batch, via
/// [`pooled_key_generate`]. One round trip per batch regardless of size,
/// at the cost of weaker per-value isolation than [`AwsDataKeySource`] —
/// a compromised key's blast radius is the whole batch, not one value.
/// Opt in deliberately; this type exists so that choice is explicit and
/// visible in code, never a silent default. See CIP-4030.
pub struct AwsPooledDataKeySource<const N: usize>(AwsDataKeySource<N>);

impl<const N: usize> AwsPooledDataKeySource<N> {
    pub fn new(client: Client, key_id: impl Into<String>) -> Self {
        Self(AwsDataKeySource::new(client, key_id))
    }
}

impl<const N: usize> GenerateDataKey<N> for AwsPooledDataKeySource<N> {
    type Error = Error;

    async fn generate_data_key(&self) -> Result<GeneratedDataKey<N>, Self::Error> {
        self.0.generate_data_key().await
    }
}

impl<const N: usize> RetrieveDataKey<N> for AwsPooledDataKeySource<N> {
    type Error = Error;

    const RECONSTRUCTION: KeyReconstruction = KeyReconstruction::ServerOnly;

    async fn retrieve_data_key(&self, key_id: &KeyId) -> Result<Protected<[u8; N]>, Self::Error> {
        self.0.retrieve_data_key(key_id).await
    }
}

impl<const N: usize> BatchGenerateDataKey<N> for AwsPooledDataKeySource<N> {
    const ISOLATION: KeyIsolation = KeyIsolation::Pooled;

    async fn generate_data_keys(&self, count: usize) -> Result<Vec<GeneratedDataKey<N>>, Self::Error> {
        pooled_key_generate(&self.0, count).await
    }
}

impl<const N: usize> BatchRetrieveDataKey<N> for AwsPooledDataKeySource<N> {
    async fn retrieve_data_keys(&self, key_ids: &[KeyId]) -> Result<Vec<Protected<[u8; N]>>, Self::Error> {
        // Retrieve doesn't need its own pooled/non-pooled split — it just
        // needs to be correct given whatever generate already decided
        // upstream (CIP-3987/CIP-3988). Dedup degrades gracefully to a
        // single retrieve when every id is identical, as it will be here.
        dedup_retrieve(&self.0, key_ids).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_kms::operation::decrypt::DecryptOutput;
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
        let source = AwsPooledDataKeySource::<32>::new(client, TEST_KEY_ID);

        let keys = source.generate_data_keys(5).await.unwrap();

        assert_eq!(keys.len(), 5);
        assert_eq!(generate_rule.num_calls(), 1);
        assert_eq!(
            AwsPooledDataKeySource::<32>::ISOLATION,
            KeyIsolation::Pooled
        );
    }
}
