use crate::crypt::{DecryptWithKey, EncryptWithKey};
use crate::data_key::{
    dedup_retrieve, fan_out_generate, BatchGenerateDataKey, BatchRetrieveDataKey, Binding,
    GenerateDataKey, GeneratedDataKey, KeyCustody, KeyReconstruction, RetrieveDataKey,
    DEFAULT_MAX_IN_FLIGHT,
};
use crate::key_id::KeyId;
use aws_sdk_kms::{primitives::Blob, Client};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use thiserror::Error;
use vitaminc_protected::{Controlled, Protected};

/// Errors from the AWS KMS data key source.
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

/// AWS KMS-backed data key source with per-value key isolation — one
/// distinct key per item, via
/// [`fan_out_generate`]. AWS KMS has no native batch primitive for
/// `GenerateDataKey`/`Decrypt` (one operation per network call); this is
/// the N-round-trips option that preserves the same per-value isolation
/// property ZeroKMS already provides. See CIP-4030.
pub struct AwsDataKeySource<const N: usize> {
    client: Client,
    key_id: String,
    max_in_flight: NonZeroUsize,
}

impl<const N: usize> AwsDataKeySource<N> {
    /// `key_id` is the AWS KMS key ARN/ID/alias this instance is bound to
    /// — construction-time key binding, per CIP-3986's convention.
    pub fn new(client: Client, key_id: impl Into<String>) -> Self {
        Self {
            client,
            key_id: key_id.into(),
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
        }
    }

    /// Sets how many requests a batch keeps in flight at one time. The
    /// default is [`DEFAULT_MAX_IN_FLIGHT`]. Set a lower value when the
    /// key's request quota or the client's connection pool is small.
    #[must_use]
    pub fn with_max_in_flight(mut self, max_in_flight: NonZeroUsize) -> Self {
        self.max_in_flight = max_in_flight;
        self
    }
}

/// The `EncryptionContext` entry a non-empty [`Binding`] becomes.
///
/// AWS requires printable string keys and values, and a binding is
/// arbitrary bytes, so the bytes are base64 (standard, padded). One fixed
/// key holds them: AWS matches the context as a whole map, so a single
/// entry under a name nothing else uses cannot collide with a context the
/// caller sets elsewhere on the same key.
///
/// An **empty** binding is no entry under this key, not an entry with an
/// empty value. The [`USE_CONTEXT_KEY`] entry still makes the context of a
/// data key under `Binding::EMPTY` differ from that of direct encryption.
const BINDING_CONTEXT_KEY: &str = "vitaminc:binding";

/// The `EncryptionContext` entry that names the use of a ciphertext, on
/// every call this source makes.
///
/// A data key and a direct ciphertext are both a `CiphertextBlob` under the
/// same KMS key, and AWS opens a blob only under the context it was sealed
/// with. A data key sends [`DATA_KEY_USE`] here, direct encryption sends
/// [`DIRECT_ENCRYPTION_USE`], and AWS matches the whole map, so neither use
/// opens the other's ciphertexts (ADR 0006). Without it, a data key under
/// `Binding::EMPTY` (an index key, for example) and a direct ciphertext had
/// the same, empty context, and `decrypt` opened the index key.
///
/// An `EncryptionContext` is not secret: AWS writes it to CloudTrail in
/// plaintext. This entry tells a reader only which of the two uses a call
/// was.
const USE_CONTEXT_KEY: &str = "vitaminc:use";

/// The [`USE_CONTEXT_KEY`] value of every data-key call.
const DATA_KEY_USE: &str = "data-key";

/// The [`USE_CONTEXT_KEY`] value of every direct `Encrypt` and `Decrypt`.
const DIRECT_ENCRYPTION_USE: &str = "encrypt-with-key";

/// The whole `EncryptionContext` of a data key under `binding`: the use
/// entry always, and the binding entry when the binding is not empty.
fn data_key_context(binding: Binding<'_>) -> HashMap<String, String> {
    use base64::Engine as _;
    let mut context = HashMap::from([(USE_CONTEXT_KEY.to_owned(), DATA_KEY_USE.to_owned())]);
    let bytes = binding.as_bytes();
    if !bytes.is_empty() {
        context.insert(
            BINDING_CONTEXT_KEY.to_owned(),
            base64::engine::general_purpose::STANDARD.encode(bytes),
        );
    }
    context
}

/// The whole `EncryptionContext` of a direct `Encrypt` or `Decrypt`.
fn direct_encryption_context() -> HashMap<String, String> {
    HashMap::from([(USE_CONTEXT_KEY.to_owned(), DIRECT_ENCRYPTION_USE.to_owned())])
}

impl<const N: usize> GenerateDataKey<N> for AwsDataKeySource<N> {
    type Error = Error;

    async fn generate_data_key(
        &self,
        binding: Binding<'_>,
    ) -> Result<GeneratedDataKey<N>, Self::Error> {
        let response = self
            .client
            .generate_data_key()
            .key_id(&self.key_id)
            .number_of_bytes(N as i32)
            .set_encryption_context(Some(data_key_context(binding)))
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

    /// The `CiphertextBlob` this source returns is the data key wrapped
    /// under the CMK. KMS keeps no copy of the data key, so that blob is the
    /// only one.
    const CUSTODY: KeyCustody = KeyCustody::ClientHeld;

    /// AWS KMS binds the `EncryptionContext` into the data key and refuses a
    /// `Decrypt` that presents a different one. The context names the use
    /// as well as the binding, so a direct ciphertext does not open here.
    async fn retrieve_data_key(
        &self,
        key_id: &KeyId,
        binding: Binding<'_>,
    ) -> Result<Protected<[u8; N]>, Self::Error> {
        let response = self
            .client
            .decrypt()
            .ciphertext_blob(Blob::new(key_id.as_bytes().to_vec()))
            .key_id(&self.key_id)
            .set_encryption_context(Some(data_key_context(binding)))
            .send()
            .await
            .map_err(aws_sdk_kms::Error::from)?;

        let plaintext = response.plaintext.ok_or(Error::MissingPlaintext)?;
        Ok(Protected::new(into_sized(plaintext.into_inner())?))
    }
}

/// Direct encryption under the bound symmetric key — the `Encrypt`
/// operation, not envelope encryption. The one fixed `EncryptionContext`
/// `{"vitaminc:use": "encrypt-with-key"}` is sent, so the ciphertext is
/// decryptable by [`DecryptWithKey`] below with no extra state to carry
/// alongside it. This context differs from that of every data key, so the
/// ciphertext never opens as a data key, and a data key never opens through
/// [`DecryptWithKey`] (ADR 0006).
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
            .set_encryption_context(Some(direct_encryption_context()))
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
/// same backend key and the same `EncryptionContext` decrypts here.
impl<const N: usize> DecryptWithKey for AwsDataKeySource<N> {
    type Error = Error;

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Protected<Vec<u8>>, Self::Error> {
        let response = self
            .client
            .decrypt()
            .ciphertext_blob(Blob::new(ciphertext.to_vec()))
            .key_id(&self.key_id)
            .set_encryption_context(Some(direct_encryption_context()))
            .send()
            .await
            .map_err(aws_sdk_kms::Error::from)?;

        let plaintext = response.plaintext.ok_or(Error::MissingPlaintext)?;
        Ok(Protected::new(plaintext.into_inner()))
    }
}

impl<const N: usize> BatchGenerateDataKey<N> for AwsDataKeySource<N> {
    async fn generate_data_keys(
        &self,
        bindings: &[Binding<'_>],
    ) -> Result<Vec<GeneratedDataKey<N>>, Self::Error> {
        fan_out_generate(self, bindings, self.max_in_flight).await
    }
}

impl<const N: usize> BatchRetrieveDataKey<N> for AwsDataKeySource<N> {
    async fn retrieve_data_keys(
        &self,
        keys: &[(KeyId, Binding<'_>)],
    ) -> Result<Vec<Protected<[u8; N]>>, Self::Error> {
        dedup_retrieve(self, keys, self.max_in_flight).await
    }
}

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

    /// The key id this source returns is the data key in wrapped form,
    /// not a reference the backend can resolve: losing it loses the key.
    #[test]
    fn the_key_id_is_the_wrapped_key() {
        assert_eq!(
            <AwsDataKeySource<32> as RetrieveDataKey<32>>::CUSTODY,
            KeyCustody::ClientHeld
        );
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

        let generated = source.generate_data_key(Binding::EMPTY).await.unwrap();
        assert_eq!(generated.key_id.as_bytes(), fixed_ciphertext_blob());

        let retrieved = source
            .retrieve_data_key(&generated.key_id, Binding::EMPTY)
            .await
            .unwrap();
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

        let keys = source
            .generate_data_keys(&[Binding::EMPTY; 3])
            .await
            .unwrap();

        assert_eq!(keys.len(), 3);
        assert_eq!(generate_rule.num_calls(), 3);
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

    #[tokio::test]
    async fn batch_retrieve_returns_each_key_ids_own_material_and_dedupes() {
        let one = mock!(Client::decrypt)
            .match_requests(|input| {
                input.ciphertext_blob().unwrap().as_ref() == b"blob-one".as_slice()
            })
            .then_output(|| {
                DecryptOutput::builder()
                    .plaintext(Blob::new(vec![1u8; 32]))
                    .key_id(TEST_KEY_ID)
                    .build()
            });
        let two = mock!(Client::decrypt)
            .match_requests(|input| {
                input.ciphertext_blob().unwrap().as_ref() == b"blob-two".as_slice()
            })
            .then_output(|| {
                DecryptOutput::builder()
                    .plaintext(Blob::new(vec![2u8; 32]))
                    .key_id(TEST_KEY_ID)
                    .build()
            });
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&one, &two]);
        let source = AwsDataKeySource::<32>::new(client, TEST_KEY_ID);

        let ids = [
            KeyId::new(b"blob-one".to_vec()),
            KeyId::new(b"blob-two".to_vec()),
            KeyId::new(b"blob-one".to_vec()),
        ];
        let keys = source
            .retrieve_data_keys(&crate::data_key::with_empty_binding(&ids))
            .await
            .unwrap();

        // One slot per id, each holding the material that id decrypts to.
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].clone().risky_unwrap(), [1u8; 32]);
        assert_eq!(keys[1].clone().risky_unwrap(), [2u8; 32]);
        assert_eq!(keys[2].clone().risky_unwrap(), [1u8; 32]);
        // The repeated id costs no second round trip.
        assert_eq!(one.num_calls(), 1);
        assert_eq!(two.num_calls(), 1);
    }

    #[tokio::test]
    async fn key_provider_generate_mints_one_key_per_binding() {
        use crate::provider::{Binding, KeyProvider};

        let generate_rule = mock!(Client::generate_data_key).then_output(|| {
            GenerateDataKeyOutput::builder()
                .plaintext(Blob::new(fixed_plaintext().to_vec()))
                .ciphertext_blob(Blob::new(fixed_ciphertext_blob()))
                .key_id(TEST_KEY_ID)
                .build()
        });
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&generate_rule]);
        let per_value = AwsDataKeySource::<32>::new(client, TEST_KEY_ID);
        let bindings = [
            Binding::from("users/email"),
            Binding::from("users/age"),
            Binding::from("users/name"),
        ];

        // Per-value isolation: one round trip per binding.
        let keys = per_value.generate_keys(&bindings).await.unwrap();
        assert_eq!(keys.len(), 3);
        assert_eq!(generate_rule.num_calls(), 3);
    }

    #[tokio::test]
    async fn key_provider_retrieve_returns_keys_in_request_order() {
        use crate::provider::{Binding, KeyProvider};

        let one = mock!(Client::decrypt)
            .match_requests(|input| {
                input.ciphertext_blob().unwrap().as_ref() == b"blob-one".as_slice()
            })
            .then_output(|| {
                DecryptOutput::builder()
                    .plaintext(Blob::new(vec![1u8; 32]))
                    .key_id(TEST_KEY_ID)
                    .build()
            });
        let two = mock!(Client::decrypt)
            .match_requests(|input| {
                input.ciphertext_blob().unwrap().as_ref() == b"blob-two".as_slice()
            })
            .then_output(|| {
                DecryptOutput::builder()
                    .plaintext(Blob::new(vec![2u8; 32]))
                    .key_id(TEST_KEY_ID)
                    .build()
            });
        let client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, &[&one, &two]);
        let source = AwsDataKeySource::<32>::new(client, TEST_KEY_ID);

        let requests = [
            (
                KeyId::new(b"blob-two".to_vec()),
                Binding::from("users/email"),
            ),
            (KeyId::new(b"blob-one".to_vec()), Binding::from("users/age")),
            // A source dedupes on the id and the binding together, so
            // the repeat names the same binding to be one call.
            (
                KeyId::new(b"blob-two".to_vec()),
                Binding::from("users/email"),
            ),
        ];
        let keys = source.retrieve_keys(&requests).await.unwrap();

        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].clone().risky_unwrap(), [2u8; 32]);
        assert_eq!(keys[1].clone().risky_unwrap(), [1u8; 32]);
        assert_eq!(keys[2].clone().risky_unwrap(), [2u8; 32]);
        assert_eq!(one.num_calls(), 1);
        assert_eq!(two.num_calls(), 1);
    }

    /// AWS refuses a `CiphertextBlob` from a different KMS key only when the
    /// `Decrypt` request names the expected key in `KeyId` (CIP-5029).
    /// Without it, AWS opens the blob under the key the blob itself names,
    /// and this source would accept a data key or a direct ciphertext that
    /// another key sealed. The rules match only a request with the bound
    /// key id, so a call count of one each is the assertion.
    #[tokio::test]
    async fn every_decrypt_names_the_bound_key() {
        let retrieve_rule = mock!(Client::decrypt)
            .match_requests(|input| {
                input.key_id() == Some(TEST_KEY_ID)
                    && input.ciphertext_blob().unwrap().as_ref() == b"data-key-blob".as_slice()
            })
            .then_output(|| {
                DecryptOutput::builder()
                    .plaintext(Blob::new(fixed_plaintext().to_vec()))
                    .key_id(TEST_KEY_ID)
                    .build()
            });
        let direct_rule = mock!(Client::decrypt)
            .match_requests(|input| {
                input.key_id() == Some(TEST_KEY_ID)
                    && input.ciphertext_blob().unwrap().as_ref() == b"direct-blob".as_slice()
            })
            .then_output(|| {
                DecryptOutput::builder()
                    .plaintext(Blob::new(b"a short secret".to_vec()))
                    .key_id(TEST_KEY_ID)
                    .build()
            });
        let client = mock_client!(
            aws_sdk_kms,
            RuleMode::MatchAny,
            &[&retrieve_rule, &direct_rule]
        );
        let source = AwsDataKeySource::<32>::new(client, TEST_KEY_ID);

        let _ = source
            .retrieve_data_key(&KeyId::new(b"data-key-blob".to_vec()), Binding::EMPTY)
            .await
            .unwrap();
        let _ = source.decrypt(b"direct-blob").await.unwrap();

        assert_eq!(retrieve_rule.num_calls(), 1);
        assert_eq!(direct_rule.num_calls(), 1);
    }

    /// A generate rule and a decrypt rule for one binding. Each matches only
    /// its own exact `EncryptionContext`, and the decrypt rule also matches
    /// only its own `blob`. The rules return `material` as the key, so the
    /// caller can see which rule served each slot.
    fn rules_for_binding(
        binding: &'static [u8],
        blob: &'static [u8],
        material: u8,
    ) -> (aws_smithy_mocks::Rule, aws_smithy_mocks::Rule) {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(binding);
        let expected = context_of(&[("vitaminc:use", "data-key"), ("vitaminc:binding", &encoded)]);
        let sent = expected.clone();
        let generate_rule = mock!(Client::generate_data_key)
            .match_requests(move |req| req.encryption_context() == Some(&sent))
            .then_output(move || {
                GenerateDataKeyOutput::builder()
                    .plaintext(Blob::new(vec![material; 32]))
                    .ciphertext_blob(Blob::new(blob.to_vec()))
                    .key_id(TEST_KEY_ID)
                    .build()
            });
        let decrypt_rule = mock!(Client::decrypt)
            .match_requests(move |req| {
                req.encryption_context() == Some(&expected)
                    && req.ciphertext_blob().unwrap().as_ref() == blob
            })
            .then_output(move || {
                DecryptOutput::builder()
                    .plaintext(Blob::new(vec![material; 32]))
                    .key_id(TEST_KEY_ID)
                    .build()
            });
        (generate_rule, decrypt_rule)
    }

    /// Each binding given to [`KeyProvider`](crate::provider::KeyProvider)
    /// reaches its own request, in order (CIP-5039). The `KeyProvider` impl
    /// comes from a macro that forwards to the batch traits. The other tests
    /// with a non-empty binding call the batch traits directly, so they do
    /// not see a macro that drops, reorders or swaps the bindings. Two
    /// different bindings make a swap visible: on generate, slot 0 holds the
    /// key of the second rule; on retrieve, an id arrives with the other
    /// binding and no rule matches.
    #[tokio::test]
    async fn key_provider_sends_each_binding_with_its_own_request() {
        use crate::provider::KeyProvider;

        let (generate_email, decrypt_email) = rules_for_binding(b"users/email", b"blob-email", 1);
        let (generate_age, decrypt_age) = rules_for_binding(b"users/age", b"blob-age", 2);
        let client = mock_client!(
            aws_sdk_kms,
            RuleMode::MatchAny,
            &[&generate_email, &decrypt_email, &generate_age, &decrypt_age]
        );
        let source = AwsDataKeySource::<32>::new(client, TEST_KEY_ID);
        let email = Binding::from("users/email");
        let age = Binding::from("users/age");

        let generated = KeyProvider::generate_keys(&source, &[email, age])
            .await
            .unwrap();

        assert_eq!(generated.len(), 2);
        assert_eq!(generated[0].key_id.as_bytes(), b"blob-email");
        assert_eq!(generated[0].plaintext.clone().risky_unwrap(), [1u8; 32]);
        assert_eq!(generated[1].key_id.as_bytes(), b"blob-age");
        assert_eq!(generated[1].plaintext.clone().risky_unwrap(), [2u8; 32]);
        assert_eq!(generate_email.num_calls(), 1);
        assert_eq!(generate_age.num_calls(), 1);

        let requests = [
            (generated[0].key_id.clone(), email),
            (generated[1].key_id.clone(), age),
        ];
        let retrieved = KeyProvider::retrieve_keys(&source, &requests)
            .await
            .unwrap();

        assert_eq!(retrieved.len(), 2);
        assert_eq!(retrieved[0].clone().risky_unwrap(), [1u8; 32]);
        assert_eq!(retrieved[1].clone().risky_unwrap(), [2u8; 32]);
        assert_eq!(decrypt_email.num_calls(), 1);
        assert_eq!(decrypt_age.num_calls(), 1);
    }

    /// Against LocalStack on `localhost:4566` — see the crate README for
    /// how to bring it up.
    mod localstack {
        use super::*;
        use crate::aws::testing::{encrypt_decrypt_key, localstack_client};

        #[tokio::test]
        async fn data_key_generate_and_retrieve_round_trip() {
            let client = localstack_client();
            let key_id = encrypt_decrypt_key(&client).await;
            let source = AwsDataKeySource::<32>::new(client, key_id);

            let generated = source.generate_data_key(Binding::EMPTY).await.unwrap();
            let retrieved = source
                .retrieve_data_key(&generated.key_id, Binding::EMPTY)
                .await
                .unwrap();

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

        /// A direct ciphertext of exactly `N` bytes must not open as a data
        /// key, under the empty binding or any other. Before CIP-5094 both
        /// uses sent no context for an empty binding, and this opened.
        #[tokio::test]
        async fn a_direct_ciphertext_is_not_a_data_key() {
            let client = localstack_client();
            let key_id = encrypt_decrypt_key(&client).await;
            let source = AwsDataKeySource::<32>::new(client, key_id);

            let ciphertext = source.encrypt(Protected::new(vec![7u8; 32])).await.unwrap();
            let key_id = KeyId::new(ciphertext);

            for binding in [Binding::EMPTY, Binding::from("encrypt-with-key")] {
                let error = source
                    .retrieve_data_key(&key_id, binding)
                    .await
                    .unwrap_err();
                assert!(
                    matches!(
                        error,
                        Error::AwsSdk(aws_sdk_kms::Error::InvalidCiphertextException(_))
                    ),
                    "{error:?}"
                );
            }
        }

        /// The other direction: a data key minted under `Binding::EMPTY`, as
        /// an index key is, does not open through `decrypt`. If it did, any
        /// caller of `decrypt` that can read the index `KeyId` would get the
        /// index key. A data key under a binding does not open either.
        #[tokio::test]
        async fn a_data_key_is_not_a_direct_ciphertext() {
            let client = localstack_client();
            let key_id = encrypt_decrypt_key(&client).await;
            let source = AwsDataKeySource::<32>::new(client, key_id);

            for binding in [Binding::EMPTY, Binding::from("users/email")] {
                let generated = source.generate_data_key(binding).await.unwrap();
                let error = source
                    .decrypt(generated.key_id.as_bytes())
                    .await
                    .unwrap_err();
                assert!(
                    matches!(
                        error,
                        Error::AwsSdk(aws_sdk_kms::Error::InvalidCiphertextException(_))
                    ),
                    "{error:?}"
                );
            }
        }

        /// A data key that key A minted does not open through a source bound
        /// to key B (CIP-5029). The blob names key A, and AWS opens it under
        /// that key unless the `Decrypt` request names a `KeyId`. This
        /// source sends its own key id, so AWS refuses the blob.
        #[tokio::test]
        async fn a_data_key_from_another_key_does_not_open() {
            let client = localstack_client();
            let key_a = encrypt_decrypt_key(&client).await;
            let key_b = encrypt_decrypt_key(&client).await;
            let source_a = AwsDataKeySource::<32>::new(client.clone(), key_a);
            let source_b = AwsDataKeySource::<32>::new(client, key_b);

            for binding in [Binding::EMPTY, Binding::from("users/email")] {
                let generated = source_a.generate_data_key(binding).await.unwrap();
                let error = source_b
                    .retrieve_data_key(&generated.key_id, binding)
                    .await
                    .unwrap_err();
                assert!(
                    matches!(
                        error,
                        Error::AwsSdk(aws_sdk_kms::Error::IncorrectKeyException(_))
                    ),
                    "{error:?}"
                );
            }
        }

        /// The index key is a data key under `Binding::EMPTY`, and it still
        /// comes back through `FixedIndexKeySource`.
        #[tokio::test]
        async fn the_index_key_round_trips_under_the_empty_binding() {
            use crate::provider::{FixedIndexKeySource, IndexKeyProvider};

            let client = localstack_client();
            let key_id = encrypt_decrypt_key(&client).await;
            let source = AwsDataKeySource::<32>::new(client, key_id);
            let provisioned = source.generate_data_key(Binding::EMPTY).await.unwrap();
            let index = FixedIndexKeySource::new(source, provisioned.key_id);

            let loaded = IndexKeyProvider::<32>::load_index_key(&index)
                .await
                .unwrap();

            assert_eq!(
                loaded.0.risky_unwrap(),
                provisioned.plaintext.risky_unwrap()
            );
        }
    }

    /// `entries` as the owned map that a request's context is compared to.
    fn context_of(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    /// A generate rule and a decrypt rule that each match only a request
    /// whose `EncryptionContext` is exactly `expected`.
    fn data_key_rules_for(
        expected: HashMap<String, String>,
    ) -> (aws_smithy_mocks::Rule, aws_smithy_mocks::Rule) {
        let sent = expected.clone();
        let generate_rule = mock!(Client::generate_data_key)
            .match_requests(move |req| req.encryption_context() == Some(&sent))
            .then_output(|| {
                GenerateDataKeyOutput::builder()
                    .plaintext(Blob::new(fixed_plaintext().to_vec()))
                    .ciphertext_blob(Blob::new(fixed_ciphertext_blob()))
                    .key_id(TEST_KEY_ID)
                    .build()
            });
        let decrypt_rule = mock!(Client::decrypt)
            .match_requests(move |req| req.encryption_context() == Some(&expected))
            .then_output(|| {
                DecryptOutput::builder()
                    .plaintext(Blob::new(fixed_plaintext().to_vec()))
                    .key_id(TEST_KEY_ID)
                    .build()
            });
        (generate_rule, decrypt_rule)
    }

    /// The binding has to reach AWS, or the claim that AWS binds has
    /// nothing behind it. Asserts the `EncryptionContext` on **both** calls,
    /// because a context sent on generate and dropped on decrypt would make
    /// every key unretrievable, and a test that only checked generate would
    /// not notice.
    #[tokio::test]
    async fn the_binding_reaches_aws_as_an_encryption_context_on_both_calls() {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"users/email");
        let (generate_rule, decrypt_rule) = data_key_rules_for(context_of(&[
            ("vitaminc:use", "data-key"),
            ("vitaminc:binding", &encoded),
        ]));

        let client = mock_client!(
            aws_sdk_kms,
            RuleMode::MatchAny,
            &[&generate_rule, &decrypt_rule]
        );
        let source = AwsDataKeySource::<32>::new(client, TEST_KEY_ID);
        let binding = Binding::from("users/email");

        let generated = source.generate_data_key(binding).await.unwrap();
        let _ = source
            .retrieve_data_key(&generated.key_id, binding)
            .await
            .unwrap();

        // The rules only match when the context is exactly right, so a call
        // count of one each is the assertion.
        assert_eq!(generate_rule.num_calls(), 1);
        assert_eq!(decrypt_rule.num_calls(), 1);
    }

    /// An empty binding sends exactly `{"vitaminc:use": "data-key"}` on
    /// generate **and** on decrypt (CIP-5036): no binding entry, but never
    /// an empty context, because an empty context is what direct
    /// encryption sent before CIP-5094, and the index key, which is a data
    /// key under `Binding::EMPTY`, then opened through `decrypt`.
    #[tokio::test]
    async fn an_empty_binding_sends_only_the_data_key_use_on_both_calls() {
        let (generate_rule, decrypt_rule) =
            data_key_rules_for(context_of(&[("vitaminc:use", "data-key")]));
        let client = mock_client!(
            aws_sdk_kms,
            RuleMode::MatchAny,
            &[&generate_rule, &decrypt_rule]
        );
        let source = AwsDataKeySource::<32>::new(client, TEST_KEY_ID);

        let generated = source.generate_data_key(Binding::EMPTY).await.unwrap();
        let _ = source
            .retrieve_data_key(&generated.key_id, Binding::EMPTY)
            .await
            .unwrap();

        assert_eq!(generate_rule.num_calls(), 1);
        assert_eq!(decrypt_rule.num_calls(), 1);
    }

    /// Direct encryption sends exactly `{"vitaminc:use": "encrypt-with-key"}`
    /// on `Encrypt` and on `Decrypt`.
    #[tokio::test]
    async fn direct_encryption_sends_its_own_use_on_both_calls() {
        let expected = context_of(&[("vitaminc:use", "encrypt-with-key")]);
        let sent = expected.clone();
        let encrypt_rule = mock!(Client::encrypt)
            .match_requests(move |req| req.encryption_context() == Some(&sent))
            .then_output(|| {
                EncryptOutput::builder()
                    .ciphertext_blob(Blob::new(fixed_ciphertext_blob()))
                    .key_id(TEST_KEY_ID)
                    .build()
            });
        let decrypt_rule = mock!(Client::decrypt)
            .match_requests(move |req| req.encryption_context() == Some(&expected))
            .then_output(|| {
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
            .encrypt(Protected::new(b"a short secret".to_vec()))
            .await
            .unwrap();
        let _ = source.decrypt(&ciphertext).await.unwrap();

        assert_eq!(encrypt_rule.num_calls(), 1);
        assert_eq!(decrypt_rule.num_calls(), 1);
    }
}
