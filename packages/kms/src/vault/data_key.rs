use super::batch::{
    BatchDecryptItem, BatchDecryptRequest, BatchDecryptResponse, GenerateDataKeysRequest,
    GenerateDataKeysResponse,
};
use super::{b64_decode, b64_encode};
use crate::crypt::{DecryptWithKey, EncryptWithKey};
use crate::data_key::{
    BatchGenerateDataKey, BatchRetrieveDataKey, GenerateDataKey, GeneratedDataKey, KeyIsolation,
    KeyReconstruction, RetrieveDataKey,
};
use crate::key_id::KeyId;
use private::ValidDataKeySize;
use thiserror::Error;
use vaultrs::api::transit::requests::{DataKeyType, GenerateDataKeyRequest};
use vaultrs::client::VaultClient;
use vitaminc_protected::{Controlled, Protected};

/// Errors from [`VaultDataKeySource`].
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Vault(#[from] vaultrs::error::ClientError),
    /// Vault encodes key material and plaintext as base64 in JSON.
    #[error("Vault returned data that is not valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    /// Only `datakey/wrapped/...` omits the plaintext, and this adapter
    /// never asks for that path — so this means a malformed response.
    #[error("Vault returned no plaintext for a `datakey/plaintext` call")]
    MissingPlaintext,
    /// Guards the `Vec<u8>` -> `[u8; N]` conversion, so a truncated or
    /// mis-sized response surfaces as an error rather than a panic.
    #[error("Vault returned {received} bytes of key material, expected {expected}")]
    UnexpectedKeyLength { expected: usize, received: usize },
    /// A [`KeyId`] minted by this adapter is the `vault:v<N>:...` string
    /// as UTF-8 bytes. Anything else did not come from here.
    #[error("this KeyId is not a UTF-8 Vault ciphertext string")]
    KeyIdNotUtf8,
    /// [`DecryptWithKey`] takes `&[u8]`, but a Vault ciphertext is text.
    #[error("this ciphertext is not a UTF-8 Vault ciphertext string")]
    CiphertextNotUtf8,
    /// Vault documents that `batch_results` matches `batch_input` in both
    /// length and order; the adapter relies on that and checks it.
    #[error("Vault returned {received} batch results for a batch of {expected}")]
    UnexpectedBatchLength { expected: usize, received: usize },
    /// One item of a batch failed. Vault reports these per item rather
    /// than failing the request, but a partly-decrypted batch is not a
    /// useful answer, so the whole call fails and names the index.
    #[error("Vault failed batch item {index}: {message}")]
    BatchItem { index: usize, message: String },
    /// A `batch_results` slot with neither `plaintext` nor `error`.
    #[error("Vault returned neither plaintext nor an error for batch item {index}")]
    BatchItemEmpty { index: usize },
}

fn into_sized<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], Error> {
    let received = bytes.len();
    bytes.try_into().map_err(|_| Error::UnexpectedKeyLength {
        expected: N,
        received,
    })
}

/// A Vault Transit-backed data key source with per-value key isolation
/// (`KeyIsolation::PerValue`), bound to one Transit key at construction.
///
/// Vault is the only backend of the four with a native batch primitive on
/// both sides — `datakeys/plaintext/:name` with a `count`, and `decrypt`
/// with a `batch_input` — so this is the one adapter that gets per-value
/// isolation at one round trip per batch instead of N (ADR 0002). There is
/// deliberately no pooled Vault source: pooling trades isolation for round
/// trips, and here there is nothing to trade.
///
/// One caveat the vendor documentation omits: the `datakeys` half is
/// Enterprise-only, so batch *generation* fails against Community Vault.
/// See [`generate_data_keys`](BatchGenerateDataKey::generate_data_keys).
///
/// `N` is the data key size in bytes and must be 16, 32 or 64; Vault
/// accepts only 128-, 256- and 512-bit data keys.
///
/// The bound key must not be `derived`: the capability traits carry no
/// derivation context, and Vault rejects a context-less call against a
/// derived key.
///
/// The same instance also implements [`EncryptWithKey`]/[`DecryptWithKey`]
/// for direct encryption under the Transit key, which is the same key
/// purpose (see `CONTEXT.md`) and so the same adapter.
pub struct VaultDataKeySource<const N: usize> {
    client: VaultClient,
    mount: String,
    name: String,
}

impl<const N: usize> VaultDataKeySource<N>
where
    Self: ValidDataKeySize<N>,
{
    /// `mount` is the path the Transit engine is mounted at — `"transit"`
    /// unless it was mounted elsewhere — and `name` the Transit key this
    /// instance is bound to: construction-time key binding, as every
    /// adapter uses.
    pub fn new(client: VaultClient, mount: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            client,
            mount: mount.into(),
            name: name.into(),
        }
    }

    fn decode_key(plaintext: &str) -> Result<Protected<[u8; N]>, Error> {
        Ok(Protected::new(into_sized(b64_decode(plaintext)?)?))
    }

    fn ciphertext_of(key_id: &KeyId) -> Result<String, Error> {
        String::from_utf8(key_id.as_bytes().to_vec()).map_err(|_| Error::KeyIdNotUtf8)
    }
}

impl<const N: usize> GenerateDataKey<N> for VaultDataKeySource<N>
where
    Self: ValidDataKeySize<N>,
{
    type Error = Error;

    async fn generate_data_key(&self) -> Result<GeneratedDataKey<N>, Self::Error> {
        let mut opts = GenerateDataKeyRequest::builder();
        opts.bits(Self::BITS);

        let response = vaultrs::transit::generate::data_key(
            &self.client,
            &self.mount,
            &self.name,
            DataKeyType::Plaintext,
            Some(&mut opts),
        )
        .await?;

        let plaintext = response.plaintext.ok_or(Error::MissingPlaintext)?;

        Ok(GeneratedDataKey {
            plaintext: Self::decode_key(&plaintext)?,
            // The `vault:v<N>:...` handle, passed through verbatim as
            // UTF-8 bytes — Vault's own encoding is the KeyId encoding.
            key_id: KeyId::new(response.ciphertext.into_bytes()),
        })
    }
}

impl<const N: usize> RetrieveDataKey<N> for VaultDataKeySource<N>
where
    Self: ValidDataKeySize<N>,
{
    type Error = Error;

    /// Vault rebuilds the data key from the ciphertext plus its own key
    /// material; the caller holds nothing the backend needs.
    const RECONSTRUCTION: KeyReconstruction = KeyReconstruction::ServerOnly;

    async fn retrieve_data_key(&self, key_id: &KeyId) -> Result<Protected<[u8; N]>, Self::Error> {
        let response = vaultrs::transit::data::decrypt(
            &self.client,
            &self.mount,
            &self.name,
            &Self::ciphertext_of(key_id)?,
            None,
        )
        .await?;

        Self::decode_key(&response.plaintext)
    }
}

impl<const N: usize> BatchGenerateDataKey<N> for VaultDataKeySource<N>
where
    Self: ValidDataKeySize<N>,
{
    /// Every key in a `datakeys` batch is distinct — native batching costs
    /// nothing in isolation here, unlike the pooled fallback the backends
    /// without a batch primitive need.
    const ISOLATION: KeyIsolation = KeyIsolation::PerValue;

    /// One round trip, `count` distinct keys.
    ///
    /// # Editions
    ///
    /// `POST {mount}/datakeys/:type/:name` is **Vault Enterprise only**,
    /// although HashiCorp's API reference does not mark it so: Community
    /// Vault registers only the singular `datakey/...` path and answers
    /// this one with `404 unsupported path`. Against Community Vault this
    /// call therefore fails, and the caller can either batch with
    /// [`fan_out_generate`](crate::fan_out_generate) over
    /// [`generate_data_key`](GenerateDataKey::generate_data_key) or wrap
    /// this source in a [`PooledDataKeySource`](crate::PooledDataKeySource)
    /// and accept pooled isolation.
    ///
    /// [`retrieve_data_keys`](BatchRetrieveDataKey::retrieve_data_keys) is
    /// unaffected: `batch_input` on `decrypt` is in both editions.
    async fn generate_data_keys(
        &self,
        count: usize,
    ) -> Result<Vec<GeneratedDataKey<N>>, Self::Error> {
        if count == 0 {
            return Ok(Vec::new());
        }

        let endpoint = GenerateDataKeysRequest {
            mount: self.mount.clone(),
            name: self.name.clone(),
            count: count as u64,
            bits: Self::BITS,
        };

        let response: GenerateDataKeysResponse =
            vaultrs::api::exec_with_result(&self.client, endpoint).await?;

        if response.key_pairs.len() != count {
            return Err(Error::UnexpectedBatchLength {
                expected: count,
                received: response.key_pairs.len(),
            });
        }

        response
            .key_pairs
            .into_iter()
            .map(|pair| {
                Ok(GeneratedDataKey {
                    plaintext: Self::decode_key(&pair.plaintext)?,
                    key_id: KeyId::new(pair.ciphertext.into_bytes()),
                })
            })
            .collect()
    }
}

impl<const N: usize> BatchRetrieveDataKey<N> for VaultDataKeySource<N>
where
    Self: ValidDataKeySize<N>,
{
    async fn retrieve_data_keys(
        &self,
        key_ids: &[KeyId],
    ) -> Result<Vec<Protected<[u8; N]>>, Self::Error> {
        if key_ids.is_empty() {
            return Ok(Vec::new());
        }

        let batch_input = key_ids
            .iter()
            .map(|key_id| {
                Ok(BatchDecryptItem {
                    ciphertext: Self::ciphertext_of(key_id)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let endpoint = BatchDecryptRequest {
            mount: self.mount.clone(),
            name: self.name.clone(),
            batch_input,
            // See `batch.rs`: 200 keeps the per-item detail readable.
            partial_failure_response_code: 200,
        };

        let response: BatchDecryptResponse =
            vaultrs::api::exec_with_result(&self.client, endpoint).await?;

        if response.batch_results.len() != key_ids.len() {
            return Err(Error::UnexpectedBatchLength {
                expected: key_ids.len(),
                received: response.batch_results.len(),
            });
        }

        // Order is preserved by Vault, so position is the correlation —
        // repeated ids are fine and each gets its own slot.
        //
        // `error` is read first and on purpose: a failed slot still
        // carries `"plaintext": ""`, so reading `plaintext` first would
        // turn "item 1 failed to decrypt" into "Vault returned 0 bytes of
        // key material" and lose the index and the reason.
        response
            .batch_results
            .into_iter()
            .enumerate()
            .map(|(index, result)| match (result.error, result.plaintext) {
                (Some(message), _) if !message.is_empty() => {
                    Err(Error::BatchItem { index, message })
                }
                (_, Some(plaintext)) => Self::decode_key(&plaintext),
                _ => Err(Error::BatchItemEmpty { index }),
            })
            .collect()
    }
}

/// Direct encryption under the bound Transit key — not envelope
/// encryption. Vault's 32MB request cap is the most generous of the four
/// backends, but the trait still promises nothing about size.
impl<const N: usize> EncryptWithKey for VaultDataKeySource<N> {
    type Error = Error;

    async fn encrypt(&self, plaintext: Protected<Vec<u8>>) -> Result<Vec<u8>, Self::Error> {
        let encoded = b64_encode(&plaintext.risky_unwrap());

        let response =
            vaultrs::transit::data::encrypt(&self.client, &self.mount, &self.name, &encoded, None)
                .await?;

        // Passed through as the `vault:v<N>:...` string's bytes, the same
        // encoding a KeyId uses.
        Ok(response.ciphertext.into_bytes())
    }
}

impl<const N: usize> DecryptWithKey for VaultDataKeySource<N> {
    type Error = Error;

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Protected<Vec<u8>>, Self::Error> {
        let ciphertext = std::str::from_utf8(ciphertext).map_err(|_| Error::CiphertextNotUtf8)?;

        let response =
            vaultrs::transit::data::decrypt(&self.client, &self.mount, &self.name, ciphertext, None)
                .await?;

        Ok(Protected::new(b64_decode(&response.plaintext)?))
    }
}

mod private {
    /// Sealed: only 128-, 256- and 512-bit data keys exist in Vault, so
    /// only `N` of 16, 32 and 64 can build a [`VaultDataKeySource`].
    pub trait ValidDataKeySize<const N: usize> {
        const BITS: u16;
    }

    impl ValidDataKeySize<16> for super::VaultDataKeySource<16> {
        const BITS: u16 = 128;
    }

    impl ValidDataKeySize<32> for super::VaultDataKeySource<32> {
        const BITS: u16 = 256;
    }

    impl ValidDataKeySize<64> for super::VaultDataKeySource<64> {
        const BITS: u16 = 512;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::tests::{data, test_client, KEY_NAME};
    use httpmock::prelude::*;
    use serde_json::json;

    #[tokio::test]
    async fn generate_asks_for_the_right_bit_size_and_decodes_the_plaintext() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/datakey/plaintext/{KEY_NAME}"))
                    .json_body(json!({ "bits": 256 }));
                then.status(200).json_body(data(json!({
                    "plaintext": b64_encode(&[7u8; 32]),
                    "ciphertext": "vault:v1:abc",
                })));
            })
            .await;

        let source = VaultDataKeySource::<32>::new(test_client(&server), "transit", KEY_NAME);
        let generated = source.generate_data_key().await.unwrap();

        mock.assert_async().await;
        assert_eq!(generated.plaintext.risky_unwrap(), [7u8; 32]);
        assert_eq!(generated.key_id.as_bytes(), b"vault:v1:abc");
    }

    #[tokio::test]
    async fn generate_rejects_key_material_of_the_wrong_length() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(POST);
                then.status(200).json_body(data(json!({
                    "plaintext": b64_encode(&[7u8; 16]),
                    "ciphertext": "vault:v1:abc",
                })));
            })
            .await;

        let source = VaultDataKeySource::<32>::new(test_client(&server), "transit", KEY_NAME);

        assert!(matches!(
            source.generate_data_key().await,
            Err(Error::UnexpectedKeyLength {
                expected: 32,
                received: 16
            })
        ));
    }

    #[tokio::test]
    async fn retrieve_passes_the_key_id_through_as_the_ciphertext() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/decrypt/{KEY_NAME}"))
                    .json_body(json!({ "ciphertext": "vault:v1:abc" }));
                then.status(200)
                    .json_body(data(json!({ "plaintext": b64_encode(&[9u8; 32]) })));
            })
            .await;

        let source = VaultDataKeySource::<32>::new(test_client(&server), "transit", KEY_NAME);
        let key = source
            .retrieve_data_key(&KeyId::new(b"vault:v1:abc".to_vec()))
            .await
            .unwrap();

        mock.assert_async().await;
        assert_eq!(key.risky_unwrap(), [9u8; 32]);
    }

    #[tokio::test]
    async fn batch_generate_posts_count_and_bits_to_the_plural_path() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/datakeys/plaintext/{KEY_NAME}"))
                    .json_body(json!({ "count": 3, "bits": 256 }));
                then.status(200).json_body(data(json!({
                    "key_pairs": [
                        { "plaintext": b64_encode(&[1u8; 32]), "ciphertext": "vault:v1:one" },
                        { "plaintext": b64_encode(&[2u8; 32]), "ciphertext": "vault:v1:two" },
                        { "plaintext": b64_encode(&[3u8; 32]), "ciphertext": "vault:v1:three" },
                    ],
                    "key_version": 1,
                })));
            })
            .await;

        let source = VaultDataKeySource::<32>::new(test_client(&server), "transit", KEY_NAME);
        let keys = source.generate_data_keys(3).await.unwrap();

        // One round trip for the whole batch is the point of ADR 0002.
        mock.assert_calls_async(1).await;
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[2].plaintext.clone().risky_unwrap(), [3u8; 32]);
        assert_eq!(keys[2].key_id.as_bytes(), b"vault:v1:three");
        assert_eq!(VaultDataKeySource::<32>::ISOLATION, KeyIsolation::PerValue);
    }

    #[tokio::test]
    async fn batch_retrieve_sends_batch_input_and_keeps_the_order() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/decrypt/{KEY_NAME}"))
                    .json_body(json!({
                        "batch_input": [
                            { "ciphertext": "vault:v1:one" },
                            { "ciphertext": "vault:v1:two" },
                            { "ciphertext": "vault:v1:one" },
                        ],
                        "partial_failure_response_code": 200,
                    }));
                then.status(200).json_body(data(json!({
                    "batch_results": [
                        { "plaintext": b64_encode(&[1u8; 32]) },
                        { "plaintext": b64_encode(&[2u8; 32]) },
                        { "plaintext": b64_encode(&[1u8; 32]) },
                    ],
                })));
            })
            .await;

        let source = VaultDataKeySource::<32>::new(test_client(&server), "transit", KEY_NAME);
        let ids = [
            KeyId::new(b"vault:v1:one".to_vec()),
            KeyId::new(b"vault:v1:two".to_vec()),
            KeyId::new(b"vault:v1:one".to_vec()),
        ];
        let keys = source.retrieve_data_keys(&ids).await.unwrap();

        mock.assert_calls_async(1).await;
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].clone().risky_unwrap(), [1u8; 32]);
        assert_eq!(keys[1].clone().risky_unwrap(), [2u8; 32]);
        assert_eq!(keys[2].clone().risky_unwrap(), [1u8; 32]);
    }

    #[tokio::test]
    async fn one_failed_batch_item_fails_the_whole_call_and_names_its_index() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(POST);
                // A failed slot still carries an empty `plaintext`, which
                // is how Vault really answers — reading it in preference
                // to `error` would lose both the index and the reason.
                then.status(200).json_body(data(json!({
                    "batch_results": [
                        { "plaintext": b64_encode(&[1u8; 32]), "reference": "" },
                        { "plaintext": "", "error": "cipher: message authentication failed", "reference": "" },
                    ],
                })));
            })
            .await;

        let source = VaultDataKeySource::<32>::new(test_client(&server), "transit", KEY_NAME);
        let ids = [
            KeyId::new(b"vault:v1:one".to_vec()),
            KeyId::new(b"vault:v1:bad".to_vec()),
        ];

        let err = source.retrieve_data_keys(&ids).await.unwrap_err();

        assert!(matches!(err, Error::BatchItem { index: 1, .. }));
        assert!(err.to_string().contains("batch item 1"));
    }

    #[tokio::test]
    async fn a_short_batch_response_is_an_error_not_a_short_vec() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(POST);
                then.status(200).json_body(data(json!({
                    "key_pairs": [
                        { "plaintext": b64_encode(&[1u8; 32]), "ciphertext": "vault:v1:one" },
                    ],
                    "key_version": 1,
                })));
            })
            .await;

        let source = VaultDataKeySource::<32>::new(test_client(&server), "transit", KEY_NAME);

        assert!(matches!(
            source.generate_data_keys(2).await,
            Err(Error::UnexpectedBatchLength {
                expected: 2,
                received: 1
            })
        ));
    }

    #[tokio::test]
    async fn encrypt_base64s_the_plaintext_and_decrypt_reverses_it() {
        let server = MockServer::start_async().await;
        let encrypt = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/encrypt/{KEY_NAME}"))
                    .json_body(json!({ "plaintext": b64_encode(b"hello") }));
                then.status(200)
                    .json_body(data(json!({ "ciphertext": "vault:v1:xyz" })));
            })
            .await;
        let decrypt = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/decrypt/{KEY_NAME}"))
                    .json_body(json!({ "ciphertext": "vault:v1:xyz" }));
                then.status(200)
                    .json_body(data(json!({ "plaintext": b64_encode(b"hello") })));
            })
            .await;

        let source = VaultDataKeySource::<32>::new(test_client(&server), "transit", KEY_NAME);

        let ciphertext = source
            .encrypt(Protected::new(b"hello".to_vec()))
            .await
            .unwrap();
        assert_eq!(ciphertext, b"vault:v1:xyz");

        let plaintext = source.decrypt(&ciphertext).await.unwrap();
        assert_eq!(plaintext.risky_unwrap(), b"hello");

        encrypt.assert_async().await;
        decrypt.assert_async().await;
    }

    #[test]
    fn a_key_id_that_is_not_utf8_is_rejected_before_any_request() {
        assert!(matches!(
            VaultDataKeySource::<32>::ciphertext_of(&KeyId::new(vec![0xFF, 0xFE])),
            Err(Error::KeyIdNotUtf8)
        ));
    }
}

/// Round trips against the dev-mode Vault of
/// `packages/kms/docker-compose.yml`.
#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::vault::tests::transit_key;
    use crate::vault::tests::DEFAULT_MOUNT;
    use vaultrs::api::transit::KeyType;

    async fn source() -> VaultDataKeySource<32> {
        let (client, name) = transit_key(KeyType::Aes256Gcm96).await;
        VaultDataKeySource::new(client, DEFAULT_MOUNT, name)
    }

    #[tokio::test]
    async fn a_generated_data_key_comes_back_from_its_key_id() {
        let source = source().await;

        let generated = source.generate_data_key().await.unwrap();
        let retrieved = source.retrieve_data_key(&generated.key_id).await.unwrap();

        assert!(generated.key_id.as_bytes().starts_with(b"vault:v1:"));
        assert_eq!(
            retrieved.risky_unwrap(),
            generated.plaintext.clone().risky_unwrap()
        );
    }

    /// `datakeys` (plural) is Vault **Enterprise**-only, so it answers 404
    /// on the Community server the rest of these tests run against. See
    /// the note on [`generate_data_keys`](BatchGenerateDataKey).
    fn is_enterprise_only(error: &Error) -> bool {
        matches!(
            error,
            Error::Vault(vaultrs::error::ClientError::APIError { code: 404, errors })
                if errors.iter().any(|e| e.contains("unsupported path"))
        )
    }

    #[tokio::test]
    async fn a_native_batch_mints_distinct_keys() {
        let source = source().await;

        assert_eq!(VaultDataKeySource::<32>::ISOLATION, KeyIsolation::PerValue);

        let keys = match source.generate_data_keys(5).await {
            Ok(keys) => keys,
            Err(e) if is_enterprise_only(&e) => {
                eprintln!("`datakeys` is Enterprise-only; this Vault has no such path");
                return;
            }
            Err(e) => panic!("generate_data_keys failed: {e}"),
        };

        assert_eq!(keys.len(), 5);

        // `KeyIsolation::PerValue` is the claim; distinctness is the test.
        let material: Vec<[u8; 32]> = keys
            .iter()
            .map(|k| k.plaintext.clone().risky_unwrap())
            .collect();
        for (i, a) in material.iter().enumerate() {
            for b in &material[i + 1..] {
                assert_ne!(a, b, "a batch must not repeat key material");
            }
        }

        let ids: Vec<KeyId> = keys.iter().map(|k| k.key_id.clone()).collect();
        let retrieved = source.retrieve_data_keys(&ids).await.unwrap();
        assert_eq!(retrieved[4].clone().risky_unwrap(), material[4]);
    }

    /// Batch *retrieve* — `decrypt` with `batch_input` — is in Community
    /// Vault, so this exercises the real endpoint whatever the edition.
    #[tokio::test]
    async fn a_native_batch_retrieve_keeps_the_order_and_allows_repeats() {
        let source = source().await;

        let mut keys = Vec::new();
        for _ in 0..3 {
            keys.push(source.generate_data_key().await.unwrap());
        }
        let material: Vec<[u8; 32]> = keys
            .iter()
            .map(|k| k.plaintext.clone().risky_unwrap())
            .collect();

        // A repeated id is legal and must get its own, matching slot.
        let ids = [
            keys[2].key_id.clone(),
            keys[0].key_id.clone(),
            keys[2].key_id.clone(),
        ];
        let retrieved = source.retrieve_data_keys(&ids).await.unwrap();

        assert_eq!(retrieved.len(), 3);
        assert_eq!(retrieved[0].clone().risky_unwrap(), material[2]);
        assert_eq!(retrieved[1].clone().risky_unwrap(), material[0]);
        assert_eq!(retrieved[2].clone().risky_unwrap(), material[2]);
    }

    #[tokio::test]
    async fn a_bad_key_id_in_a_batch_fails_the_whole_call_with_its_index() {
        let source = source().await;
        let good = source.generate_data_key().await.unwrap();
        let ids = [
            good.key_id.clone(),
            KeyId::new(b"vault:v1:bm90LWEtcmVhbC1jaXBoZXJ0ZXh0".to_vec()),
        ];

        let err = source.retrieve_data_keys(&ids).await.unwrap_err();

        assert!(
            matches!(err, Error::BatchItem { index: 1, .. }),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn direct_encryption_round_trips() {
        let source = source().await;

        let ciphertext = source
            .encrypt(Protected::new(b"a short message".to_vec()))
            .await
            .unwrap();
        let plaintext = source.decrypt(&ciphertext).await.unwrap();

        assert!(ciphertext.starts_with(b"vault:v1:"));
        assert_eq!(plaintext.risky_unwrap(), b"a short message");
    }
}
