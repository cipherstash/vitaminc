use super::batch::{
    BatchDecryptItem, BatchDecryptRequest, BatchDecryptResponse, GenerateDataKeysRequest,
    GenerateDataKeysResponse, KeyDerivationResponse, ReadKeyDerivationRequest,
};
use super::{b64_decode, b64_encode};
use crate::crypt::{DecryptWithKey, EncryptWithKey};
use crate::data_key::{
    fan_out_generate, BatchGenerateDataKey, BatchRetrieveDataKey, Binding, BindingSupport,
    GenerateDataKey, GeneratedDataKey, KeyCustody, KeyIsolation, KeyReconstruction,
    RetrieveDataKey,
};
use crate::key_id::KeyId;
use private::ValidDataKeySize;
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;
use vaultrs::api::transit::requests::{
    DataKeyType, DecryptDataRequest, EncryptDataRequest, GenerateDataKeyRequest,
};
use vaultrs::client::VaultClient;
use vitaminc_protected::{Controlled, Protected};

/// The first byte of every data-key derivation context. The binding
/// follows it.
///
/// A derived key refuses an empty context, and [`Binding::EMPTY`] is a
/// binding like any other. The tag makes every context non-empty, and the
/// encoding stays one-to-one: two bindings give the same context only if
/// they are the same bytes.
const DATA_KEY_CONTEXT_TAG: u8 = 0x01;

/// The derivation context of [`EncryptWithKey`] and [`DecryptWithKey`].
///
/// A derived key refuses every call that has no context, and direct
/// encryption has no binding to send. So it sends this fixed context. Its
/// first byte is not [`DATA_KEY_CONTEXT_TAG`], so no binding gives the same
/// context, and a direct ciphertext never opens as a data key.
const DIRECT_ENCRYPTION_CONTEXT: &[u8] = b"\x00vitaminc-kms/vault/encrypt-with-key";

/// Errors from [`VaultDataKeySource`].
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Vault(#[from] vaultrs::error::ClientError),
    /// The Transit key was not created with `derived=true`. A key that is
    /// not derived ignores the derivation context, so it cannot bind a data
    /// key, and [`VaultDataKeySource::new`] refuses it.
    #[error(
        "the Transit key {name:?} is not derived, so it cannot bind a data key; \
         create it with derived=true"
    )]
    NotDerived { name: String },
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
    crate::data_key::into_sized(bytes, |expected, received| Error::UnexpectedKeyLength {
        expected,
        received,
    })
}

/// A Vault Transit-backed data key source with per-value key isolation
/// (`KeyIsolation::PerValue`), bound to one Transit key at construction.
///
/// Vault is the only backend of the four with native batch primitives:
/// `decrypt` with a `batch_input` (every edition) and
/// `datakeys/plaintext/:name` with a `count` (Vault Enterprise only, a
/// restriction HashiCorp's API reference omits). Batch retrieval is one
/// round trip everywhere. Batch generation is one round trip on
/// Enterprise and falls back to one `datakey` call per key on Community,
/// after the server has once answered `404 unsupported path` or
/// `403 permission denied`; see
/// [`generate_data_keys`](BatchGenerateDataKey::generate_data_keys).
/// Isolation is per value either way (ADR 0003).
///
/// # Binding
///
/// The bound key must be created with `derived=true`. Vault then derives a
/// key from the Transit key and a per-call `context`, and the [`Binding`] is
/// that context. A retrieval under a different binding derives a different
/// key, and Vault refuses to decrypt the [`KeyId`]. A key that is not
/// derived accepts a context and silently ignores it, so it cannot bind:
/// [`new`](Self::new) reads the key's metadata and refuses one.
///
/// The context is one tag byte and then the binding bytes, base64-encoded.
/// A derived key refuses an empty context, and the tag byte means
/// [`Binding::EMPTY`] still gives a non-empty one.
///
/// # Token policy
///
/// The token needs `read` on `<mount>/keys/<name>`, for the check in
/// [`new`](Self::new), and `update` on these paths, with `<mount>` and
/// `<name>` as given to [`new`](Self::new):
///
/// - `<mount>/datakey/plaintext/<name>` for generation;
/// - `<mount>/decrypt/<name>` for retrieval and direct decryption;
/// - `<mount>/encrypt/<name>` for direct encryption only.
///
/// `update` on `<mount>/datakeys/plaintext/<name>` is optional, and is
/// useful only on Vault Enterprise: it lets a batch be one round trip.
/// Without it, Vault answers that path with `403 permission denied`, and
/// this source then uses the fan-out for every batch until it is rebuilt.
///
/// `N` is the data key size in bytes and must be 16, 32 or 64; Vault
/// accepts only 128-, 256- and 512-bit data keys.
///
/// The same instance also implements [`EncryptWithKey`]/[`DecryptWithKey`]
/// for direct encryption under the Transit key, which is the same key
/// purpose (see `CONTEXT.md`) and so the same adapter. Direct encryption
/// has no binding, so it sends one fixed derivation context.
pub struct VaultDataKeySource<const N: usize> {
    client: VaultClient,
    mount: String,
    name: String,
    /// Set once the server has answered the plural `datakeys` path with
    /// `404 unsupported path` (Community Vault) or `403 permission
    /// denied` (a token without that path in its policy), so later
    /// batches go straight to the fan-out without probing again. Never
    /// reset: build a new source to probe again, for example after a
    /// policy change.
    native_batch_unsupported: AtomicBool,
}

impl<const N: usize> VaultDataKeySource<N>
where
    Self: ValidDataKeySize<N>,
{
    /// `mount` is the path the Transit engine is mounted at — `"transit"`
    /// unless it was mounted elsewhere — and `name` the Transit key this
    /// instance is bound to: construction-time key binding, as every
    /// adapter uses.
    ///
    /// This makes one round trip, `GET <mount>/keys/<name>`, and returns
    /// [`Error::NotDerived`] when the key was not created with
    /// `derived=true`. A key that is not derived would silently ignore
    /// every binding. Build a source once and keep it: the check is not
    /// repeated per call.
    pub async fn new(
        client: VaultClient,
        mount: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, Error> {
        let source = Self::unchecked(client, mount, name);

        let endpoint = ReadKeyDerivationRequest {
            mount: source.mount.clone(),
            name: source.name.clone(),
        };
        let metadata: KeyDerivationResponse =
            vaultrs::api::exec_with_result(&source.client, endpoint).await?;
        if !metadata.derived {
            return Err(Error::NotDerived { name: source.name });
        }

        Ok(source)
    }

    /// A source over `name` with no check that the key is derived. Only
    /// [`new`](Self::new) and the unit tests call it.
    fn unchecked(client: VaultClient, mount: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            client,
            mount: mount.into(),
            name: name.into(),
            native_batch_unsupported: AtomicBool::new(false),
        }
    }

    /// The base64 derivation context for `binding`: [`DATA_KEY_CONTEXT_TAG`],
    /// then the binding bytes.
    fn context_of(binding: Binding<'_>) -> String {
        let mut context = Vec::with_capacity(1 + binding.as_bytes().len());
        context.push(DATA_KEY_CONTEXT_TAG);
        context.extend_from_slice(binding.as_bytes());
        b64_encode(&context)
    }

    /// The one binding every item shares, if they all share one.
    fn shared_binding<'a>(bindings: &[Binding<'a>]) -> Option<Binding<'a>> {
        let (first, rest) = bindings.split_first()?;
        rest.iter().all(|b| b == first).then_some(*first)
    }

    /// True when the plural `datakeys` path is not available to this
    /// client, so a batch must fan out instead.
    ///
    /// Community Vault registers only the singular `datakey/...` path and
    /// answers the plural one with `404 unsupported path`. Vault checks
    /// the token's policy before it routes a request, so a token without
    /// the plural path in its policy gets `403` first, on either edition.
    /// A 403 that has another cause also makes the fan-out fail, with the
    /// error of the singular path.
    fn native_batch_unavailable(error: &Error) -> bool {
        use vaultrs::error::ClientError::APIError;

        match error {
            Error::Vault(APIError { code: 404, errors }) => {
                errors.iter().any(|e| e.contains("unsupported path"))
            }
            Error::Vault(APIError { code: 403, .. }) => true,
            _ => false,
        }
    }

    /// One round trip via the Enterprise-only `datakeys` endpoint, every key
    /// under the one `binding`.
    async fn generate_data_keys_natively(
        &self,
        count: usize,
        binding: Binding<'_>,
    ) -> Result<Vec<GeneratedDataKey<N>>, Error> {
        let endpoint = GenerateDataKeysRequest {
            mount: self.mount.clone(),
            name: self.name.clone(),
            count: count as u64,
            bits: Self::BITS,
            context: Self::context_of(binding),
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

    /// The binding is the derivation context. See the
    /// [type docs](VaultDataKeySource#binding).
    async fn generate_data_key(
        &self,
        binding: Binding<'_>,
    ) -> Result<GeneratedDataKey<N>, Self::Error> {
        let mut opts = GenerateDataKeyRequest::builder();
        opts.bits(Self::BITS).context(Self::context_of(binding));

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

    /// Transit hands the data key back as ciphertext (`vault:v1:...`). The
    /// mount keeps no copy of the data key, so that ciphertext is the only one.
    const CUSTODY: KeyCustody = KeyCustody::ClientHeld;

    /// The binding is the derivation context, and [`new`](Self::new)
    /// refuses a key that is not derived. Under another binding, Vault
    /// derives another key and refuses to decrypt.
    const BINDING: BindingSupport = BindingSupport::Bound;

    async fn retrieve_data_key(
        &self,
        key_id: &KeyId,
        binding: Binding<'_>,
    ) -> Result<Protected<[u8; N]>, Self::Error> {
        let mut opts = DecryptDataRequest::builder();
        opts.context(Self::context_of(binding));

        let response = vaultrs::transit::data::decrypt(
            &self.client,
            &self.mount,
            &self.name,
            &Self::ciphertext_of(key_id)?,
            Some(&mut opts),
        )
        .await?;

        Self::decode_key(&response.plaintext)
    }
}

impl<const N: usize> BatchGenerateDataKey<N> for VaultDataKeySource<N>
where
    Self: ValidDataKeySize<N>,
{
    /// Every key in a `datakeys` batch is distinct, so native batching
    /// costs nothing in isolation.
    const ISOLATION: KeyIsolation = KeyIsolation::PerValue;

    /// `count` distinct keys: one round trip on Vault Enterprise, `count`
    /// concurrent `datakey` calls on Community.
    ///
    /// # Editions
    ///
    /// `POST {mount}/datakeys/:type/:name` is **Vault Enterprise only**,
    /// although HashiCorp's API reference does not mark it so: Community
    /// Vault registers only the singular `datakey/...` path and answers
    /// this one with `404 unsupported path`. A token without `update` on
    /// this path gets `403 permission denied` on either edition. The first
    /// batch pays that one failed probe, then this adapter remembers the
    /// answer and uses [`fan_out_generate`] for every batch after it, until
    /// the source is rebuilt. The result is the same either way: `count`
    /// distinct keys at `KeyIsolation::PerValue`; only the round-trip
    /// count differs. See the [token policy](VaultDataKeySource#token-policy).
    ///
    /// [`retrieve_data_keys`](BatchRetrieveDataKey::retrieve_data_keys) is
    /// unaffected: `batch_input` on `decrypt` is in both editions.
    ///
    /// # Bindings
    ///
    /// `datakeys` takes one derivation context for the whole batch. So the
    /// native path is used only when every key in the batch has the same
    /// binding. A batch with mixed bindings always fans out, one `datakey`
    /// call per key, each under its own binding.
    async fn generate_data_keys(
        &self,
        bindings: &[Binding<'_>],
    ) -> Result<Vec<GeneratedDataKey<N>>, Self::Error> {
        if bindings.is_empty() {
            return Ok(Vec::new());
        }

        if let Some(binding) = Self::shared_binding(bindings) {
            if !self.native_batch_unsupported.load(Ordering::Relaxed) {
                match self
                    .generate_data_keys_natively(bindings.len(), binding)
                    .await
                {
                    Err(e) if Self::native_batch_unavailable(&e) => {
                        self.native_batch_unsupported.store(true, Ordering::Relaxed);
                    }
                    result => return result,
                }
            }
        }

        fan_out_generate(self, bindings).await
    }
}

impl<const N: usize> BatchRetrieveDataKey<N> for VaultDataKeySource<N>
where
    Self: ValidDataKeySize<N>,
{
    async fn retrieve_data_keys(
        &self,
        keys: &[(KeyId, Binding<'_>)],
    ) -> Result<Vec<Protected<[u8; N]>>, Self::Error> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        let batch_input = keys
            .iter()
            .map(|(key_id, binding)| {
                Ok(BatchDecryptItem {
                    ciphertext: Self::ciphertext_of(key_id)?,
                    context: Self::context_of(*binding),
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

        if response.batch_results.len() != keys.len() {
            return Err(Error::UnexpectedBatchLength {
                expected: keys.len(),
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
impl<const N: usize> EncryptWithKey for VaultDataKeySource<N>
where
    Self: ValidDataKeySize<N>,
{
    type Error = Error;

    async fn encrypt(&self, plaintext: Protected<Vec<u8>>) -> Result<Vec<u8>, Self::Error> {
        let encoded = b64_encode(&plaintext.risky_unwrap());
        let mut opts = EncryptDataRequest::builder();
        opts.context(b64_encode(DIRECT_ENCRYPTION_CONTEXT));

        let response = vaultrs::transit::data::encrypt(
            &self.client,
            &self.mount,
            &self.name,
            &encoded,
            Some(&mut opts),
        )
        .await?;

        // Passed through as the `vault:v<N>:...` string's bytes, the same
        // encoding a KeyId uses.
        Ok(response.ciphertext.into_bytes())
    }
}

impl<const N: usize> DecryptWithKey for VaultDataKeySource<N>
where
    Self: ValidDataKeySize<N>,
{
    type Error = Error;

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Protected<Vec<u8>>, Self::Error> {
        let ciphertext = std::str::from_utf8(ciphertext).map_err(|_| Error::CiphertextNotUtf8)?;
        let mut opts = DecryptDataRequest::builder();
        opts.context(b64_encode(DIRECT_ENCRYPTION_CONTEXT));

        let response = vaultrs::transit::data::decrypt(
            &self.client,
            &self.mount,
            &self.name,
            ciphertext,
            Some(&mut opts),
        )
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

    /// The binding the tests mint and retrieve under.
    pub(super) const BINDING: Binding<'static> = Binding::new(b"users/email");

    /// [`BINDING`] as the base64 derivation context Vault receives.
    fn context() -> String {
        b64_encode(b"\x01users/email")
    }

    /// Pairs each id with [`BINDING`].
    pub(super) fn bound(ids: &[KeyId]) -> Vec<(KeyId, Binding<'static>)> {
        ids.iter().map(|id| (id.clone(), BINDING)).collect()
    }

    /// The key id this source returns is the data key in wrapped form,
    /// not a reference the backend can resolve: losing it loses the key.
    #[test]
    fn the_key_id_is_the_wrapped_key() {
        assert_eq!(
            <VaultDataKeySource<32> as RetrieveDataKey<32>>::CUSTODY,
            KeyCustody::ClientHeld
        );
    }

    #[tokio::test]
    async fn generate_asks_for_the_right_bit_size_and_decodes_the_plaintext() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/datakey/plaintext/{KEY_NAME}"))
                    .json_body(json!({ "bits": 256, "context": context() }));
                then.status(200).json_body(data(json!({
                    "plaintext": b64_encode(&[7u8; 32]),
                    "ciphertext": "vault:v1:abc",
                })));
            })
            .await;

        let source = VaultDataKeySource::<32>::unchecked(test_client(&server), "transit", KEY_NAME);
        let generated = source.generate_data_key(BINDING).await.unwrap();

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

        let source = VaultDataKeySource::<32>::unchecked(test_client(&server), "transit", KEY_NAME);

        assert!(matches!(
            source.generate_data_key(BINDING).await,
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
                    .json_body(json!({ "ciphertext": "vault:v1:abc", "context": context() }));
                then.status(200)
                    .json_body(data(json!({ "plaintext": b64_encode(&[9u8; 32]) })));
            })
            .await;

        let source = VaultDataKeySource::<32>::unchecked(test_client(&server), "transit", KEY_NAME);
        let key = source
            .retrieve_data_key(&KeyId::new(b"vault:v1:abc".to_vec()), BINDING)
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
                    .json_body(json!({ "count": 3, "bits": 256, "context": context() }));
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

        let source = VaultDataKeySource::<32>::unchecked(test_client(&server), "transit", KEY_NAME);
        let keys = source.generate_data_keys(&[BINDING; 3]).await.unwrap();

        // One round trip for the whole batch is the point of ADR 0003.
        mock.assert_calls_async(1).await;
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[2].plaintext.clone().risky_unwrap(), [3u8; 32]);
        assert_eq!(keys[2].key_id.as_bytes(), b"vault:v1:three");
        assert_eq!(VaultDataKeySource::<32>::ISOLATION, KeyIsolation::PerValue);
    }

    #[tokio::test]
    async fn batch_generate_falls_back_to_singular_calls_on_community_vault() {
        let server = MockServer::start_async().await;
        let plural = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/datakeys/plaintext/{KEY_NAME}"));
                then.status(404).json_body(
                    json!({ "errors": ["1 error occurred:\n\t* unsupported path\n\n"] }),
                );
            })
            .await;
        let singular = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/datakey/plaintext/{KEY_NAME}"))
                    .json_body(json!({ "bits": 256, "context": context() }));
                then.status(200).json_body(data(json!({
                    "plaintext": b64_encode(&[9u8; 32]),
                    "ciphertext": "vault:v1:single",
                })));
            })
            .await;

        let source = VaultDataKeySource::<32>::unchecked(test_client(&server), "transit", KEY_NAME);

        let first = source.generate_data_keys(&[BINDING; 3]).await.unwrap();
        assert_eq!(first.len(), 3);
        plural.assert_calls_async(1).await;
        singular.assert_calls_async(3).await;

        // The 404 is remembered: the second batch never probes the plural
        // path again.
        let second = source.generate_data_keys(&[BINDING; 2]).await.unwrap();
        assert_eq!(second.len(), 2);
        plural.assert_calls_async(1).await;
        singular.assert_calls_async(5).await;
    }

    #[tokio::test]
    async fn batch_generate_falls_back_to_singular_calls_on_a_403() {
        let server = MockServer::start_async().await;
        let plural = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/datakeys/plaintext/{KEY_NAME}"));
                then.status(403).json_body(
                    json!({ "errors": ["1 error occurred:\n\t* permission denied\n\n"] }),
                );
            })
            .await;
        let singular = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/datakey/plaintext/{KEY_NAME}"))
                    .json_body(json!({ "bits": 256, "context": context() }));
                then.status(200).json_body(data(json!({
                    "plaintext": b64_encode(&[9u8; 32]),
                    "ciphertext": "vault:v1:single",
                })));
            })
            .await;

        let source = VaultDataKeySource::<32>::unchecked(test_client(&server), "transit", KEY_NAME);

        let first = source.generate_data_keys(&[BINDING; 3]).await.unwrap();
        assert_eq!(first.len(), 3);
        plural.assert_calls_async(1).await;
        singular.assert_calls_async(3).await;

        // The 403 is remembered too: a least-privilege token does not
        // write a permission-denied audit entry on every batch.
        let second = source.generate_data_keys(&[BINDING; 2]).await.unwrap();
        assert_eq!(second.len(), 2);
        plural.assert_calls_async(1).await;
        singular.assert_calls_async(5).await;
    }

    #[tokio::test]
    async fn batch_generate_does_not_treat_other_404s_as_community_vault() {
        let server = MockServer::start_async().await;
        let plural = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/datakeys/plaintext/{KEY_NAME}"));
                then.status(404)
                    .json_body(json!({ "errors": ["no such key"] }));
            })
            .await;

        let source = VaultDataKeySource::<32>::unchecked(test_client(&server), "transit", KEY_NAME);

        let Err(err) = source.generate_data_keys(&[BINDING; 2]).await else {
            panic!("a 404 that is not `unsupported path` must not be swallowed");
        };
        assert!(matches!(err, Error::Vault(_)), "{err}");
        plural.assert_calls_async(1).await;
        assert!(!source.native_batch_unsupported.load(Ordering::Relaxed));
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
                            { "ciphertext": "vault:v1:one", "context": context() },
                            { "ciphertext": "vault:v1:two", "context": context() },
                            { "ciphertext": "vault:v1:one", "context": context() },
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

        let source = VaultDataKeySource::<32>::unchecked(test_client(&server), "transit", KEY_NAME);
        let ids = [
            KeyId::new(b"vault:v1:one".to_vec()),
            KeyId::new(b"vault:v1:two".to_vec()),
            KeyId::new(b"vault:v1:one".to_vec()),
        ];
        let keys = source.retrieve_data_keys(&bound(&ids)).await.unwrap();

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

        let source = VaultDataKeySource::<32>::unchecked(test_client(&server), "transit", KEY_NAME);
        let ids = [
            KeyId::new(b"vault:v1:one".to_vec()),
            KeyId::new(b"vault:v1:bad".to_vec()),
        ];

        let err = source.retrieve_data_keys(&bound(&ids)).await.unwrap_err();

        assert!(matches!(err, Error::BatchItem { index: 1, .. }));
        assert!(err.to_string().contains("batch item 1"));
    }

    #[tokio::test]
    async fn a_batch_slot_with_an_empty_error_and_no_plaintext_is_reported_as_empty() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(POST);
                // Vault writes `"error": ""` into the slots that did not
                // fail, so an empty `error` is not a failure: a slot with
                // one and no plaintext is a slot with nothing in it, and
                // saying "item 1 failed: " would name no reason at all.
                then.status(200).json_body(data(json!({
                    "batch_results": [
                        { "plaintext": b64_encode(&[1u8; 32]), "error": "" },
                        { "error": "" },
                    ],
                })));
            })
            .await;

        let source = VaultDataKeySource::<32>::unchecked(test_client(&server), "transit", KEY_NAME);
        let ids = [
            KeyId::new(b"vault:v1:one".to_vec()),
            KeyId::new(b"vault:v1:two".to_vec()),
        ];

        let err = source.retrieve_data_keys(&bound(&ids)).await.unwrap_err();

        assert!(matches!(err, Error::BatchItemEmpty { index: 1 }), "{err}");
        assert_eq!(
            err.to_string(),
            "Vault returned neither plaintext nor an error for batch item 1"
        );
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

        let source = VaultDataKeySource::<32>::unchecked(test_client(&server), "transit", KEY_NAME);

        assert!(matches!(
            source.generate_data_keys(&[BINDING; 2]).await,
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
                    .json_body(json!({
                        "plaintext": b64_encode(b"hello"),
                        "context": b64_encode(DIRECT_ENCRYPTION_CONTEXT),
                    }));
                then.status(200).json_body(data(json!({
                    "ciphertext": "vault:v1:xyz",
                    "context": b64_encode(DIRECT_ENCRYPTION_CONTEXT),
                })));
            })
            .await;
        let decrypt = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/decrypt/{KEY_NAME}"))
                    .json_body(json!({
                        "ciphertext": "vault:v1:xyz",
                        "context": b64_encode(DIRECT_ENCRYPTION_CONTEXT),
                    }));
                then.status(200).json_body(data(json!({
                    "plaintext": b64_encode(b"hello"),
                    "context": b64_encode(DIRECT_ENCRYPTION_CONTEXT),
                })));
            })
            .await;

        let source = VaultDataKeySource::<32>::unchecked(test_client(&server), "transit", KEY_NAME);

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

    /// The key-metadata response for a Transit key, with only the field the
    /// source reads.
    fn key_metadata(derived: bool) -> serde_json::Value {
        data(json!({ "name": KEY_NAME, "type": "aes256-gcm96", "derived": derived }))
    }

    #[tokio::test]
    async fn new_accepts_a_derived_key() {
        let server = MockServer::start_async().await;
        let read = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(format!("/v1/transit/keys/{KEY_NAME}"));
                then.status(200).json_body(key_metadata(true));
            })
            .await;

        VaultDataKeySource::<32>::new(test_client(&server), "transit", KEY_NAME)
            .await
            .unwrap();

        read.assert_async().await;
    }

    #[tokio::test]
    async fn new_refuses_a_key_that_is_not_derived() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(format!("/v1/transit/keys/{KEY_NAME}"));
                then.status(200).json_body(key_metadata(false));
            })
            .await;

        let Err(err) =
            VaultDataKeySource::<32>::new(test_client(&server), "transit", KEY_NAME).await
        else {
            panic!("a key that is not derived must not build a data key source");
        };

        assert!(matches!(err, Error::NotDerived { ref name } if name == KEY_NAME));
        assert!(err.to_string().contains("derived=true"), "{err}");
    }

    #[test]
    fn the_context_is_a_tag_byte_and_then_the_binding() {
        type Source = VaultDataKeySource<32>;

        assert_eq!(Source::context_of(BINDING), context());
        // An empty binding is still a context Vault accepts.
        assert_eq!(Source::context_of(Binding::EMPTY), b64_encode(&[0x01]));
        // No binding gives the context of direct encryption.
        assert_ne!(DIRECT_ENCRYPTION_CONTEXT[0], DATA_KEY_CONTEXT_TAG);
    }

    #[tokio::test]
    async fn a_batch_with_mixed_bindings_fans_out_each_under_its_own_context() {
        let server = MockServer::start_async().await;
        let plural = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/datakeys/plaintext/{KEY_NAME}"));
                then.status(500);
            })
            .await;
        let mut singular = Vec::new();
        for binding in ["users/email", "users/name"] {
            singular.push(
                server
                    .mock_async(|when, then| {
                        when.method(POST)
                            .path(format!("/v1/transit/datakey/plaintext/{KEY_NAME}"))
                            .json_body(
                                json!({ "bits": 256, "context": VaultDataKeySource::<32>::context_of(Binding::from(binding)) }),
                            );
                        then.status(200).json_body(data(json!({
                            "plaintext": b64_encode(&[9u8; 32]),
                            "ciphertext": "vault:v1:single",
                        })));
                    })
                    .await,
            );
        }

        let source = VaultDataKeySource::<32>::unchecked(test_client(&server), "transit", KEY_NAME);
        let keys = source
            .generate_data_keys(&[Binding::from("users/email"), Binding::from("users/name")])
            .await
            .unwrap();

        // One `datakeys` call takes one context, so a mixed batch never
        // tries it.
        assert_eq!(keys.len(), 2);
        plural.assert_calls_async(0).await;
        for mock in singular {
            mock.assert_calls_async(1).await;
        }
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
    use super::tests::{bound, BINDING};
    use super::*;
    use crate::vault::tests::least_privilege_client;
    use crate::vault::tests::DEFAULT_MOUNT;
    use crate::vault::tests::{derived_transit_key, transit_key};
    use vaultrs::api::transit::KeyType;

    async fn source() -> VaultDataKeySource<32> {
        let (client, name) = derived_transit_key(KeyType::Aes256Gcm96).await;
        VaultDataKeySource::new(client, DEFAULT_MOUNT, name)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_generated_data_key_comes_back_from_its_key_id() {
        let source = source().await;

        let generated = source.generate_data_key(BINDING).await.unwrap();
        let retrieved = source
            .retrieve_data_key(&generated.key_id, BINDING)
            .await
            .unwrap();

        assert!(generated.key_id.as_bytes().starts_with(b"vault:v1:"));
        assert_eq!(
            retrieved.risky_unwrap(),
            generated.plaintext.clone().risky_unwrap()
        );
    }

    /// On Enterprise this is one `datakeys` round trip; on the Community
    /// server the compose file runs, the adapter falls back to five
    /// `datakey` calls. Either way the contract below must hold.
    #[tokio::test]
    async fn a_batch_mints_distinct_keys_on_either_edition() {
        let source = source().await;

        assert_eq!(VaultDataKeySource::<32>::ISOLATION, KeyIsolation::PerValue);

        let keys = source.generate_data_keys(&[BINDING; 5]).await.unwrap();

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
        let retrieved = source.retrieve_data_keys(&bound(&ids)).await.unwrap();
        assert_eq!(retrieved[4].clone().risky_unwrap(), material[4]);
    }

    /// A token with only the policy that the type's docs name gets `403`
    /// on `datakeys`, on either edition, and must still mint a batch.
    #[tokio::test]
    async fn a_least_privilege_token_mints_a_batch_through_the_fan_out() {
        let (root, name) = derived_transit_key(KeyType::Aes256Gcm96).await;
        let client = least_privilege_client(
            &root,
            &format!(
                r#"
                path "{DEFAULT_MOUNT}/keys/{name}" {{ capabilities = ["read"] }}
                path "{DEFAULT_MOUNT}/datakey/plaintext/{name}" {{ capabilities = ["update"] }}
                path "{DEFAULT_MOUNT}/decrypt/{name}" {{ capabilities = ["update"] }}
                "#
            ),
        )
        .await;
        let source = VaultDataKeySource::<32>::new(client, DEFAULT_MOUNT, name)
            .await
            .unwrap();

        let keys = source.generate_data_keys(&[BINDING; 3]).await.unwrap();

        assert_eq!(keys.len(), 3);
        assert!(source.native_batch_unsupported.load(Ordering::Relaxed));
        let ids: Vec<KeyId> = keys.iter().map(|k| k.key_id.clone()).collect();
        let retrieved = source.retrieve_data_keys(&bound(&ids)).await.unwrap();
        assert_eq!(
            retrieved[2].clone().risky_unwrap(),
            keys[2].plaintext.clone().risky_unwrap()
        );
    }

    /// Batch *retrieve* — `decrypt` with `batch_input` — is in Community
    /// Vault, so this exercises the real endpoint whatever the edition.
    #[tokio::test]
    async fn a_native_batch_retrieve_keeps_the_order_and_allows_repeats() {
        let source = source().await;

        let mut keys = Vec::new();
        for _ in 0..3 {
            keys.push(source.generate_data_key(BINDING).await.unwrap());
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
        let retrieved = source.retrieve_data_keys(&bound(&ids)).await.unwrap();

        assert_eq!(retrieved.len(), 3);
        assert_eq!(retrieved[0].clone().risky_unwrap(), material[2]);
        assert_eq!(retrieved[1].clone().risky_unwrap(), material[0]);
        assert_eq!(retrieved[2].clone().risky_unwrap(), material[2]);
    }

    #[tokio::test]
    async fn a_bad_key_id_in_a_batch_fails_the_whole_call_with_its_index() {
        let source = source().await;
        let good = source.generate_data_key(BINDING).await.unwrap();
        let ids = [
            good.key_id.clone(),
            KeyId::new(b"vault:v1:bm90LWEtcmVhbC1jaXBoZXJ0ZXh0".to_vec()),
        ];

        let err = source.retrieve_data_keys(&bound(&ids)).await.unwrap_err();

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

    /// A key that is not derived accepts a context and ignores it, so it
    /// would silently drop every binding. Construction is where that stops.
    #[tokio::test]
    async fn a_key_that_is_not_derived_cannot_build_a_source() {
        let (client, name) = transit_key(KeyType::Aes256Gcm96).await;

        let Err(err) = VaultDataKeySource::<32>::new(client, DEFAULT_MOUNT, name.clone()).await
        else {
            panic!("a key that is not derived must not build a data key source");
        };

        assert!(
            matches!(err, Error::NotDerived { name: ref n } if *n == name),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_retrieve_under_a_different_binding_fails() {
        let source = source().await;
        let generated = source.generate_data_key(BINDING).await.unwrap();

        let err = source
            .retrieve_data_key(&generated.key_id, Binding::from("users/name"))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Vault(_)), "{err}");

        // An empty binding is a different binding too.
        assert!(source
            .retrieve_data_key(&generated.key_id, Binding::EMPTY)
            .await
            .is_err());
    }

    /// A derived key refuses an empty context, but the tag byte means an
    /// empty binding never sends one. So a key minted under
    /// `Binding::EMPTY`, as an index key is, comes back under it.
    #[tokio::test]
    async fn a_key_minted_under_an_empty_binding_comes_back_under_it() {
        let source = source().await;
        let generated = source.generate_data_key(Binding::EMPTY).await.unwrap();

        let retrieved = source
            .retrieve_data_key(&generated.key_id, Binding::EMPTY)
            .await
            .unwrap();
        assert_eq!(
            retrieved.risky_unwrap(),
            generated.plaintext.clone().risky_unwrap()
        );

        assert!(source
            .retrieve_data_key(&generated.key_id, BINDING)
            .await
            .is_err());
    }

    /// Direct encryption and data keys use different contexts, so a direct
    /// ciphertext does not open as a data key under any binding.
    #[tokio::test]
    async fn a_direct_ciphertext_is_not_a_data_key() {
        let source = source().await;
        let ciphertext = source.encrypt(Protected::new(vec![7u8; 32])).await.unwrap();

        let key_id = KeyId::new(ciphertext);
        for binding in [
            Binding::EMPTY,
            Binding::from("vitaminc-kms/vault/encrypt-with-key"),
        ] {
            assert!(source.retrieve_data_key(&key_id, binding).await.is_err());
        }
    }

    /// Each item of a batch carries its own binding, so one wrong binding
    /// fails the batch and names its index.
    #[tokio::test]
    async fn a_batch_retrieve_checks_each_item_against_its_own_binding() {
        let source = source().await;
        let email = source
            .generate_data_key(Binding::from("users/email"))
            .await
            .unwrap();
        let name = source
            .generate_data_key(Binding::from("users/name"))
            .await
            .unwrap();

        let retrieved = source
            .retrieve_data_keys(&[
                (email.key_id.clone(), Binding::from("users/email")),
                (name.key_id.clone(), Binding::from("users/name")),
            ])
            .await
            .unwrap();
        assert_eq!(
            retrieved[1].clone().risky_unwrap(),
            name.plaintext.clone().risky_unwrap()
        );

        let err = source
            .retrieve_data_keys(&[
                (email.key_id, Binding::from("users/email")),
                (name.key_id, Binding::from("users/email")),
            ])
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::BatchItem { index: 1, .. }),
            "unexpected error: {err}"
        );
    }
}
