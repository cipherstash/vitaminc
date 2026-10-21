use super::envelope::{Envelope, EnvelopeError};
use crate::crypt::{DecryptWithKey, EncryptWithKey};
use crate::data_key::{
    dedup_retrieve, fan_out_generate, BatchGenerateDataKey, BatchRetrieveDataKey, Binding,
    GenerateDataKey, GeneratedDataKey, KeyCustody, KeyReconstruction, RetrieveDataKey,
    DEFAULT_MAX_IN_FLIGHT,
};
use crate::key_id::KeyId;
use azure_security_keyvault_keys::models::{
    EncryptionAlgorithm, KeyClientEncryptOptions, KeyOperationParameters,
};
use azure_security_keyvault_keys::{KeyClient, ResourceId};
use std::num::NonZeroUsize;
use std::str::FromStr;
use thiserror::Error;
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::{Generatable, SafeRand};

/// The AES-GCM initialization vector length Key Vault's `A256GCM` expects,
/// in bytes. The service will not invent one, so the adapter mints it.
const GCM_IV_LEN: usize = 12;

/// Errors from the Azure Key Vault data key source.
#[derive(Debug, Error)]
pub enum Error {
    /// The vault, the transport or the credential failed. An
    /// [`AzureDataKeySource`] bound to a key that is not `oct-HSM`
    /// surfaces here on its first call, because only an `oct-HSM` key does
    /// `A256GCM`. A retrieval under a binding the key was not minted with
    /// also surfaces here: the vault refuses the authentication tag.
    #[error(transparent)]
    Azure(#[from] azure_core::Error),
    /// The local CSPRNG could not be seeded, so no data key was minted.
    #[error("could not generate data key material locally: {0}")]
    Random(#[from] vitaminc_random::RandomError),
    /// A successful response left out a field the operation must produce.
    #[error("Azure Key Vault returned no {0}")]
    MissingField(&'static str),
    /// The decrypted key material is not `N` bytes. Guards the
    /// `Vec<u8>` -> `[u8; N]` conversion so a malformed response is an error
    /// rather than a panic.
    #[error("Azure Key Vault returned {received} bytes of key material, expected {expected}")]
    UnexpectedKeyLength { expected: usize, received: usize },
    /// The `KeyId` was not produced by this adapter, or has been corrupted.
    #[error("the KeyId is not a usable Azure key reference: {0}")]
    MalformedKeyId(String),
    /// The ciphertext was not produced by this adapter, or has been corrupted.
    #[error("the ciphertext is not an Azure ciphertext: {0}")]
    MalformedCiphertext(String),
    /// The reference names a different backend key. Retrieving it would
    /// silently use a key this source is not bound to, so it is refused.
    #[error("{what} names key {found:?}, but this source is bound to key {expected:?}")]
    ForeignKey {
        what: &'static str,
        expected: String,
        found: String,
    },
}

/// An Azure Managed HSM-backed data key source, with per-value key
/// isolation: one distinct key per item.
///
/// The bound key must be an `oct-HSM` 256-bit symmetric key. Only that key
/// type does `A256GCM`, and `A256GCM` is the only Key Vault operation that
/// takes additional authenticated data, so it is the only way to bind a
/// data key. `oct-HSM` keys are production-ready on Managed HSM only; on Key
/// Vault Premium they are in preview, and Standard Key Vault has none. An
/// RSA or EC key cannot back this source: its first call fails with the
/// vault's own rejection, as [`Error::Azure`].
///
/// Key Vault has no "generate data key" call, so a data key is two steps:
/// mint `N` bytes locally with a CSPRNG, then `encrypt` them under the
/// backend key with `A256GCM`, a fresh IV and the caller's [`Binding`] as
/// the additional authenticated data. [`RetrieveDataKey`] reverses that
/// with `decrypt`, and the vault refuses a binding other than the one the
/// key was minted under. The same type also encrypts and decrypts small
/// payloads directly under the backend key
/// ([`EncryptWithKey`]/[`DecryptWithKey`]), with no additional
/// authenticated data.
///
/// The adapter binds to a key *name*. New work (`encrypt`) goes to whichever
/// version the vault currently considers current, and the `KeyId` and the
/// ciphertext both record the exact version that did the work, so rotating
/// the key never strands data. [`Self::with_key_version`] pins a version
/// instead.
///
/// Key Vault has no batch `encrypt` endpoint, so [`BatchGenerateDataKey`]
/// is N round trips ([`fan_out_generate`]).
///
/// No emulator covers this source. Lowkey Vault, which the other Azure
/// adapters test against, rejects `A256GCM`, so stub-transport unit tests
/// cover it, and opt-in tests against a real Managed HSM (CIP-4072).
pub struct AzureDataKeySource<const N: usize> {
    client: KeyClient,
    key_name: String,
    key_version: Option<String>,
    max_in_flight: NonZeroUsize,
}

impl<const N: usize> AzureDataKeySource<N> {
    /// Binds to the `oct-HSM` key named `key_name` in the Managed HSM
    /// `client` points at.
    pub fn new(client: KeyClient, key_name: impl Into<String>) -> Self {
        Self {
            client,
            key_name: key_name.into(),
            key_version: None,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
        }
    }

    /// Pins new work to one key version instead of the vault's current one.
    ///
    /// Retrieval and decryption always use the version recorded in the
    /// `KeyId` or the ciphertext, so this only affects `encrypt`.
    #[must_use]
    pub fn with_key_version(mut self, key_version: impl Into<String>) -> Self {
        self.key_version = Some(key_version.into());
        self
    }

    /// Sets how many requests a batch keeps in flight at one time. The
    /// default is [`DEFAULT_MAX_IN_FLIGHT`]. Set a lower value when the
    /// key's request quota or the client's connection pool is small.
    #[must_use]
    pub fn with_max_in_flight(mut self, max_in_flight: NonZeroUsize) -> Self {
        self.max_in_flight = max_in_flight;
        self
    }

    /// The version segment of a reference this source produced, after
    /// checking the reference belongs to the key this source is bound to.
    fn version_of(&self, kid: &str, what: Reference) -> Result<String, Error> {
        let resource = ResourceId::from_str(kid).map_err(|e| what.malformed(e.to_string()))?;
        if resource.name != self.key_name {
            return Err(Error::ForeignKey {
                what: what.description(),
                expected: self.key_name.clone(),
                found: resource.name,
            });
        }
        // The vault always writes the version into `kid`; a reference
        // without one did not come from here, and decrypting it under
        // "current" would silently pick the wrong key after a rotation.
        resource
            .version
            .ok_or_else(|| what.malformed("the kid carries no key version".to_owned()))
    }

    /// `A256GCM` `encrypt` under a fresh IV, with `aad` as the additional
    /// authenticated data.
    async fn seal(&self, plaintext: Vec<u8>, aad: &[u8]) -> Result<Envelope, Error> {
        let mut rng = SafeRand::from_entropy()?;
        let sent_iv: [u8; GCM_IV_LEN] = Generatable::random(&mut rng)?;

        let parameters = KeyOperationParameters {
            algorithm: Some(EncryptionAlgorithm::A256Gcm),
            value: Some(plaintext),
            iv: Some(sent_iv.to_vec()),
            additional_authenticated_data: as_aad(aad),
            ..Default::default()
        };
        let options = KeyClientEncryptOptions {
            key_version: self.key_version.clone(),
            ..Default::default()
        };
        let result = self
            .client
            .encrypt(&self.key_name, parameters.try_into()?, Some(options))
            .await?
            .into_model()?;

        let iv = result.iv.unwrap_or_else(|| sent_iv.to_vec());
        let tag = result
            .authentication_tag
            .ok_or(Error::MissingField("authentication tag"))?;
        let kid = result.kid.ok_or(Error::MissingField("kid"))?;
        let value = result.result.ok_or(Error::MissingField("result value"))?;
        Ok(Envelope::new(kid, value, iv, tag))
    }

    /// `A256GCM` `decrypt` of `bytes`, which `what` names, against the key
    /// version they record, with `aad` as the additional authenticated data.
    async fn open(&self, bytes: &[u8], aad: &[u8], what: Reference) -> Result<Vec<u8>, Error> {
        let envelope = Envelope::decode(bytes).map_err(|e| what.malformed(e.to_string()))?;
        let version = self.version_of(&envelope.kid, what)?;

        let parameters = KeyOperationParameters {
            algorithm: Some(EncryptionAlgorithm::A256Gcm),
            value: Some(envelope.value),
            iv: Some(envelope.iv),
            authentication_tag: Some(envelope.tag),
            additional_authenticated_data: as_aad(aad),
        };
        let result = self
            .client
            .decrypt(&self.key_name, &version, parameters.try_into()?, None)
            .await?
            .into_model()?;

        result.result.ok_or(Error::MissingField("result value"))
    }
}

/// An empty binding is sent as *no* `aad`, not an empty one. AES-GCM
/// authenticates the two the same way, and AWS and Google send an empty
/// binding as an absent field too.
fn as_aad(aad: &[u8]) -> Option<Vec<u8>> {
    (!aad.is_empty()).then(|| aad.to_vec())
}

/// Which of the two blobs an [`Envelope`] can carry is being read, so an
/// error names the one the caller passed in.
#[derive(Debug, Clone, Copy)]
enum Reference {
    KeyId,
    Ciphertext,
}

impl Reference {
    fn description(self) -> &'static str {
        match self {
            Self::KeyId => "the KeyId",
            Self::Ciphertext => "the ciphertext",
        }
    }

    fn malformed(self, reason: String) -> Error {
        match self {
            Self::KeyId => Error::MalformedKeyId(reason),
            Self::Ciphertext => Error::MalformedCiphertext(reason),
        }
    }
}

fn into_sized<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], Error> {
    crate::data_key::into_sized(bytes, |expected, received| Error::UnexpectedKeyLength {
        expected,
        received,
    })
}

fn encode(envelope: &Envelope, what: Reference) -> Result<Vec<u8>, Error> {
    envelope
        .encode()
        .map_err(|e: EnvelopeError| what.malformed(e.to_string()))
}

impl<const N: usize> GenerateDataKey<N> for AzureDataKeySource<N> {
    type Error = Error;

    /// The binding is the `aad` of the `A256GCM` encryption, so only the
    /// same binding can retrieve the key.
    async fn generate_data_key(
        &self,
        binding: Binding<'_>,
    ) -> Result<GeneratedDataKey<N>, Self::Error> {
        let mut rng = SafeRand::from_entropy()?;
        let plaintext: Protected<[u8; N]> = Generatable::random(&mut rng)?;

        let envelope = self
            .seal(plaintext.risky_ref().to_vec(), binding.as_bytes())
            .await?;

        Ok(GeneratedDataKey {
            plaintext,
            key_id: KeyId::new(encode(&envelope, Reference::KeyId)?),
        })
    }
}

impl<const N: usize> RetrieveDataKey<N> for AzureDataKeySource<N> {
    type Error = Error;

    /// The vault holds the whole key and decrypts on its own, so the `KeyId`
    /// plus the caller's Entra ID authorization is enough.
    const RECONSTRUCTION: KeyReconstruction = KeyReconstruction::ServerOnly;

    /// The envelope holds the data key encrypted by the vault key. The vault
    /// keeps no copy of the data key, so the envelope is the only one.
    const CUSTODY: KeyCustody = KeyCustody::ClientHeld;

    /// The binding is the `aad` of the `A256GCM` encryption. The vault
    /// refuses the authentication tag under any other binding.
    async fn retrieve_data_key(
        &self,
        key_id: &KeyId,
        binding: Binding<'_>,
    ) -> Result<Protected<[u8; N]>, Self::Error> {
        let value = self
            .open(key_id.as_bytes(), binding.as_bytes(), Reference::KeyId)
            .await?;
        Ok(Protected::new(into_sized(value)?))
    }
}

impl<const N: usize> BatchGenerateDataKey<N> for AzureDataKeySource<N> {
    async fn generate_data_keys(
        &self,
        bindings: &[Binding<'_>],
    ) -> Result<Vec<GeneratedDataKey<N>>, Self::Error> {
        fan_out_generate(self, bindings, self.max_in_flight).await
    }
}

impl<const N: usize> BatchRetrieveDataKey<N> for AzureDataKeySource<N> {
    async fn retrieve_data_keys(
        &self,
        keys: &[(KeyId, Binding<'_>)],
    ) -> Result<Vec<Protected<[u8; N]>>, Self::Error> {
        dedup_retrieve(self, keys, self.max_in_flight).await
    }
}

impl<const N: usize> EncryptWithKey for AzureDataKeySource<N> {
    type Error = Error;

    async fn encrypt(&self, plaintext: Protected<Vec<u8>>) -> Result<Vec<u8>, Self::Error> {
        let envelope = self.seal(plaintext.risky_unwrap(), &[]).await?;
        encode(&envelope, Reference::Ciphertext)
    }
}

impl<const N: usize> DecryptWithKey for AzureDataKeySource<N> {
    type Error = Error;

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Protected<Vec<u8>>, Self::Error> {
        let value = self.open(ciphertext, &[], Reference::Ciphertext).await?;
        Ok(Protected::new(value))
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{responder_client, stub_client, RecordedRequest};
    use super::*;
    use azure_core::base64;
    use azure_core::http::StatusCode;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const VAULT: &str = "https://my-vault.vault.azure.net";
    const VERSION: &str = "0123456789abcdef0123456789abcdef";

    fn kid(key_name: &str) -> String {
        format!("{VAULT}/keys/{key_name}/{VERSION}")
    }

    fn operation_response(key_name: &str, value: &[u8]) -> String {
        format!(
            r#"{{"kid":"{}","value":"{}"}}"#,
            kid(key_name),
            base64::encode_url_safe(value)
        )
    }

    fn gcm_response(key_name: &str, value: &[u8], iv: &[u8], tag: &[u8]) -> String {
        format!(
            r#"{{"kid":"{}","value":"{}","iv":"{}","tag":"{}"}}"#,
            kid(key_name),
            base64::encode_url_safe(value),
            base64::encode_url_safe(iv),
            base64::encode_url_safe(tag)
        )
    }

    /// An envelope as this source writes one, over `value`.
    fn sealed(key_name: &str, value: Vec<u8>) -> KeyId {
        KeyId::new(
            Envelope::new(kid(key_name), value, vec![7u8; GCM_IV_LEN], vec![8u8; 16])
                .encode()
                .unwrap(),
        )
    }

    /// A base64url field of a request body, decoded.
    fn field(body: &serde_json::Value, name: &str) -> Option<Vec<u8>> {
        body.get(name)
            .map(|v| base64::decode_url_safe(v.as_str().unwrap()).unwrap())
    }

    /// Stands in for the vault's AES-GCM check. `encrypt` remembers the
    /// `aad` under the IV it was sent and echoes the plaintext as the
    /// ciphertext. `decrypt` answers `400`, as Key Vault does for a tag
    /// that does not verify, unless it gets the same `aad` again.
    fn fake_vault() -> impl Fn(&RecordedRequest) -> (StatusCode, String) + Send + Sync + 'static {
        let sealed: Mutex<HashMap<Vec<u8>, Option<Vec<u8>>>> = Mutex::new(HashMap::new());
        move |request| {
            let body = request.json();
            let iv = field(&body, "iv").expect("every A256GCM call carries an IV");
            let aad = field(&body, "aad");
            let value = field(&body, "value").unwrap();

            if request.path().ends_with("/encrypt") {
                sealed.lock().unwrap().insert(iv.clone(), aad);
                (
                    StatusCode::Ok,
                    gcm_response("my-key", &value, &iv, &[8u8; 16]),
                )
            } else if sealed.lock().unwrap().get(&iv) == Some(&aad) {
                (StatusCode::Ok, operation_response("my-key", &value))
            } else {
                (
                    StatusCode::BadRequest,
                    r#"{"error":{"code":"BadParameter","message":"Decryption failed"}}"#.to_owned(),
                )
            }
        }
    }

    // --- zero-network unit tests ------------------------------------------

    /// The key id this source returns is the data key in encrypted form,
    /// not a reference the backend can resolve: losing it loses the key.
    #[test]
    fn the_key_id_is_the_encrypted_key() {
        assert_eq!(
            <AzureDataKeySource<32> as RetrieveDataKey<32>>::CUSTODY,
            KeyCustody::ClientHeld
        );
    }

    #[tokio::test]
    async fn generate_encrypts_locally_minted_material_with_the_binding_as_aad() {
        let (client, transport) = stub_client(&[&gcm_response(
            "my-key",
            &[9u8; 32],
            &[7u8; GCM_IV_LEN],
            &[8u8; 16],
        )]);
        let source = AzureDataKeySource::<32>::new(client, "my-key");

        let generated = source
            .generate_data_key(Binding::from("users/email"))
            .await
            .unwrap();

        let request = &transport.requests()[0];
        assert_eq!(request.path(), "/keys/my-key//encrypt");
        let body = request.json();
        assert_eq!(body["alg"], "A256GCM");
        // The encrypted value is the 32 bytes the adapter minted.
        let sent = field(&body, "value").unwrap();
        assert_eq!(sent, generated.plaintext.clone().risky_unwrap().to_vec());
        assert_eq!(field(&body, "iv").unwrap().len(), GCM_IV_LEN);
        assert_eq!(field(&body, "aad").unwrap(), b"users/email");

        // The KeyId is self-describing: the kid, the ciphertext, the IV and
        // the tag.
        let envelope = Envelope::decode(generated.key_id.as_bytes()).unwrap();
        assert_eq!(envelope.kid, kid("my-key"));
        assert_eq!(envelope.value, vec![9u8; 32]);
        assert_eq!(envelope.iv, vec![7u8; GCM_IV_LEN]);
        assert_eq!(envelope.tag, vec![8u8; 16]);
    }

    #[tokio::test]
    async fn an_empty_binding_sends_no_aad() {
        let (client, transport) = stub_client(&[&gcm_response(
            "my-key",
            &[9u8; 32],
            &[7u8; GCM_IV_LEN],
            &[8u8; 16],
        )]);
        let source = AzureDataKeySource::<32>::new(client, "my-key");

        source.generate_data_key(Binding::EMPTY).await.unwrap();

        assert!(transport.requests()[0].json().get("aad").is_none());
    }

    #[tokio::test]
    async fn retrieve_decrypts_against_the_exact_version_with_the_iv_tag_and_binding() {
        let (client, transport) = stub_client(&[&operation_response("my-key", &[4u8; 32])]);
        let source = AzureDataKeySource::<32>::new(client, "my-key");

        let retrieved = source
            .retrieve_data_key(
                &sealed("my-key", vec![9u8; 32]),
                Binding::from("users/email"),
            )
            .await
            .unwrap();

        assert_eq!(retrieved.risky_unwrap(), [4u8; 32]);
        let request = &transport.requests()[0];
        assert_eq!(request.path(), format!("/keys/my-key/{VERSION}/decrypt"));
        let body = request.json();
        assert_eq!(body["alg"], "A256GCM");
        assert_eq!(field(&body, "value").unwrap(), vec![9u8; 32]);
        assert_eq!(field(&body, "iv").unwrap(), vec![7u8; GCM_IV_LEN]);
        assert_eq!(field(&body, "tag").unwrap(), vec![8u8; 16]);
        assert_eq!(field(&body, "aad").unwrap(), b"users/email");
    }

    #[tokio::test]
    async fn a_key_comes_back_under_the_binding_it_was_minted_with() {
        let (client, _) = responder_client(fake_vault());
        let source = AzureDataKeySource::<32>::new(client, "my-key");

        let generated = source
            .generate_data_key(Binding::from("users/email"))
            .await
            .unwrap();
        let retrieved = source
            .retrieve_data_key(&generated.key_id, Binding::from("users/email"))
            .await
            .unwrap();

        assert_eq!(retrieved.risky_unwrap(), generated.plaintext.risky_unwrap());
    }

    #[tokio::test]
    async fn a_retrieve_under_a_different_binding_fails() {
        let (client, transport) = responder_client(fake_vault());
        let source = AzureDataKeySource::<32>::new(client, "my-key");

        let generated = source
            .generate_data_key(Binding::from("users/email"))
            .await
            .unwrap();
        let error = source
            .retrieve_data_key(&generated.key_id, Binding::from("users/name"))
            .await
            .unwrap_err();

        assert!(matches!(error, Error::Azure(_)), "{error}");
        // The wrong binding reached the vault, which is what refused it.
        assert_eq!(
            field(&transport.requests()[1].json(), "aad").unwrap(),
            b"users/name"
        );
        // An empty binding is a different binding too.
        assert!(source
            .retrieve_data_key(&generated.key_id, Binding::EMPTY)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn retrieve_refuses_a_key_id_belonging_to_another_key_without_calling_the_vault() {
        let (client, transport) = stub_client(&[]);
        let source = AzureDataKeySource::<32>::new(client, "my-key");

        let error = source
            .retrieve_data_key(&sealed("someone-elses-key", vec![1u8; 16]), Binding::EMPTY)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            Error::ForeignKey { ref expected, ref found, .. }
                if expected == "my-key" && found == "someone-elses-key"
        ));
        // The message names which of the two blobs the caller handed over.
        assert_eq!(
            error.to_string(),
            r#"the KeyId names key "someone-elses-key", but this source is bound to key "my-key""#
        );
        assert_eq!(transport.call_count(), 0);
    }

    #[tokio::test]
    async fn decrypt_refuses_a_ciphertext_belonging_to_another_key_and_says_so() {
        let ciphertext = sealed("someone-elses-key", b"ciphertext".to_vec());
        let (client, transport) = stub_client(&[]);
        let source = AzureDataKeySource::<32>::new(client, "my-key");

        let error = source.decrypt(ciphertext.as_bytes()).await.unwrap_err();

        // The same guard, reported against the other blob.
        assert_eq!(
            error.to_string(),
            r#"the ciphertext names key "someone-elses-key", but this source is bound to key "my-key""#
        );
        assert_eq!(transport.call_count(), 0);
    }

    #[tokio::test]
    async fn retrieve_rejects_a_corrupted_key_id_without_calling_the_vault() {
        let (client, transport) = stub_client(&[]);
        let source = AzureDataKeySource::<32>::new(client, "my-key");

        let error = source
            .retrieve_data_key(&KeyId::new(vec![0xff, 0xff, 0xff]), Binding::EMPTY)
            .await
            .unwrap_err();

        assert!(matches!(error, Error::MalformedKeyId(_)));
        assert_eq!(transport.call_count(), 0);
    }

    #[tokio::test]
    async fn retrieve_rejects_key_material_of_the_wrong_length() {
        let (client, _) = stub_client(&[&operation_response("my-key", &[4u8; 16])]);
        let source = AzureDataKeySource::<32>::new(client, "my-key");

        let error = source
            .retrieve_data_key(&sealed("my-key", vec![1u8; 16]), Binding::EMPTY)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            Error::UnexpectedKeyLength {
                expected: 32,
                received: 16
            }
        ));
    }

    #[tokio::test]
    async fn an_encrypt_response_without_a_tag_is_an_error() {
        let (client, _) = stub_client(&[&operation_response("my-key", &[9u8; 32])]);
        let source = AzureDataKeySource::<32>::new(client, "my-key");

        let Err(error) = source.generate_data_key(Binding::EMPTY).await else {
            panic!("a response without a tag must not produce a KeyId");
        };

        assert!(matches!(error, Error::MissingField("authentication tag")));
    }

    #[tokio::test]
    async fn batch_generate_makes_one_call_per_item_each_under_its_own_binding() {
        let responses: Vec<String> = (0..3)
            .map(|i| gcm_response("my-key", &[i as u8; 32], &[7u8; GCM_IV_LEN], &[8u8; 16]))
            .collect();
        let borrowed: Vec<&str> = responses.iter().map(String::as_str).collect();
        let (client, transport) = stub_client(&borrowed);
        let source = AzureDataKeySource::<32>::new(client, "my-key");

        let keys = source
            .generate_data_keys(&[Binding::from("a"), Binding::from("b"), Binding::from("c")])
            .await
            .unwrap();

        assert_eq!(keys.len(), 3);
        assert_eq!(transport.call_count(), 3);
        let mut sent: Vec<Vec<u8>> = transport
            .requests()
            .iter()
            .map(|request| field(&request.json(), "aad").unwrap())
            .collect();
        sent.sort();
        assert_eq!(sent, [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    }

    #[tokio::test]
    async fn batch_retrieve_dedupes_repeated_key_ids() {
        let key_id = sealed("my-key", vec![1u8; 16]);
        let (client, transport) = stub_client(&[&operation_response("my-key", &[4u8; 32])]);
        let source = AzureDataKeySource::<32>::new(client, "my-key");

        let retrieved = source
            .retrieve_data_keys(&crate::data_key::with_empty_binding(&[
                key_id.clone(),
                key_id.clone(),
                key_id,
            ]))
            .await
            .unwrap();

        assert_eq!(retrieved.len(), 3);
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn encrypt_sends_an_iv_and_no_aad_and_keeps_the_tag() {
        let (client, transport) = stub_client(&[&gcm_response(
            "my-key",
            b"ciphertext",
            &[7u8; GCM_IV_LEN],
            &[8u8; 16],
        )]);
        let source = AzureDataKeySource::<32>::new(client, "my-key");

        let ciphertext = source
            .encrypt(Protected::new(b"hello".to_vec()))
            .await
            .unwrap();

        let body = transport.requests()[0].json();
        assert_eq!(body["alg"], "A256GCM");
        assert_eq!(field(&body, "iv").unwrap().len(), GCM_IV_LEN);
        assert!(body.get("aad").is_none());

        let envelope = Envelope::decode(&ciphertext).unwrap();
        assert_eq!(envelope.value, b"ciphertext");
        assert_eq!(envelope.iv, vec![7u8; GCM_IV_LEN]);
        assert_eq!(envelope.tag, vec![8u8; 16]);
    }

    #[tokio::test]
    async fn every_encryption_sends_a_fresh_iv() {
        // The adapter makes the IV, not the vault, and an IV used twice under
        // one AES-GCM key breaks both confidentiality and integrity. The stub
        // responses can repeat an IV: the test reads the IVs from the requests.
        // A data key and a direct encryption share one path, so the test
        // makes one of each.
        let first = gcm_response("my-key", &[1u8; 32], &[7u8; GCM_IV_LEN], &[8u8; 16]);
        let second = gcm_response("my-key", b"ciphertext", &[7u8; GCM_IV_LEN], &[8u8; 16]);
        let (client, transport) = stub_client(&[&first, &second]);
        let source = AzureDataKeySource::<32>::new(client, "my-key");

        source.generate_data_key(Binding::EMPTY).await.unwrap();
        source
            .encrypt(Protected::new(b"hello".to_vec()))
            .await
            .unwrap();

        let ivs: Vec<Vec<u8>> = transport
            .requests()
            .iter()
            .map(|request| field(&request.json(), "iv").unwrap())
            .collect();
        assert_eq!(ivs.len(), 2);
        assert_ne!(ivs[0], ivs[1]);
    }

    #[tokio::test]
    async fn decrypt_replays_the_iv_and_tag_the_ciphertext_carries() {
        let ciphertext = sealed("my-key", b"ciphertext".to_vec());
        let (client, transport) = stub_client(&[&operation_response("my-key", b"hello")]);
        let source = AzureDataKeySource::<32>::new(client, "my-key");

        let plaintext = source.decrypt(ciphertext.as_bytes()).await.unwrap();

        assert_eq!(plaintext.risky_unwrap(), b"hello".to_vec());
        let request = &transport.requests()[0];
        assert_eq!(request.path(), format!("/keys/my-key/{VERSION}/decrypt"));
        let body = request.json();
        assert_eq!(field(&body, "iv").unwrap(), vec![7u8; GCM_IV_LEN]);
        assert_eq!(field(&body, "tag").unwrap(), vec![8u8; 16]);
        assert!(body.get("aad").is_none());
    }

    #[tokio::test]
    async fn a_pinned_version_is_used_for_new_work() {
        let (client, transport) = stub_client(&[&gcm_response(
            "my-key",
            &[9u8; 32],
            &[7u8; GCM_IV_LEN],
            &[8u8; 16],
        )]);
        let source = AzureDataKeySource::<32>::new(client, "my-key").with_key_version("v7");

        source.generate_data_key(Binding::EMPTY).await.unwrap();

        assert_eq!(transport.requests()[0].path(), "/keys/my-key/v7/encrypt");
    }

    // There are no Lowkey Vault integration tests here. Lowkey Vault 7.3.98
    // rejects `A256GCM` outright (HTTP 400, before it looks at the key), and
    // `A256GCM` is the only data-key path. CIP-4072 tracks the gap.
}
