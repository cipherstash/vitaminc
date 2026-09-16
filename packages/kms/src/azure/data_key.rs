use super::envelope::{Envelope, EnvelopeError};
use crate::crypt::{DecryptWithKey, EncryptWithKey};
use crate::data_key::{
    dedup_retrieve, fan_out_generate, BatchGenerateDataKey, BatchRetrieveDataKey, GenerateDataKey,
    GeneratedDataKey, KeyIsolation, KeyReconstruction, RetrieveDataKey,
};
use crate::key_id::KeyId;
use azure_security_keyvault_keys::models::{
    EncryptionAlgorithm, KeyClientEncryptOptions, KeyClientWrapKeyOptions, KeyOperationParameters,
    KeyOperationResult,
};
use azure_security_keyvault_keys::{KeyClient, ResourceId};
use std::str::FromStr;
use thiserror::Error;
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::{Generatable, SafeRand};

/// The AES-GCM initialization vector length Key Vault's `A256GCM` expects,
/// in bytes. The service will not invent one, so the adapter mints it.
const GCM_IV_LEN: usize = 12;

/// Which kind of backend key an [`AzureDataKeySource`] is bound to.
///
/// Key Vault picks the algorithm from the key type, so the caller states the
/// type once at construction and the adapter chooses the algorithms:
///
/// | Kind | Wrap and unwrap | Encrypt and decrypt |
/// |---|---|---|
/// | [`Rsa`](AzureKeyKind::Rsa) | `RSA-OAEP-256` | `RSA-OAEP-256` |
/// | [`OctHsm`](AzureKeyKind::OctHsm) | `A256KW` | `A256GCM` |
///
/// The CBC algorithms are deliberately absent: they carry no authentication
/// tag, and Microsoft's own documentation warns against decrypting their
/// output without a separate integrity check.
///
/// There is no EC member. A Key Vault EC key cannot wrap, unwrap, encrypt or
/// decrypt at all — Microsoft's support matrix marks every one of those "NA",
/// because Key Vault has no ECIES equivalent. Nothing in the local state can
/// catch that at construction, since the key type is only knowable from the
/// vault; an [`AzureDataKeySource`] bound to an EC key therefore fails on its
/// first call with the vault's own rejection, as [`Error::Azure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AzureKeyKind {
    /// An `RSA` or `RSA-HSM` key.
    Rsa,
    /// An `oct-HSM` 256-bit symmetric key. Production-ready on Managed HSM
    /// only; Key Vault Premium offers it in preview, and Standard Key Vault
    /// not at all.
    OctHsm,
}

impl AzureKeyKind {
    /// The algorithm for `wrapKey` and `unwrapKey`.
    fn wrap_algorithm(self) -> EncryptionAlgorithm {
        match self {
            Self::Rsa => EncryptionAlgorithm::RsaOaep256,
            Self::OctHsm => EncryptionAlgorithm::A256Kw,
        }
    }

    /// The algorithm for `encrypt` and `decrypt`.
    fn encrypt_algorithm(self) -> EncryptionAlgorithm {
        match self {
            Self::Rsa => EncryptionAlgorithm::RsaOaep256,
            Self::OctHsm => EncryptionAlgorithm::A256Gcm,
        }
    }

    /// Whether [`Self::encrypt_algorithm`] is authenticated, and so needs an
    /// IV on the way in and returns a tag.
    fn encrypt_is_aead(self) -> bool {
        matches!(self, Self::OctHsm)
    }
}

/// Errors from the Azure Key Vault data key source.
#[derive(Debug, Error)]
pub enum Error {
    /// The vault, the transport or the credential failed. An
    /// [`AzureDataKeySource`] bound to an EC key surfaces here on its first
    /// call: EC keys support none of `wrapKey`, `unwrapKey`, `encrypt` or
    /// `decrypt`.
    #[error(transparent)]
    Azure(#[from] azure_core::Error),
    /// The local CSPRNG could not be seeded, so no data key was minted.
    #[error("could not generate data key material locally: {0}")]
    Random(#[from] vitaminc_random::RandomError),
    /// A successful response left out a field the operation must produce.
    #[error("Azure Key Vault returned no {0}")]
    MissingField(&'static str),
    /// The unwrapped key material is not `N` bytes. Guards the
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
    /// The ciphertext was produced under the other [`AzureKeyKind`]: an
    /// AES-GCM ciphertext carries an IV and a tag, an RSA-OAEP one does not.
    #[error("the ciphertext {found} an IV and a tag, so it was not produced by this key kind")]
    CiphertextKindMismatch { found: &'static str },
}

/// An Azure Key Vault-backed data key source, with per-value key isolation
/// (`KeyIsolation::PerValue`).
///
/// Key Vault has no "generate data key" call, so a data key is two steps:
/// mint `N` bytes locally with a CSPRNG, then `wrapKey` them under the
/// backend key. [`RetrieveDataKey`] reverses that with `unwrapKey`. The same
/// type also encrypts and decrypts small payloads directly under the backend
/// key ([`EncryptWithKey`]/[`DecryptWithKey`]) — for an
/// [`Rsa`](AzureKeyKind::Rsa) key that is a round trip doing what a caller
/// holding the public key could do locally, which Microsoft's own guidance
/// prefers.
///
/// The adapter binds to a key *name*. New work (`wrapKey`, `encrypt`) goes to
/// whichever version the vault currently considers current, and the `KeyId`
/// and the ciphertext both record the exact version that did the work, so
/// rotating the key never strands data. [`Self::with_key_version`] pins a
/// version instead.
///
/// Neither `wrapKey` nor `encrypt` has a batch endpoint on Key Vault, so
/// [`BatchGenerateDataKey`] is N round trips ([`fan_out_generate`]). Wrap
/// this source in [`PooledDataKeySource`](crate::PooledDataKeySource) to
/// trade per-value isolation for one round trip per batch.
pub struct AzureDataKeySource<const N: usize> {
    client: KeyClient,
    key_name: String,
    key_version: Option<String>,
    kind: AzureKeyKind,
}

impl<const N: usize> AzureDataKeySource<N> {
    /// Binds to the key named `key_name` in the vault `client` points at.
    ///
    /// `kind` states what sort of key that is; see [`AzureKeyKind`] for what
    /// each one means and why there is no EC option.
    pub fn new(client: KeyClient, key_name: impl Into<String>, kind: AzureKeyKind) -> Self {
        Self {
            client,
            key_name: key_name.into(),
            key_version: None,
            kind,
        }
    }

    /// Pins new work to one key version instead of the vault's current one.
    ///
    /// Retrieval and decryption always use the version recorded in the
    /// `KeyId` or the ciphertext, so this only affects `wrapKey` and
    /// `encrypt`. Pinning is also what makes the Lowkey Vault emulator
    /// usable: it serves no route for the empty version segment that means
    /// "current version" to the real service.
    #[must_use]
    pub fn with_key_version(mut self, key_version: impl Into<String>) -> Self {
        self.key_version = Some(key_version.into());
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
        // An empty version means "current", which is what the service does
        // with an empty path segment.
        Ok(resource.version.unwrap_or_default())
    }
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
    let received = bytes.len();
    bytes.try_into().map_err(|_| Error::UnexpectedKeyLength {
        expected: N,
        received,
    })
}

/// The `kid` and `value` every crypto operation must return.
fn kid_and_value(result: KeyOperationResult) -> Result<(String, Vec<u8>), Error> {
    let kid = result.kid.ok_or(Error::MissingField("a kid"))?;
    let value = result.result.ok_or(Error::MissingField("a result value"))?;
    Ok((kid, value))
}

fn envelope_to_bytes(envelope: &Envelope) -> Result<Vec<u8>, Error> {
    envelope
        .encode()
        .map_err(|e: EnvelopeError| Error::MalformedKeyId(e.to_string()))
}

impl<const N: usize> GenerateDataKey<N> for AzureDataKeySource<N> {
    type Error = Error;

    async fn generate_data_key(&self) -> Result<GeneratedDataKey<N>, Self::Error> {
        let mut rng = SafeRand::from_entropy()?;
        let plaintext: Protected<[u8; N]> = Generatable::random(&mut rng)?;

        let parameters = KeyOperationParameters {
            algorithm: Some(self.kind.wrap_algorithm()),
            value: Some(plaintext.clone().risky_unwrap().to_vec()),
            ..Default::default()
        };
        let options = KeyClientWrapKeyOptions {
            key_version: self.key_version.clone(),
            ..Default::default()
        };
        let result = self
            .client
            .wrap_key(&self.key_name, parameters.try_into()?, Some(options))
            .await?
            .into_model()?;

        let (kid, value) = kid_and_value(result)?;
        Ok(GeneratedDataKey {
            plaintext,
            key_id: KeyId::new(envelope_to_bytes(&Envelope::plain(kid, value))?),
        })
    }
}

impl<const N: usize> RetrieveDataKey<N> for AzureDataKeySource<N> {
    type Error = Error;

    /// The vault holds the whole wrapping key and unwraps on its own, so the
    /// `KeyId` plus the caller's Entra ID authorization is enough.
    const RECONSTRUCTION: KeyReconstruction = KeyReconstruction::ServerOnly;

    async fn retrieve_data_key(&self, key_id: &KeyId) -> Result<Protected<[u8; N]>, Self::Error> {
        let envelope = Envelope::decode(key_id.as_bytes())
            .map_err(|e| Error::MalformedKeyId(e.to_string()))?;
        let version = self.version_of(&envelope.kid, Reference::KeyId)?;

        let parameters = KeyOperationParameters {
            algorithm: Some(self.kind.wrap_algorithm()),
            value: Some(envelope.value),
            ..Default::default()
        };
        let result = self
            .client
            .unwrap_key(&self.key_name, &version, parameters.try_into()?, None)
            .await?
            .into_model()?;

        let value = result.result.ok_or(Error::MissingField("a result value"))?;
        Ok(Protected::new(into_sized(value)?))
    }
}

impl<const N: usize> BatchGenerateDataKey<N> for AzureDataKeySource<N> {
    const ISOLATION: KeyIsolation = KeyIsolation::PerValue;

    async fn generate_data_keys(
        &self,
        count: usize,
    ) -> Result<Vec<GeneratedDataKey<N>>, Self::Error> {
        fan_out_generate(self, count).await
    }
}

impl<const N: usize> BatchRetrieveDataKey<N> for AzureDataKeySource<N> {
    async fn retrieve_data_keys(
        &self,
        key_ids: &[KeyId],
    ) -> Result<Vec<Protected<[u8; N]>>, Self::Error> {
        dedup_retrieve(self, key_ids).await
    }
}

impl<const N: usize> EncryptWithKey for AzureDataKeySource<N> {
    type Error = Error;

    async fn encrypt(&self, plaintext: Protected<Vec<u8>>) -> Result<Vec<u8>, Self::Error> {
        let sent_iv = if self.kind.encrypt_is_aead() {
            let mut rng = SafeRand::from_entropy()?;
            let iv: [u8; GCM_IV_LEN] = Generatable::random(&mut rng)?;
            Some(iv.to_vec())
        } else {
            None
        };

        let parameters = KeyOperationParameters {
            algorithm: Some(self.kind.encrypt_algorithm()),
            value: Some(plaintext.risky_unwrap()),
            iv: sent_iv.clone(),
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

        let iv = result.iv.clone().or(sent_iv);
        let tag = result.authentication_tag.clone();
        let (kid, value) = kid_and_value(result)?;

        let envelope = if self.kind.encrypt_is_aead() {
            Envelope::aead(
                kid,
                value,
                iv.ok_or(Error::MissingField("an IV"))?,
                tag.ok_or(Error::MissingField("an authentication tag"))?,
            )
        } else {
            Envelope::plain(kid, value)
        };
        envelope
            .encode()
            .map_err(|e| Error::MalformedCiphertext(e.to_string()))
    }
}

impl<const N: usize> DecryptWithKey for AzureDataKeySource<N> {
    type Error = Error;

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Protected<Vec<u8>>, Self::Error> {
        let envelope =
            Envelope::decode(ciphertext).map_err(|e| Error::MalformedCiphertext(e.to_string()))?;
        let version = self.version_of(&envelope.kid, Reference::Ciphertext)?;

        match (self.kind.encrypt_is_aead(), envelope.iv.is_some()) {
            (true, false) => {
                return Err(Error::CiphertextKindMismatch {
                    found: "carries no",
                })
            }
            (false, true) => return Err(Error::CiphertextKindMismatch { found: "carries" }),
            _ => {}
        }

        let parameters = KeyOperationParameters {
            algorithm: Some(self.kind.encrypt_algorithm()),
            value: Some(envelope.value),
            iv: envelope.iv,
            authentication_tag: envelope.tag,
            ..Default::default()
        };
        let result = self
            .client
            .decrypt(&self.key_name, &version, parameters.try_into()?, None)
            .await?
            .into_model()?;

        let value = result.result.ok_or(Error::MissingField("a result value"))?;
        Ok(Protected::new(value))
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{create_key, lowkey_client, stub_client, unique_key_name};
    use super::*;
    use azure_core::base64;
    use azure_security_keyvault_keys::models::{KeyOperation, KeyType};

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

    // --- zero-network unit tests ------------------------------------------

    #[tokio::test]
    async fn generate_wraps_locally_minted_material_with_rsa_oaep_256() {
        let (client, transport) = stub_client(&[&operation_response("my-key", &[9u8; 256])]);
        let source = AzureDataKeySource::<32>::new(client, "my-key", AzureKeyKind::Rsa);

        let generated = source.generate_data_key().await.unwrap();

        let request = &transport.requests()[0];
        assert_eq!(request.path(), "/keys/my-key//wrapkey");
        let body = request.json();
        assert_eq!(body["alg"], "RSA-OAEP-256");
        // The wrapped value is the 32 bytes the adapter minted, base64url.
        let sent = base64::decode_url_safe(body["value"].as_str().unwrap()).unwrap();
        assert_eq!(sent.len(), 32);
        assert_eq!(sent, generated.plaintext.clone().risky_unwrap().to_vec());
        assert!(body.get("iv").is_none());

        // The KeyId is self-describing: the kid plus the wrapped bytes.
        let envelope = Envelope::decode(generated.key_id.as_bytes()).unwrap();
        assert_eq!(envelope.kid, kid("my-key"));
        assert_eq!(envelope.value, vec![9u8; 256]);
    }

    #[tokio::test]
    async fn generate_wraps_with_a256kw_for_an_oct_hsm_key() {
        let (client, transport) = stub_client(&[&operation_response("my-key", &[3u8; 40])]);
        let source = AzureDataKeySource::<32>::new(client, "my-key", AzureKeyKind::OctHsm);

        source.generate_data_key().await.unwrap();

        assert_eq!(transport.requests()[0].json()["alg"], "A256KW");
    }

    #[tokio::test]
    async fn retrieve_unwraps_against_the_exact_version_the_key_id_names() {
        let wrapped = vec![9u8; 256];
        let key_id = KeyId::new(
            Envelope::plain(kid("my-key"), wrapped.clone())
                .encode()
                .unwrap(),
        );
        let (client, transport) = stub_client(&[&operation_response("my-key", &[4u8; 32])]);
        let source = AzureDataKeySource::<32>::new(client, "my-key", AzureKeyKind::Rsa);

        let retrieved = source.retrieve_data_key(&key_id).await.unwrap();

        assert_eq!(retrieved.risky_unwrap(), [4u8; 32]);
        let request = &transport.requests()[0];
        assert_eq!(request.path(), format!("/keys/my-key/{VERSION}/unwrapkey"));
        assert_eq!(
            base64::decode_url_safe(request.json()["value"].as_str().unwrap()).unwrap(),
            wrapped
        );
    }

    #[tokio::test]
    async fn retrieve_refuses_a_key_id_belonging_to_another_key_without_calling_the_vault() {
        let key_id = KeyId::new(
            Envelope::plain(kid("someone-elses-key"), vec![1u8; 16])
                .encode()
                .unwrap(),
        );
        let (client, transport) = stub_client(&[]);
        let source = AzureDataKeySource::<32>::new(client, "my-key", AzureKeyKind::Rsa);

        let error = source.retrieve_data_key(&key_id).await.unwrap_err();

        assert!(matches!(
            error,
            Error::ForeignKey { ref expected, ref found, .. }
                if expected == "my-key" && found == "someone-elses-key"
        ));
        assert_eq!(transport.call_count(), 0);
    }

    #[tokio::test]
    async fn retrieve_rejects_a_corrupted_key_id_without_calling_the_vault() {
        let (client, transport) = stub_client(&[]);
        let source = AzureDataKeySource::<32>::new(client, "my-key", AzureKeyKind::Rsa);

        let error = source
            .retrieve_data_key(&KeyId::new(vec![0xff, 0xff, 0xff]))
            .await
            .unwrap_err();

        assert!(matches!(error, Error::MalformedKeyId(_)));
        assert_eq!(transport.call_count(), 0);
    }

    #[tokio::test]
    async fn retrieve_rejects_key_material_of_the_wrong_length() {
        let key_id = KeyId::new(
            Envelope::plain(kid("my-key"), vec![1u8; 16])
                .encode()
                .unwrap(),
        );
        let (client, _) = stub_client(&[&operation_response("my-key", &[4u8; 16])]);
        let source = AzureDataKeySource::<32>::new(client, "my-key", AzureKeyKind::Rsa);

        let error = source.retrieve_data_key(&key_id).await.unwrap_err();

        assert!(matches!(
            error,
            Error::UnexpectedKeyLength {
                expected: 32,
                received: 16
            }
        ));
    }

    #[tokio::test]
    async fn batch_generate_makes_one_call_per_item() {
        let responses: Vec<String> = (0..3)
            .map(|i| operation_response("my-key", &[i as u8; 64]))
            .collect();
        let borrowed: Vec<&str> = responses.iter().map(String::as_str).collect();
        let (client, transport) = stub_client(&borrowed);
        let source = AzureDataKeySource::<32>::new(client, "my-key", AzureKeyKind::Rsa);

        let keys = source.generate_data_keys(3).await.unwrap();

        assert_eq!(keys.len(), 3);
        assert_eq!(transport.call_count(), 3);
        assert_eq!(AzureDataKeySource::<32>::ISOLATION, KeyIsolation::PerValue);
    }

    #[tokio::test]
    async fn batch_retrieve_dedupes_repeated_key_ids() {
        let key_id = KeyId::new(
            Envelope::plain(kid("my-key"), vec![1u8; 16])
                .encode()
                .unwrap(),
        );
        let (client, transport) = stub_client(&[&operation_response("my-key", &[4u8; 32])]);
        let source = AzureDataKeySource::<32>::new(client, "my-key", AzureKeyKind::Rsa);

        let retrieved = source
            .retrieve_data_keys(&[key_id.clone(), key_id.clone(), key_id])
            .await
            .unwrap();

        assert_eq!(retrieved.len(), 3);
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn encrypt_under_an_oct_hsm_key_sends_an_iv_and_keeps_the_tag() {
        let (client, transport) = stub_client(&[&gcm_response(
            "my-key",
            b"ciphertext",
            &[7u8; GCM_IV_LEN],
            &[8u8; 16],
        )]);
        let source = AzureDataKeySource::<32>::new(client, "my-key", AzureKeyKind::OctHsm);

        let ciphertext = source
            .encrypt(Protected::new(b"hello".to_vec()))
            .await
            .unwrap();

        let body = transport.requests()[0].json();
        assert_eq!(body["alg"], "A256GCM");
        assert_eq!(
            base64::decode_url_safe(body["iv"].as_str().unwrap())
                .unwrap()
                .len(),
            GCM_IV_LEN
        );

        let envelope = Envelope::decode(&ciphertext).unwrap();
        assert_eq!(envelope.value, b"ciphertext");
        assert_eq!(envelope.iv.unwrap(), vec![7u8; GCM_IV_LEN]);
        assert_eq!(envelope.tag.unwrap(), vec![8u8; 16]);
    }

    #[tokio::test]
    async fn encrypt_under_an_rsa_key_sends_no_iv() {
        let (client, transport) = stub_client(&[&operation_response("my-key", b"ciphertext")]);
        let source = AzureDataKeySource::<32>::new(client, "my-key", AzureKeyKind::Rsa);

        let ciphertext = source
            .encrypt(Protected::new(b"hello".to_vec()))
            .await
            .unwrap();

        let body = transport.requests()[0].json();
        assert_eq!(body["alg"], "RSA-OAEP-256");
        assert!(body.get("iv").is_none());
        assert!(Envelope::decode(&ciphertext).unwrap().iv.is_none());
    }

    #[tokio::test]
    async fn decrypt_replays_the_iv_and_tag_the_ciphertext_carries() {
        let ciphertext = Envelope::aead(
            kid("my-key"),
            b"ciphertext".to_vec(),
            vec![7u8; GCM_IV_LEN],
            vec![8u8; 16],
        )
        .encode()
        .unwrap();
        let (client, transport) = stub_client(&[&operation_response("my-key", b"hello")]);
        let source = AzureDataKeySource::<32>::new(client, "my-key", AzureKeyKind::OctHsm);

        let plaintext = source.decrypt(&ciphertext).await.unwrap();

        assert_eq!(plaintext.risky_unwrap(), b"hello".to_vec());
        let request = &transport.requests()[0];
        assert_eq!(request.path(), format!("/keys/my-key/{VERSION}/decrypt"));
        let body = request.json();
        assert_eq!(
            base64::decode_url_safe(body["iv"].as_str().unwrap()).unwrap(),
            vec![7u8; GCM_IV_LEN]
        );
        assert_eq!(
            base64::decode_url_safe(body["tag"].as_str().unwrap()).unwrap(),
            vec![8u8; 16]
        );
    }

    #[tokio::test]
    async fn decrypt_refuses_a_ciphertext_from_the_other_key_kind() {
        let rsa_ciphertext = Envelope::plain(kid("my-key"), b"ciphertext".to_vec())
            .encode()
            .unwrap();
        let (client, transport) = stub_client(&[]);
        let source = AzureDataKeySource::<32>::new(client, "my-key", AzureKeyKind::OctHsm);

        let error = source.decrypt(&rsa_ciphertext).await.unwrap_err();

        assert!(matches!(error, Error::CiphertextKindMismatch { .. }));
        assert_eq!(transport.call_count(), 0);
    }

    #[tokio::test]
    async fn a_pinned_version_is_used_for_new_work() {
        let (client, transport) = stub_client(&[&operation_response("my-key", &[9u8; 256])]);
        let source = AzureDataKeySource::<32>::new(client, "my-key", AzureKeyKind::Rsa)
            .with_key_version("v7");

        source.generate_data_key().await.unwrap();

        assert_eq!(transport.requests()[0].path(), "/keys/my-key/v7/wrapkey");
    }

    // --- Lowkey Vault integration tests -----------------------------------
    //
    // These need `docker compose -f packages/kms/docker-compose.yml up -d`.
    //
    // Only the RSA kind is exercised here. Lowkey Vault 7.3.98 rejects both
    // `A256KW` and `A256GCM` outright (HTTP 400, before it looks at the key),
    // so the oct-HSM path has stub-transport cover above and nothing here.

    async fn lowkey_rsa_source() -> AzureDataKeySource<32> {
        let client = lowkey_client();
        let key_name = unique_key_name("dk-rsa");
        // Lowkey Vault denies any operation the key was not created with,
        // and it maps `wrapKey`/`unwrapKey` onto the ENCRYPT/DECRYPT
        // permissions, so all four are granted.
        let version = create_key(
            &client,
            &key_name,
            KeyType::Rsa,
            Some(2048),
            None,
            &[
                KeyOperation::Encrypt,
                KeyOperation::Decrypt,
                KeyOperation::WrapKey,
                KeyOperation::UnwrapKey,
            ],
        )
        .await;
        AzureDataKeySource::new(client, key_name, AzureKeyKind::Rsa).with_key_version(version)
    }

    #[tokio::test]
    async fn lowkey_generate_then_retrieve_round_trips() {
        let source = lowkey_rsa_source().await;

        let generated = source.generate_data_key().await.unwrap();
        let retrieved = source.retrieve_data_key(&generated.key_id).await.unwrap();

        assert_eq!(retrieved.risky_unwrap(), generated.plaintext.risky_unwrap());
    }

    #[tokio::test]
    async fn lowkey_batch_generate_then_batch_retrieve_round_trips() {
        let source = lowkey_rsa_source().await;

        let generated = source.generate_data_keys(3).await.unwrap();
        let ids: Vec<KeyId> = generated.iter().map(|k| k.key_id.clone()).collect();
        let retrieved = source.retrieve_data_keys(&ids).await.unwrap();

        assert_eq!(retrieved.len(), 3);
        for (got, want) in retrieved.into_iter().zip(generated) {
            assert_eq!(got.risky_unwrap(), want.plaintext.risky_unwrap());
        }
        // Per-value isolation: three distinct keys, three distinct ids.
        assert_eq!(AzureDataKeySource::<32>::ISOLATION, KeyIsolation::PerValue);
    }

    #[tokio::test]
    async fn lowkey_encrypt_then_decrypt_round_trips_under_an_rsa_key() {
        let source = lowkey_rsa_source().await;

        let ciphertext = source
            .encrypt(Protected::new(b"a short secret".to_vec()))
            .await
            .unwrap();
        let plaintext = source.decrypt(&ciphertext).await.unwrap();

        assert_eq!(plaintext.risky_unwrap(), b"a short secret".to_vec());
    }

    #[tokio::test]
    async fn lowkey_retrieve_refuses_a_key_id_from_another_key() {
        let source = lowkey_rsa_source().await;
        let other = lowkey_rsa_source().await;

        let generated = other.generate_data_key().await.unwrap();
        let error = source
            .retrieve_data_key(&generated.key_id)
            .await
            .unwrap_err();

        assert!(matches!(error, Error::ForeignKey { .. }));
    }
}
