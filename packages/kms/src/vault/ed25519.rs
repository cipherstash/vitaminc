use super::batch::{SignMessageRequest, VerifyMessageRequest};
use super::{b64_decode, b64_encode, strip_key_version, with_key_version};
use crate::encoding::{ed25519_spki, EncodingError};
use crate::sign::{GetPublicKey, SignMessage, VerifyMessage};
use thiserror::Error;
use vaultrs::api::transit::requests::{ExportKeyType, ExportVersion};
use vaultrs::api::transit::responses::{SignDataResponse, VerifySignedDataResponse};
use vaultrs::client::VaultClient;
use vitaminc_protected::{Controlled, Protected};

/// The length in bytes of every Ed25519 signature (RFC 8032).
const SIGNATURE_LEN: usize = 64;

/// Errors from [`VaultEd25519Key`].
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Vault(#[from] vaultrs::error::ClientError),
    #[error("Vault returned a value that is not valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    /// The public key comes back as the raw 32 bytes and has to become DER
    /// `SubjectPublicKeyInfo` for the trait boundary (ADR 0002).
    #[error(transparent)]
    Encoding(#[from] EncodingError),
    /// The adapter is bound to one key version and asks for it by number,
    /// so a signature under any other version means the response does not
    /// match the request.
    #[error("Vault returned {returned:?}, expected a `vault:v{expected}:` signature")]
    UnexpectedKeyVersion { expected: u32, returned: String },
    /// `export/public-key/:name/:version` answers with a version-keyed
    /// map; the bound version has to be in it.
    #[error("Vault exported no public key for version {0}")]
    MissingPublicKey(u32),
    /// An Ed25519 signature is always 64 bytes. Any other length means the
    /// bound Transit key is not an `ed25519` key: an ECDSA or RSA key also
    /// signs a message sent with `prehashed: false`, after it hashes the
    /// message itself.
    #[error("Vault returned a {0}-byte signature, but an Ed25519 signature is 64 bytes")]
    NotEd25519Signature(usize),
}

/// A Vault Transit-backed Ed25519 key, bound to one `ed25519` Transit key
/// and **one key version** at construction.
///
/// [`SignMessage`] sends the whole message, base64-encoded, with
/// `prehashed: false`: Vault Transit signs only pure Ed25519 (RFC 8032),
/// which hashes inside the signature, and refuses a pre-hashed input.
/// That is why this is its own type and not a
/// [`SignatureAlgorithm`](crate::SignatureAlgorithm) of
/// [`VaultSigningKey`](super::VaultSigningKey): it does not implement
/// [`Sign`](crate::Sign), so a digest cannot go to it by mistake.
///
/// Signatures cross the trait boundary as the raw 64 bytes, and the public
/// key as DER `SubjectPublicKeyInfo` (ADR 0002).
///
/// A digest key does not take a message either. Neither of these compiles:
///
/// ```compile_fail
/// fn signs_a_digest<K: vitaminc_kms::Sign>() {}
/// signs_a_digest::<vitaminc_kms::vault::VaultEd25519Key>();
/// ```
///
/// ```compile_fail
/// fn signs_a_message<K: vitaminc_kms::SignMessage>() {}
/// signs_a_message::<vitaminc_kms::vault::VaultSigningKey>();
/// ```
///
/// The key version is part of construction for the reason
/// [`VaultSigningKey`](super::VaultSigningKey) gives. The bound key must
/// not be `derived`: [`SignMessage`] carries no derivation context, and
/// Vault refuses to sign with a derived key without one.
pub struct VaultEd25519Key {
    client: VaultClient,
    mount: String,
    name: String,
    key_version: u32,
}

impl VaultEd25519Key {
    /// `mount` is the Transit mount path — `"transit"` unless the engine
    /// was mounted elsewhere — `name` the Transit key, which must be of
    /// type `ed25519`, and `key_version` the version of it this instance
    /// signs and verifies under (not `0`, which would mean "whatever is
    /// latest" and let a rotation silently change what the adapter
    /// produces).
    pub fn new(
        client: VaultClient,
        mount: impl Into<String>,
        name: impl Into<String>,
        key_version: u32,
    ) -> Self {
        Self {
            client,
            mount: mount.into(),
            name: name.into(),
            key_version,
        }
    }

    fn input(message: &Protected<Vec<u8>>) -> String {
        b64_encode(message.risky_ref())
    }
}

impl SignMessage for VaultEd25519Key {
    type Error = Error;

    async fn sign_message(&self, message: &Protected<Vec<u8>>) -> Result<Vec<u8>, Self::Error> {
        let endpoint = SignMessageRequest {
            mount: self.mount.clone(),
            name: self.name.clone(),
            input: Self::input(message),
            key_version: u64::from(self.key_version),
            prehashed: false,
        };

        let response: SignDataResponse =
            vaultrs::api::exec_with_result(&self.client, endpoint).await?;

        let payload =
            strip_key_version(&response.signature, self.key_version).ok_or_else(|| {
                Error::UnexpectedKeyVersion {
                    expected: self.key_version,
                    returned: response.signature.clone(),
                }
            })?;

        let signature = b64_decode(payload)?;
        if signature.len() != SIGNATURE_LEN {
            return Err(Error::NotEd25519Signature(signature.len()));
        }
        Ok(signature)
    }
}

impl VerifyMessage for VaultEd25519Key {
    type Error = Error;

    /// Vault answers `{"valid": false}` for any signature that does not
    /// verify, malformed ones included. A signature that is not 64 bytes
    /// cannot verify, so the adapter returns `Ok(false)` for it with no
    /// round trip.
    async fn verify_message(
        &self,
        message: &Protected<Vec<u8>>,
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        if signature.len() != SIGNATURE_LEN {
            return Ok(false);
        }

        let endpoint = VerifyMessageRequest {
            mount: self.mount.clone(),
            name: self.name.clone(),
            input: Self::input(message),
            // Vault needs its own prefix back; the trait boundary dropped it.
            signature: with_key_version(self.key_version, signature),
            prehashed: false,
        };

        let response: VerifySignedDataResponse =
            vaultrs::api::exec_with_result(&self.client, endpoint).await?;

        Ok(response.valid)
    }
}

impl GetPublicKey for VaultEd25519Key {
    type Error = Error;

    /// `export/public-key/:name/:version`, as for
    /// [`VaultSigningKey`](super::VaultSigningKey). For an `ed25519` key,
    /// Vault returns the raw 32-byte public key in base64, not PEM; ADR
    /// 0002 promises DER `SubjectPublicKeyInfo`.
    async fn get_public_key(&self) -> Result<Vec<u8>, Self::Error> {
        let response = vaultrs::transit::key::export(
            &self.client,
            &self.mount,
            &self.name,
            ExportKeyType::PublicKey,
            ExportVersion::Version(u64::from(self.key_version)),
        )
        .await?;

        let raw = response
            .keys
            .get(&self.key_version.to_string())
            .ok_or(Error::MissingPublicKey(self.key_version))?;

        Ok(ed25519_spki(&b64_decode(raw)?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::tests::{data, test_client, KEY_NAME};
    use httpmock::prelude::*;
    use serde_json::json;

    const SIGNATURE: [u8; 64] = [7u8; 64];

    fn message() -> Protected<Vec<u8>> {
        Protected::new(b"a whole message, not a digest".to_vec())
    }

    fn key(server: &MockServer, key_version: u32) -> VaultEd25519Key {
        VaultEd25519Key::new(test_client(server), "transit", KEY_NAME, key_version)
    }

    #[tokio::test]
    async fn sign_sends_the_message_not_prehashed_and_strips_the_prefix() {
        let server = MockServer::start_async().await;
        // `json_body` matches the whole body, so a hash or marshaling
        // field would fail the match.
        let mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/sign/{KEY_NAME}"))
                    .json_body(json!({
                        "input": b64_encode(b"a whole message, not a digest"),
                        "key_version": 3,
                        "prehashed": false,
                    }));
                then.status(200).json_body(data(json!({
                    "signature": format!("vault:v3:{}", b64_encode(&SIGNATURE)),
                })));
            })
            .await;

        let signature = key(&server, 3).sign_message(&message()).await.unwrap();

        mock.assert_async().await;
        assert_eq!(signature, SIGNATURE);
    }

    #[tokio::test]
    async fn a_message_of_any_length_is_sent_as_it_is() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .json_body_includes(json!({ "input": b64_encode(&[0xAB; 1000]) }).to_string());
                then.status(200).json_body(data(json!({
                    "signature": format!("vault:v1:{}", b64_encode(&SIGNATURE)),
                })));
            })
            .await;

        key(&server, 1)
            .sign_message(&Protected::new(vec![0xAB; 1000]))
            .await
            .unwrap();

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn sign_rejects_a_signature_from_another_key_version() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(POST);
                then.status(200).json_body(data(json!({
                    "signature": format!("vault:v5:{}", b64_encode(&SIGNATURE)),
                })));
            })
            .await;

        assert!(matches!(
            key(&server, 2).sign_message(&message()).await.unwrap_err(),
            Error::UnexpectedKeyVersion { expected: 2, .. }
        ));
    }

    #[tokio::test]
    async fn a_signature_that_is_not_64_bytes_means_the_key_is_not_ed25519() {
        let server = MockServer::start_async().await;
        // What an `ecdsa-p256` key returns for the same request: a DER
        // signature over the SHA-256 of the message.
        server
            .mock_async(|when, then| {
                when.method(POST);
                then.status(200).json_body(data(json!({
                    "signature": format!("vault:v1:{}", b64_encode(&[0x30; 71])),
                })));
            })
            .await;

        assert!(matches!(
            key(&server, 1).sign_message(&message()).await.unwrap_err(),
            Error::NotEd25519Signature(71)
        ));
    }

    #[tokio::test]
    async fn verify_rebuilds_the_prefix_and_reports_false_as_ok() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/verify/{KEY_NAME}"))
                    .json_body(json!({
                        "input": b64_encode(b"a whole message, not a digest"),
                        "signature": format!("vault:v2:{}", b64_encode(&SIGNATURE)),
                        "prehashed": false,
                    }));
                then.status(200).json_body(data(json!({ "valid": false })));
            })
            .await;

        assert!(!key(&server, 2)
            .verify_message(&message(), &SIGNATURE)
            .await
            .unwrap());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn verify_reports_a_valid_signature_as_true() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(POST);
                then.status(200).json_body(data(json!({ "valid": true })));
            })
            .await;

        assert!(key(&server, 1)
            .verify_message(&message(), &SIGNATURE)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn a_signature_that_is_not_64_bytes_is_false_with_no_round_trip() {
        let server = MockServer::start_async().await;
        let anything = server
            .mock_async(|when, then| {
                when.any_request();
                then.status(200).json_body(data(json!({ "valid": true })));
            })
            .await;

        let key = key(&server, 1);

        assert!(!key.verify_message(&message(), b"garbage").await.unwrap());
        assert!(!key.verify_message(&message(), &[]).await.unwrap());
        assert!(!key.verify_message(&message(), &[7u8; 65]).await.unwrap());
        anything.assert_calls_async(0).await;
    }

    #[tokio::test]
    async fn vault_errors_on_verify_stay_errors() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(POST);
                then.status(403)
                    .json_body(json!({ "errors": ["permission denied"] }));
            })
            .await;

        assert!(matches!(
            key(&server, 1)
                .verify_message(&message(), &SIGNATURE)
                .await
                .unwrap_err(),
            Error::Vault(_)
        ));
    }

    #[tokio::test]
    async fn the_raw_public_key_comes_back_as_der_spki() {
        let raw = [0x42u8; 32];

        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(format!("/v1/transit/export/public-key/{KEY_NAME}/4"));
                then.status(200).json_body(data(json!({
                    "name": KEY_NAME,
                    "type": "ed25519",
                    "keys": { "4": b64_encode(&raw) },
                })));
            })
            .await;

        assert_eq!(
            key(&server, 4).get_public_key().await.unwrap(),
            ed25519_spki(&raw).unwrap()
        );
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn a_pem_public_key_means_the_key_is_not_ed25519() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET);
                then.status(200).json_body(data(json!({
                    "name": KEY_NAME,
                    "keys": { "1": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n" },
                })));
            })
            .await;

        assert!(matches!(
            key(&server, 1).get_public_key().await.unwrap_err(),
            Error::Base64(_)
        ));
    }

    #[tokio::test]
    async fn an_export_without_the_bound_version_is_an_error() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET);
                then.status(200).json_body(data(json!({
                    "name": KEY_NAME,
                    "keys": { "1": b64_encode(&[0u8; 32]) },
                })));
            })
            .await;

        assert!(matches!(
            key(&server, 4).get_public_key().await.unwrap_err(),
            Error::MissingPublicKey(4)
        ));
    }
}

/// Round trips against the dev-mode Vault of
/// `packages/kms/docker-compose.yml`.
#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::vault::tests::{transit_key, DEFAULT_MOUNT};
    use ed25519_dalek::pkcs8::DecodePublicKey;
    use vaultrs::api::transit::KeyType;

    async fn ed25519_key() -> VaultEd25519Key {
        let (client, name) = transit_key(KeyType::Ed25519).await;
        VaultEd25519Key::new(client, DEFAULT_MOUNT, name, 1)
    }

    fn message() -> Protected<Vec<u8>> {
        // Longer than any digest, so the test cannot pass by accident if
        // Vault were to treat the input as a digest.
        Protected::new((0..=255u8).cycle().take(1000).collect())
    }

    #[tokio::test]
    async fn ed25519_signs_and_verifies_a_message() {
        let key = ed25519_key().await;
        let message = message();

        let signature = key.sign_message(&message).await.unwrap();
        assert_eq!(signature.len(), 64);
        assert!(key.verify_message(&message, &signature).await.unwrap());

        let mut tampered = signature.clone();
        tampered[63] ^= 0xFF;
        assert!(!key.verify_message(&message, &tampered).await.unwrap());

        let mut other = message.clone().risky_unwrap();
        other[0] ^= 0xFF;
        assert!(!key
            .verify_message(&Protected::new(other), &signature)
            .await
            .unwrap());
    }

    /// A verifier that has never talked to Vault accepts the signature,
    /// given only the public key the adapter exports. This proves that
    /// the signature is pure Ed25519 over the message and that the public
    /// key is DER SPKI (ADR 0002).
    #[tokio::test]
    async fn the_signature_verifies_locally_against_the_exported_public_key() {
        let key = ed25519_key().await;
        let message = message();

        let signature = key.sign_message(&message).await.unwrap();
        let der = key.get_public_key().await.unwrap();

        let verifying_key = ed25519_dalek::VerifyingKey::from_public_key_der(&der).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();
        let message = message.risky_unwrap();

        verifying_key
            .verify_strict(&message, &signature)
            .expect("a pure Ed25519 signature over the message");

        let mut tampered = message.clone();
        tampered[0] ^= 0xFF;
        assert!(verifying_key.verify_strict(&tampered, &signature).is_err());
    }

    #[tokio::test]
    async fn a_signature_that_is_not_a_signature_is_false() {
        let key = ed25519_key().await;

        for signature in [&b"garbage"[..], &[], &[0u8; 64]] {
            assert!(
                !key.verify_message(&message(), signature).await.unwrap(),
                "{signature:?} should not verify"
            );
        }
    }

    /// The wrong key type is caught on the first signature, not by a
    /// verifier much later.
    #[tokio::test]
    async fn an_ecdsa_key_is_refused_on_the_first_signature() {
        let (client, name) = transit_key(KeyType::EcdsaP384).await;
        let key = VaultEd25519Key::new(client, DEFAULT_MOUNT, name, 1);

        assert!(matches!(
            key.sign_message(&message()).await.unwrap_err(),
            Error::NotEd25519Signature(_)
        ));
    }
}
