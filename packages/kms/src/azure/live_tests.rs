//! Round trips against a real Azure Managed HSM (CIP-4072).
//!
//! Lowkey Vault, the emulator of the other Azure tests, rejects `A256GCM`
//! and HMAC on `oct-HSM` keys, so [`AzureDataKeySource`] and
//! [`AzureMacKey`] have only stub-transport cover without these. Each test
//! skips unless `VITAMINC_KMS_LIVE_AZURE` is on. See
//! `packages/kms/docs/live-tests.md` for the keys, roles and variables.
//!
//! The tests use keys that already exist, and create nothing, so a run
//! leaves the HSM as it found it.

use super::{AzureDataKeySource, AzureMacKey};
use crate::crypt::{DecryptWithKey, EncryptWithKey};
use crate::data_key::{
    BatchGenerateDataKey, BatchRetrieveDataKey, Binding, GenerateDataKey, RetrieveDataKey,
};
use crate::key_id::KeyId;
use crate::live::{enabled, Backend, LiveEnv};
use crate::mac::{GenerateMac, VerifyMac};
use async_trait::async_trait;
use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
use azure_core::time::{Duration, OffsetDateTime};
use azure_security_keyvault_keys::{KeyClient, KeyClientOptions, ResourceExt};
use std::sync::Arc;
use vitaminc_protected::{Controlled, Protected};

const HSM_URL: &str = "VITAMINC_KMS_AZURE_HSM_URL";
const DATA_KEY: &str = "VITAMINC_KMS_AZURE_DATA_KEY";
const MAC_KEY: &str = "VITAMINC_KMS_AZURE_MAC_KEY";
const API_VERSION: &str = "VITAMINC_KMS_AZURE_API_VERSION";

/// `None`, after one `skipped:` line, unless the Managed HSM tests are on.
fn live(test: &str) -> Option<LiveEnv> {
    enabled(
        Backend::AzureManagedHsm,
        test,
        &[HSM_URL],
        &[DATA_KEY, MAC_KEY, API_VERSION],
    )
}

/// A credential that asks the Azure CLI for each token, as `az account
/// get-access-token --scope <scope>` does.
///
/// This is what `azure_identity`'s `AzureCliCredential` does. It is here
/// rather than that crate because only these tests need a real credential,
/// and the CLI is already signed in wherever they run: on a laptop after
/// `az login`, and in CI after `azure/login` with OIDC.
#[derive(Debug)]
struct AzureCliCredential;

#[async_trait]
impl TokenCredential for AzureCliCredential {
    async fn get_token(
        &self,
        scopes: &[&str],
        _options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        let scope = scopes.first().copied().unwrap_or_default();
        let output = std::process::Command::new("az")
            .args(["account", "get-access-token", "--output", "json", "--scope"])
            .arg(scope)
            .output()
            .map_err(|e| {
                azure_core::Error::with_message(
                    azure_core::error::ErrorKind::Credential,
                    format!("could not run the Azure CLI (`az`): {e}"),
                )
            })?;
        if !output.status.success() {
            return Err(azure_core::Error::with_message(
                azure_core::error::ErrorKind::Credential,
                format!(
                    "`az account get-access-token --scope {scope}` failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            ));
        }

        let token: serde_json::Value = serde_json::from_slice(&output.stdout)
            .expect("the Azure CLI should print a JSON token");
        let access_token = token["accessToken"]
            .as_str()
            .expect("the Azure CLI token should have an accessToken")
            .to_owned();
        // `expires_on` is a Unix time in Azure CLI 2.54 and later. Without
        // it, ask again in five minutes rather than guess.
        let expires_on = token["expires_on"]
            .as_i64()
            .and_then(|t| OffsetDateTime::from_unix_timestamp(t).ok())
            .unwrap_or_else(|| OffsetDateTime::now_utc() + Duration::minutes(5));

        Ok(AccessToken::new(access_token, expires_on))
    }
}

/// A [`KeyClient`] for the Managed HSM that `env` names.
fn client(env: &LiveEnv) -> KeyClient {
    let mut options = KeyClientOptions::default();
    // Unset, the crate's own default applies.
    let api_version = env.optional(API_VERSION, "");
    if !api_version.is_empty() {
        options.api_version = api_version.to_owned();
    }
    KeyClient::new(
        env.required(HSM_URL),
        Arc::new(AzureCliCredential),
        Some(options),
    )
    .expect("the Managed HSM client should build")
}

fn data_key_source(env: &LiveEnv) -> AzureDataKeySource<32> {
    AzureDataKeySource::new(client(env), env.optional(DATA_KEY, "vitaminc-live-aes256"))
}

/// The MAC key at its current version, which the HSM reports.
async fn mac_key(env: &LiveEnv) -> AzureMacKey<32> {
    let client = client(env);
    let name = env.optional(MAC_KEY, "vitaminc-live-hmac256").to_owned();
    let version = client
        .get_key(&name, None)
        .await
        .unwrap_or_else(|e| panic!("could not read the MAC key {name:?}: {e}"))
        .into_model()
        .expect("the key should deserialize")
        .resource_id()
        .expect("the key should carry a parseable kid")
        .version
        .expect("the key should have a version");
    AzureMacKey::new(client, name, version)
}

#[tokio::test]
async fn a_data_key_comes_back_under_its_binding() {
    let Some(env) = live("a_data_key_comes_back_under_its_binding") else {
        return;
    };
    let source = data_key_source(&env);

    let generated = source
        .generate_data_key(Binding::from("users/email"))
        .await
        .unwrap();
    let retrieved = source
        .retrieve_data_key(&generated.key_id, Binding::from("users/email"))
        .await
        .unwrap();

    assert_eq!(
        retrieved.risky_unwrap(),
        generated.plaintext.clone().risky_unwrap()
    );
}

#[tokio::test]
async fn a_data_key_does_not_come_back_under_another_binding() {
    let Some(env) = live("a_data_key_does_not_come_back_under_another_binding") else {
        return;
    };
    let source = data_key_source(&env);
    let generated = source
        .generate_data_key(Binding::from("users/email"))
        .await
        .unwrap();

    for binding in [Binding::from("users/name"), Binding::EMPTY] {
        let error = source
            .retrieve_data_key(&generated.key_id, binding)
            .await
            .unwrap_err();
        assert!(
            matches!(error, super::AzureDataKeySourceError::Azure(_)),
            "the HSM must refuse the tag: {error}"
        );
    }
}

#[tokio::test]
async fn a_data_key_minted_under_an_empty_binding_comes_back_under_it() {
    let Some(env) = live("a_data_key_minted_under_an_empty_binding_comes_back_under_it") else {
        return;
    };
    let source = data_key_source(&env);

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
        .retrieve_data_key(&generated.key_id, Binding::from("users/email"))
        .await
        .is_err());
}

#[tokio::test]
async fn a_batch_of_data_keys_comes_back_in_order() {
    let Some(env) = live("a_batch_of_data_keys_comes_back_in_order") else {
        return;
    };
    let source = data_key_source(&env);
    let bindings = [
        Binding::from("users/email"),
        Binding::from("users/name"),
        Binding::from("users/email"),
    ];

    let keys = source.generate_data_keys(&bindings).await.unwrap();
    let pairs: Vec<_> = keys
        .iter()
        .map(|k| k.key_id.clone())
        .zip(bindings)
        .collect();
    let retrieved = source.retrieve_data_keys(&pairs).await.unwrap();

    assert_eq!(retrieved.len(), 3);
    for (key, back) in keys.iter().zip(&retrieved) {
        assert_eq!(
            back.clone().risky_unwrap(),
            key.plaintext.clone().risky_unwrap()
        );
    }
    assert_ne!(
        keys[0].plaintext.clone().risky_unwrap(),
        keys[2].plaintext.clone().risky_unwrap(),
        "each key in a batch must be new key material"
    );
}

#[tokio::test]
async fn direct_encryption_round_trips() {
    let Some(env) = live("direct_encryption_round_trips") else {
        return;
    };
    let source = data_key_source(&env);

    let ciphertext = source
        .encrypt(Protected::new(b"a short message".to_vec()))
        .await
        .unwrap();
    let plaintext = source.decrypt(&ciphertext).await.unwrap();

    assert_eq!(plaintext.risky_unwrap(), b"a short message");
}

/// A data key and a direct ciphertext bind different additional
/// authenticated data (ADR 0006), so neither opens as the other. The
/// direct ciphertext is exactly 32 bytes, the size of a data key, and the
/// data key is minted under `Binding::EMPTY`, as an index key is.
#[tokio::test]
async fn data_keys_and_direct_ciphertexts_do_not_open_as_each_other() {
    let Some(env) = live("data_keys_and_direct_ciphertexts_do_not_open_as_each_other") else {
        return;
    };
    let source = data_key_source(&env);

    let ciphertext = source.encrypt(Protected::new(vec![7u8; 32])).await.unwrap();
    let error = source
        .retrieve_data_key(&KeyId::new(ciphertext), Binding::EMPTY)
        .await
        .unwrap_err();
    assert!(
        matches!(error, super::AzureDataKeySourceError::Azure(_)),
        "the HSM must refuse the tag: {error}"
    );

    let generated = source.generate_data_key(Binding::EMPTY).await.unwrap();
    let error = source
        .decrypt(generated.key_id.as_bytes())
        .await
        .unwrap_err();
    assert!(
        matches!(error, super::AzureDataKeySourceError::Azure(_)),
        "the HSM must refuse the tag: {error}"
    );
}

#[tokio::test]
async fn a_mac_verifies_and_is_deterministic() {
    let Some(env) = live("a_mac_verifies_and_is_deterministic") else {
        return;
    };
    let key = mac_key(&env).await;
    let message = Protected::new(b"a message".to_vec());

    let tag = key.generate_mac(&message).await.unwrap();

    assert!(key.verify_mac(&message, &tag).await.unwrap());
    assert_eq!(key.generate_mac(&message).await.unwrap(), tag);
}

#[tokio::test]
async fn a_tampered_mac_or_message_does_not_verify() {
    let Some(env) = live("a_tampered_mac_or_message_does_not_verify") else {
        return;
    };
    let key = mac_key(&env).await;
    let message = Protected::new(b"a message".to_vec());
    let tag = key.generate_mac(&message).await.unwrap();

    let mut tampered = tag;
    tampered[0] ^= 0x01;
    assert!(!key.verify_mac(&message, &tampered).await.unwrap());

    let other = Protected::new(b"another message".to_vec());
    assert!(!key.verify_mac(&other, &tag).await.unwrap());
}
