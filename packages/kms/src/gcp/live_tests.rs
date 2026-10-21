//! Round trips against a real Google Cloud KMS project (CIP-4073).
//!
//! No emulator for Google Cloud KMS exists, so without these the adapters
//! have only the official crate's stub trait as cover. Each test skips
//! unless `VITAMINC_KMS_LIVE_GCP` is on. See
//! `packages/kms/docs/live-tests.md` for the keys, roles and variables.
//!
//! The tests use version 1 of keys that already exist, and create
//! nothing, so a run leaves the project as it found it. Credentials are
//! Application Default Credentials, which the client finds itself.

use super::{GcpDataKeySource, GcpEd25519Key, GcpMacKey, GcpSigningKey};
use crate::algorithm::SignatureAlgorithm;
use crate::crypt::{DecryptWithKey, EncryptWithKey};
use crate::data_key::{
    BatchGenerateDataKey, BatchRetrieveDataKey, Binding, GenerateDataKey, RetrieveDataKey,
};
use crate::live::{enabled, Backend, LiveEnv};
use crate::mac::{GenerateMac, VerifyMac};
use crate::sign::{GetPublicKey, Sign, SignMessage, Verify, VerifyMessage};
use google_cloud_kms_v1::client::KeyManagementService;
use sha2::Digest as _;
use vitaminc_protected::{Controlled, Protected};

const PROJECT: &str = "VITAMINC_KMS_GCP_PROJECT";
const LOCATION: &str = "VITAMINC_KMS_GCP_LOCATION";
const KEY_RING: &str = "VITAMINC_KMS_GCP_KEY_RING";

/// Each key: its variable, and the name it has when that is not set.
const ENCRYPT_KEY: (&str, &str) = ("VITAMINC_KMS_GCP_ENCRYPT_KEY", "vitaminc-live-encrypt");
const MAC_KEY: (&str, &str) = ("VITAMINC_KMS_GCP_MAC_KEY", "vitaminc-live-hmac-sha256");
const EC_P256_KEY: (&str, &str) = ("VITAMINC_KMS_GCP_EC_P256_KEY", "vitaminc-live-ec-p256");
const EC_P384_KEY: (&str, &str) = ("VITAMINC_KMS_GCP_EC_P384_KEY", "vitaminc-live-ec-p384");
const RSA_PSS_KEY: (&str, &str) = ("VITAMINC_KMS_GCP_RSA_PSS_KEY", "vitaminc-live-rsa-pss");
const RSA_PKCS1_KEY: (&str, &str) = ("VITAMINC_KMS_GCP_RSA_PKCS1_KEY", "vitaminc-live-rsa-pkcs1");
const ED25519_KEY: (&str, &str) = ("VITAMINC_KMS_GCP_ED25519_KEY", "vitaminc-live-ed25519");

/// `None`, after one `skipped:` line, unless the Cloud KMS tests are on.
fn live(test: &str) -> Option<LiveEnv> {
    enabled(
        Backend::GoogleCloudKms,
        test,
        &[PROJECT, LOCATION, KEY_RING],
        &[
            ENCRYPT_KEY.0,
            MAC_KEY.0,
            EC_P256_KEY.0,
            EC_P384_KEY.0,
            RSA_PSS_KEY.0,
            RSA_PKCS1_KEY.0,
            ED25519_KEY.0,
        ],
    )
}

/// The full resource name of a `CryptoKey` in the key ring `env` names.
fn crypto_key(env: &LiveEnv, (var, default): (&'static str, &'static str)) -> String {
    format!(
        "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}",
        env.required(PROJECT),
        env.required(LOCATION),
        env.required(KEY_RING),
        env.optional(var, default),
    )
}

/// Version 1 of that `CryptoKey`.
fn version_1(env: &LiveEnv, key: (&'static str, &'static str)) -> String {
    format!("{}/cryptoKeyVersions/1", crypto_key(env, key))
}

/// A client with Application Default Credentials.
async fn client() -> KeyManagementService {
    KeyManagementService::builder()
        .build()
        .await
        .expect("the Cloud KMS client should build with Application Default Credentials")
}

#[tokio::test]
async fn a_data_key_comes_back_under_its_binding_and_no_other() {
    let Some(env) = live("a_data_key_comes_back_under_its_binding_and_no_other") else {
        return;
    };
    let source = GcpDataKeySource::<32>::new(client().await, crypto_key(&env, ENCRYPT_KEY));

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

    for binding in [Binding::from("users/name"), Binding::EMPTY] {
        let error = source
            .retrieve_data_key(&generated.key_id, binding)
            .await
            .unwrap_err();
        assert!(
            matches!(error, super::GcpDataKeySourceError::Gcp(_)),
            "Cloud KMS must refuse the AAD: {error}"
        );
    }
}

#[tokio::test]
async fn a_data_key_minted_under_an_empty_binding_comes_back_under_it() {
    let Some(env) = live("a_data_key_minted_under_an_empty_binding_comes_back_under_it") else {
        return;
    };
    let source = GcpDataKeySource::<32>::new(client().await, crypto_key(&env, ENCRYPT_KEY));

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
    let source = GcpDataKeySource::<32>::new(client().await, crypto_key(&env, ENCRYPT_KEY));
    let bindings = [Binding::from("users/email"), Binding::from("users/name")];

    let keys = source.generate_data_keys(&bindings).await.unwrap();
    let pairs: Vec<_> = keys
        .iter()
        .map(|k| k.key_id.clone())
        .zip(bindings)
        .collect();
    let retrieved = source.retrieve_data_keys(&pairs).await.unwrap();

    for (key, back) in keys.iter().zip(&retrieved) {
        assert_eq!(
            back.clone().risky_unwrap(),
            key.plaintext.clone().risky_unwrap()
        );
    }
}

#[tokio::test]
async fn direct_encryption_round_trips() {
    let Some(env) = live("direct_encryption_round_trips") else {
        return;
    };
    let source = GcpDataKeySource::<32>::new(client().await, crypto_key(&env, ENCRYPT_KEY));

    let ciphertext = source
        .encrypt(Protected::new(b"a short message".to_vec()))
        .await
        .unwrap();
    let plaintext = source.decrypt(&ciphertext).await.unwrap();

    assert_eq!(plaintext.risky_unwrap(), b"a short message");
}

/// `macVerify` answers with `success` and `verifiedSuccessIntegrity`. The
/// adapter turns a pair that disagree into `Error::Integrity`, so an
/// `Ok(true)` and an `Ok(false)` here mean the real service set the flag
/// to match each verdict.
#[tokio::test]
async fn a_mac_verifies_and_a_tampered_one_does_not() {
    let Some(env) = live("a_mac_verifies_and_a_tampered_one_does_not") else {
        return;
    };
    let key = GcpMacKey::<32>::new(client().await, version_1(&env, MAC_KEY));
    let message = Protected::new(b"a message".to_vec());

    let tag = key.generate_mac(&message).await.unwrap();
    assert!(key.verify_mac(&message, &tag).await.unwrap());
    assert_eq!(key.generate_mac(&message).await.unwrap(), tag);

    let mut tampered = tag;
    tampered[0] ^= 0x01;
    assert!(!key.verify_mac(&message, &tampered).await.unwrap());

    let other = Protected::new(b"another message".to_vec());
    assert!(!key.verify_mac(&other, &tag).await.unwrap());
}

/// Sign a digest of `message`, verify it, and check that a changed digest
/// and a changed signature do not verify. Returns the DER public key.
async fn sign_and_verify(
    env: &LiveEnv,
    key: (&'static str, &'static str),
    algorithm: SignatureAlgorithm,
) -> Vec<u8> {
    let signer = GcpSigningKey::new(client().await, version_1(env, key), algorithm)
        .await
        .unwrap_or_else(|e| panic!("could not bind to the {algorithm:?} key: {e}"));
    let message = b"a message";
    let digest = match algorithm.digest_len() {
        32 => sha2::Sha256::digest(message).to_vec(),
        48 => sha2::Sha384::digest(message).to_vec(),
        64 => sha2::Sha512::digest(message).to_vec(),
        other => unreachable!("no {other}-byte digest"),
    };
    let digest = Protected::new(digest);

    let signature = signer.sign(&digest).await.unwrap();
    assert!(signer.verify(&digest, &signature).await.unwrap());

    let mut other_digest = digest.clone().risky_unwrap();
    other_digest[0] ^= 0x01;
    assert!(!signer
        .verify(&Protected::new(other_digest), &signature)
        .await
        .unwrap());

    let mut tampered = signature.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(!signer.verify(&digest, &tampered).await.unwrap());

    signer.get_public_key().await.unwrap()
}

#[tokio::test]
async fn an_ecdsa_p256_key_signs_and_verifies() {
    use p256::pkcs8::DecodePublicKey;

    let Some(env) = live("an_ecdsa_p256_key_signs_and_verifies") else {
        return;
    };
    let der = sign_and_verify(&env, EC_P256_KEY, SignatureAlgorithm::EcdsaP256Sha256).await;

    p256::PublicKey::from_public_key_der(&der).expect("a DER P-256 SubjectPublicKeyInfo");
}

#[tokio::test]
async fn an_ecdsa_p384_key_signs_and_verifies() {
    use p384::pkcs8::DecodePublicKey;

    let Some(env) = live("an_ecdsa_p384_key_signs_and_verifies") else {
        return;
    };
    let der = sign_and_verify(&env, EC_P384_KEY, SignatureAlgorithm::EcdsaP384Sha384).await;

    p384::PublicKey::from_public_key_der(&der).expect("a DER P-384 SubjectPublicKeyInfo");
}

#[tokio::test]
async fn an_rsa_pss_key_signs_and_verifies() {
    use rsa::pkcs8::DecodePublicKey;

    let Some(env) = live("an_rsa_pss_key_signs_and_verifies") else {
        return;
    };
    let der = sign_and_verify(&env, RSA_PSS_KEY, SignatureAlgorithm::RsaPssSha256).await;

    rsa::RsaPublicKey::from_public_key_der(&der).expect("a DER RSA SubjectPublicKeyInfo");
}

#[tokio::test]
async fn an_rsa_pkcs1_key_signs_and_verifies() {
    use rsa::pkcs8::DecodePublicKey;

    let Some(env) = live("an_rsa_pkcs1_key_signs_and_verifies") else {
        return;
    };
    let der = sign_and_verify(&env, RSA_PKCS1_KEY, SignatureAlgorithm::RsaPkcs1Sha256).await;

    rsa::RsaPublicKey::from_public_key_der(&der).expect("a DER RSA SubjectPublicKeyInfo");
}

/// A key bound with the wrong algorithm fails at construction, against
/// the algorithm the real `getPublicKey` reports.
#[tokio::test]
async fn a_signing_key_refuses_an_algorithm_its_version_does_not_have() {
    let Some(env) = live("a_signing_key_refuses_an_algorithm_its_version_does_not_have") else {
        return;
    };

    let Err(error) = GcpSigningKey::new(
        client().await,
        version_1(&env, EC_P256_KEY),
        SignatureAlgorithm::RsaPssSha256,
    )
    .await
    else {
        panic!("a P-256 key version must not bind as RSA-PSS");
    };
    assert!(
        matches!(error, super::GcpSigningKeyError::AlgorithmMismatch { .. }),
        "{error}"
    );
}

#[tokio::test]
async fn an_ed25519_key_signs_and_verifies_the_message() {
    use ed25519_dalek::pkcs8::DecodePublicKey;

    let Some(env) = live("an_ed25519_key_signs_and_verifies_the_message") else {
        return;
    };
    let key = GcpEd25519Key::new(client().await, version_1(&env, ED25519_KEY))
        .await
        .unwrap();
    let message = Protected::new(b"a message".to_vec());

    let signature = key.sign_message(&message).await.unwrap();
    assert_eq!(signature.len(), 64);
    assert!(key.verify_message(&message, &signature).await.unwrap());

    let other = Protected::new(b"another message".to_vec());
    assert!(!key.verify_message(&other, &signature).await.unwrap());
    let mut tampered = signature.clone();
    tampered[0] ^= 0x01;
    assert!(!key.verify_message(&message, &tampered).await.unwrap());

    // The DER key parses on its own, and checks the signature without the
    // adapter.
    let der = key.get_public_key().await.unwrap();
    let verifying_key = ed25519_dalek::VerifyingKey::from_public_key_der(&der)
        .expect("a DER Ed25519 SubjectPublicKeyInfo");
    let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();
    verifying_key
        .verify_strict(b"a message", &signature)
        .expect("the signature should verify without the adapter");
}
