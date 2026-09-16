use super::{b64_decode, b64_encode, strip_key_version, with_key_version};
use crate::algorithm::SignatureAlgorithm;
use crate::encoding::{pem_public_key_to_der, EncodingError};
use crate::sign::{GetPublicKey, Sign, Verify};
use thiserror::Error;
use vaultrs::api::transit::requests::{
    ExportKeyType, ExportVersion, SignDataRequest, VerifySignedDataRequest,
};
use vaultrs::api::transit::{
    HashAlgorithm, MarshalingAlgorithm, SignatureAlgorithm as VaultSignatureAlgorithm,
};
use vaultrs::client::VaultClient;
use vitaminc_protected::{Controlled, Protected};

/// Errors from [`VaultSigningKey`].
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Vault(#[from] vaultrs::error::ClientError),
    #[error("Vault returned a signature that is not valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    /// The public key comes back as PEM and has to become DER
    /// `SubjectPublicKeyInfo` for the trait boundary (ADR 0001).
    #[error(transparent)]
    Encoding(#[from] EncodingError),
    /// [`Sign`] takes a pre-computed digest, so the adapter can check its
    /// length against the configured algorithm before spending a round
    /// trip on a digest Vault would reject anyway.
    #[error("digest is {received} bytes, expected {expected} for {algorithm:?}")]
    UnexpectedDigestLength {
        algorithm: SignatureAlgorithm,
        expected: usize,
        received: usize,
    },
    /// The adapter is bound to one key version and asks for it by number,
    /// so a signature under any other version means the response does not
    /// match the request.
    #[error("Vault returned {returned:?}, expected a `vault:v{expected}:` signature")]
    UnexpectedKeyVersion { expected: u32, returned: String },
    /// `export/public-key/:name/:version` answers with a version-keyed
    /// map; the bound version has to be in it.
    #[error("Vault exported no public key for version {0}")]
    MissingPublicKey(u32),
}

/// A Vault Transit-backed signing key, bound to one Transit key, **one key
/// version** and one [`SignatureAlgorithm`] at construction.
///
/// [`Sign`] takes a pre-computed digest, which the adapter sends with
/// `prehashed: true`. ECDSA signatures use `marshaling_algorithm: asn1`,
/// so they are already the DER `SEQUENCE { INTEGER r, INTEGER s }` ADR
/// 0001 promises; RSA signatures are the raw signature bytes either way.
/// For RSA-PSS the adapter leaves Vault's `salt_length` at its `auto`
/// default, which is the digest length — what
/// [`SignatureAlgorithm::RsaPssSha256`] and its siblings document.
///
/// # Why the key version is part of construction
///
/// Vault answers `sign` with `vault:v<N>:<base64>` and will not take a
/// bare signature back on `verify`. [`Sign`] hands the caller raw bytes,
/// so the adapter strips that prefix and has to rebuild it — which means
/// knowing the version. See the [module docs](super) for what that means
/// after a rotation.
///
/// The bound key must not be `derived`: [`Sign`] carries no derivation
/// context. (Vault only honours one on `ed25519` keys, which this crate's
/// [`SignatureAlgorithm`] has no member for.)
pub struct VaultSigningKey {
    client: VaultClient,
    mount: String,
    name: String,
    key_version: u32,
    algorithm: SignatureAlgorithm,
}

/// Vault's `hash_algorithm` for a digest of this size.
const fn hash_algorithm(algorithm: SignatureAlgorithm) -> HashAlgorithm {
    match algorithm.digest_len() {
        32 => HashAlgorithm::Sha2_256,
        48 => HashAlgorithm::Sha2_384,
        _ => HashAlgorithm::Sha2_512,
    }
}

/// Vault's RSA-only `signature_algorithm`. `None` for ECDSA, where Vault
/// documents the parameter as unused.
const fn signature_algorithm(algorithm: SignatureAlgorithm) -> Option<VaultSignatureAlgorithm> {
    match algorithm {
        SignatureAlgorithm::RsaPssSha256
        | SignatureAlgorithm::RsaPssSha384
        | SignatureAlgorithm::RsaPssSha512 => Some(VaultSignatureAlgorithm::Pss),
        SignatureAlgorithm::RsaPkcs1Sha256
        | SignatureAlgorithm::RsaPkcs1Sha384
        | SignatureAlgorithm::RsaPkcs1Sha512 => Some(VaultSignatureAlgorithm::Pkcs1v15),
        _ => None,
    }
}

impl VaultSigningKey {
    /// `mount` is the Transit mount path — `"transit"` unless the engine
    /// was mounted elsewhere — `name` the Transit key, `key_version` the
    /// version of it this instance signs and verifies under (not `0`,
    /// which would mean "whatever is latest" and let a rotation silently
    /// change what the adapter produces), and `algorithm` the scheme,
    /// which must match the bound key's type (`ecdsa-p256`/`p384`/`p521`
    /// or `rsa-2048`/`3072`/`4096`).
    pub fn new(
        client: VaultClient,
        mount: impl Into<String>,
        name: impl Into<String>,
        key_version: u32,
        algorithm: SignatureAlgorithm,
    ) -> Self {
        Self {
            client,
            mount: mount.into(),
            name: name.into(),
            key_version,
            algorithm,
        }
    }

    fn checked_digest(&self, digest: &Protected<Vec<u8>>) -> Result<String, Error> {
        let digest = digest.clone().risky_unwrap();
        let expected = self.algorithm.digest_len();
        if digest.len() != expected {
            return Err(Error::UnexpectedDigestLength {
                algorithm: self.algorithm,
                expected,
                received: digest.len(),
            });
        }
        Ok(b64_encode(&digest))
    }
}

impl Sign for VaultSigningKey {
    type Error = Error;

    async fn sign(&self, digest: &Protected<Vec<u8>>) -> Result<Vec<u8>, Self::Error> {
        // Checked first, so a wrong-sized digest costs no round trip.
        let input = self.checked_digest(digest)?;

        let mut opts = SignDataRequest::builder();
        opts.key_version(u64::from(self.key_version));
        opts.hash_algorithm(hash_algorithm(self.algorithm));
        opts.prehashed(true);
        opts.marshaling_algorithm(MarshalingAlgorithm::Asn1);
        if let Some(signature_algorithm) = signature_algorithm(self.algorithm) {
            opts.signature_algorithm(signature_algorithm);
        }

        let response = vaultrs::transit::data::sign(
            &self.client,
            &self.mount,
            &self.name,
            &input,
            Some(&mut opts),
        )
        .await?;

        let payload =
            strip_key_version(&response.signature, self.key_version).ok_or_else(|| {
                Error::UnexpectedKeyVersion {
                    expected: self.key_version,
                    returned: response.signature.clone(),
                }
            })?;

        Ok(b64_decode(payload)?)
    }
}

impl Verify for VaultSigningKey {
    type Error = Error;

    /// Vault's `verify` answers `{"valid": false}` even for a malformed
    /// signature rather than failing, so it maps straight onto
    /// `Ok(false)`.
    async fn verify(
        &self,
        digest: &Protected<Vec<u8>>,
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        let input = self.checked_digest(digest)?;

        let mut opts = VerifySignedDataRequest::builder();
        opts.hash_algorithm(hash_algorithm(self.algorithm));
        opts.prehashed(true);
        opts.marshaling_algorithm(MarshalingAlgorithm::Asn1);
        if let Some(signature_algorithm) = signature_algorithm(self.algorithm) {
            opts.signature_algorithm(signature_algorithm);
        }
        // Vault needs its own prefix back; the trait boundary dropped it.
        opts.signature(with_key_version(self.key_version, signature));

        let response = vaultrs::transit::data::verify(
            &self.client,
            &self.mount,
            &self.name,
            &input,
            Some(&mut opts),
        )
        .await?;

        Ok(response.valid)
    }
}

impl GetPublicKey for VaultSigningKey {
    type Error = Error;

    /// `export/public-key/:name/:version` is ungated by the key's
    /// `exportable` flag — it only ever hands out the public half — so
    /// this works on any asymmetric Transit key without extra
    /// configuration. Vault returns PEM; ADR 0001 promises DER
    /// `SubjectPublicKeyInfo`.
    async fn get_public_key(&self) -> Result<Vec<u8>, Self::Error> {
        let response = vaultrs::transit::key::export(
            &self.client,
            &self.mount,
            &self.name,
            ExportKeyType::PublicKey,
            ExportVersion::Version(u64::from(self.key_version)),
        )
        .await?;

        let pem = response
            .keys
            .get(&self.key_version.to_string())
            .ok_or(Error::MissingPublicKey(self.key_version))?;

        Ok(pem_public_key_to_der(pem)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::tests::{data, test_client, KEY_NAME};
    use httpmock::prelude::*;
    use serde_json::json;

    const DIGEST_32: [u8; 32] = [4u8; 32];

    fn digest(len: usize) -> Protected<Vec<u8>> {
        Protected::new(vec![4u8; len])
    }

    #[tokio::test]
    async fn sign_sends_a_prehashed_asn1_request_and_strips_the_prefix() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/sign/{KEY_NAME}"))
                    .json_body(json!({
                        "key_version": 2,
                        "hash_algorithm": "sha2-256",
                        "input": b64_encode(&DIGEST_32),
                        "prehashed": true,
                        "marshaling_algorithm": "asn1",
                    }));
                then.status(200).json_body(data(json!({
                    "signature": format!("vault:v2:{}", b64_encode(b"der-signature")),
                })));
            })
            .await;

        let key = VaultSigningKey::new(
            test_client(&server),
            "transit",
            KEY_NAME,
            2,
            SignatureAlgorithm::EcdsaP256Sha256,
        );
        let signature = key.sign(&digest(32)).await.unwrap();

        mock.assert_async().await;
        assert_eq!(signature, b"der-signature");
    }

    #[tokio::test]
    async fn an_rsa_pss_key_names_its_signature_algorithm() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/sign/{KEY_NAME}"))
                    .json_body(json!({
                        "key_version": 1,
                        "hash_algorithm": "sha2-384",
                        "input": b64_encode(&[4u8; 48]),
                        "prehashed": true,
                        "marshaling_algorithm": "asn1",
                        "signature_algorithm": "pss",
                    }));
                then.status(200).json_body(data(json!({
                    "signature": format!("vault:v1:{}", b64_encode(b"raw-rsa")),
                })));
            })
            .await;

        let key = VaultSigningKey::new(
            test_client(&server),
            "transit",
            KEY_NAME,
            1,
            SignatureAlgorithm::RsaPssSha384,
        );

        assert_eq!(key.sign(&digest(48)).await.unwrap(), b"raw-rsa");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn a_pkcs1_key_names_pkcs1v15_instead() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST).json_body_includes(
                    json!({
                        "signature_algorithm": "pkcs1v15",
                        "hash_algorithm": "sha2-512",
                    })
                    .to_string(),
                );
                then.status(200).json_body(data(json!({
                    "signature": format!("vault:v1:{}", b64_encode(b"raw-rsa")),
                })));
            })
            .await;

        let key = VaultSigningKey::new(
            test_client(&server),
            "transit",
            KEY_NAME,
            1,
            SignatureAlgorithm::RsaPkcs1Sha512,
        );
        key.sign(&digest(64)).await.unwrap();

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn a_wrong_sized_digest_costs_no_round_trip() {
        let server = MockServer::start_async().await;
        // Matches anything, so any request at all would register here.
        let anything = server
            .mock_async(|when, then| {
                when.any_request();
                then.status(200).json_body(data(json!({})));
            })
            .await;

        let key = VaultSigningKey::new(
            test_client(&server),
            "transit",
            KEY_NAME,
            1,
            SignatureAlgorithm::EcdsaP256Sha256,
        );

        let sign = key.sign(&digest(31)).await.unwrap_err();
        let verify = key.verify(&digest(31), b"anything").await.unwrap_err();

        assert!(matches!(
            sign,
            Error::UnexpectedDigestLength {
                expected: 32,
                received: 31,
                ..
            }
        ));
        assert!(matches!(verify, Error::UnexpectedDigestLength { .. }));
        anything.assert_calls_async(0).await;
    }

    #[tokio::test]
    async fn sign_rejects_a_signature_from_another_key_version() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(POST);
                then.status(200).json_body(data(json!({
                    "signature": format!("vault:v5:{}", b64_encode(b"der")),
                })));
            })
            .await;

        let key = VaultSigningKey::new(
            test_client(&server),
            "transit",
            KEY_NAME,
            2,
            SignatureAlgorithm::EcdsaP256Sha256,
        );

        assert!(matches!(
            key.sign(&digest(32)).await.unwrap_err(),
            Error::UnexpectedKeyVersion { expected: 2, .. }
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
                        "hash_algorithm": "sha2-256",
                        "input": b64_encode(&DIGEST_32),
                        "prehashed": true,
                        "marshaling_algorithm": "asn1",
                        "signature": format!("vault:v2:{}", b64_encode(b"der-signature")),
                    }));
                then.status(200).json_body(data(json!({ "valid": false })));
            })
            .await;

        let key = VaultSigningKey::new(
            test_client(&server),
            "transit",
            KEY_NAME,
            2,
            SignatureAlgorithm::EcdsaP256Sha256,
        );

        assert!(!key.verify(&digest(32), b"der-signature").await.unwrap());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn the_public_key_comes_back_as_der_spki() {
        let spki =
            crate::encoding::ec_spki(crate::encoding::EcCurve::P256, &[0x01], &[0x02]).unwrap();
        let pem =
            pem_rfc7468::encode_string("PUBLIC KEY", pem_rfc7468::LineEnding::LF, &spki).unwrap();

        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(format!("/v1/transit/export/public-key/{KEY_NAME}/4"));
                then.status(200).json_body(data(json!({
                    "name": KEY_NAME,
                    "keys": { "4": pem },
                })));
            })
            .await;

        let key = VaultSigningKey::new(
            test_client(&server),
            "transit",
            KEY_NAME,
            4,
            SignatureAlgorithm::EcdsaP256Sha256,
        );

        assert_eq!(key.get_public_key().await.unwrap(), spki);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn an_export_without_the_bound_version_is_an_error() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET);
                then.status(200).json_body(data(json!({
                    "name": KEY_NAME,
                    "keys": { "1": "unused" },
                })));
            })
            .await;

        let key = VaultSigningKey::new(
            test_client(&server),
            "transit",
            KEY_NAME,
            4,
            SignatureAlgorithm::EcdsaP256Sha256,
        );

        assert!(matches!(
            key.get_public_key().await.unwrap_err(),
            Error::MissingPublicKey(4)
        ));
    }

    #[test]
    fn every_algorithm_maps_to_a_hash_and_an_rsa_scheme() {
        use SignatureAlgorithm::*;

        for (algorithm, hash) in [
            (EcdsaP256Sha256, "sha2-256"),
            (EcdsaP384Sha384, "sha2-384"),
            (EcdsaP521Sha512, "sha2-512"),
            (RsaPssSha256, "sha2-256"),
            (RsaPkcs1Sha384, "sha2-384"),
        ] {
            let json = serde_json::to_value(hash_algorithm(algorithm)).unwrap();
            assert_eq!(json, hash, "{algorithm:?}");
        }

        assert!(signature_algorithm(EcdsaP256Sha256).is_none());
        assert!(matches!(
            signature_algorithm(RsaPssSha512),
            Some(VaultSignatureAlgorithm::Pss)
        ));
        assert!(matches!(
            signature_algorithm(RsaPkcs1Sha256),
            Some(VaultSignatureAlgorithm::Pkcs1v15)
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

    async fn signing_key(key_type: KeyType, algorithm: SignatureAlgorithm) -> VaultSigningKey {
        let (client, name) = transit_key(key_type).await;
        VaultSigningKey::new(client, DEFAULT_MOUNT, name, 1, algorithm)
    }

    fn digest(algorithm: SignatureAlgorithm) -> Protected<Vec<u8>> {
        Protected::new((0..algorithm.digest_len()).map(|i| i as u8).collect())
    }

    async fn assert_round_trip(key_type: KeyType, algorithm: SignatureAlgorithm) {
        let key = signing_key(key_type, algorithm).await;
        let digest = digest(algorithm);

        let signature = key.sign(&digest).await.unwrap();
        assert!(
            key.verify(&digest, &signature).await.unwrap(),
            "{algorithm:?} should verify its own signature"
        );

        let mut tampered = signature.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert!(
            !key.verify(&digest, &tampered).await.unwrap(),
            "{algorithm:?} should reject a tampered signature"
        );

        // A different digest of the same length must not verify either.
        let mut other = digest.clone().risky_unwrap();
        other[0] ^= 0xFF;
        assert!(!key
            .verify(&Protected::new(other), &signature)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn ecdsa_p256_signs_and_verifies_a_digest() {
        assert_round_trip(KeyType::EcdsaP256, SignatureAlgorithm::EcdsaP256Sha256).await;
    }

    #[tokio::test]
    async fn rsa_pss_signs_and_verifies_a_digest() {
        assert_round_trip(KeyType::Rsa2048, SignatureAlgorithm::RsaPssSha256).await;
    }

    #[tokio::test]
    async fn rsa_pkcs1_signs_and_verifies_a_digest() {
        assert_round_trip(KeyType::Rsa2048, SignatureAlgorithm::RsaPkcs1Sha256).await;
    }

    #[tokio::test]
    async fn an_ecdsa_signature_is_der_not_raw_r_s() {
        let algorithm = SignatureAlgorithm::EcdsaP256Sha256;
        let key = signing_key(KeyType::EcdsaP256, algorithm).await;

        let signature = key.sign(&digest(algorithm)).await.unwrap();

        // ADR 0001: `SEQUENCE { INTEGER r, INTEGER s }`, never 64 raw
        // bytes. Round-tripping through the canonical helpers proves it
        // parses as DER rather than merely starting with 0x30.
        assert_eq!(signature[0], 0x30);
        let raw = crate::encoding::ecdsa_der_to_raw(&signature, 32).unwrap();
        assert_eq!(raw.len(), 64);
        assert_eq!(
            crate::encoding::ecdsa_raw_to_der(&raw, 32).unwrap(),
            signature
        );
    }

    #[tokio::test]
    async fn the_public_key_of_each_key_type_parses_as_spki() {
        for (key_type, algorithm) in [
            (KeyType::EcdsaP256, SignatureAlgorithm::EcdsaP256Sha256),
            (KeyType::EcdsaP384, SignatureAlgorithm::EcdsaP384Sha384),
            (KeyType::Rsa2048, SignatureAlgorithm::RsaPssSha256),
        ] {
            let key = signing_key(key_type, algorithm).await;

            let der = key.get_public_key().await.unwrap();

            spki::SubjectPublicKeyInfoRef::try_from(der.as_slice())
                .unwrap_or_else(|e| panic!("{key_type:?} public key is not DER SPKI: {e}"));
        }
    }
}
