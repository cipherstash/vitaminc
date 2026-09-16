use super::{b64_decode, b64_encode, strip_key_version, with_key_version};
use crate::mac::{GenerateMac, VerifyMac};
use private::ValidMacSize;
use thiserror::Error;
use vaultrs::api::transit::requests::{GenerateHmacRequest, VerifySignedDataRequest};
use vaultrs::client::VaultClient;
use vitaminc_protected::{Controlled, Protected};

/// Errors from [`VaultMacKey`].
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Vault(#[from] vaultrs::error::ClientError),
    #[error("Vault returned a tag that is not valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    /// The adapter is bound to one key version and asks for it by number,
    /// so a tag under any other version means the response does not match
    /// the request.
    #[error("Vault returned {returned:?}, expected a `vault:v{expected}:` tag")]
    UnexpectedKeyVersion { expected: u32, returned: String },
    #[error("Vault returned a {received}-byte tag, expected {expected}")]
    UnexpectedMacLength { expected: usize, received: usize },
}

/// A Vault Transit-backed MAC key, bound to one Transit key **and one key
/// version** at construction.
///
/// `N` is the tag size in bytes and must be 28, 32, 48 or 64, which select
/// `sha2-224`, `sha2-256`, `sha2-384` and `sha2-512`. Every Transit key
/// carries its own independent HMAC secret whatever its primary algorithm
/// is, so any key type can back a MAC key.
///
/// # Why the key version is part of construction
///
/// Vault answers `hmac` with `vault:v<N>:<base64>` and will not take a
/// bare tag back on `verify`. [`GenerateMac`] hands the caller raw bytes,
/// so the adapter strips that prefix and has to rebuild it — which means
/// knowing the version. See the [module docs](super) for what that means
/// after a rotation.
///
/// The bound key must not be `derived`: [`GenerateMac`] carries no
/// derivation context.
pub struct VaultMacKey<const N: usize> {
    client: VaultClient,
    mount: String,
    name: String,
    key_version: u32,
}

impl<const N: usize> VaultMacKey<N>
where
    Self: ValidMacSize<N>,
{
    /// `mount` is the Transit mount path — `"transit"` unless the engine
    /// was mounted elsewhere — `name` the Transit key, and `key_version`
    /// the version of that key this instance tags and verifies under. Not
    /// `0`, which would mean "whatever is latest" and let a rotation
    /// silently change what the adapter produces.
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
}

impl<const N: usize> GenerateMac<N> for VaultMacKey<N>
where
    Self: ValidMacSize<N>,
{
    type Error = Error;

    async fn generate_mac(&self, message: &Protected<Vec<u8>>) -> Result<[u8; N], Self::Error> {
        let mut opts = GenerateHmacRequest::builder();
        opts.key_version(u64::from(self.key_version));
        opts.algorithm(Self::ALGORITHM);

        let response = vaultrs::transit::generate::hmac(
            &self.client,
            &self.mount,
            &self.name,
            &b64_encode(&message.clone().risky_unwrap()),
            Some(&mut opts),
        )
        .await?;

        let payload = strip_key_version(&response.hmac, self.key_version).ok_or_else(|| {
            Error::UnexpectedKeyVersion {
                expected: self.key_version,
                returned: response.hmac.clone(),
            }
        })?;

        let tag = b64_decode(payload)?;
        let received = tag.len();
        tag.try_into().map_err(|_| Error::UnexpectedMacLength {
            expected: N,
            received,
        })
    }
}

impl<const N: usize> VerifyMac<N> for VaultMacKey<N>
where
    Self: ValidMacSize<N>,
{
    type Error = Error;

    /// Vault's `verify` answers `{"valid": false}` even for a malformed
    /// tag rather than failing, so it maps straight onto `Ok(false)` and
    /// `Self::Error` stays reserved for infrastructure failures.
    async fn verify_mac(
        &self,
        message: &Protected<Vec<u8>>,
        mac: &[u8; N],
    ) -> Result<bool, Self::Error> {
        let mut opts = VerifySignedDataRequest::builder();
        opts.hash_algorithm(Self::ALGORITHM);
        // Vault needs its own prefix back; the trait boundary dropped it.
        opts.hmac(with_key_version(self.key_version, mac));

        let response = vaultrs::transit::data::verify(
            &self.client,
            &self.mount,
            &self.name,
            &b64_encode(&message.clone().risky_unwrap()),
            Some(&mut opts),
        )
        .await?;

        Ok(response.valid)
    }
}

mod private {
    use vaultrs::api::transit::HashAlgorithm;

    /// Sealed: only the four SHA-2 digest sizes Vault names are valid tag
    /// sizes for a [`VaultMacKey`](super::VaultMacKey).
    pub trait ValidMacSize<const N: usize> {
        const ALGORITHM: HashAlgorithm;
    }

    impl ValidMacSize<28> for super::VaultMacKey<28> {
        const ALGORITHM: HashAlgorithm = HashAlgorithm::Sha2_224;
    }

    impl ValidMacSize<32> for super::VaultMacKey<32> {
        const ALGORITHM: HashAlgorithm = HashAlgorithm::Sha2_256;
    }

    impl ValidMacSize<48> for super::VaultMacKey<48> {
        const ALGORITHM: HashAlgorithm = HashAlgorithm::Sha2_384;
    }

    impl ValidMacSize<64> for super::VaultMacKey<64> {
        const ALGORITHM: HashAlgorithm = HashAlgorithm::Sha2_512;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::tests::{data, test_client, KEY_NAME};
    use httpmock::prelude::*;
    use serde_json::json;

    #[tokio::test]
    async fn generate_asks_for_the_bound_version_and_strips_the_prefix() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/hmac/{KEY_NAME}"))
                    .json_body(json!({
                        "key_version": 3,
                        "algorithm": "sha2-256",
                        "input": b64_encode(b"a message"),
                    }));
                then.status(200).json_body(data(json!({
                    "hmac": format!("vault:v3:{}", b64_encode(&[5u8; 32])),
                })));
            })
            .await;

        let key = VaultMacKey::<32>::new(test_client(&server), "transit", KEY_NAME, 3);
        let tag = key
            .generate_mac(&Protected::new(b"a message".to_vec()))
            .await
            .unwrap();

        mock.assert_async().await;
        assert_eq!(tag, [5u8; 32]);
    }

    #[tokio::test]
    async fn generate_rejects_a_tag_from_another_key_version() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(POST);
                then.status(200).json_body(data(json!({
                    "hmac": format!("vault:v9:{}", b64_encode(&[5u8; 32])),
                })));
            })
            .await;

        let key = VaultMacKey::<32>::new(test_client(&server), "transit", KEY_NAME, 3);

        assert!(matches!(
            key.generate_mac(&Protected::new(b"a message".to_vec()))
                .await
                .unwrap_err(),
            Error::UnexpectedKeyVersion { expected: 3, .. }
        ));
    }

    #[tokio::test]
    async fn verify_rebuilds_the_prefix_with_the_bound_version() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/v1/transit/verify/{KEY_NAME}"))
                    .json_body(json!({
                        "hash_algorithm": "sha2-256",
                        "hmac": format!("vault:v3:{}", b64_encode(&[5u8; 32])),
                        "input": b64_encode(b"a message"),
                    }));
                then.status(200).json_body(data(json!({ "valid": true })));
            })
            .await;

        let key = VaultMacKey::<32>::new(test_client(&server), "transit", KEY_NAME, 3);
        let valid = key
            .verify_mac(&Protected::new(b"a message".to_vec()), &[5u8; 32])
            .await
            .unwrap();

        mock.assert_async().await;
        assert!(valid);
    }

    #[tokio::test]
    async fn a_false_verdict_is_ok_false_not_an_error() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(POST);
                then.status(200).json_body(data(json!({ "valid": false })));
            })
            .await;

        let key = VaultMacKey::<32>::new(test_client(&server), "transit", KEY_NAME, 1);

        assert!(!key
            .verify_mac(&Protected::new(b"a message".to_vec()), &[0u8; 32])
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn every_tag_size_maps_to_its_sha2_algorithm() {
        // The mock only matches the expected `algorithm`, so a hit is the
        // assertion and a miss makes the call fail outright.
        async fn assert_algorithm<const N: usize>(expected: &str)
        where
            VaultMacKey<N>: ValidMacSize<N>,
        {
            let server = MockServer::start_async().await;
            let mock = server
                .mock_async(|when, then| {
                    when.method(POST)
                        .json_body_includes(json!({ "algorithm": expected }).to_string());
                    then.status(200).json_body(data(json!({
                        "hmac": format!("vault:v1:{}", b64_encode(&vec![0u8; N])),
                    })));
                })
                .await;

            let key = VaultMacKey::<N>::new(test_client(&server), "transit", KEY_NAME, 1);
            let tag = key.generate_mac(&Protected::new(Vec::new())).await.unwrap();

            mock.assert_async().await;
            assert_eq!(tag, [0u8; N]);
        }

        assert_algorithm::<28>("sha2-224").await;
        assert_algorithm::<32>("sha2-256").await;
        assert_algorithm::<48>("sha2-384").await;
        assert_algorithm::<64>("sha2-512").await;
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

    /// Every Transit key carries its own HMAC secret whatever its primary
    /// algorithm is, so a symmetric key backs a MAC key perfectly well.
    async fn mac_key<const N: usize>() -> VaultMacKey<N>
    where
        VaultMacKey<N>: ValidMacSize<N>,
    {
        let (client, name) = transit_key(KeyType::Aes256Gcm96).await;
        VaultMacKey::new(client, DEFAULT_MOUNT, name, 1)
    }

    #[tokio::test]
    async fn a_generated_tag_verifies_and_a_tampered_one_does_not() {
        let key = mac_key::<32>().await;
        let message = Protected::new(b"the message under MAC".to_vec());

        let tag = key.generate_mac(&message).await.unwrap();
        assert!(key.verify_mac(&message, &tag).await.unwrap());

        let mut tampered = tag;
        tampered[0] ^= 0xFF;
        assert!(!key.verify_mac(&message, &tampered).await.unwrap());

        let other = Protected::new(b"a different message".to_vec());
        assert!(!key.verify_mac(&other, &tag).await.unwrap());
    }

    #[tokio::test]
    async fn every_tag_size_round_trips_against_a_real_key() {
        async fn round_trip<const N: usize>()
        where
            VaultMacKey<N>: ValidMacSize<N>,
        {
            let key = mac_key::<N>().await;
            let message = Protected::new(vec![1u8, 2, 3]);
            let tag = key.generate_mac(&message).await.unwrap();
            assert!(key.verify_mac(&message, &tag).await.unwrap(), "N = {N}");
        }

        round_trip::<28>().await;
        round_trip::<32>().await;
        round_trip::<48>().await;
        round_trip::<64>().await;
    }
}
