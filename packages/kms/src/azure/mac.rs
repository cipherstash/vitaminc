use crate::mac::{GenerateMac, VerifyMac};
use azure_security_keyvault_keys::models::{
    KeyClientSignOptions, SignParameters, VerifyParameters,
};
use azure_security_keyvault_keys::KeyClient;
use private::ValidMacSize;
use thiserror::Error;
use vitaminc_protected::{Controlled, Protected};

/// Errors from the Azure Key Vault MAC key.
#[derive(Debug, Error)]
pub enum Error {
    /// The vault, the transport or the credential failed.
    #[error(transparent)]
    Azure(#[from] azure_core::Error),
    /// A successful response left out a field the operation must produce.
    #[error("Azure Key Vault returned no {0}")]
    MissingField(&'static str),
    /// The tag is not `N` bytes. Guards the `Vec<u8>` -> `[u8; N]`
    /// conversion so a malformed response is an error rather than a panic.
    #[error("Azure Key Vault returned a {received}-byte MAC tag, expected {expected}")]
    UnexpectedMacLength { expected: usize, received: usize },
}

/// An Azure Key Vault-backed HMAC key.
///
/// Key Vault has no separate MAC endpoint: HMAC is the `sign`/`verify` pair
/// with an `HS*` algorithm over an `oct-HSM` key. `N` picks the algorithm at
/// compile time — 32 is `HS256`, 48 is `HS384`, 64 is `HS512`, and no other
/// size will compile.
///
/// [`VerifyMac`] maps straight onto Key Vault's `{"value": bool}` response:
/// a tag that does not match is `Ok(false)`, and `Self::Error` is kept for
/// genuine failures.
///
/// `oct-HSM` keys are production-ready on Managed HSM only; on Key Vault
/// Premium they are in preview, and Standard Key Vault has none.
pub struct AzureMacKey<const N: usize> {
    client: KeyClient,
    key_name: String,
    key_version: Option<String>,
}

impl<const N: usize> AzureMacKey<N>
where
    Self: ValidMacSize<N>,
{
    /// Binds to the `oct-HSM` key named `key_name` in the vault `client`
    /// points at.
    pub fn new(client: KeyClient, key_name: impl Into<String>) -> Self {
        Self {
            client,
            key_name: key_name.into(),
            key_version: None,
        }
    }

    /// Pins both operations to one key version instead of the vault's
    /// current one.
    ///
    /// A MAC is only meaningful against the key version that produced it, so
    /// pinning is how a caller keeps generation and verification on the same
    /// version across a rotation.
    #[must_use]
    pub fn with_key_version(mut self, key_version: impl Into<String>) -> Self {
        self.key_version = Some(key_version.into());
        self
    }

    /// The version path segment. Empty means the vault's current version.
    fn version(&self) -> &str {
        self.key_version.as_deref().unwrap_or_default()
    }
}

impl<const N: usize> GenerateMac<N> for AzureMacKey<N>
where
    Self: ValidMacSize<N>,
{
    type Error = Error;

    async fn generate_mac(&self, message: &Protected<Vec<u8>>) -> Result<[u8; N], Self::Error> {
        let parameters = SignParameters {
            algorithm: Some(Self::algorithm()),
            value: Some(message.clone().risky_unwrap()),
        };
        let options = KeyClientSignOptions {
            key_version: self.key_version.clone(),
            ..Default::default()
        };
        let result = self
            .client
            .sign(&self.key_name, parameters.try_into()?, Some(options))
            .await?
            .into_model()?;

        let tag = result.result.ok_or(Error::MissingField("a MAC tag"))?;
        let received = tag.len();
        tag.try_into().map_err(|_| Error::UnexpectedMacLength {
            expected: N,
            received,
        })
    }
}

impl<const N: usize> VerifyMac<N> for AzureMacKey<N>
where
    Self: ValidMacSize<N>,
{
    type Error = Error;

    async fn verify_mac(
        &self,
        message: &Protected<Vec<u8>>,
        mac: &[u8; N],
    ) -> Result<bool, Self::Error> {
        let parameters = VerifyParameters {
            algorithm: Some(Self::algorithm()),
            digest: Some(message.clone().risky_unwrap()),
            signature: Some(mac.to_vec()),
        };
        let result = self
            .client
            .verify(&self.key_name, self.version(), parameters.try_into()?, None)
            .await?
            .into_model()?;

        result.value.ok_or(Error::MissingField("a verify verdict"))
    }
}

/// Sealed: only the three tag lengths Key Vault's `HS*` algorithms produce
/// are valid, and the mapping is fixed here rather than checked at runtime.
mod private {
    use azure_security_keyvault_keys::models::SignatureAlgorithm;

    pub trait ValidMacSize<const N: usize> {
        fn algorithm() -> SignatureAlgorithm;
    }

    impl ValidMacSize<32> for super::AzureMacKey<32> {
        fn algorithm() -> SignatureAlgorithm {
            SignatureAlgorithm::Hs256
        }
    }

    impl ValidMacSize<48> for super::AzureMacKey<48> {
        fn algorithm() -> SignatureAlgorithm {
            SignatureAlgorithm::Hs384
        }
    }

    impl ValidMacSize<64> for super::AzureMacKey<64> {
        fn algorithm() -> SignatureAlgorithm {
            SignatureAlgorithm::Hs512
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::stub_client;
    use super::*;
    use azure_core::base64;

    const VAULT: &str = "https://my-vault.vault.azure.net";
    const VERSION: &str = "0123456789abcdef0123456789abcdef";

    fn sign_response(tag: &[u8]) -> String {
        format!(
            r#"{{"kid":"{VAULT}/keys/my-key/{VERSION}","value":"{}"}}"#,
            base64::encode_url_safe(tag)
        )
    }

    // Lowkey Vault 7.3.98 refuses to create an `oct-HSM` key with the SIGN
    // or VERIFY operation ("Operation not allowed for this key type: [SIGN,
    // VERIFY]"), so HMAC cannot be exercised against the emulator at all.
    // Everything below is stub-transport cover.

    #[tokio::test]
    async fn generate_mac_signs_the_message_with_hs256() {
        let (client, transport) = stub_client(&[&sign_response(&[5u8; 32])]);
        let key = AzureMacKey::<32>::new(client, "my-key");

        let tag = key
            .generate_mac(&Protected::new(b"a message".to_vec()))
            .await
            .unwrap();

        assert_eq!(tag, [5u8; 32]);
        let request = &transport.requests()[0];
        assert_eq!(request.path(), "/keys/my-key//sign");
        let body = request.json();
        assert_eq!(body["alg"], "HS256");
        assert_eq!(
            base64::decode_url_safe(body["value"].as_str().unwrap()).unwrap(),
            b"a message".to_vec()
        );
    }

    #[tokio::test]
    async fn the_tag_length_picks_the_algorithm() {
        let (client, transport) = stub_client(&[&sign_response(&[5u8; 48])]);
        AzureMacKey::<48>::new(client, "my-key")
            .generate_mac(&Protected::new(b"m".to_vec()))
            .await
            .unwrap();
        assert_eq!(transport.requests()[0].json()["alg"], "HS384");

        let (client, transport) = stub_client(&[&sign_response(&[5u8; 64])]);
        AzureMacKey::<64>::new(client, "my-key")
            .generate_mac(&Protected::new(b"m".to_vec()))
            .await
            .unwrap();
        assert_eq!(transport.requests()[0].json()["alg"], "HS512");
    }

    #[tokio::test]
    async fn a_tag_of_the_wrong_length_is_an_error_not_a_panic() {
        let (client, _) = stub_client(&[&sign_response(&[5u8; 16])]);
        let key = AzureMacKey::<32>::new(client, "my-key");

        let error = key
            .generate_mac(&Protected::new(b"m".to_vec()))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            Error::UnexpectedMacLength {
                expected: 32,
                received: 16
            }
        ));
    }

    #[tokio::test]
    async fn verify_maps_the_vaults_boolean_straight_through() {
        let (client, transport) = stub_client(&[r#"{"value":true}"#]);
        let key = AzureMacKey::<32>::new(client, "my-key");

        assert!(key
            .verify_mac(&Protected::new(b"a message".to_vec()), &[5u8; 32])
            .await
            .unwrap());

        let request = &transport.requests()[0];
        assert_eq!(request.path(), "/keys/my-key//verify");
        let body = request.json();
        assert_eq!(body["alg"], "HS256");
        assert_eq!(
            base64::decode_url_safe(body["digest"].as_str().unwrap()).unwrap(),
            b"a message".to_vec()
        );
        assert_eq!(
            base64::decode_url_safe(body["value"].as_str().unwrap()).unwrap(),
            vec![5u8; 32]
        );
    }

    #[tokio::test]
    async fn a_tag_that_does_not_match_is_ok_false_not_an_error() {
        let (client, _) = stub_client(&[r#"{"value":false}"#]);
        let key = AzureMacKey::<32>::new(client, "my-key");

        let verdict = key
            .verify_mac(&Protected::new(b"a message".to_vec()), &[0u8; 32])
            .await
            .unwrap();

        assert!(!verdict);
    }

    #[tokio::test]
    async fn a_pinned_version_is_used_for_both_operations() {
        let (client, transport) = stub_client(&[&sign_response(&[5u8; 32]), r#"{"value":true}"#]);
        let key = AzureMacKey::<32>::new(client, "my-key").with_key_version("v7");

        let message = Protected::new(b"m".to_vec());
        let tag = key.generate_mac(&message).await.unwrap();
        key.verify_mac(&message, &tag).await.unwrap();

        let requests = transport.requests();
        assert_eq!(requests[0].path(), "/keys/my-key/v7/sign");
        assert_eq!(requests[1].path(), "/keys/my-key/v7/verify");
    }
}
