use crate::algorithm::SignatureAlgorithm;
use crate::encoding::{ec_spki, ecdsa_der_to_raw, ecdsa_raw_to_der, rsa_spki, EcCurve};
use crate::sign::{GetPublicKey, Sign, Verify};
use azure_security_keyvault_keys::models::{
    CurveName, JsonWebKey, KeyClientSignOptions, KeyType, SignParameters,
    SignatureAlgorithm as AzureSignatureAlgorithm, VerifyParameters,
};
use azure_security_keyvault_keys::KeyClient;
use thiserror::Error;
use vitaminc_protected::{Controlled, Protected};

/// Errors from the Azure Key Vault signing key.
#[derive(Debug, Error)]
pub enum Error {
    /// The vault, the transport or the credential failed.
    #[error(transparent)]
    Azure(#[from] azure_core::Error),
    /// A successful response left out a field the operation must produce.
    #[error("Azure Key Vault returned no {0}")]
    MissingField(&'static str),
    /// The caller's digest is the wrong length for the configured algorithm.
    /// Checked before any network call: Key Vault signs a pre-computed
    /// digest and will not hash for you, and `RS*` in particular demands an
    /// exact length.
    #[error("the digest is {received} bytes, but {algorithm:?} signs a {expected}-byte digest")]
    DigestLength {
        algorithm: SignatureAlgorithm,
        expected: usize,
        received: usize,
    },
    /// A signature or public key could not be converted to or from the
    /// canonical encoding of ADR 0001.
    #[error("canonical encoding failed: {0}")]
    Encoding(String),
    /// `getKey` returned a key with no public part. Key Vault releases no
    /// key material at all for a symmetric key.
    #[error("key {key_name:?} is a {kty} key, which has no public key to return")]
    NoPublicKey { key_name: String, kty: String },
    /// The key is on a curve with no canonical `SubjectPublicKeyInfo` here.
    /// `P-256K` (secp256k1) is the live case: Key Vault supports it, this
    /// crate's [`SignatureAlgorithm`] does not.
    #[error("key {key_name:?} is on curve {curve}, which this crate does not support")]
    UnsupportedCurve { key_name: String, curve: String },
}

/// An Azure Key Vault-backed signing key.
///
/// Signs a pre-computed digest — Key Vault has no "hash it for me" mode, so
/// the trait's shape and the service's agree. The digest length is checked
/// against the configured algorithm before any call goes out.
///
/// Two conversions keep the canonical encodings of ADR 0001:
///
/// - Key Vault returns an ECDSA signature as raw `r || s`; [`Sign`] turns
///   that into DER, and [`Verify`] turns the caller's DER back into raw.
///   RSA signatures pass through untouched.
/// - Key Vault returns a public key as JWK fields; [`GetPublicKey`] builds
///   a DER `SubjectPublicKeyInfo` from them.
///
/// A signature that is not valid DER is `Ok(false)` from [`Verify`], not an
/// error — it is a signature that does not verify.
pub struct AzureSigningKey {
    client: KeyClient,
    key_name: String,
    key_version: Option<String>,
    algorithm: SignatureAlgorithm,
}

impl AzureSigningKey {
    /// Binds to the key named `key_name` in the vault `client` points at,
    /// signing with `algorithm`.
    ///
    /// Key Vault locks an EC key's curve to one algorithm (`ES256` needs
    /// P-256, `ES384` needs P-384, `ES512` needs P-521). Nothing local can
    /// check that pairing, since the curve is only knowable from the vault;
    /// a mismatch is the vault's own error on the first call.
    pub fn new(
        client: KeyClient,
        key_name: impl Into<String>,
        algorithm: SignatureAlgorithm,
    ) -> Self {
        Self {
            client,
            key_name: key_name.into(),
            key_version: None,
            algorithm,
        }
    }

    /// Pins every operation to one key version instead of the vault's
    /// current one.
    ///
    /// A signature only verifies against the version that produced it, so
    /// pinning is how a caller keeps signing and verification on the same
    /// version across a rotation.
    #[must_use]
    pub fn with_key_version(mut self, key_version: impl Into<String>) -> Self {
        self.key_version = Some(key_version.into());
        self
    }

    /// The algorithm this key was constructed with.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// The version path segment. Empty means the vault's current version.
    fn version(&self) -> &str {
        self.key_version.as_deref().unwrap_or_default()
    }

    fn azure_algorithm(&self) -> AzureSignatureAlgorithm {
        match self.algorithm {
            SignatureAlgorithm::EcdsaP256Sha256 => AzureSignatureAlgorithm::Es256,
            SignatureAlgorithm::EcdsaP384Sha384 => AzureSignatureAlgorithm::Es384,
            SignatureAlgorithm::EcdsaP521Sha512 => AzureSignatureAlgorithm::Es512,
            SignatureAlgorithm::RsaPssSha256 => AzureSignatureAlgorithm::Ps256,
            SignatureAlgorithm::RsaPssSha384 => AzureSignatureAlgorithm::Ps384,
            SignatureAlgorithm::RsaPssSha512 => AzureSignatureAlgorithm::Ps512,
            SignatureAlgorithm::RsaPkcs1Sha256 => AzureSignatureAlgorithm::Rs256,
            SignatureAlgorithm::RsaPkcs1Sha384 => AzureSignatureAlgorithm::Rs384,
            SignatureAlgorithm::RsaPkcs1Sha512 => AzureSignatureAlgorithm::Rs512,
        }
    }

    fn check_digest(&self, digest: &[u8]) -> Result<(), Error> {
        let expected = self.algorithm.digest_len();
        if digest.len() != expected {
            return Err(Error::DigestLength {
                algorithm: self.algorithm,
                expected,
                received: digest.len(),
            });
        }
        Ok(())
    }

    fn jwk_public_key(&self, jwk: JsonWebKey) -> Result<Vec<u8>, Error> {
        let kty = jwk.kty.ok_or(Error::MissingField("a key type"))?;
        match kty {
            KeyType::Rsa | KeyType::RsaHsm => {
                let n = jwk.n.ok_or(Error::MissingField("an RSA modulus"))?;
                let e = jwk.e.ok_or(Error::MissingField("an RSA exponent"))?;
                rsa_spki(&n, &e).map_err(|e| Error::Encoding(e.to_string()))
            }
            KeyType::Ec | KeyType::EcHsm => {
                let crv = jwk.crv.ok_or(Error::MissingField("a curve name"))?;
                let curve = match crv {
                    CurveName::P256 => EcCurve::P256,
                    CurveName::P384 => EcCurve::P384,
                    CurveName::P521 => EcCurve::P521,
                    other => {
                        return Err(Error::UnsupportedCurve {
                            key_name: self.key_name.clone(),
                            curve: other.to_string(),
                        })
                    }
                };
                let x = jwk.x.ok_or(Error::MissingField("an EC x coordinate"))?;
                let y = jwk.y.ok_or(Error::MissingField("an EC y coordinate"))?;
                ec_spki(curve, &x, &y).map_err(|e| Error::Encoding(e.to_string()))
            }
            other => Err(Error::NoPublicKey {
                key_name: self.key_name.clone(),
                kty: other.to_string(),
            }),
        }
    }
}

impl Sign for AzureSigningKey {
    type Error = Error;

    async fn sign(&self, digest: &Protected<Vec<u8>>) -> Result<Vec<u8>, Self::Error> {
        let digest = digest.clone().risky_unwrap();
        self.check_digest(&digest)?;

        let parameters = SignParameters {
            algorithm: Some(self.azure_algorithm()),
            value: Some(digest),
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

        let signature = result.result.ok_or(Error::MissingField("a signature"))?;
        match self.algorithm.ecdsa_field_len() {
            // Key Vault returns `r || s`; the traits promise DER.
            Some(field_len) => {
                ecdsa_raw_to_der(&signature, field_len).map_err(|e| Error::Encoding(e.to_string()))
            }
            None => Ok(signature),
        }
    }
}

impl Verify for AzureSigningKey {
    type Error = Error;

    async fn verify(
        &self,
        digest: &Protected<Vec<u8>>,
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        let digest = digest.clone().risky_unwrap();
        self.check_digest(&digest)?;

        let signature = match self.algorithm.ecdsa_field_len() {
            Some(field_len) => match ecdsa_der_to_raw(signature, field_len) {
                Ok(raw) => raw,
                // Not well-formed DER, so not a signature this key ever
                // produced. That is a failed verification, not a failure.
                Err(_) => return Ok(false),
            },
            None => signature.to_vec(),
        };

        let parameters = VerifyParameters {
            algorithm: Some(self.azure_algorithm()),
            digest: Some(digest),
            signature: Some(signature),
        };
        let result = self
            .client
            .verify(&self.key_name, self.version(), parameters.try_into()?, None)
            .await?
            .into_model()?;

        result.value.ok_or(Error::MissingField("a verify verdict"))
    }
}

impl GetPublicKey for AzureSigningKey {
    type Error = Error;

    async fn get_public_key(&self) -> Result<Vec<u8>, Self::Error> {
        let options = azure_security_keyvault_keys::models::KeyClientGetKeyOptions {
            key_version: self.key_version.clone(),
            ..Default::default()
        };
        let key = self
            .client
            .get_key(&self.key_name, Some(options))
            .await?
            .into_model()?;

        let jwk = key.key.ok_or(Error::MissingField("a key"))?;
        self.jwk_public_key(jwk)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{create_key, lowkey_client, stub_client, unique_key_name};
    use super::*;
    use azure_core::base64;
    use azure_security_keyvault_keys::models::KeyOperation;

    const VAULT: &str = "https://my-vault.vault.azure.net";
    const VERSION: &str = "0123456789abcdef0123456789abcdef";

    fn sign_response(signature: &[u8]) -> String {
        format!(
            r#"{{"kid":"{VAULT}/keys/my-key/{VERSION}","value":"{}"}}"#,
            base64::encode_url_safe(signature)
        )
    }

    /// A raw `r || s` P-256 signature whose `r` has its high bit set, so the
    /// DER form must gain a leading zero byte.
    fn raw_p256_signature() -> Vec<u8> {
        let mut raw = vec![0u8; 64];
        raw[0] = 0x80;
        raw[31] = 0x01;
        raw[63] = 0x02;
        raw
    }

    // --- zero-network unit tests ------------------------------------------

    #[tokio::test]
    async fn sign_converts_the_vaults_raw_ecdsa_signature_to_der() {
        let (client, transport) = stub_client(&[&sign_response(&raw_p256_signature())]);
        let key = AzureSigningKey::new(client, "my-key", SignatureAlgorithm::EcdsaP256Sha256);

        let signature = key.sign(&Protected::new(vec![1u8; 32])).await.unwrap();

        assert_eq!(transport.requests()[0].json()["alg"], "ES256");
        // DER SEQUENCE, then INTEGER r with the padding byte the high bit
        // forces.
        assert_eq!(signature[0], 0x30);
        assert_eq!(&signature[2..5], &[0x02, 0x21, 0x00]);
        assert_eq!(
            ecdsa_der_to_raw(&signature, 32).unwrap(),
            raw_p256_signature()
        );
    }

    #[tokio::test]
    async fn sign_passes_an_rsa_signature_through_untouched() {
        let (client, transport) = stub_client(&[&sign_response(&[0xABu8; 256])]);
        let key = AzureSigningKey::new(client, "my-key", SignatureAlgorithm::RsaPssSha256);

        let signature = key.sign(&Protected::new(vec![1u8; 32])).await.unwrap();

        assert_eq!(transport.requests()[0].json()["alg"], "PS256");
        assert_eq!(signature, vec![0xABu8; 256]);
    }

    #[tokio::test]
    async fn every_algorithm_maps_to_its_key_vault_identifier() {
        let cases = [
            (SignatureAlgorithm::EcdsaP256Sha256, "ES256", 32),
            (SignatureAlgorithm::EcdsaP384Sha384, "ES384", 48),
            (SignatureAlgorithm::EcdsaP521Sha512, "ES512", 64),
            (SignatureAlgorithm::RsaPssSha256, "PS256", 32),
            (SignatureAlgorithm::RsaPssSha384, "PS384", 48),
            (SignatureAlgorithm::RsaPssSha512, "PS512", 64),
            (SignatureAlgorithm::RsaPkcs1Sha256, "RS256", 32),
            (SignatureAlgorithm::RsaPkcs1Sha384, "RS384", 48),
            (SignatureAlgorithm::RsaPkcs1Sha512, "RS512", 64),
        ];

        for (algorithm, expected, digest_len) in cases {
            let signature = match algorithm.ecdsa_field_len() {
                Some(field_len) => vec![1u8; 2 * field_len],
                None => vec![0xABu8; 256],
            };
            let (client, transport) = stub_client(&[&sign_response(&signature)]);
            let key = AzureSigningKey::new(client, "my-key", algorithm);

            key.sign(&Protected::new(vec![1u8; digest_len]))
                .await
                .unwrap();

            assert_eq!(transport.requests()[0].json()["alg"], expected);
        }
    }

    #[tokio::test]
    async fn a_digest_of_the_wrong_length_makes_no_call_at_all() {
        let (client, transport) = stub_client(&[]);
        let key = AzureSigningKey::new(client, "my-key", SignatureAlgorithm::RsaPkcs1Sha256);

        let error = key.sign(&Protected::new(vec![1u8; 31])).await.unwrap_err();

        assert!(matches!(
            error,
            Error::DigestLength {
                expected: 32,
                received: 31,
                ..
            }
        ));
        assert_eq!(transport.call_count(), 0);

        let error = key
            .verify(&Protected::new(vec![1u8; 31]), &[0u8; 256])
            .await
            .unwrap_err();

        assert!(matches!(error, Error::DigestLength { .. }));
        assert_eq!(transport.call_count(), 0);
    }

    #[tokio::test]
    async fn verify_sends_the_raw_form_of_a_der_ecdsa_signature() {
        let der = ecdsa_raw_to_der(&raw_p256_signature(), 32).unwrap();
        let (client, transport) = stub_client(&[r#"{"value":true}"#]);
        let key = AzureSigningKey::new(client, "my-key", SignatureAlgorithm::EcdsaP256Sha256);

        assert!(key
            .verify(&Protected::new(vec![1u8; 32]), &der)
            .await
            .unwrap());

        let body = transport.requests()[0].json();
        assert_eq!(body["alg"], "ES256");
        assert_eq!(
            base64::decode_url_safe(body["value"].as_str().unwrap()).unwrap(),
            raw_p256_signature()
        );
    }

    #[tokio::test]
    async fn a_signature_that_is_not_der_is_ok_false_not_an_error() {
        let (client, transport) = stub_client(&[]);
        let key = AzureSigningKey::new(client, "my-key", SignatureAlgorithm::EcdsaP256Sha256);

        let verdict = key
            .verify(&Protected::new(vec![1u8; 32]), b"not DER at all")
            .await
            .unwrap();

        assert!(!verdict);
        assert_eq!(transport.call_count(), 0);
    }

    #[tokio::test]
    async fn a_false_verdict_maps_to_ok_false() {
        let (client, _) = stub_client(&[r#"{"value":false}"#]);
        let key = AzureSigningKey::new(client, "my-key", SignatureAlgorithm::RsaPssSha256);

        let verdict = key
            .verify(&Protected::new(vec![1u8; 32]), &[0u8; 256])
            .await
            .unwrap();

        assert!(!verdict);
    }

    #[tokio::test]
    async fn get_public_key_builds_an_rsa_subject_public_key_info_from_the_jwk() {
        let n = vec![0xC3u8; 256];
        let e = vec![0x01, 0x00, 0x01];
        let response = format!(
            r#"{{"key":{{"kid":"{VAULT}/keys/my-key/{VERSION}","kty":"RSA","n":"{}","e":"{}"}}}}"#,
            base64::encode_url_safe(&n),
            base64::encode_url_safe(&e)
        );
        let (client, _) = stub_client(&[&response]);
        let key = AzureSigningKey::new(client, "my-key", SignatureAlgorithm::RsaPssSha256);

        let spki = key.get_public_key().await.unwrap();

        assert_eq!(spki, rsa_spki(&n, &e).unwrap());
        assert!(spki::SubjectPublicKeyInfoRef::try_from(spki.as_slice()).is_ok());
    }

    #[tokio::test]
    async fn get_public_key_builds_an_ec_subject_public_key_info_from_the_jwk() {
        let x = vec![0x11u8; 32];
        let y = vec![0x22u8; 32];
        let response = format!(
            r#"{{"key":{{"kid":"{VAULT}/keys/my-key/{VERSION}","kty":"EC","crv":"P-256","x":"{}","y":"{}"}}}}"#,
            base64::encode_url_safe(&x),
            base64::encode_url_safe(&y)
        );
        let (client, _) = stub_client(&[&response]);
        let key = AzureSigningKey::new(client, "my-key", SignatureAlgorithm::EcdsaP256Sha256);

        let spki = key.get_public_key().await.unwrap();

        assert_eq!(spki, ec_spki(EcCurve::P256, &x, &y).unwrap());
    }

    #[tokio::test]
    async fn get_public_key_refuses_a_symmetric_key() {
        let response =
            format!(r#"{{"key":{{"kid":"{VAULT}/keys/my-key/{VERSION}","kty":"oct-HSM"}}}}"#);
        let (client, _) = stub_client(&[&response]);
        let key = AzureSigningKey::new(client, "my-key", SignatureAlgorithm::RsaPssSha256);

        let error = key.get_public_key().await.unwrap_err();

        assert!(matches!(error, Error::NoPublicKey { ref kty, .. } if kty == "oct-HSM"));
    }

    #[tokio::test]
    async fn get_public_key_refuses_the_p_256k_curve() {
        let response = format!(
            r#"{{"key":{{"kid":"{VAULT}/keys/my-key/{VERSION}","kty":"EC","crv":"P-256K","x":"EQ","y":"Ig"}}}}"#
        );
        let (client, _) = stub_client(&[&response]);
        let key = AzureSigningKey::new(client, "my-key", SignatureAlgorithm::EcdsaP256Sha256);

        let error = key.get_public_key().await.unwrap_err();

        assert!(matches!(error, Error::UnsupportedCurve { ref curve, .. } if curve == "P-256K"));
    }

    // --- Lowkey Vault integration tests -----------------------------------
    //
    // These need `docker compose -f packages/kms/docker-compose.yml up -d`.

    async fn lowkey_signing_key(
        kty: KeyType,
        key_size: Option<i32>,
        curve: Option<CurveName>,
        algorithm: SignatureAlgorithm,
    ) -> AzureSigningKey {
        let client = lowkey_client();
        let key_name = unique_key_name("sign");
        let version = create_key(
            &client,
            &key_name,
            kty,
            key_size,
            curve,
            &[KeyOperation::Sign, KeyOperation::Verify],
        )
        .await;
        AzureSigningKey::new(client, key_name, algorithm).with_key_version(version)
    }

    #[tokio::test]
    async fn lowkey_rsa_sign_then_verify_round_trips() {
        let key = lowkey_signing_key(
            KeyType::Rsa,
            Some(2048),
            None,
            SignatureAlgorithm::RsaPssSha256,
        )
        .await;
        let digest = Protected::new(vec![0x5Au8; 32]);

        let signature = key.sign(&digest).await.unwrap();

        assert!(key.verify(&digest, &signature).await.unwrap());
        assert!(!key
            .verify(&Protected::new(vec![0x5Bu8; 32]), &signature)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn lowkey_ecdsa_sign_then_verify_round_trips_through_der() {
        let key = lowkey_signing_key(
            KeyType::Ec,
            None,
            Some(CurveName::P256),
            SignatureAlgorithm::EcdsaP256Sha256,
        )
        .await;
        let digest = Protected::new(vec![0x5Au8; 32]);

        let signature = key.sign(&digest).await.unwrap();

        // The vault returns raw `r || s`; the adapter hands back DER.
        assert_eq!(signature[0], 0x30);
        assert!(key.verify(&digest, &signature).await.unwrap());
        assert!(!key
            .verify(&Protected::new(vec![0x5Bu8; 32]), &signature)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn lowkey_get_public_key_parses_as_subject_public_key_info() {
        let rsa = lowkey_signing_key(
            KeyType::Rsa,
            Some(2048),
            None,
            SignatureAlgorithm::RsaPssSha256,
        )
        .await;
        let spki = rsa.get_public_key().await.unwrap();
        let parsed = spki::SubjectPublicKeyInfoRef::try_from(spki.as_slice()).unwrap();
        assert_eq!(parsed.algorithm.oid, const_oid::db::rfc5912::RSA_ENCRYPTION);

        let ec = lowkey_signing_key(
            KeyType::Ec,
            None,
            Some(CurveName::P256),
            SignatureAlgorithm::EcdsaP256Sha256,
        )
        .await;
        let spki = ec.get_public_key().await.unwrap();
        let parsed = spki::SubjectPublicKeyInfoRef::try_from(spki.as_slice()).unwrap();
        assert_eq!(
            parsed.algorithm.oid,
            const_oid::db::rfc5912::ID_EC_PUBLIC_KEY
        );
        assert_eq!(parsed.subject_public_key.raw_bytes()[0], 0x04);
    }
}
