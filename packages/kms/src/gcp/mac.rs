use super::integrity::{self, CallError};
use crate::mac::{GenerateMac, VerifyMac};
use google_cloud_kms_v1::client::KeyManagementService;
use thiserror::Error;
use vitaminc_protected::{Controlled, Protected};

/// Errors from [`GcpMacKey`].
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Gcp(#[from] google_cloud_kms_v1::Error),
    /// Two consecutive responses failed the same CRC32C check, or two
    /// consecutive `macVerify` verdicts contradicted their own
    /// `verifiedSuccessIntegrity` flag.
    #[error("Google Cloud KMS responses failed their {0} integrity check twice")]
    Integrity(&'static str),
    /// The tag Google Cloud KMS returned is not `N` bytes long, so the
    /// bound key version's algorithm is not the one `N` names.
    #[error("Google Cloud KMS returned a {received}-byte MAC, expected {expected}")]
    UnexpectedMacLength { expected: usize, received: usize },
}

impl From<CallError> for Error {
    fn from(error: CallError) -> Self {
        match error {
            CallError::Gcp(error) => Self::Gcp(error),
            CallError::Integrity(field) => Self::Integrity(field),
        }
    }
}

/// Google Cloud KMS-backed MAC key, bound to one `CryptoKeyVersion`
/// resource name.
///
/// `N` is the tag length in bytes, and picks the algorithm the bound key
/// version must have been created with:
///
/// - 28 bytes: `HMAC_SHA224`
/// - 32 bytes: `HMAC_SHA256`
/// - 48 bytes: `HMAC_SHA384`
/// - 64 bytes: `HMAC_SHA512`
///
/// No other size compiles. Google Cloud KMS also offers `HMAC_SHA1`; this
/// adapter deliberately cannot be built over it.
///
/// The binding is a `CryptoKeyVersion`, not a `CryptoKey`: `macSign` and
/// `macVerify` are defined only on versions, so there is no "use the
/// primary version" shortcut to inherit. Rotating the backend key means
/// constructing a new adapter over the new version.
pub struct GcpMacKey<const N: usize> {
    client: KeyManagementService,
    crypto_key_version_name: String,
}

impl<const N: usize> GcpMacKey<N>
where
    Self: private::ValidMacSize<N>,
{
    /// `crypto_key_version_name` is the full resource name of the
    /// `CryptoKeyVersion` this instance is bound to
    /// (`projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}/cryptoKeyVersions/{v}`),
    /// whose `CryptoKey` purpose must be `MAC`.
    pub fn new(client: KeyManagementService, crypto_key_version_name: impl Into<String>) -> Self {
        Self {
            client,
            crypto_key_version_name: crypto_key_version_name.into(),
        }
    }
}

impl<const N: usize> GenerateMac<N> for GcpMacKey<N>
where
    Self: private::ValidMacSize<N>,
{
    type Error = Error;

    async fn generate_mac(&self, message: &Protected<Vec<u8>>) -> Result<[u8; N], Self::Error> {
        let data = message.clone().risky_unwrap();
        let checksum = integrity::crc32c(&data);

        let response = integrity::checked_call(|| {
            self.client
                .mac_sign()
                .set_name(self.crypto_key_version_name.clone())
                .set_data(data.clone())
                .set_data_crc32c(checksum)
                .send()
        })
        .await?;

        let received = response.mac.len();
        response
            .mac
            .to_vec()
            .try_into()
            .map_err(|_| Error::UnexpectedMacLength {
                expected: N,
                received,
            })
    }
}

impl<const N: usize> VerifyMac<N> for GcpMacKey<N>
where
    Self: private::ValidMacSize<N>,
{
    type Error = Error;

    /// `macVerify` answers with `success` as ordinary response data, so a
    /// bad tag is `Ok(false)` rather than an error. The second-order
    /// `verifiedSuccessIntegrity` flag on the verdict is resolved inside
    /// the adapter — a verdict that contradicts it is retried and then
    /// becomes [`Error::Integrity`], so the caller only ever sees the two
    /// states this trait promises.
    async fn verify_mac(
        &self,
        message: &Protected<Vec<u8>>,
        mac: &[u8; N],
    ) -> Result<bool, Self::Error> {
        let data = message.clone().risky_unwrap();
        let data_checksum = integrity::crc32c(&data);
        let mac_checksum = integrity::crc32c(mac);

        let response = integrity::checked_call(|| {
            self.client
                .mac_verify()
                .set_name(self.crypto_key_version_name.clone())
                .set_data(data.clone())
                .set_data_crc32c(data_checksum)
                .set_mac(mac.to_vec())
                .set_mac_crc32c(mac_checksum)
                .send()
        })
        .await?;

        Ok(response.success)
    }
}

mod private {
    /// Sealed: the tag lengths Google Cloud KMS's HMAC algorithms produce,
    /// minus `HMAC_SHA1`, which this crate does not offer.
    pub trait ValidMacSize<const N: usize> {}

    impl ValidMacSize<28> for super::GcpMacKey<28> {}
    impl ValidMacSize<32> for super::GcpMacKey<32> {}
    impl ValidMacSize<48> for super::GcpMacKey<48> {}
    impl ValidMacSize<64> for super::GcpMacKey<64> {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcp::integrity::crc32c;
    use crate::gcp::test_support::{ok, MockKms};
    use google_cloud_kms_v1::model::{MacSignResponse, MacVerifyResponse};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const VERSION: &str = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";

    fn message() -> Protected<Vec<u8>> {
        Protected::new(b"the message to authenticate".to_vec())
    }

    fn mac_sign_response(mac: Vec<u8>) -> MacSignResponse {
        MacSignResponse::new()
            .set_name(VERSION)
            .set_mac_crc32c(crc32c(&mac))
            .set_mac(mac)
            .set_verified_data_crc32c(true)
    }

    /// A verdict as Google Cloud KMS sends it: `verifiedSuccessIntegrity`
    /// agrees with `success`, and both request checksums were verified.
    fn mac_verify_response(success: bool) -> MacVerifyResponse {
        MacVerifyResponse::new()
            .set_name(VERSION)
            .set_success(success)
            .set_verified_success_integrity(success)
            .set_verified_data_crc32c(true)
            .set_verified_mac_crc32c(true)
    }

    fn mac_key<const N: usize>(stub: MockKms) -> GcpMacKey<N>
    where
        GcpMacKey<N>: private::ValidMacSize<N>,
    {
        GcpMacKey::new(KeyManagementService::from_stub(stub), VERSION)
    }

    #[tokio::test]
    async fn generate_mac_signs_the_message_under_the_bound_version() {
        let mut stub = MockKms::new();
        stub.expect_mac_sign().times(1).returning(|req, _| {
            assert_eq!(req.name, VERSION);
            assert_eq!(req.data.to_vec(), b"the message to authenticate".to_vec());
            assert_eq!(req.data_crc32c, Some(crc32c(&req.data)));
            ok(mac_sign_response(vec![7u8; 32]))
        });

        let key = mac_key::<32>(stub);

        assert_eq!(key.generate_mac(&message()).await.unwrap(), [7u8; 32]);
    }

    #[tokio::test]
    async fn a_tag_of_the_wrong_length_is_an_error() {
        let mut stub = MockKms::new();
        stub.expect_mac_sign()
            .times(1)
            .returning(|_, _| ok(mac_sign_response(vec![7u8; 64])));

        let key = mac_key::<32>(stub);

        let error = key.generate_mac(&message()).await.unwrap_err();

        assert!(matches!(
            error,
            Error::UnexpectedMacLength {
                expected: 32,
                received: 64
            }
        ));
    }

    #[tokio::test]
    async fn a_mangled_tag_checksum_is_discarded_and_the_call_retried_once() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);

        let mut stub = MockKms::new();
        stub.expect_mac_sign().times(2).returning(move |_, _| {
            let response = mac_sign_response(vec![7u8; 32]);
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                return ok(response.set_mac_crc32c(0));
            }
            ok(response)
        });

        let key = mac_key::<32>(stub);

        assert_eq!(key.generate_mac(&message()).await.unwrap(), [7u8; 32]);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn an_unverified_request_checksum_makes_mac_sign_an_integrity_error() {
        let mut stub = MockKms::new();
        stub.expect_mac_sign()
            .times(2)
            .returning(|_, _| ok(mac_sign_response(vec![7u8; 32]).set_verified_data_crc32c(false)));

        let key = mac_key::<32>(stub);

        let error = key.generate_mac(&message()).await.unwrap_err();

        assert!(matches!(error, Error::Integrity("verifiedDataCrc32c")));
    }

    #[tokio::test]
    async fn verify_mac_sends_both_payloads_and_their_checksums() {
        let mut stub = MockKms::new();
        stub.expect_mac_verify().times(1).returning(|req, _| {
            assert_eq!(req.name, VERSION);
            assert_eq!(req.data.to_vec(), b"the message to authenticate".to_vec());
            assert_eq!(req.data_crc32c, Some(crc32c(&req.data)));
            assert_eq!(req.mac.to_vec(), vec![7u8; 32]);
            assert_eq!(req.mac_crc32c, Some(crc32c(&req.mac)));
            ok(mac_verify_response(true))
        });

        let key = mac_key::<32>(stub);

        assert!(key.verify_mac(&message(), &[7u8; 32]).await.unwrap());
    }

    #[tokio::test]
    async fn a_failed_verification_is_ok_false_not_an_error() {
        let mut stub = MockKms::new();
        stub.expect_mac_verify()
            .times(1)
            .returning(|_, _| ok(mac_verify_response(false)));

        let key = mac_key::<32>(stub);

        assert!(!key.verify_mac(&message(), &[0u8; 32]).await.unwrap());
    }

    #[tokio::test]
    async fn a_verdict_contradicting_its_integrity_flag_is_retried_once() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);

        let mut stub = MockKms::new();
        stub.expect_mac_verify().times(2).returning(move |_, _| {
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                // A `true` that the integrity flag says was never verified.
                return ok(mac_verify_response(true).set_verified_success_integrity(false));
            }
            ok(mac_verify_response(true))
        });

        let key = mac_key::<32>(stub);

        assert!(key.verify_mac(&message(), &[7u8; 32]).await.unwrap());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_persistently_contradicted_verdict_is_an_integrity_error_never_a_third_state() {
        let mut stub = MockKms::new();
        stub.expect_mac_verify()
            .times(2)
            .returning(|_, _| ok(mac_verify_response(false).set_verified_success_integrity(true)));

        let key = mac_key::<32>(stub);

        let error = key.verify_mac(&message(), &[7u8; 32]).await.unwrap_err();

        assert!(matches!(
            error,
            Error::Integrity("verifiedSuccessIntegrity")
        ));
    }

    #[tokio::test]
    async fn every_valid_tag_length_is_constructible() {
        async fn round_trip<const N: usize>()
        where
            GcpMacKey<N>: private::ValidMacSize<N> + GenerateMac<N, Error = Error>,
        {
            let mut stub = MockKms::new();
            stub.expect_mac_sign()
                .times(1)
                .returning(|_, _| ok(mac_sign_response(vec![3u8; N])));

            let key = GcpMacKey::<N>::new(KeyManagementService::from_stub(stub), VERSION);

            assert_eq!(key.generate_mac(&message()).await.unwrap(), [3u8; N]);
        }

        round_trip::<28>().await;
        round_trip::<32>().await;
        round_trip::<48>().await;
        round_trip::<64>().await;
    }
}
