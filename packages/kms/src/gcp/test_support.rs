//! A mock of the Google Cloud KMS stub trait, shared by the adapter tests.
//!
//! There is no usable emulator for Google Cloud KMS, so every test in this
//! module mocks [`google_cloud_kms_v1::stub::KeyManagementService`] and
//! builds the client with `KeyManagementService::from_stub`. A mock stands
//! in for the whole transport, which means each test's stub has to behave
//! like the real service on the one thing the adapters depend on: it
//! computes the CRC32C checksums of the payloads it returns.

use google_cloud_gax::options::RequestOptions;
use google_cloud_gax::response::Response;
use google_cloud_kms_v1::model;

mockall::mock! {
    pub Kms {}

    impl google_cloud_kms_v1::stub::KeyManagementService for Kms {
        async fn encrypt(
            &self,
            req: model::EncryptRequest,
            options: RequestOptions,
        ) -> google_cloud_kms_v1::Result<Response<model::EncryptResponse>>;

        async fn decrypt(
            &self,
            req: model::DecryptRequest,
            options: RequestOptions,
        ) -> google_cloud_kms_v1::Result<Response<model::DecryptResponse>>;

        async fn mac_sign(
            &self,
            req: model::MacSignRequest,
            options: RequestOptions,
        ) -> google_cloud_kms_v1::Result<Response<model::MacSignResponse>>;

        async fn mac_verify(
            &self,
            req: model::MacVerifyRequest,
            options: RequestOptions,
        ) -> google_cloud_kms_v1::Result<Response<model::MacVerifyResponse>>;

        async fn asymmetric_sign(
            &self,
            req: model::AsymmetricSignRequest,
            options: RequestOptions,
        ) -> google_cloud_kms_v1::Result<Response<model::AsymmetricSignResponse>>;

        async fn get_public_key(
            &self,
            req: model::GetPublicKeyRequest,
            options: RequestOptions,
        ) -> google_cloud_kms_v1::Result<Response<model::PublicKey>>;
    }
}

// The stub trait requires `Debug`; `mockall` does not derive it.
impl std::fmt::Debug for MockKms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MockKms")
    }
}

/// Wraps a response body the way the transport would.
pub fn ok<T>(body: T) -> google_cloud_kms_v1::Result<Response<T>> {
    Ok(Response::from(body))
}
