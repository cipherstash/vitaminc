//! AWS KMS adapters.
//!
//! One adapter type per key purpose (see `CONTEXT.md`):
//!
//! - [`AwsDataKeySource`]: a symmetric KMS key; data keys via
//!   `GenerateDataKey`/`Decrypt`, plus direct `Encrypt`/`Decrypt`.
//! - [`AwsMacKey`]: an HMAC KMS key; `GenerateMac`/`VerifyMac`.
//! - [`AwsSigningKey`]: an asymmetric sign/verify KMS key; `Sign`/`Verify`/
//!   `GetPublicKey`.
//!
//! Every adapter takes a ready [`aws_sdk_kms::Client`]; credentials,
//! region and endpoint are the caller's concern.
//!
//! [`AwsKmsHmac`] is the older streaming MAC construction and is unrelated
//! to the adapter types.

mod data_key;
mod hmac;
mod mac;
mod sign;

pub use data_key::{AwsDataKeySource, AwsPooledDataKeySource, Error as AwsDataKeySourceError};
pub use hmac::{AwsKmsHmac, Error as AwsKmsHmacError};
pub use mac::{AwsMacKey, Error as AwsMacKeyError};
pub use sign::{AwsSigningKey, Error as AwsSigningKeyError};

#[cfg(test)]
mod testing {
    use aws_config::{BehaviorVersion, Region};
    use aws_sdk_kms::Client;

    /// A client pointed at LocalStack on `localhost:4566` with throwaway
    /// credentials, for the integration tests each adapter module keeps in
    /// its own `localstack` submodule. See the crate README for how to
    /// bring LocalStack up.
    pub fn localstack_client() -> Client {
        let credentials = aws_sdk_kms::config::Credentials::new("fake", "fake", None, None, "test");

        Client::from_conf(
            aws_sdk_kms::config::Builder::default()
                .behavior_version(BehaviorVersion::v2026_01_12())
                .region(Region::new("us-east-1"))
                .credentials_provider(credentials)
                .endpoint_url("http://localhost:4566")
                .build(),
        )
    }
}
