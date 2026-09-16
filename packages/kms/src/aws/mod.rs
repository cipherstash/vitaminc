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

pub use data_key::{AwsDataKeySource, AwsPooledDataKeySource, Error as AwsDataKeySourceError};
pub use hmac::{AwsKmsHmac, Error as AwsKmsHmacError};
