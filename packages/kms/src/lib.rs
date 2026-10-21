#![doc = include_str!("../README.md")]

mod algorithm;
mod crypt;
mod data_key;
mod index_key;
mod key_id;
mod mac;
pub mod provider;
mod sign;

#[cfg(feature = "canonical-encoding")]
pub(crate) mod encoding;

/// The opt-in switch for the tests against real Vault Enterprise, Azure
/// Managed HSM and Google Cloud KMS.
#[cfg(all(test, any(feature = "azure", feature = "gcp", feature = "vault")))]
pub(crate) mod live;

#[cfg(feature = "aws")]
pub mod aws;
#[cfg(feature = "azure")]
pub mod azure;
#[cfg(feature = "gcp")]
pub mod gcp;
#[cfg(feature = "vault")]
pub mod vault;

pub use algorithm::{DigestLengthError, SignatureAlgorithm};
pub use crypt::{DecryptWithKey, EncryptWithKey};
pub use data_key::{
    dedup_retrieve, fan_out_generate, BatchGenerateDataKey, BatchRetrieveDataKey, GenerateDataKey,
    GeneratedDataKey, KeyCustody, KeyIsolation, KeyReconstruction, RetrieveDataKey,
};
pub use index_key::{load_index_key, IndexKeyMaterial};
pub use key_id::KeyId;
pub use mac::{GenerateMac, VerifyMac};
pub use provider::{Binding, IndexKeyProvider, KeyProvider};
pub use sign::{GetPublicKey, Sign, SignMessage, Verify, VerifyMessage};

// The AWS names below predate the vendor modules and stay at the crate
// root for compatibility. Every other adapter lives in its vendor module
// (`aws::AwsMacKey`, `azure::AzureDataKeySource`, ...).
/// The error type of [`AwsKmsHmac`], re-exported at the crate root under
/// its pre-adapter name for compatibility.
#[cfg(feature = "aws")]
pub use aws::AwsKmsHmacError as Error;
#[cfg(feature = "aws")]
pub use aws::{AwsDataKeySource, AwsDataKeySourceError, AwsKmsHmac};

/// Named type to represent _non-sensitive_ data that is passed to the `update` method.
/// Using a specific type allows us to reason about the input type and its sensitivity.
/// TODO: This probably should be part of the `vitaminc_traits` crate.
pub struct Info(pub &'static str);
