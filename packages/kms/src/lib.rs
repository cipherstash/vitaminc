#![doc = include_str!("../README.md")]

mod algorithm;
mod caching;
mod crypt;
mod data_key;
mod index_key;
mod key_id;
mod mac;
mod pooled;
mod sign;

#[cfg(feature = "canonical-encoding")]
// TODO(adapters): drop once the Azure and Vault adapters use these helpers.
#[allow(dead_code)]
pub(crate) mod encoding;

#[cfg(feature = "aws")]
pub mod aws;
#[cfg(feature = "azure")]
pub mod azure;
#[cfg(feature = "gcp")]
pub mod gcp;
#[cfg(feature = "vault")]
pub mod vault;

pub use algorithm::SignatureAlgorithm;
pub use caching::CachingRetrieveDataKey;
pub use crypt::{DecryptWithKey, EncryptWithKey};
pub use data_key::{
    dedup_retrieve, fan_out_generate, pooled_key_generate, BatchGenerateDataKey,
    BatchRetrieveDataKey, GenerateDataKey, GeneratedDataKey, KeyIsolation, KeyReconstruction,
    RetrieveDataKey,
};
pub use index_key::{load_index_key, IndexKeyMaterial};
pub use key_id::KeyId;
pub use mac::{GenerateMac, VerifyMac};
pub use pooled::PooledDataKeySource;
pub use sign::{GetPublicKey, Sign, Verify};

#[cfg(feature = "aws")]
pub use aws::*;
/// The error type of [`AwsKmsHmac`], re-exported at the crate root under
/// its pre-adapter name for compatibility.
#[cfg(feature = "aws")]
pub use aws::AwsKmsHmacError as Error;
#[cfg(feature = "azure")]
#[allow(unused_imports)] // TODO(adapters): drop once the module exports adapters.
pub use azure::*;
#[cfg(feature = "gcp")]
#[allow(unused_imports)] // TODO(adapters): drop once the module exports adapters.
pub use gcp::*;
#[cfg(feature = "vault")]
#[allow(unused_imports)] // TODO(adapters): drop once the module exports adapters.
pub use vault::*;

/// Named type to represent _non-sensitive_ data that is passed to the `update` method.
/// Using a specific type allows us to reason about the input type and its sensitivity.
/// TODO: This probably should be part of the `vitaminc_traits` crate.
pub struct Info(pub &'static str);
