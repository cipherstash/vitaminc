//! A `Mac` implementation that uses AWS KMS to generate HMACs.
//!
//! This implementation is asynchronous and uses the `aws_sdk_kms` crate to interact with AWS KMS.
//!
//! # Example
//!
//! ```
//! use aws_sdk_kms::Client;
//! use vitaminc_protected::Protected;
//! use vitaminc_traits::Update;
//! use vitaminc_async_traits::AsyncFixedOutput;
//! use vitaminc_kms::{AwsKmsHmac, Info};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     # use aws_sdk_kms::types::{KeySpec, KeyUsageType};
//!     # let endpoint_url = "http://localhost:4566";
//!     # let creds = aws_sdk_kms::config::Credentials::new("fake", "fake", None, None, "test");
//!     use aws_config::{BehaviorVersion, Region};
//!
//!     let config = aws_sdk_kms::config::Builder::default()
//!         .behavior_version(BehaviorVersion::v2024_03_28())
//!         .region(Region::new("us-east-1"))
//!     #   .credentials_provider(creds)
//!         .endpoint_url(endpoint_url)
//!         .build();
//!
//!     # let key = Client::from_conf(config.clone())
//!     #   .create_key()
//!     #   .key_usage(KeyUsageType::GenerateVerifyMac)
//!     #   .key_spec(KeySpec::Hmac512)
//!     #   .send()
//!     #   .await?;
//!     # let key_id = key.key_metadata().unwrap().key_id().to_owned();
//!     // `key_id` is the ID or ARN of the KMS key to use
//!     let tag = AwsKmsHmac::<64>::new(config, key_id)
//!         .chain(&Protected::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]))
//!         .chain(Info("account_id"))
//!         .try_finalize_fixed()
//!         .await?;
//!     
//!     Ok(())
//! }
//! ```
//!
use crate::private::ValidMacSize;
use aws_sdk_kms::{primitives::Blob, Client, Config};
use thiserror::Error;
use vitaminc_async_traits::{AsyncFixedOutput, AsyncFixedOutputReset};
use vitaminc_protected::{AsProtectedRef, Controlled, Protected, ProtectedRef};
use vitaminc_traits::Update;
use zeroize::Zeroize;

/// A `Mac` implementation that uses AWS KMS to generate HMACs of `N` bytes.
/// Valid sizes are 28, 32, 48, and 64 bytes.
///
/// These corespond to the following algorithms:
/// - 28 bytes: HMAC-SHA224
/// - 32 bytes: HMAC-SHA256
/// - 48 bytes: HMAC-SHA384
/// - 64 bytes: HMAC-SHA512
///
pub struct AwsKmsHmac<const N: usize> {
    client: Client,
    key_id: String,
    // TODO: Consider using heapless::Vec
    input: Protected<Vec<u8>>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    AwsSdk(#[from] aws_sdk_kms::Error),
}

impl<const N: usize> AwsKmsHmac<N>
where
    Self: private::ValidMacSize<N>,
{
    pub fn new(config: Config, key_id: impl Into<String>) -> Self {
        Self {
            client: Client::from_conf(config),
            key_id: key_id.into(),
            input: Protected::new(Vec::new()),
        }
    }

    async fn generate_mac(&self) -> Result<Blob, Error> {
        self.client
            .generate_mac()
            .key_id(&self.key_id)
            .mac_algorithm(Self::spec())
            // TODO: Prefer not to unwrap - async map for Paranoid?
            .message(Blob::new(self.input.clone().risky_unwrap()))
            .send()
            .await
            .map(|response| response.mac.unwrap())
            .map_err(aws_sdk_kms::Error::from)
            .map_err(Error::AwsSdk)
    }
}

/// Named type to represent _non-sensitive_ data that is passed to the `update` method.
/// Using a specific type allows us to reason about the input type and its sensitivity.
/// TODO: This probably should be part of the `vitaminc_traits` crate.
pub struct Info(pub &'static str);

impl<const N: usize, T> Update<&Protected<T>> for AwsKmsHmac<N>
where
    T: AsRef<[u8]> + Zeroize,
{
    fn update(&mut self, data: &Protected<T>) {
        let pref: ProtectedRef<[u8]> = data.as_protected_ref();
        self.input.update_with_ref(pref, |input, data| {
            input.extend(data);
        });
    }
}

impl<const N: usize, T> Update<Protected<T>> for AwsKmsHmac<N>
where
    T: AsRef<[u8]> + Zeroize,
{
    fn update(&mut self, data: Protected<T>) {
        self.input.update_with(data, |input, mut data| {
            input.extend_from_slice(data.as_ref());
            data.zeroize();
        });
    }
}

impl<const N: usize> Update<Info> for AwsKmsHmac<N> {
    fn update(&mut self, data: Info) {
        let pref: ProtectedRef<[u8]> = data.0.as_protected_ref();
        self.input.update_with_ref(pref, |input, data| {
            input.extend(data);
        });
    }
}

impl<'r, const N: usize> Update<ProtectedRef<'r, [u8]>> for AwsKmsHmac<N> {
    fn update(&mut self, pref: ProtectedRef<[u8]>) {
        self.input.update_with_ref(pref, |input, data| {
            input.extend(data);
        });
    }
}

impl<const N: usize> AsyncFixedOutput<N, Protected<[u8; N]>> for AwsKmsHmac<N>
where
    Self: private::ValidMacSize<N>,
{
    type Error = Error;

    async fn try_finalize_into(self, out: &mut Protected<[u8; N]>) -> Result<(), Self::Error> {
        let output = self.generate_mac().await?;
        let response = Protected::new(output.into_inner());

        out.update_with(response, |out, data| {
            out.copy_from_slice(data.as_ref());
        });

        Ok(())
    }
}

impl<const N: usize> AsyncFixedOutputReset<N, Protected<[u8; N]>> for AwsKmsHmac<N>
where
    Self: private::ValidMacSize<N>,
{
    type Error = Error;

    async fn try_finalize_into_reset(
        &mut self,
        out: &mut Protected<[u8; N]>,
    ) -> Result<(), Self::Error> {
        let output = self.generate_mac().await?;
        let response = Protected::new(output.into_inner());

        out.update_with(response, |out, data| {
            out.copy_from_slice(data.as_ref());
        });

        self.input.update(|input| input.clear());

        Ok(())
    }
}

mod private {
    use aws_sdk_kms::types::MacAlgorithmSpec;

    pub trait ValidMacSize<const N: usize> {
        fn spec() -> MacAlgorithmSpec;
    }

    impl ValidMacSize<28> for super::AwsKmsHmac<28> {
        fn spec() -> MacAlgorithmSpec {
            MacAlgorithmSpec::HmacSha224
        }
    }

    impl ValidMacSize<32> for super::AwsKmsHmac<32> {
        fn spec() -> MacAlgorithmSpec {
            MacAlgorithmSpec::HmacSha256
        }
    }

    impl ValidMacSize<48> for super::AwsKmsHmac<48> {
        fn spec() -> MacAlgorithmSpec {
            MacAlgorithmSpec::HmacSha384
        }
    }

    impl ValidMacSize<64> for super::AwsKmsHmac<64> {
        fn spec() -> MacAlgorithmSpec {
            MacAlgorithmSpec::HmacSha512
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{AwsKmsHmac, Info};
    use aws_sdk_kms::{
        types::{KeySpec, KeyUsageType},
        Client, Config,
    };
    use vitaminc_async_traits::AsyncFixedOutput;
    use vitaminc_protected::{Controlled, Protected};
    use vitaminc_traits::Update;

    fn get_config() -> Config {
        use aws_config::{BehaviorVersion, Region};

        // Set up AWS client
        let endpoint_url = "http://localhost:4566";
        let creds = aws_sdk_kms::config::Credentials::new("fake", "fake", None, None, "test");

        aws_sdk_kms::config::Builder::default()
            .behavior_version(BehaviorVersion::v2024_03_28())
            .region(Region::new("us-east-1"))
            .credentials_provider(creds)
            .endpoint_url(endpoint_url)
            .build()
    }

    async fn get_key_id(
        client: &Client,
        keyspec: KeySpec,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let key = client
            .create_key()
            .key_usage(KeyUsageType::GenerateVerifyMac)
            .key_spec(keyspec)
            .send()
            .await?;

        Ok(key.key_metadata().unwrap().key_id().to_owned())
    }

    #[tokio::test]
    async fn test_update() -> Result<(), Box<dyn std::error::Error>> {
        let mut hmac: AwsKmsHmac<32> =
            AwsKmsHmac::new(get_config(), "0cce5331-13a6-437f-a477-1c8988667281");
        hmac.update(&Protected::new(vec![0, 1]));
        hmac.update(&Protected::new(vec![2, 3]));
        hmac.update(Info("test"));

        assert_eq!(
            hmac.input.risky_unwrap(),
            vec![0, 1, 2, 3, 116, 101, 115, 116]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_chain() -> Result<(), Box<dyn std::error::Error>> {
        // TODO: Test all the variants
        // Also doctest with invalid sizes
        let hmac: AwsKmsHmac<32> =
            AwsKmsHmac::new(get_config(), "0cce5331-13a6-437f-a477-1c8988667281")
                .chain(&Protected::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]))
                .chain(&Protected::new(vec![11, 12]));

        assert_eq!(
            hmac.input.risky_unwrap(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 11, 12]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_finalize() -> Result<(), Box<dyn std::error::Error>> {
        let config = get_config();
        let client = Client::from_conf(config);
        let key_id = get_key_id(&client, KeySpec::Hmac512).await?;

        AwsKmsHmac::<64>::new(get_config(), key_id)
            .chain(&Protected::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]))
            .try_finalize_fixed()
            .await?;

        Ok(())
    }
}
