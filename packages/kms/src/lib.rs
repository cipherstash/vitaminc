#![doc = include_str!("../README.md")]
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
/// These correspond to the following algorithms:
/// - 28 bytes: HMAC-SHA224
/// - 32 bytes: HMAC-SHA256
/// - 48 bytes: HMAC-SHA384
/// - 64 bytes: HMAC-SHA512
///
/// Updates append bytes to a local protected buffer. Finalization sends the
/// entire message to KMS; it is not a streaming network operation. Key material
/// remains in KMS. SDK request/response buffers are not `Protected` wrappers.
///
/// # Failure, reset, and cancellation
///
/// SDK errors leave the caller's output untouched. Reset finalization retains
/// the buffered input on SDK error or cancellation while awaiting KMS, allowing
/// retry. On success it copies the MAC to the output, then clears the input's
/// length. This clear retains capacity and does not immediately wipe the old
/// message bytes; the protected buffer is wiped when dropped. Consuming
/// finalization drops the instance on success, failure, or cancellation.
/// A cancelled request may still complete remotely.
///
/// # Panics
///
/// Finalization currently panics if a successful KMS response omits its MAC
/// or returns a MAC whose length is not `N`. These malformed-response cases
/// are not represented by [`enum@Error`].
pub struct AwsKmsHmac<const N: usize> {
    client: Client,
    key_id: String,
    // TODO: Consider using heapless::Vec
    input: Protected<Vec<u8>>,
}

/// Failure returned by an AWS KMS operation.
#[derive(Debug, Error)]
pub enum Error {
    /// An SDK/service error, including failed requests or rejected key parameters.
    #[error(transparent)]
    AwsSdk(#[from] aws_sdk_kms::Error),
}

impl<const N: usize> AwsKmsHmac<N>
where
    Self: private::ValidMacSize<N>,
{
    /// Create an empty message accumulator for an existing KMS HMAC key.
    ///
    /// `key_id` is passed unchanged to KMS. The key must support the HMAC
    /// algorithm selected by `N`, and the configured credentials must permit
    /// `GenerateMac`. Construction makes no request and does not validate key
    /// access; failures are reported when finalizing.
    ///
    /// # Panics
    ///
    /// Inherits the configuration requirements and panics of [`Client::from_conf`].
    pub fn new(config: Config, key_id: impl Into<String>) -> Self {
        Self {
            client: Client::from_conf(config),
            key_id: key_id.into(),
            input: Protected::new(Vec::new()),
        }
    }

    // `aws_sdk_kms::Error` is large and we re-export it as-is through our own
    // `Error`, so shrinking it would mean boxing a public variant. Not worth a
    // breaking change for an error on a network round-trip.
    #[allow(clippy::result_large_err)]
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
        let pref: ProtectedRef<T> = data.as_protected_ref();
        self.input.update_with_ref(pref, |input, data| {
            input.extend(data.as_ref());
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

    /// Send the buffered message to KMS and copy its MAC into `out`.
    /// SDK errors and cancellation during the request leave `out` unchanged;
    /// the consumed instance is dropped. See [`AwsKmsHmac`] for malformed-
    /// response panics and remote cancellation limitations.
    async fn try_finalize_into(self, out: &mut Protected<[u8; N]>) -> Result<(), Self::Error> {
        let output = self.generate_mac().await?;
        let response = Protected::new(output.into_inner());

        out.update_with(response, |out, data| {
            out.copy_from_slice(data.as_ref());
        });

        Ok(())
    }
}

impl<const N: usize, C> AsyncFixedOutputReset<N, C> for AwsKmsHmac<N>
where
    Self: private::ValidMacSize<N>,
    C: Controlled<Inner = [u8; N]>,
{
    type Error = Error;

    /// Send the buffered message to KMS, write the MAC, and clear the input length.
    /// SDK errors and cancellation during the request retain the input and
    /// leave `out` unchanged. Success retains input capacity without immediately
    /// wiping the previous message. See [`AwsKmsHmac`] for panic behavior.
    async fn try_finalize_into_reset(&mut self, out: &mut C) -> Result<(), Self::Error> {
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
            .behavior_version(BehaviorVersion::v2026_01_12())
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
