use async_trait::async_trait;
use aws_sdk_kms::{primitives::Blob, Client};
use vitaminc_protected::{AsProtectedRef, Paranoid, Protected, ProtectedRef};
use vitaminc_traits::{AsyncMac, Update};

/// Re-export the `MacAlgorithmSpec` type from the `aws_sdk_kms` crate.
pub use aws_sdk_kms::types::MacAlgorithmSpec;

/// A `Mac` implementation that uses AWS KMS to generate HMACs.
///
/// This implementation is asynchronous and uses the `aws_sdk_kms` crate to interact with AWS KMS.
///
/// # Example
///
/// ```
/// use aws_sdk_kms::Client;
/// use vitaminc_protected::Protected;
/// use vitaminc_traits::{AsyncMac, Update};
/// use vitaminc_kms::{AwsKmsHmac, Info};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     # use aws_config::{BehaviorVersion, Region};
///     # let endpoint_url = "http://localhost:4566";
///     # let creds = aws_sdk_kms::config::Credentials::new("fake", "fake", None, None, "test");
///     # let config = aws_sdk_kms::config::Builder::default()
///     #     .behavior_version(BehaviorVersion::v2024_03_28())
///     #     .region(Region::new("us-east-1"))
///     #     .credentials_provider(creds)
///     #     .endpoint_url(endpoint_url)
///     #     .build();
///     # let client = Client::from_conf(config);
///     #  
///     # let key = client
///     #     .create_key()
///     #     .key_usage(aws_sdk_kms::types::KeyUsageType::GenerateVerifyMac)
///     #     .key_spec(aws_sdk_kms::types::KeySpec::Hmac256)
///     #     .send()
///     #     .await?;
///     # let key_id = key.key_metadata().unwrap().key_id().to_owned();
///     // `key_id` is the ID or ARN of the KMS key to use
///     let tag = AwsKmsHmac::new(&client, key_id)
///         .chain(&Protected::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]))
///         .chain(&Info::new("account_id"))
///         .finalize_async()
///         .await?;
///     
///     Ok(())
/// }
/// ```
pub struct AwsKmsHmac<'c> {
    client: &'c Client,
    spec: MacAlgorithmSpec,
    key_id: String,
    input: Protected<Vec<u8>>,
}

impl<'c> AwsKmsHmac<'c> {
    pub fn new(client: &'c Client, key_id: impl Into<String>) -> Self {
        Self {
            client,
            spec: MacAlgorithmSpec::HmacSha256,
            key_id: key_id.into(),
            input: Protected::new(Vec::new()),
        }
    }

    pub fn set_mac_algorithm(mut self, spec: MacAlgorithmSpec) -> Self {
        self.spec = spec;
        self
    }
}

/// Named type to represent _non-sensitive_ data that is passed to the `update` method.
/// Using a specific type allows us to reason about the input type and its sensitivity.
pub struct Info<'s>(&'s str);

impl<'s> Info<'s> {
    pub fn new(s: &'s str) -> Self {
        Self(s)
    }
}

impl AsProtectedRef<'_, [u8]> for Info<'_> {
    fn as_protected_ref(&self) -> ProtectedRef<[u8]> {
        self.0.as_protected_ref()
    }
}

impl<'c> Update<Protected<Vec<u8>>> for AwsKmsHmac<'c> {
    fn update(&mut self, data: &Protected<Vec<u8>>) {
        let pref: ProtectedRef<[u8]> = data.as_protected_ref();
        self.input.update_with_ref(pref, |input, data| {
            input.extend(data);
        });
    }
}

impl<'c> Update<Info<'c>> for AwsKmsHmac<'c> {
    fn update(&mut self, data: &Info) {
        let pref: ProtectedRef<[u8]> = data.as_protected_ref();
        self.input.update_with_ref(pref, |input, data| {
            input.extend(data);
        });
    }
}

#[async_trait]
impl<'c> AsyncMac for AwsKmsHmac<'c> {
    type Output = Protected<Vec<u8>>;
    type Error = aws_sdk_kms::Error;

    async fn finalize_async(self) -> Result<Self::Output, Self::Error> {
        let output = self
            .client
            .generate_mac()
            .message(Blob::new(self.input.unwrap()))
            .key_id(self.key_id)
            .mac_algorithm(self.spec)
            .send()
            .await?
            .mac
            .unwrap() // Mac will always be Some
            .into_inner();

        Ok(Protected::new(output))
    }
}

#[cfg(test)]
mod tests {
    use crate::{AwsKmsHmac, Info};
    use aws_sdk_kms::{
        types::{KeySpec, KeyUsageType},
        Client,
    };
    use vitaminc_protected::{Paranoid, Protected};
    use vitaminc_traits::{AsyncMac, Update};

    async fn get_client() -> Result<Client, Box<dyn std::error::Error>> {
        use aws_config::{BehaviorVersion, Region};

        // Set up AWS client
        let endpoint_url = "http://localhost:4566";
        let creds = aws_sdk_kms::config::Credentials::new("fake", "fake", None, None, "test");

        let config = aws_sdk_kms::config::Builder::default()
            .behavior_version(BehaviorVersion::v2024_03_28())
            .region(Region::new("us-east-1"))
            .credentials_provider(creds)
            .endpoint_url(endpoint_url)
            .build();

        Ok(Client::from_conf(config))
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
        let client = get_client().await?;

        let mut hmac = AwsKmsHmac::new(&client, "0cce5331-13a6-437f-a477-1c8988667281");
        hmac.update(&Protected::new(vec![0, 1]));
        hmac.update(&Protected::new(vec![2, 3]));
        hmac.update(&Info::new("test"));

        assert_eq!(hmac.input.unwrap(), vec![0, 1, 2, 3, 116, 101, 115, 116]);

        Ok(())
    }

    #[tokio::test]
    async fn test_chain() -> Result<(), Box<dyn std::error::Error>> {
        let client = get_client().await?;

        let hmac = AwsKmsHmac::new(&client, "0cce5331-13a6-437f-a477-1c8988667281")
            .chain(&Protected::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]))
            .chain(&Protected::new(vec![11, 12]));

        assert_eq!(
            hmac.input.unwrap(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 11, 12]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_finalize() -> Result<(), Box<dyn std::error::Error>> {
        let client = get_client().await?;

        let key_id = get_key_id(&client, KeySpec::Hmac512).await?;

        AwsKmsHmac::new(&client, key_id)
            .set_mac_algorithm(super::MacAlgorithmSpec::HmacSha512)
            .chain(&Protected::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]))
            .finalize_async()
            .await?;

        Ok(())
    }
}
