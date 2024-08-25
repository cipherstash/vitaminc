use async_trait::async_trait;
use aws_sdk_kms::{primitives::Blob, Client};
use vitaminc_protected::{Paranoid, Protected};
use vitaminc_traits::AsyncMac;

/// Re-export the `MacAlgorithmSpec` type from the `aws_sdk_kms` crate.
pub use aws_sdk_kms::types::MacAlgorithmSpec;

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

    pub fn update(mut self, input: Protected<Vec<u8>>) -> Self {
        self.input = self.input.zip(input, |mut input, data| {
            input.extend(data);
            input
        });
        self
    }

    pub fn set_mac_algorithm(mut self, spec: MacAlgorithmSpec) -> Self {
        self.spec = spec;
        self
    }
}

#[async_trait]
impl<'c> AsyncMac for AwsKmsHmac<'c> {
    type Output = Protected<Vec<u8>>;
    type Error = aws_sdk_kms::Error;

    async fn finalize_async(self) -> Result<Self::Output, Self::Error> {
        let request = self
            .client
            .generate_mac()
            .message(Blob::new(self.input.unwrap()))
            .key_id(self.key_id)
            .mac_algorithm(self.spec);

        dbg!(&request);
        let output = request.send().await?;
        dbg!(&output);

        // TODO: What if mac is None?
        Ok(Protected::new(output.mac.unwrap().into_inner()))
    }
}

#[cfg(test)]
mod tests {
    use aws_config::{BehaviorVersion, Region};
    use aws_sdk_kms::{
        types::{KeySpec, KeyUsageType},
        Client,
    };
    use vitaminc_protected::{Paranoid, Protected};
    use vitaminc_traits::AsyncMac;

    async fn get_client() -> Result<Client, Box<dyn std::error::Error>> {
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

        let hmac = super::AwsKmsHmac::new(&client, "0cce5331-13a6-437f-a477-1c8988667281")
            .update(Protected::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]))
            .update(Protected::new(vec![11, 12]));

        assert_eq!(
            hmac.input.unwrap(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 11, 12]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_finalize() -> Result<(), Box<dyn std::error::Error>> {
        let client = get_client().await?;

        println!("bbbbb");
        let key_id = get_key_id(&client, KeySpec::Hmac512).await?;
        println!("bbbbbccc");

        let hmac = super::AwsKmsHmac::new(&client, key_id)
            .update(Protected::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]))
            .set_mac_algorithm(super::MacAlgorithmSpec::HmacSha512);

        hmac.finalize_async().await?;

        Ok(())
    }
}
