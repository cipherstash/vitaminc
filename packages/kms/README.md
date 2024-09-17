# Vitamin C KMS

[![Crates.io](https://img.shields.io/crates/v/vitaminc-permutation.svg)](https://crates.io/crates/vitaminc-permutation)
[![Workflow Status](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml)

A `MAC` implementation using [vitaminc](https://github.com/cipherstash/vitaminc) that uses AWS KMS to generate HMACs.
This implementation is asynchronous and uses the [aws_sdk_kms] crate to interact with AWS KMS.

This crate is part of the [Vitamin C](https://github.com/cipherstash/vitaminc) framework to make cryptography code healthy.

# Example

```rust
use aws_sdk_kms::Client;
use vitaminc_protected::Protected;
use vitaminc_traits::Update;
use vitaminc_async_traits::AsyncFixedOutput;
use vitaminc_kms::{AwsKmsHmac, Info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    # use aws_sdk_kms::types::{KeySpec, KeyUsageType};
    # let endpoint_url = "http://localhost:4566";
    # let creds = aws_sdk_kms::config::Credentials::new("fake", "fake", None, None, "test");
    use aws_config::{BehaviorVersion, Region};

    let config = aws_sdk_kms::config::Builder::default()
        .behavior_version(BehaviorVersion::v2024_03_28())
        .region(Region::new("us-east-1"))
    #   .credentials_provider(creds)
        .endpoint_url(endpoint_url)
        .build();

    # let key = Client::from_conf(config.clone())
    #   .create_key()
    #   .key_usage(KeyUsageType::GenerateVerifyMac)
    #   .key_spec(KeySpec::Hmac512)
    #   .send()
    #   .await?;
    # let key_id = key.key_metadata().unwrap().key_id().to_owned();
    // `key_id` is the ID or ARN of the KMS key to use
    let tag = AwsKmsHmac::<64>::new(config, key_id)
        .chain(&Protected::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]))
        .chain(Info("account_id"))
        .try_finalize_fixed()
        .await?;
    
    Ok(())
}
```
