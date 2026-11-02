# Vitamin C KMS

[![Crates.io](https://img.shields.io/crates/v/vitaminc-kms.svg)](https://crates.io/crates/vitaminc-kms)
[![Workflow Status](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml)

A `MAC` implementation using [vitaminc](https://github.com/cipherstash/vitaminc) that uses AWS KMS to generate HMACs.
This implementation is asynchronous and uses the [AWS KMS SDK](https://docs.rs/aws-sdk-kms).

This crate is part of the [Vitamin C](https://github.com/cipherstash/vitaminc) framework to make cryptography code healthy.

## Using AWS KMS

The example below generates a 64-byte HMAC using an existing AWS KMS key.
It requires:

- AWS credentials from a configured profile, environment, or workload role.
- A region containing the key, set through `AWS_REGION` or your AWS profile.
- An `HMAC_512` key with key usage `GENERATE_VERIFY_MAC`.
- Permission to call `kms:GenerateMac` on that key.

See the AWS SDK guides for [credentials](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credentials.html)
and [regions](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/region.html), and
KMS's [GenerateMac requirements](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateMac.html).

For example, with an AWS CLI profile already configured:

```sh
export AWS_PROFILE=your-profile
export AWS_REGION=us-east-1
export KMS_KEY_ID=your-existing-key-id-or-arn
```

If you need a new key, this command creates one in your AWS account and
requires `kms:CreateKey` permission. AWS KMS charges apply.

```sh
aws kms create-key --key-spec HMAC_512 --key-usage GENERATE_VERIFY_MAC \
  --query KeyMetadata.KeyId --output text
```

Set `KMS_KEY_ID` to the returned ID. Add these dependencies to a Rust binary:

```sh
cargo add vitaminc-kms vitaminc-protected vitaminc-traits vitaminc-async-traits
cargo add aws-config aws-sdk-kms
cargo add tokio --features macros,rt-multi-thread
```

Copy this into `src/main.rs`, then run `cargo run`. Documentation tests compile
this example; running it sends a request to AWS KMS.

```no_run
use aws_config::BehaviorVersion;
use vitaminc_async_traits::AsyncFixedOutput;
use vitaminc_kms::{AwsKmsHmac, Info};
use vitaminc_protected::{Controlled, Protected};
use vitaminc_traits::Update;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_id = std::env::var("KMS_KEY_ID")?;
    let shared = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let config = aws_sdk_kms::config::Builder::from(&shared).build();

    let tag = AwsKmsHmac::<64>::new(config, key_id)
        .chain(&Protected::new(b"example account".to_vec()))
        .chain(Info("account_id"))
        .try_finalize_fixed()
        .await?;

    assert_eq!(tag.risky_ref().len(), 64);
    Ok(())
}
```

## Using LocalStack

For local development, start a LocalStack instance with KMS support at
`http://localhost:4566`. With the `awslocal` CLI installed, create a local key:

```sh
export KMS_KEY_ID=$(awslocal kms create-key \
  --region us-east-1 --key-spec HMAC_512 --key-usage GENERATE_VERIFY_MAC \
  --query KeyMetadata.KeyId --output text)
```

In the Rust example above, replace the `shared` and `config` declarations
with this block. It sets the local endpoint and test credentials explicitly;
the resulting configuration is only for LocalStack.

```rust
use aws_sdk_kms::config::{BehaviorVersion, Credentials, Region};

let config = aws_sdk_kms::config::Builder::default()
    .behavior_version(BehaviorVersion::latest())
    .region(Region::new("us-east-1"))
    .credentials_provider(Credentials::new("test", "test", None, None, "localstack"))
    .endpoint_url("http://localhost:4566")
    .build();
# assert_eq!(config.region().unwrap().as_ref(), "us-east-1");
```

Run the modified program with `cargo run`. The local key ID and endpoint must
belong to the same LocalStack instance. Documentation tests check the
configuration block without contacting LocalStack.

## Cargo features

This crate defines no Cargo feature flags.

## Compatibility

Requires Rust <!-- msrv:vitaminc-kms -->**1.94.1**<!-- /msrv --> and the Rust standard library (`std`).
The AWS SDK gives this crate a higher Rust requirement than the rest of the
workspace. This adapter targets native applications.
MSRV increases require a minor release; patch releases retain the existing
floor. See the [workspace compatibility policy](https://github.com/cipherstash/vitaminc#compatibility).

## CipherStash

Vitamin C is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT
