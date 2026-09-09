use vitaminc_protected::Protected;

/// Takes a pre-computed digest, never a raw message — Azure has no
/// "hash it for me" option at all, so the base trait targets the common
/// subset every vendor supports. Signing configuration (and the expected
/// digest length) is fixed at construction time, not passed per call.
#[allow(async_fn_in_trait)]
pub trait Sign {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn sign(&self, digest: &Protected<Vec<u8>>) -> Result<Vec<u8>, Self::Error>;
}

/// See [`VerifyMac`](crate::VerifyMac)'s doc comment for the
/// `Result<bool, Error>` reasoning — applies identically here.
#[allow(async_fn_in_trait)]
pub trait Verify {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn verify(&self, digest: &Protected<Vec<u8>>, signature: &[u8]) -> Result<bool, Self::Error>;
}

#[allow(async_fn_in_trait)]
pub trait GetPublicKey {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn get_public_key(&self) -> Result<Vec<u8>, Self::Error>;
}
