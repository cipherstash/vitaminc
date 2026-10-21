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

    async fn verify(
        &self,
        digest: &Protected<Vec<u8>>,
        signature: &[u8],
    ) -> Result<bool, Self::Error>;
}

/// Signs the whole message, never a digest. This is the trait for
/// schemes that hash inside the signature, such as pure Ed25519 (RFC
/// 8032): the vendors that offer Ed25519 (Google Cloud KMS and Vault
/// Transit) have no pre-hashed mode for it, so it cannot implement
/// [`Sign`].
///
/// The two trait pairs are separate on purpose. An adapter implements one
/// pair or the other, never both, so a digest cannot go to a key that
/// signs messages, and a message cannot go to a key that signs digests:
/// the call does not compile. The method names are different too, so a
/// caller that has both traits in scope gets no ambiguity.
///
/// The adapter type fixes the scheme, as with [`Sign`], and signatures
/// cross the trait boundary in the canonical encoding of ADR 0002 (for
/// Ed25519, the raw 64 bytes).
#[allow(async_fn_in_trait)]
pub trait SignMessage {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn sign_message(&self, message: &Protected<Vec<u8>>) -> Result<Vec<u8>, Self::Error>;
}

/// The verifying half of [`SignMessage`]. Like [`Verify`], it returns
/// `Ok(false)` for a signature that does not verify, malformed ones
/// included.
#[allow(async_fn_in_trait)]
pub trait VerifyMessage {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn verify_message(
        &self,
        message: &Protected<Vec<u8>>,
        signature: &[u8],
    ) -> Result<bool, Self::Error>;
}

/// The public half of a signing key, as DER `SubjectPublicKeyInfo` (ADR
/// 0002). Keys behind [`Sign`] and keys behind [`SignMessage`] both
/// implement it.
#[allow(async_fn_in_trait)]
pub trait GetPublicKey {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn get_public_key(&self) -> Result<Vec<u8>, Self::Error>;
}
