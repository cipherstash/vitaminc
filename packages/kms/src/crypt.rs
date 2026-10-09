use vitaminc_protected::Protected;

/// Encrypt small plaintext directly under a KMS-held key — not envelope
/// encryption (see [`GenerateDataKey`](crate::GenerateDataKey)/
/// [`RetrieveDataKey`](crate::RetrieveDataKey) for that shape). The key
/// never leaves the backend; construction-time key binding means there's
/// no key identifier to pass or return. Not for bulk data: per-vendor
/// size limits vary enormously (~190 bytes for AWS asymmetric RSA up to
/// 32MB for Vault) and are surfaced only via `Self::Error`.
#[allow(async_fn_in_trait)]
pub trait EncryptWithKey {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn encrypt(&self, plaintext: Protected<Vec<u8>>) -> Result<Vec<u8>, Self::Error>;
}

/// The inverse of [`EncryptWithKey`]. Independent trait, not a supertrait
/// — a backend restricted to one direction (e.g. an asymmetric key scoped
/// to encrypt-only via IAM) can implement just one.
#[allow(async_fn_in_trait)]
pub trait DecryptWithKey {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Protected<Vec<u8>>, Self::Error>;
}
