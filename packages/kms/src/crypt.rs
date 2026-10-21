use vitaminc_protected::Protected;

/// Encrypt small plaintext directly under a KMS-held key — not envelope
/// encryption (see [`GenerateDataKey`](crate::GenerateDataKey)/
/// [`RetrieveDataKey`](crate::RetrieveDataKey) for that shape). The key
/// never leaves the backend; construction-time key binding means there's
/// no key identifier to pass or return. Not for bulk data: per-vendor
/// size limits vary enormously (~190 bytes for AWS asymmetric RSA up to
/// 32MB for Vault) and are surfaced only via `Self::Error`.
///
/// # Domain separation from data keys
///
/// A type that implements this trait and also
/// [`GenerateDataKey`](crate::GenerateDataKey) under the same backend key
/// must keep the two uses apart. A direct ciphertext must not open as a data
/// key under any [`Binding`](crate::Binding), and a data key's
/// [`KeyId`](crate::KeyId) must not open through [`DecryptWithKey`]. So
/// the backend must bind a fixed value into each direct ciphertext that no
/// binding can give a data key.
///
/// Without that, the index key is exposed. The index key is a data key
/// under [`Binding::EMPTY`](crate::Binding::EMPTY), so a caller that may
/// use `decrypt` and can read the index `KeyId` gets the index key. And a
/// caller that can write a stored `KeyId` can put a direct ciphertext there,
/// and so choose a data key.
///
/// Every vendor source in this crate keeps the two uses apart. ADR 0006 has
/// the exact bytes each one binds. In short: AWS KMS sends the
/// `EncryptionContext` entry `"vitaminc:use"`, with the value `"data-key"`
/// or `"encrypt-with-key"`. Google Cloud KMS, Azure Managed HSM and Vault
/// Transit bind `0x01` and then the binding for a data key, and `0x00` and
/// then `vitaminc-kms/<vendor>/encrypt-with-key` for direct encryption.
#[allow(async_fn_in_trait)]
pub trait EncryptWithKey {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn encrypt(&self, plaintext: Protected<Vec<u8>>) -> Result<Vec<u8>, Self::Error>;
}

/// The inverse of [`EncryptWithKey`]. Independent trait, not a supertrait
/// — a backend restricted to one direction (e.g. an asymmetric key scoped
/// to encrypt-only via IAM) can implement just one.
///
/// The same separation applies here: `decrypt` must refuse a data key's
/// [`KeyId`](crate::KeyId), also one minted under
/// [`Binding::EMPTY`](crate::Binding::EMPTY). See [`EncryptWithKey`].
#[allow(async_fn_in_trait)]
pub trait DecryptWithKey {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Protected<Vec<u8>>, Self::Error>;
}
