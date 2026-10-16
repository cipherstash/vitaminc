//! Key providers: the consumer-facing shape a client library such as Stack
//! Encrypt is generic over (see `CONTEXT.md`).
//!
//! A [`KeyProvider`] mints and retrieves *batches* of data keys, each under
//! a caller-supplied [`Binding`], against one backend key bound at
//! construction. An [`IndexKeyProvider`] loads the one fixed index key for
//! that backend key. The two are separate traits because a vendor data key
//! source supplies the first natively and the second only through
//! [`FixedIndexKeySource`], while a service like ZeroKMS supplies both.
//!
//! Every vendor data key source in this crate implements [`KeyProvider`]
//! (one concrete impl each, in `sources.rs`), so the same `StackCipher` runs on AWS KMS, Azure Key
//! Vault, Google Cloud KMS, Vault Transit, or ZeroKMS. The binding is the
//! one place the backends differ in *meaning*: each declares through
//! [`BindingSupport`] whether it binds the bytes into the key server-side
//! or ignores them.

#[cfg(feature = "caching")]
mod caching;
mod fixed_index_key;
mod maybe_send;
mod sources;

#[cfg(feature = "test-support")]
mod fake;

use std::future::Future;

use crate::{GeneratedDataKey, IndexKeyMaterial, KeyId, KeyIsolation, KeyReconstruction};
use vitaminc_protected::Protected;

pub use crate::data_key::{Binding, BindingSupport};
#[cfg(feature = "caching")]
pub use caching::CachingKeyProvider;
#[cfg(feature = "test-support")]
pub use fake::{FakeKeyProvider, FakeKeyProviderError};
pub use fixed_index_key::FixedIndexKeySource;
pub use maybe_send::MaybeSend;

/// Mint and retrieve batches of data keys against one backend key bound at
/// construction.
///
/// `generate_keys` returns exactly one key per binding, in order.
/// `retrieve_keys` returns exactly one key per `(KeyId, Binding)` pair, in
/// order; the same `KeyId` may appear more than once. Any failure fails the
/// whole batch. Round-trip count is the backend's business: one for ZeroKMS
/// and Vault, one per key for the vendors without a batch primitive.
pub trait KeyProvider<const N: usize> {
    type Error: std::error::Error + Send + Sync + 'static;

    /// See [`KeyReconstruction`].
    const RECONSTRUCTION: KeyReconstruction;
    /// See [`KeyIsolation`].
    const ISOLATION: KeyIsolation;
    /// See [`BindingSupport`].
    const BINDING: BindingSupport;

    fn generate_keys(
        &self,
        bindings: &[Binding<'_>],
    ) -> impl Future<Output = Result<Vec<GeneratedDataKey<N>>, Self::Error>> + MaybeSend;

    fn retrieve_keys(
        &self,
        keys: &[(KeyId, Binding<'_>)],
    ) -> impl Future<Output = Result<Vec<Protected<[u8; N]>>, Self::Error>> + MaybeSend;
}

/// The error of a provider that wraps another: either the inner provider's
/// own error, or the inner provider broke the one-result-per-input contract
/// of [`KeyProvider::retrieve_keys`], which a wrapper reports rather than
/// panics on.
#[derive(Debug, thiserror::Error)]
pub enum DelegatedError<E: std::error::Error + 'static> {
    #[error(transparent)]
    Inner(E),
    #[error("the inner key provider returned {received} keys for a batch of {expected}")]
    BatchLength { expected: usize, received: usize },
}

/// Load the one fixed index key for the backend key a provider is bound to.
/// Deterministic: every call returns the same material.
pub trait IndexKeyProvider<const N: usize> {
    type Error: std::error::Error + Send + Sync + 'static;

    fn load_index_key(
        &self,
    ) -> impl Future<Output = Result<IndexKeyMaterial<N>, Self::Error>> + MaybeSend;
}
