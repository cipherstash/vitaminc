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
//! Vault, Google Cloud KMS, Vault Transit, or ZeroKMS. Every provider binds
//! the caller's [`Binding`] into the key, so a key comes back only under
//! the binding it was minted with. What differs in *meaning*
//! between backends, rather than in mechanism, is [`KeyCustody`]: whether
//! the key id a provider hands back is the data key in wrapped form or a
//! reference the backend resolves. A provider declares it.
//!
//! `AuthorityKeySource` (feature `authority-keys`) is a provider that
//! makes one backend call per cache refresh instead of one per value. It
//! caches an *authority key* and derives each value's own data key from it
//! locally (ADR 0007). It says so by implementing
//! [`DerivesFromAuthorityKey`].

#[cfg(feature = "authority-keys")]
mod authority_key;
#[cfg(feature = "caching")]
mod caching;
mod fixed_index_key;
mod maybe_send;
mod sources;

#[cfg(feature = "test-support")]
mod fake;

use std::future::Future;
use std::time::Duration;

use crate::{GeneratedDataKey, IndexKeyMaterial, KeyCustody, KeyId, KeyReconstruction};
use vitaminc_protected::Protected;

pub use crate::data_key::Binding;
#[cfg(feature = "authority-keys")]
pub use authority_key::{
    AuthorityKeyError, AuthorityKeySource, AuthorityKeyVersion, AuthorityKeys, AuthorityKeysError,
};
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
    /// See [`KeyCustody`].
    const CUSTODY: KeyCustody;

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

/// The one result of a single-input call to an inner provider, or
/// [`DelegatedError::BatchLength`] when it returned some other number.
pub(crate) fn only<T, E: std::error::Error + 'static>(
    mut results: Vec<T>,
) -> Result<T, DelegatedError<E>> {
    match (results.pop(), results.len()) {
        (Some(result), 0) => Ok(result),
        (result, rest) => Err(DelegatedError::BatchLength {
            expected: 1,
            received: rest + usize::from(result.is_some()),
        }),
    }
}

/// Load the one fixed index key for the backend key a provider is bound to.
/// Deterministic: every call returns the same material.
pub trait IndexKeyProvider<const N: usize> {
    type Error: std::error::Error + Send + Sync + 'static;

    fn load_index_key(
        &self,
    ) -> impl Future<Output = Result<IndexKeyMaterial<N>, Self::Error>> + MaybeSend;
}

/// How long, and how many, authority keys a [`DerivesFromAuthorityKey`]
/// source keeps in memory in plaintext.
///
/// Both limits are **security controls**, not memory controls. While an
/// authority key is cached, it can derive every data key under its
/// version, and the backend sees no call for any of them. So `ttl` is the
/// longest time for which a revoked or disabled backend key still mints and
/// retrieves data keys in this process, and `max_entries` is the most
/// authority-key versions held at one time. There is no `Default`: a
/// deployment chooses both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityKeyCachePolicy {
    /// The most authority-key versions held at one time. A deployment that
    /// retrieves under its current version and one earlier version needs 2.
    pub max_entries: u64,
    /// The longest time for which one fetch of an authority key is used.
    /// After it, the next call fetches the key from the backend again. See
    /// [`DerivesFromAuthorityKey::purge_expired`] for when the expired key
    /// leaves memory.
    pub ttl: Duration,
}

/// Capability: this provider derives data keys locally from cached
/// authority material, instead of one backend call per value (ADR 0007).
///
/// A provider that implements this still delivers one distinct data key
/// per value, under that value's own binding. What changes is what the
/// backend sees and what stays in memory:
///
/// * **Per-value retrieval is not per-value authorization.** The backend
///   authorizes, and logs, one fetch of the authority key per cache
///   refresh. It does not see the values derived from it. A deployment that
///   needs an audit record or a policy check per value must use a source
///   that makes one backend call per value, and must not use this.
/// * **Plaintext authority material stays in memory** for up to the
///   [`ttl`](AuthorityKeyCachePolicy::ttl) of its
///   [`cache_policy`](Self::cache_policy), in [`Protected`] memory that
///   zeroizes when the entry leaves the cache.
///
/// The cache policy is configuration on the provider, not a property of
/// its type, so a deployment reads the policy in force from the value.
pub trait DerivesFromAuthorityKey {
    /// The cache policy this provider was built with.
    fn cache_policy(&self) -> AuthorityKeyCachePolicy;

    /// Drop, and so zeroize, every cached authority key whose `ttl` has
    /// passed.
    ///
    /// A cache can drop expired entries only when it runs maintenance. Call
    /// this on a timer to put a hard limit on how long expired authority
    /// material stays in memory while the provider is idle.
    fn purge_expired(&self) -> impl Future<Output = ()> + MaybeSend;
}
