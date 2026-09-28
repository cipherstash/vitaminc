use crate::key_id::KeyId;
use futures::future::try_join_all;
use vitaminc_protected::Protected;

/// `Vec<u8>` to `[u8; N]`, with a wrong length reported through the
/// caller's own error rather than a panic. Every adapter's key-material
/// path ends here.
#[cfg(any(feature = "aws", feature = "azure", feature = "gcp", feature = "vault"))]
pub(crate) fn into_sized<const N: usize, E>(
    bytes: Vec<u8>,
    wrong_length: impl FnOnce(usize, usize) -> E,
) -> Result<[u8; N], E> {
    let received = bytes.len();
    bytes.try_into().map_err(|_| wrong_length(N, received))
}

/// Bytes a caller attaches to a data key when it is minted and must present
/// again to retrieve it. Stack Encrypt passes each leaf's rendered context
/// (its descriptor).
///
/// A newtype rather than a bare `&[u8]`, so a plaintext or a key id cannot
/// be passed where a binding belongs. What a source does with it is declared
/// by [`RetrieveDataKey::BINDING`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Binding<'a>(&'a [u8]);

impl<'a> Binding<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }

    /// The binding to pass when the caller has nothing to bind.
    pub const EMPTY: Binding<'static> = Binding(&[]);
}

impl<'a> From<&'a [u8]> for Binding<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
}

impl<'a> From<&'a str> for Binding<'a> {
    fn from(s: &'a str) -> Self {
        Self(s.as_bytes())
    }
}

/// Whether a source honours the [`Binding`] it is given.
///
/// `Bound`: the source has its backend bind the bytes into the data key, so
/// retrieving with a different binding fails. ZeroKMS binds its descriptor
/// and logs it per retrieval; AWS KMS binds an `EncryptionContext`; Google
/// Cloud KMS and Azure Key Vault bind additional authenticated data.
///
/// `Unbound`: the source ignores the bytes, and the caller's own
/// authenticated data is the only thing tying a key to its context. A
/// non-derived Vault Transit key has nothing to bind with, and a pooled
/// source cannot bind — one key shared across a batch cannot carry the
/// batch's several bindings.
///
/// An `Unbound` source never errors on a non-empty binding. A caller that
/// requires binding checks this constant up front.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingSupport {
    Bound,
    Unbound,
}

pub struct GeneratedDataKey<const N: usize> {
    pub plaintext: Protected<[u8; N]>,
    pub key_id: KeyId,
}

impl<const N: usize> Clone for GeneratedDataKey<N> {
    fn clone(&self) -> Self {
        Self {
            plaintext: self.plaintext.clone(),
            key_id: self.key_id.clone(),
        }
    }
}

/// Capability: mint a fresh data key. One implementor instance is bound to
/// one backend key at construction time (an AWS key ARN, a Vault transit
/// key name, a ZeroKMS keyset, ...) — no per-call selector.
#[allow(async_fn_in_trait)]
pub trait GenerateDataKey<const N: usize> {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Whether the backend does this in one round trip (AWS, Vault) or two
    /// (Azure, GCP: generate locally, then wrap) is hidden here.
    async fn generate_data_key(
        &self,
        binding: Binding<'_>,
    ) -> Result<GeneratedDataKey<N>, Self::Error>;
}

/// Whether a backend can reconstruct a previously-generated key from
/// server-side material alone (`ServerOnly`), or requires both the
/// server's material and something the client holds locally
/// (`ClientAndServer`) — e.g. ZeroKMS's recipher-based keyset. A
/// `ServerOnly` backend means a server-side compromise plus a stored
/// identifier is sufficient to recover a key; `ClientAndServer` means it
/// is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyReconstruction {
    ClientAndServer,
    ServerOnly,
}

/// Capability: re-derive/unwrap a previously generated data key.
#[allow(async_fn_in_trait)]
pub trait RetrieveDataKey<const N: usize> {
    type Error: std::error::Error + Send + Sync + 'static;

    const RECONSTRUCTION: KeyReconstruction;

    /// See [`BindingSupport`]. Declared on retrieval because retrieval is
    /// where a binding is enforced: a `Bound` source refuses a key id
    /// presented under a binding it was not minted with.
    const BINDING: BindingSupport;

    async fn retrieve_data_key(
        &self,
        key_id: &KeyId,
        binding: Binding<'_>,
    ) -> Result<Protected<[u8; N]>, Self::Error>;
}

/// Whether a batch-generate implementation mints one distinct key per
/// item (`PerValue` — every value access is its own auditable retrieval)
/// or shares one key across the whole batch (`Pooled` — a compromised
/// key's blast radius is the batch, not one value). See
/// [`pooled_key_generate`]/[`fan_out_generate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyIsolation {
    PerValue,
    Pooled,
}

#[allow(async_fn_in_trait)]
pub trait BatchGenerateDataKey<const N: usize>: GenerateDataKey<N> {
    const ISOLATION: KeyIsolation;

    /// One key per binding, in order.
    async fn generate_data_keys(
        &self,
        bindings: &[Binding<'_>],
    ) -> Result<Vec<GeneratedDataKey<N>>, Self::Error>;
}

#[allow(async_fn_in_trait)]
pub trait BatchRetrieveDataKey<const N: usize>: RetrieveDataKey<N> {
    /// One key per `(KeyId, Binding)` pair, in order. The same key id may
    /// appear more than once, and may appear under different bindings.
    async fn retrieve_data_keys(
        &self,
        keys: &[(KeyId, Binding<'_>)],
    ) -> Result<Vec<Protected<[u8; N]>>, Self::Error>;
}

/// N round trips, one distinct key per item — preserves per-value key
/// isolation (every value access is its own auditable retrieval). Fails
/// the whole batch if any item fails (fail-fast); does not roll back keys
/// already minted server-side before the failure.
pub async fn fan_out_generate<const N: usize, T: GenerateDataKey<N> + Sync>(
    backend: &T,
    bindings: &[Binding<'_>],
) -> Result<Vec<GeneratedDataKey<N>>, T::Error> {
    try_join_all(bindings.iter().map(|b| backend.generate_data_key(*b))).await
}

/// One round trip: mints a single key and clones it `count` times.
/// WEAKENS per-value isolation — every value in this batch shares one key.
/// Opt in deliberately; never a default.
///
/// Mints under [`Binding::EMPTY`], and so cannot honour a binding: one key
/// cannot carry the several bindings a batch may ask for, and binding it to
/// the first would make every other item unretrievable. A pooled source is
/// therefore [`BindingSupport::Unbound`], and pooling is a choice against
/// binding as well as against per-value isolation.
pub async fn pooled_key_generate<const N: usize, T: GenerateDataKey<N>>(
    backend: &T,
    count: usize,
) -> Result<Vec<GeneratedDataKey<N>>, T::Error> {
    let key = backend.generate_data_key(Binding::EMPTY).await?;
    Ok((0..count).map(|_| key.clone()).collect())
}

/// Dedupes by KeyId, retrieves each distinct id once, expands to input
/// order/length. Degrades to N round trips against a fan-out-generated
/// batch (ids always distinct); gets the full benefit against a
/// pooled-key-generated batch (ids repeat) — no separate opt-in needed.
/// Dedupes on the whole `(KeyId, Binding)` pair, not on the id alone: a
/// `Bound` backend answers the same id differently under different
/// bindings — one of them by refusing — so collapsing them would hand one
/// item a key it never asked for.
pub async fn dedup_retrieve<const N: usize, T: RetrieveDataKey<N> + Sync>(
    backend: &T,
    keys: &[(KeyId, Binding<'_>)],
) -> Result<Vec<Protected<[u8; N]>>, T::Error> {
    use std::collections::HashMap;

    let mut distinct: Vec<&(KeyId, Binding<'_>)> = Vec::new();
    for key in keys {
        if !distinct.contains(&key) {
            distinct.push(key);
        }
    }

    let retrieved: Vec<Protected<[u8; N]>> = try_join_all(
        distinct
            .iter()
            .map(|(id, binding)| backend.retrieve_data_key(id, *binding)),
    )
    .await?;

    let by_key: HashMap<&(KeyId, Binding<'_>), &Protected<[u8; N]>> =
        distinct.iter().copied().zip(retrieved.iter()).collect();

    Ok(keys.iter().map(|key| by_key[key].clone()).collect())
}

/// Pairs each id with [`Binding::EMPTY`], for tests whose backend is
/// `Unbound` or whose assertion is about something other than binding.
#[cfg(test)]
pub(crate) fn unbound(ids: &[KeyId]) -> Vec<(KeyId, Binding<'static>)> {
    ids.iter().map(|id| (id.clone(), Binding::EMPTY)).collect()
}
