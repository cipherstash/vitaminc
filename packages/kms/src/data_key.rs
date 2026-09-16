use crate::key_id::KeyId;
use futures::future::try_join_all;
use vitaminc_protected::Protected;

/// `Vec<u8>` to `[u8; N]`, with a wrong length reported through the
/// caller's own error rather than a panic. Every adapter's key-material
/// path ends here.
pub(crate) fn into_sized<const N: usize, E>(
    bytes: Vec<u8>,
    wrong_length: impl FnOnce(usize, usize) -> E,
) -> Result<[u8; N], E> {
    let received = bytes.len();
    bytes.try_into().map_err(|_| wrong_length(N, received))
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
/// one backend key/keyset at construction time (an AWS key ARN, a Vault
/// transit key name, a ZeroKMS keyset, ...) — no per-call selector.
#[allow(async_fn_in_trait)]
pub trait GenerateDataKey<const N: usize> {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Whether the backend does this in one round trip (AWS, Vault) or two
    /// (Azure, GCP: generate locally, then wrap) is hidden here.
    async fn generate_data_key(&self) -> Result<GeneratedDataKey<N>, Self::Error>;
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

    async fn retrieve_data_key(&self, key_id: &KeyId) -> Result<Protected<[u8; N]>, Self::Error>;
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

    async fn generate_data_keys(
        &self,
        count: usize,
    ) -> Result<Vec<GeneratedDataKey<N>>, Self::Error>;
}

#[allow(async_fn_in_trait)]
pub trait BatchRetrieveDataKey<const N: usize>: RetrieveDataKey<N> {
    async fn retrieve_data_keys(
        &self,
        key_ids: &[KeyId],
    ) -> Result<Vec<Protected<[u8; N]>>, Self::Error>;
}

/// N round trips, one distinct key per item — preserves per-value key
/// isolation (every value access is its own auditable retrieval). Fails
/// the whole batch if any item fails (fail-fast); does not roll back keys
/// already minted server-side before the failure.
pub async fn fan_out_generate<const N: usize, T: GenerateDataKey<N> + Sync>(
    backend: &T,
    count: usize,
) -> Result<Vec<GeneratedDataKey<N>>, T::Error> {
    try_join_all((0..count).map(|_| backend.generate_data_key())).await
}

/// One round trip: mints a single key and clones it `count` times.
/// WEAKENS per-value isolation — every value in this batch shares one key.
/// Opt in deliberately; never a default.
pub async fn pooled_key_generate<const N: usize, T: GenerateDataKey<N>>(
    backend: &T,
    count: usize,
) -> Result<Vec<GeneratedDataKey<N>>, T::Error> {
    let key = backend.generate_data_key().await?;
    Ok((0..count).map(|_| key.clone()).collect())
}

/// Dedupes by KeyId, retrieves each distinct id once, expands to input
/// order/length. Degrades to N round trips against a fan-out-generated
/// batch (ids always distinct); gets the full benefit against a
/// pooled-key-generated batch (ids repeat) — no separate opt-in needed.
pub async fn dedup_retrieve<const N: usize, T: RetrieveDataKey<N> + Sync>(
    backend: &T,
    key_ids: &[KeyId],
) -> Result<Vec<Protected<[u8; N]>>, T::Error> {
    use std::collections::HashMap;

    let mut distinct: Vec<&KeyId> = Vec::new();
    for id in key_ids {
        if !distinct.contains(&id) {
            distinct.push(id);
        }
    }

    let retrieved: Vec<Protected<[u8; N]>> =
        try_join_all(distinct.iter().map(|id| backend.retrieve_data_key(id))).await?;

    let by_id: HashMap<&KeyId, &Protected<[u8; N]>> =
        distinct.iter().copied().zip(retrieved.iter()).collect();

    Ok(key_ids.iter().map(|id| by_id[id].clone()).collect())
}
