use super::{Binding, BindingSupport, IndexKeyProvider, KeyProvider};
use crate::{GeneratedDataKey, IndexKeyMaterial, KeyId, KeyIsolation, KeyReconstruction};
use vitaminc_protected::Protected;

/// Pairs any [`KeyProvider`] with the one fixed, persisted [`KeyId`] its
/// deployment provisioned once for index-key derivation.
///
/// Vendor backends have no deterministic-derivation primitive, so the index
/// key's determinism comes entirely from the caller presenting the same
/// stored identifier every time (see [`load_index_key`](crate::load_index_key)).
/// Provisioning that `KeyId` is a one-time, out-of-band step: call the
/// backend's `generate_data_key()` once, persist the resulting `key_id`
/// durably (configuration, a secrets store), and construct this wrapper
/// with it on every subsequent run. Minting a fresh one at startup makes
/// every previously written index term unfindable.
///
/// The index key is retrieved with [`Binding::EMPTY`]: it belongs to the
/// keyset, not to any value's context.
///
/// Implements both provider traits, delegating [`KeyProvider`] to the inner
/// source, so one value satisfies a consumer that needs both.
pub struct FixedIndexKeySource<T> {
    inner: T,
    index_key_id: KeyId,
}

impl<T> FixedIndexKeySource<T> {
    pub fn new(inner: T, index_key_id: KeyId) -> Self {
        Self {
            inner,
            index_key_id,
        }
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    pub fn index_key_id(&self) -> &KeyId {
        &self.index_key_id
    }
}

impl<const N: usize, T> IndexKeyProvider<N> for FixedIndexKeySource<T>
where
    T: KeyProvider<N> + Sync,
{
    type Error = T::Error;

    async fn load_index_key(&self) -> Result<IndexKeyMaterial<N>, Self::Error> {
        // retrieve_keys returns exactly one entry per input, in order: a
        // single-element slice in, take the one result out.
        let mut keys = self
            .inner
            .retrieve_keys(&[(self.index_key_id.clone(), Binding::EMPTY)])
            .await?;
        Ok(IndexKeyMaterial(keys.remove(0)))
    }
}

impl<const N: usize, T: KeyProvider<N> + Sync> KeyProvider<N> for FixedIndexKeySource<T> {
    type Error = T::Error;

    const RECONSTRUCTION: KeyReconstruction = T::RECONSTRUCTION;
    const ISOLATION: KeyIsolation = T::ISOLATION;
    const BINDING: BindingSupport = T::BINDING;

    async fn generate_keys(
        &self,
        bindings: &[Binding<'_>],
    ) -> Result<Vec<GeneratedDataKey<N>>, Self::Error> {
        self.inner.generate_keys(bindings).await
    }

    async fn retrieve_keys(
        &self,
        keys: &[(KeyId, Binding<'_>)],
    ) -> Result<Vec<Protected<[u8; N]>>, Self::Error> {
        self.inner.retrieve_keys(keys).await
    }
}
