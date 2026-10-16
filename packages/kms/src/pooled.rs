use crate::data_key::{
    dedup_retrieve, pooled_key_generate, BatchGenerateDataKey, BatchRetrieveDataKey, Binding,
    BindingSupport, GenerateDataKey, GeneratedDataKey, KeyIsolation, KeyReconstruction,
    RetrieveDataKey,
};
use crate::key_id::KeyId;
use vitaminc_protected::Protected;

/// Wraps any data key source to give it pooled key isolation
/// (`KeyIsolation::Pooled`): one key shared across a whole batch, via
/// [`pooled_key_generate`]. One round trip per batch regardless of size,
/// at the cost of weaker per-value isolation than the inner source — a
/// compromised key's blast radius is the whole batch, not one value.
///
/// Pooling also gives up **binding**, whatever the inner source supports:
/// one key cannot carry the several bindings a batch may ask for, so this
/// wrapper is always [`BindingSupport::Unbound`] and passes
/// [`Binding::EMPTY`] to the inner source on both sides. Wrapping a `Bound`
/// source does not produce a bound pool — it produces an unbound one, and
/// says so.
///
/// Opt in deliberately; this type exists so that choice is explicit and
/// visible in code, never a silent default. It only makes sense over a
/// backend with no native batch primitive (AWS, Azure, GCP); Vault
/// Transit batches natively at per-value isolation, so there is no pooled
/// Vault source. See CIP-4030.
pub struct PooledDataKeySource<T>(T);

impl<T> PooledDataKeySource<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }

    pub fn inner(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: GenerateDataKey<N>, const N: usize> GenerateDataKey<N> for PooledDataKeySource<T> {
    type Error = T::Error;

    /// Forwards [`Binding::EMPTY`], not the caller's binding: see the type
    /// docs. A single-key generate through this wrapper is still the pooled
    /// contract's generate.
    async fn generate_data_key(
        &self,
        _binding: Binding<'_>,
    ) -> Result<GeneratedDataKey<N>, Self::Error> {
        self.0.generate_data_key(Binding::EMPTY).await
    }
}

impl<T: RetrieveDataKey<N>, const N: usize> RetrieveDataKey<N> for PooledDataKeySource<T> {
    type Error = T::Error;

    const RECONSTRUCTION: KeyReconstruction = T::RECONSTRUCTION;

    /// Never `T::BINDING`. The pooled key was minted under
    /// [`Binding::EMPTY`], so retrieving it under anything else would fail
    /// against a `Bound` inner source — the wrapper drops the binding on
    /// both sides so the two halves agree.
    const BINDING: BindingSupport = BindingSupport::Unbound;

    async fn retrieve_data_key(
        &self,
        key_id: &KeyId,
        _binding: Binding<'_>,
    ) -> Result<Protected<[u8; N]>, Self::Error> {
        self.0.retrieve_data_key(key_id, Binding::EMPTY).await
    }
}

impl<T: GenerateDataKey<N>, const N: usize> BatchGenerateDataKey<N> for PooledDataKeySource<T> {
    const ISOLATION: KeyIsolation = KeyIsolation::Pooled;

    async fn generate_data_keys(
        &self,
        bindings: &[Binding<'_>],
    ) -> Result<Vec<GeneratedDataKey<N>>, Self::Error> {
        pooled_key_generate(&self.0, bindings.len()).await
    }
}

impl<T: RetrieveDataKey<N> + Sync, const N: usize> BatchRetrieveDataKey<N>
    for PooledDataKeySource<T>
{
    async fn retrieve_data_keys(
        &self,
        keys: &[(KeyId, Binding<'_>)],
    ) -> Result<Vec<Protected<[u8; N]>>, Self::Error> {
        // Retrieve doesn't need its own pooled/non-pooled split — it just
        // needs to be correct given whatever generate already decided
        // upstream (CIP-3987/CIP-3988). Dedup degrades gracefully to a
        // single retrieve when every id is identical, as it will be here.
        // Every binding dropped, matching what generate minted under.
        let stripped: Vec<(KeyId, Binding<'_>)> = keys
            .iter()
            .map(|(id, _)| (id.clone(), Binding::EMPTY))
            .collect();
        dedup_retrieve(&self.0, &stripped).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use vitaminc_protected::Controlled;

    #[derive(Default)]
    struct CountingSource {
        generates: AtomicUsize,
        retrieves: AtomicUsize,
        /// Every binding the wrapper forwarded, so a test can prove it
        /// forwards `EMPTY` rather than the caller's.
        bindings: Mutex<Vec<Vec<u8>>>,
    }

    impl GenerateDataKey<4> for CountingSource {
        type Error = std::convert::Infallible;

        async fn generate_data_key(
            &self,
            binding: Binding<'_>,
        ) -> Result<GeneratedDataKey<4>, Self::Error> {
            self.bindings
                .lock()
                .unwrap()
                .push(binding.as_bytes().to_vec());
            let n = self.generates.fetch_add(1, Ordering::SeqCst) as u8;
            Ok(GeneratedDataKey {
                plaintext: Protected::new([n; 4]),
                key_id: KeyId::new(vec![n]),
            })
        }
    }

    impl RetrieveDataKey<4> for CountingSource {
        type Error = std::convert::Infallible;
        const RECONSTRUCTION: KeyReconstruction = KeyReconstruction::ServerOnly;
        const BINDING: BindingSupport = BindingSupport::Bound;

        async fn retrieve_data_key(
            &self,
            key_id: &KeyId,
            binding: Binding<'_>,
        ) -> Result<Protected<[u8; 4]>, Self::Error> {
            self.bindings
                .lock()
                .unwrap()
                .push(binding.as_bytes().to_vec());
            self.retrieves.fetch_add(1, Ordering::SeqCst);
            Ok(Protected::new([key_id.as_bytes()[0]; 4]))
        }
    }

    #[tokio::test]
    async fn batch_generate_makes_one_call_and_shares_the_key() {
        let pooled = PooledDataKeySource::new(CountingSource::default());

        let keys = pooled
            .generate_data_keys(&[Binding::EMPTY; 5])
            .await
            .unwrap();

        assert_eq!(keys.len(), 5);
        assert_eq!(pooled.inner().generates.load(Ordering::SeqCst), 1);
        assert!(keys.iter().all(|k| k.key_id == keys[0].key_id));
        assert_eq!(
            <PooledDataKeySource<CountingSource> as BatchGenerateDataKey<4>>::ISOLATION,
            KeyIsolation::Pooled
        );
    }

    #[tokio::test]
    async fn batch_retrieve_of_a_pooled_batch_makes_one_call() {
        let pooled = PooledDataKeySource::new(CountingSource::default());
        let keys = pooled
            .generate_data_keys(&[Binding::EMPTY; 3])
            .await
            .unwrap();
        let ids: Vec<(KeyId, Binding<'_>)> = keys
            .iter()
            .map(|k| (k.key_id.clone(), Binding::EMPTY))
            .collect();

        let retrieved = pooled.retrieve_data_keys(&ids).await.unwrap();

        assert_eq!(retrieved.len(), 3);
        assert_eq!(pooled.inner().retrieves.load(Ordering::SeqCst), 1);
        assert_eq!(
            retrieved[2].clone().risky_unwrap(),
            keys[2].plaintext.clone().risky_unwrap()
        );
    }

    #[tokio::test]
    async fn retrieve_hands_back_the_inner_sources_material_for_the_id_it_was_given() {
        let pooled = PooledDataKeySource::new(CountingSource::default());

        // The counting source derives its material from the id, so the
        // bytes here can only have come from the inner source.
        let key = pooled
            .retrieve_data_key(&KeyId::new(vec![9]), Binding::EMPTY)
            .await
            .unwrap();

        assert_eq!(key.risky_unwrap(), [9u8; 4]);
        assert_eq!(pooled.inner().retrieves.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn reconstruction_is_forwarded_from_the_inner_source() {
        assert_eq!(
            <PooledDataKeySource<CountingSource> as RetrieveDataKey<4>>::RECONSTRUCTION,
            KeyReconstruction::ServerOnly
        );
    }

    /// Wrapping a `Bound` source does not produce a bound pool. One key
    /// cannot carry a batch's several bindings, so the wrapper drops them on
    /// both sides — and must say `Unbound`, or a caller would trust a
    /// binding that was never sent.
    #[tokio::test]
    async fn a_pool_over_a_bound_source_is_unbound_and_forwards_no_binding() {
        assert_eq!(
            <CountingSource as RetrieveDataKey<4>>::BINDING,
            BindingSupport::Bound,
            "the inner source binds"
        );
        assert_eq!(
            <PooledDataKeySource<CountingSource> as RetrieveDataKey<4>>::BINDING,
            BindingSupport::Unbound,
            "the pool over it does not"
        );

        let pooled = PooledDataKeySource::new(CountingSource::default());
        let keys = pooled
            .generate_data_keys(&[Binding::from("a"), Binding::from("b")])
            .await
            .unwrap();
        let _ = pooled
            .retrieve_data_keys(&[
                (keys[0].key_id.clone(), Binding::from("a")),
                (keys[1].key_id.clone(), Binding::from("b")),
            ])
            .await
            .unwrap();

        let forwarded = pooled.inner().bindings.lock().unwrap().clone();
        assert!(
            forwarded.iter().all(Vec::is_empty),
            "every binding reaching the inner source is empty, got {forwarded:?}"
        );
    }
}
