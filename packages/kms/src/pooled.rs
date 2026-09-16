use crate::data_key::{
    dedup_retrieve, pooled_key_generate, BatchGenerateDataKey, BatchRetrieveDataKey,
    GenerateDataKey, GeneratedDataKey, KeyIsolation, KeyReconstruction, RetrieveDataKey,
};
use crate::key_id::KeyId;
use vitaminc_protected::Protected;

/// Wraps any data key source to give it pooled key isolation
/// (`KeyIsolation::Pooled`): one key shared across a whole batch, via
/// [`pooled_key_generate`]. One round trip per batch regardless of size,
/// at the cost of weaker per-value isolation than the inner source — a
/// compromised key's blast radius is the whole batch, not one value.
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

    async fn generate_data_key(&self) -> Result<GeneratedDataKey<N>, Self::Error> {
        self.0.generate_data_key().await
    }
}

impl<T: RetrieveDataKey<N>, const N: usize> RetrieveDataKey<N> for PooledDataKeySource<T> {
    type Error = T::Error;

    const RECONSTRUCTION: KeyReconstruction = T::RECONSTRUCTION;

    async fn retrieve_data_key(&self, key_id: &KeyId) -> Result<Protected<[u8; N]>, Self::Error> {
        self.0.retrieve_data_key(key_id).await
    }
}

impl<T: GenerateDataKey<N>, const N: usize> BatchGenerateDataKey<N> for PooledDataKeySource<T> {
    const ISOLATION: KeyIsolation = KeyIsolation::Pooled;

    async fn generate_data_keys(
        &self,
        count: usize,
    ) -> Result<Vec<GeneratedDataKey<N>>, Self::Error> {
        pooled_key_generate(&self.0, count).await
    }
}

impl<T: RetrieveDataKey<N> + Sync, const N: usize> BatchRetrieveDataKey<N>
    for PooledDataKeySource<T>
{
    async fn retrieve_data_keys(
        &self,
        key_ids: &[KeyId],
    ) -> Result<Vec<Protected<[u8; N]>>, Self::Error> {
        // Retrieve doesn't need its own pooled/non-pooled split — it just
        // needs to be correct given whatever generate already decided
        // upstream (CIP-3987/CIP-3988). Dedup degrades gracefully to a
        // single retrieve when every id is identical, as it will be here.
        dedup_retrieve(&self.0, key_ids).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use vitaminc_protected::Controlled;

    #[derive(Default)]
    struct CountingSource {
        generates: AtomicUsize,
        retrieves: AtomicUsize,
    }

    impl GenerateDataKey<4> for CountingSource {
        type Error = std::convert::Infallible;

        async fn generate_data_key(&self) -> Result<GeneratedDataKey<4>, Self::Error> {
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

        async fn retrieve_data_key(
            &self,
            key_id: &KeyId,
        ) -> Result<Protected<[u8; 4]>, Self::Error> {
            self.retrieves.fetch_add(1, Ordering::SeqCst);
            Ok(Protected::new([key_id.as_bytes()[0]; 4]))
        }
    }

    #[tokio::test]
    async fn batch_generate_makes_one_call_and_shares_the_key() {
        let pooled = PooledDataKeySource::new(CountingSource::default());

        let keys = pooled.generate_data_keys(5).await.unwrap();

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
        let keys = pooled.generate_data_keys(3).await.unwrap();
        let ids: Vec<KeyId> = keys.iter().map(|k| k.key_id.clone()).collect();

        let retrieved = pooled.retrieve_data_keys(&ids).await.unwrap();

        assert_eq!(retrieved.len(), 3);
        assert_eq!(pooled.inner().retrieves.load(Ordering::SeqCst), 1);
        assert_eq!(
            retrieved[2].clone().risky_unwrap(),
            keys[2].plaintext.clone().risky_unwrap()
        );
    }

    #[test]
    fn reconstruction_is_forwarded_from_the_inner_source() {
        assert_eq!(
            <PooledDataKeySource<CountingSource> as RetrieveDataKey<4>>::RECONSTRUCTION,
            KeyReconstruction::ServerOnly
        );
    }
}
