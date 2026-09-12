use crate::data_key::{KeyReconstruction, RetrieveDataKey};
use crate::key_id::KeyId;
use vitaminc_protected::Protected;

/// Caches [`RetrieveDataKey`] results only — never `GenerateDataKey` (that
/// would silently reintroduce the `Pooled` isolation trade-off as a cache
/// side effect rather than an explicit, named choice; see
/// [`crate::pooled_key_generate`]). Reusable by any `RetrieveDataKey<N>`
/// implementor, not AWS-specific: retrieve's determinism (the same
/// `KeyId` always yields the same key) holds for every backend.
///
/// A cache hit is pure memoization — same input, same output, no
/// behavior change and no security trade-off, unlike caching `generate`.
/// It does not speed up the encrypt/write path, only repeated decryption
/// of the same value.
pub struct CachingRetrieveDataKey<T, const N: usize> {
    inner: T,
    cache: moka::future::Cache<KeyId, Protected<[u8; N]>>,
}

impl<T, const N: usize> CachingRetrieveDataKey<T, N> {
    /// `max_entries` and `ttl` bound memory/hygiene (how long decrypted
    /// key material sits in memory) — not correctness. A `KeyId` always
    /// maps to the same key, so nothing here ever needs invalidating for
    /// staleness.
    pub fn new(inner: T, max_entries: u64, ttl: std::time::Duration) -> Self {
        Self {
            inner,
            cache: moka::future::Cache::builder()
                .max_capacity(max_entries)
                .time_to_live(ttl)
                .build(),
        }
    }
}

impl<T: RetrieveDataKey<N>, const N: usize> RetrieveDataKey<N> for CachingRetrieveDataKey<T, N> {
    type Error = T::Error;

    const RECONSTRUCTION: KeyReconstruction = T::RECONSTRUCTION;

    async fn retrieve_data_key(&self, key_id: &KeyId) -> Result<Protected<[u8; N]>, Self::Error> {
        if let Some(key) = self.cache.get(key_id).await {
            return Ok(key);
        }
        let key = self.inner.retrieve_data_key(key_id).await?;
        self.cache.insert(key_id.clone(), key.clone()).await;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use vitaminc_protected::Controlled;

    #[derive(Default)]
    struct CountingSource {
        calls: AtomicUsize,
    }

    impl RetrieveDataKey<4> for CountingSource {
        type Error = std::convert::Infallible;
        const RECONSTRUCTION: KeyReconstruction = KeyReconstruction::ServerOnly;

        async fn retrieve_data_key(&self, _key_id: &KeyId) -> Result<Protected<[u8; 4]>, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Protected::new([1, 2, 3, 4]))
        }
    }

    #[tokio::test]
    async fn second_retrieve_for_the_same_key_id_is_a_cache_hit() {
        let caching = CachingRetrieveDataKey::new(CountingSource::default(), 10, Duration::from_secs(60));
        let key_id = KeyId::new(vec![0xAB; 8]);

        let first = caching.retrieve_data_key(&key_id).await.unwrap();
        let second = caching.retrieve_data_key(&key_id).await.unwrap();

        assert_eq!(first.risky_unwrap(), second.risky_unwrap());
        assert_eq!(caching.inner.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn different_key_ids_both_reach_the_inner_source() {
        let caching = CachingRetrieveDataKey::new(CountingSource::default(), 10, Duration::from_secs(60));

        caching.retrieve_data_key(&KeyId::new(vec![1])).await.unwrap();
        caching.retrieve_data_key(&KeyId::new(vec![2])).await.unwrap();

        assert_eq!(caching.inner.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn reconstruction_is_forwarded_from_the_inner_source() {
        assert_eq!(
            <CachingRetrieveDataKey<CountingSource, 4> as RetrieveDataKey<4>>::RECONSTRUCTION,
            KeyReconstruction::ServerOnly
        );
    }
}
