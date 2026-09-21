use super::{Binding, BindingSupport, DelegatedError, IndexKeyProvider, KeyProvider};
use crate::{GeneratedDataKey, IndexKeyMaterial, KeyId, KeyIsolation, KeyReconstruction};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use vitaminc_protected::Protected;

/// What one cached data key is filed under: the [`KeyId`] *and* the
/// [`Binding`] bytes it was retrieved with, never the id alone.
type CacheKey = (KeyId, Vec<u8>);

/// Memoizes retrieved data keys in front of any [`KeyProvider`], keyed on
/// the `(KeyId, Binding)` pair.
///
/// Retrieval is deterministic — the same pair always yields the same key —
/// so a hit is pure memoization. The binding is part of the cache key
/// because it is part of the question: a hit must never hand back a key
/// that the backend would have refused, or checked differently, under the
/// binding the caller actually presented (`docs/adr/0002` in
/// cipherstash-suite). An id on its own is not the question the caller
/// asked.
///
/// Only retrieval is cached. `generate_keys` passes straight through and
/// its keys never enter the cache: serving a fresh mint from a cache would
/// hand one key to more than one value, reintroducing the
/// [`Pooled`](KeyIsolation::Pooled) isolation trade-off as a silent side
/// effect instead of the explicit choice
/// [`pooled_key_generate`](crate::pooled_key_generate) makes a caller name.
///
/// `max_entries` and `ttl` bound memory, and how long plaintext key
/// material sits in memory — not correctness. Nothing here ever needs
/// invalidating for staleness. Cached entries are [`Protected`] and zeroize
/// on drop, so eviction or expiry wipes the material.
///
/// **Opt in deliberately; never a default.** Against a
/// [`Bound`](BindingSupport::Bound) backend such as ZeroKMS, every
/// retrieval is an authorization decision the backend logs: a hit skips
/// that round trip, and with it the audit entry and the policy check for
/// that access. A deployment that relies on per-retrieval auditing must
/// not wrap its provider in this.
pub struct CachingKeyProvider<T, const N: usize> {
    inner: T,
    cache: moka::future::Cache<CacheKey, Protected<[u8; N]>>,
}

impl<T, const N: usize> CachingKeyProvider<T, N> {
    /// Wrap `inner`, holding at most `max_entries` keys for at most `ttl`
    /// each. Both are deliberate, caller-chosen limits on how much
    /// plaintext key material lives in this process and for how long, so
    /// there is no default for either.
    pub fn new(inner: T, max_entries: u64, ttl: Duration) -> Self {
        Self {
            inner,
            cache: moka::future::Cache::builder()
                .max_capacity(max_entries)
                .time_to_live(ttl)
                .build(),
        }
    }

    /// The provider this one caches in front of.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    fn cache_key(id: &KeyId, binding: Binding<'_>) -> CacheKey {
        (id.clone(), binding.as_bytes().to_vec())
    }
}

impl<const N: usize, T: KeyProvider<N> + Sync> KeyProvider<N> for CachingKeyProvider<T, N> {
    type Error = DelegatedError<T::Error>;

    const RECONSTRUCTION: KeyReconstruction = T::RECONSTRUCTION;
    const ISOLATION: KeyIsolation = T::ISOLATION;
    const BINDING: BindingSupport = T::BINDING;

    /// Straight through to the inner provider. See the type's docs for why
    /// minting is never cached.
    async fn generate_keys(
        &self,
        bindings: &[Binding<'_>],
    ) -> Result<Vec<GeneratedDataKey<N>>, Self::Error> {
        self.inner
            .generate_keys(bindings)
            .await
            .map_err(DelegatedError::Inner)
    }

    async fn retrieve_keys(
        &self,
        requests: &[(KeyId, Binding<'_>)],
    ) -> Result<Vec<Protected<[u8; N]>>, Self::Error> {
        let mut hits: Vec<Option<Protected<[u8; N]>>> = Vec::with_capacity(requests.len());
        for (id, binding) in requests {
            hits.push(self.cache.get(&Self::cache_key(id, *binding)).await);
        }

        // The misses, deduped by `(KeyId, binding)`: a batch that repeats a
        // pair costs one fetch, as `dedup_retrieve` does for bare ids.
        let mut misses: Vec<(KeyId, Binding<'_>)> = Vec::new();
        let mut queued: HashSet<CacheKey> = HashSet::new();
        for ((id, binding), hit) in requests.iter().zip(&hits) {
            if hit.is_none() && queued.insert(Self::cache_key(id, *binding)) {
                misses.push((id.clone(), *binding));
            }
        }

        // Every key was cached: no inner call at all.
        if misses.is_empty() {
            return Ok(hits.into_iter().flatten().collect());
        }

        let fetched = self
            .inner
            .retrieve_keys(&misses)
            .await
            .map_err(DelegatedError::Inner)?;
        if fetched.len() != misses.len() {
            return Err(DelegatedError::BatchLength {
                expected: misses.len(),
                received: fetched.len(),
            });
        }
        let mut by_key: HashMap<CacheKey, Protected<[u8; N]>> =
            HashMap::with_capacity(misses.len());
        for ((id, binding), key) in misses.iter().zip(fetched) {
            let cache_key = Self::cache_key(id, *binding);
            self.cache.insert(cache_key.clone(), key.clone()).await;
            by_key.insert(cache_key, key);
        }

        // Reassemble in the caller's order and length, hits and fetches alike.
        // Every miss was fetched (the length check above), so the lookup
        // cannot fail; it is still an error, not a panic, if it ever does.
        requests
            .iter()
            .zip(hits)
            .map(|((id, binding), hit)| match hit {
                Some(key) => Ok(key),
                None => by_key.get(&Self::cache_key(id, *binding)).cloned().ok_or(
                    DelegatedError::BatchLength {
                        expected: misses.len(),
                        received: by_key.len(),
                    },
                ),
            })
            .collect()
    }
}

/// Pure delegation: the index key is one fixed key the inner provider
/// already answers for, and caching it here would only duplicate whatever
/// that provider does.
impl<const N: usize, T: IndexKeyProvider<N> + Sync> IndexKeyProvider<N>
    for CachingKeyProvider<T, N>
{
    type Error = DelegatedError<T::Error>;

    async fn load_index_key(&self) -> Result<IndexKeyMaterial<N>, Self::Error> {
        self.inner
            .load_index_key()
            .await
            .map_err(DelegatedError::Inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{Binding, BindingSupport, KeyProvider};
    use crate::{GeneratedDataKey, KeyId, KeyIsolation, KeyReconstruction};
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;
    use vitaminc_protected::{Controlled, Protected};

    /// One recorded `retrieve_keys` batch, as `(id, binding)` pairs.
    type RetrieveBatch = Vec<(KeyId, Vec<u8>)>;

    /// A provider that records every batch it is asked for and answers
    /// with key material derived from the `(id, binding)` pair, so a test
    /// can tell a key retrieved under one binding from the same id's key
    /// under another.
    #[derive(Default)]
    struct CountingProvider {
        retrieve_batches: Mutex<Vec<RetrieveBatch>>,
        generate_calls: AtomicUsize,
        generated: AtomicUsize,
    }

    fn material(id: &KeyId, binding: &[u8]) -> Protected<[u8; 4]> {
        Protected::new([
            id.as_bytes().first().copied().unwrap_or(0),
            binding.first().copied().unwrap_or(0),
            id.as_bytes().len() as u8,
            binding.len() as u8,
        ])
    }

    impl CountingProvider {
        fn retrieve_calls(&self) -> usize {
            self.retrieve_batches.lock().unwrap().len()
        }

        fn last_retrieve_batch(&self) -> RetrieveBatch {
            self.retrieve_batches
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .clone()
        }
    }

    impl KeyProvider<4> for CountingProvider {
        type Error = Infallible;

        const RECONSTRUCTION: KeyReconstruction = KeyReconstruction::ClientAndServer;
        const ISOLATION: KeyIsolation = KeyIsolation::Pooled;
        const BINDING: BindingSupport = BindingSupport::Bound;

        async fn generate_keys(
            &self,
            bindings: &[Binding<'_>],
        ) -> Result<Vec<GeneratedDataKey<4>>, Self::Error> {
            self.generate_calls.fetch_add(1, Ordering::SeqCst);
            Ok(bindings
                .iter()
                .map(|binding| {
                    let n = self.generated.fetch_add(1, Ordering::SeqCst) as u8;
                    let key_id = KeyId::new(vec![n]);
                    let plaintext = material(&key_id, binding.as_bytes());
                    GeneratedDataKey { plaintext, key_id }
                })
                .collect())
        }

        async fn retrieve_keys(
            &self,
            requests: &[(KeyId, Binding<'_>)],
        ) -> Result<Vec<Protected<[u8; 4]>>, Self::Error> {
            self.retrieve_batches.lock().unwrap().push(
                requests
                    .iter()
                    .map(|(id, binding)| (id.clone(), binding.as_bytes().to_vec()))
                    .collect(),
            );
            Ok(requests
                .iter()
                .map(|(id, binding)| material(id, binding.as_bytes()))
                .collect())
        }
    }

    fn caching(ttl: Duration) -> CachingKeyProvider<CountingProvider, 4> {
        CachingKeyProvider::new(CountingProvider::default(), 100, ttl)
    }

    fn minute() -> Duration {
        Duration::from_secs(60)
    }

    fn bytes(key: &Protected<[u8; 4]>) -> [u8; 4] {
        key.clone().risky_unwrap()
    }

    #[tokio::test]
    async fn a_second_retrieve_of_the_same_id_and_binding_never_reaches_the_inner_provider() {
        let cache = caching(minute());
        let request = [(KeyId::new(vec![1]), Binding::from("users/email"))];

        let first = cache.retrieve_keys(&request).await.unwrap();
        let second = cache.retrieve_keys(&request).await.unwrap();

        assert_eq!(bytes(&first[0]), bytes(&second[0]));
        assert_eq!(cache.inner().retrieve_calls(), 1);
    }

    #[tokio::test]
    async fn the_same_id_under_a_different_binding_is_a_miss() {
        let cache = caching(minute());
        let id = KeyId::new(vec![1]);

        let first = cache
            .retrieve_keys(&[(id.clone(), Binding::from("users/email"))])
            .await
            .unwrap();
        let second = cache
            .retrieve_keys(&[(id.clone(), Binding::from("users/age"))])
            .await
            .unwrap();

        assert_eq!(cache.inner().retrieve_calls(), 2);
        assert_ne!(bytes(&first[0]), bytes(&second[0]));
        assert_eq!(
            cache.inner().last_retrieve_batch(),
            vec![(id, b"users/age".to_vec())]
        );
    }

    #[tokio::test]
    async fn a_mixed_batch_fetches_only_the_distinct_misses_in_one_call() {
        let cache = caching(minute());
        let binding = Binding::from("users/email");
        let (a, b, c) = (
            KeyId::new(vec![1]),
            KeyId::new(vec![2]),
            KeyId::new(vec![3]),
        );

        cache.retrieve_keys(&[(a.clone(), binding)]).await.unwrap();

        let batch = [
            (a.clone(), binding),
            (b.clone(), binding),
            (c.clone(), binding),
            (b.clone(), binding),
            (a.clone(), binding),
        ];
        let keys = cache.retrieve_keys(&batch).await.unwrap();

        assert_eq!(cache.inner().retrieve_calls(), 2);
        assert_eq!(
            cache.inner().last_retrieve_batch(),
            vec![
                (b.clone(), binding.as_bytes().to_vec()),
                (c.clone(), binding.as_bytes().to_vec()),
            ]
        );
        assert_eq!(keys.len(), batch.len());
        let expected: Vec<[u8; 4]> = batch
            .iter()
            .map(|(id, binding)| bytes(&material(id, binding.as_bytes())))
            .collect();
        let got: Vec<[u8; 4]> = keys.iter().map(bytes).collect();
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn a_fully_cached_batch_makes_no_inner_call_at_all() {
        let cache = caching(minute());
        let binding = Binding::from("users/email");
        let batch = [
            (KeyId::new(vec![1]), binding),
            (KeyId::new(vec![2]), binding),
        ];

        cache.retrieve_keys(&batch).await.unwrap();
        cache.retrieve_keys(&batch).await.unwrap();
        cache.retrieve_keys(&batch).await.unwrap();

        assert_eq!(cache.inner().retrieve_calls(), 1);
    }

    #[tokio::test]
    async fn generate_always_reaches_the_inner_provider_and_never_warms_the_cache() {
        let cache = caching(minute());
        let binding = Binding::from("users/email");

        let generated = cache.generate_keys(&[binding, binding]).await.unwrap();
        cache.generate_keys(&[binding]).await.unwrap();
        assert_eq!(cache.inner().generate_calls.load(Ordering::SeqCst), 2);

        let retrieved = cache
            .retrieve_keys(&[(generated[0].key_id.clone(), binding)])
            .await
            .unwrap();

        assert_eq!(cache.inner().retrieve_calls(), 1);
        assert_eq!(bytes(&retrieved[0]), bytes(&generated[0].plaintext));
    }

    #[tokio::test]
    async fn an_entry_is_gone_once_its_ttl_has_passed() {
        let cache = caching(Duration::from_millis(50));
        let request = [(KeyId::new(vec![1]), Binding::from("users/email"))];

        cache.retrieve_keys(&request).await.unwrap();
        cache.retrieve_keys(&request).await.unwrap();
        assert_eq!(cache.inner().retrieve_calls(), 1);

        tokio::time::sleep(Duration::from_millis(200)).await;

        cache.retrieve_keys(&request).await.unwrap();
        assert_eq!(cache.inner().retrieve_calls(), 2);
    }

    #[test]
    fn the_inner_provider_constants_are_forwarded() {
        type Cached = CachingKeyProvider<CountingProvider, 4>;
        assert_eq!(
            <Cached as KeyProvider<4>>::RECONSTRUCTION,
            KeyReconstruction::ClientAndServer
        );
        assert_eq!(<Cached as KeyProvider<4>>::ISOLATION, KeyIsolation::Pooled);
        assert_eq!(<Cached as KeyProvider<4>>::BINDING, BindingSupport::Bound);
    }
}
