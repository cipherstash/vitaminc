use super::{Binding, DelegatedError, IndexKeyProvider, KeyProvider, MaybeSync};
use crate::{GeneratedDataKey, IndexKeyMaterial, KeyCustody, KeyId, KeyReconstruction};
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
/// hand one key to more than one value, as a silent side effect. It would
/// also give up binding, because one key cannot carry the bindings of
/// several values.
///
/// `max_entries` bounds memory and `ttl` bounds how long a cached key can be
/// served — not correctness. Nothing here ever needs invalidating for
/// staleness. Cached entries are [`Protected`] and zeroize on drop, so
/// eviction or expiry wipes the material.
///
/// `ttl` does not bound how long plaintext key material stays in memory.
/// The cache has no background task: it drops an expired entry, and so
/// zeroizes it, only during maintenance, which runs on later cache calls.
/// An idle cache keeps its expired entries until then. A caller that needs
/// a hard bound calls [`purge_expired`](Self::purge_expired) on its own
/// schedule.
///
/// **Opt in deliberately; never a default.** Against a backend that
/// audits each retrieval, such as ZeroKMS, every retrieval is an
/// authorization decision the backend logs: a hit skips that round trip,
/// and with it the audit entry and the policy check for that access. A
/// deployment that relies on per-retrieval auditing must not wrap its
/// provider in this.
///
/// `AuthorityKeySource` (feature
/// `authority-keys`) makes the same trade one tier up, and makes it the
/// normal path: it caches one authority key and derives every value's key
/// from it, so the backend sees one call per refresh and none per value.
/// There, `ttl` is a security control, because a cached authority key can
/// derive any data key under its version (ADR 0007). Here, a cached entry
/// is one data key that the caller already retrieved, so `max_entries`
/// and `ttl` bound memory and staleness. The auditing caveat above applies
/// to both.
pub struct CachingKeyProvider<T, const N: usize> {
    inner: T,
    cache: moka::future::Cache<CacheKey, Protected<[u8; N]>>,
}

impl<T, const N: usize> CachingKeyProvider<T, N> {
    /// Wrap `inner`, holding at most `max_entries` keys and serving each for
    /// at most `ttl`. Both are deliberate, caller-chosen limits on how much
    /// plaintext key material this process holds and for how long it uses
    /// it, so there is no default for either. See the type's docs for when
    /// expired entries leave memory.
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

    /// Drop, and so zeroize, every entry whose `ttl` has passed.
    ///
    /// The cache drops expired entries only during maintenance, which runs
    /// on later cache calls. Call this on a timer to put a hard bound on
    /// how long expired plaintext key material stays in memory when the
    /// cache can sit idle.
    pub async fn purge_expired(&self) {
        self.cache.run_pending_tasks().await;
    }

    fn cache_key(id: &KeyId, binding: Binding<'_>) -> CacheKey {
        (id.clone(), binding.as_bytes().to_vec())
    }
}

impl<const N: usize, T: KeyProvider<N> + MaybeSync> KeyProvider<N> for CachingKeyProvider<T, N> {
    type Error = DelegatedError<T::Error>;

    const RECONSTRUCTION: KeyReconstruction = T::RECONSTRUCTION;
    const CUSTODY: KeyCustody = T::CUSTODY;

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
impl<const N: usize, T: IndexKeyProvider<N> + MaybeSync> IndexKeyProvider<N>
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
    use crate::provider::{Binding, KeyProvider};
    use crate::{GeneratedDataKey, KeyId, KeyReconstruction};
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
        const CUSTODY: KeyCustody = KeyCustody::BackendHeld;

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

    #[tokio::test]
    async fn purge_expired_drops_an_expired_entry_from_memory() {
        let cache = caching(Duration::from_millis(50));
        let request = [(KeyId::new(vec![1]), Binding::from("users/email"))];

        cache.retrieve_keys(&request).await.unwrap();
        cache.purge_expired().await;
        assert_eq!(cache.cache.entry_count(), 1);

        tokio::time::sleep(Duration::from_millis(200)).await;

        cache.purge_expired().await;
        assert_eq!(cache.cache.entry_count(), 0);
    }

    /// How a [`Miscounting`] provider gets the length of its answer wrong.
    #[derive(Clone, Copy)]
    enum Miscount {
        OneTooMany,
        OneTooFew,
    }

    /// A provider that breaks the one-key-per-request contract of
    /// `retrieve_keys`. It records each batch in a [`CountingProvider`] and
    /// answers correctly until a test arms it. After that, it adds one key
    /// to each answer or removes the last key from it.
    struct Miscounting {
        inner: CountingProvider,
        miscount: Mutex<Option<Miscount>>,
    }

    impl Miscounting {
        fn arm(&self, miscount: Miscount) {
            *self.miscount.lock().unwrap() = Some(miscount);
        }
    }

    impl KeyProvider<4> for Miscounting {
        type Error = Infallible;

        const RECONSTRUCTION: KeyReconstruction = KeyReconstruction::ClientAndServer;
        const CUSTODY: KeyCustody = KeyCustody::BackendHeld;

        async fn generate_keys(
            &self,
            bindings: &[Binding<'_>],
        ) -> Result<Vec<GeneratedDataKey<4>>, Self::Error> {
            self.inner.generate_keys(bindings).await
        }

        async fn retrieve_keys(
            &self,
            requests: &[(KeyId, Binding<'_>)],
        ) -> Result<Vec<Protected<[u8; 4]>>, Self::Error> {
            let mut keys = self.inner.retrieve_keys(requests).await?;
            match *self.miscount.lock().unwrap() {
                Some(Miscount::OneTooMany) => keys.push(Protected::new([0xff; 4])),
                Some(Miscount::OneTooFew) => {
                    keys.pop();
                }
                None => {}
            }
            Ok(keys)
        }
    }

    fn miscounting(miscount: Miscount) -> CachingKeyProvider<Miscounting, 4> {
        let provider = Miscounting {
            inner: CountingProvider::default(),
            miscount: Mutex::new(None),
        };
        provider.arm(miscount);
        CachingKeyProvider::new(provider, 100, minute())
    }

    /// A batch in the form that `CountingProvider` records it.
    fn pairs(batch: &[(KeyId, Binding<'_>)]) -> RetrieveBatch {
        batch
            .iter()
            .map(|(id, binding)| (id.clone(), binding.as_bytes().to_vec()))
            .collect()
    }

    #[tokio::test]
    async fn one_key_too_many_is_a_batch_length_error_and_caches_nothing() {
        let cache = miscounting(Miscount::OneTooMany);
        let request = [(KeyId::new(vec![1]), Binding::from("users/email"))];

        let result = cache.retrieve_keys(&request).await;
        assert!(matches!(
            result,
            Err(DelegatedError::BatchLength {
                expected: 1,
                received: 2
            })
        ));

        // The cache stored nothing, so the same request is a miss again.
        let result = cache.retrieve_keys(&request).await;
        assert!(matches!(
            result,
            Err(DelegatedError::BatchLength {
                expected: 1,
                received: 2
            })
        ));
        assert_eq!(cache.inner().inner.retrieve_calls(), 2);
        assert_eq!(cache.inner().inner.last_retrieve_batch(), pairs(&request));
    }

    /// Two misses, not one: with one miss and no key in the answer, the
    /// reassembly step also fails, so that test cannot show that the length
    /// check itself rejects the answer. With two misses and one key, a cache
    /// without the length check stores the first key under the first id.
    #[tokio::test]
    async fn one_key_too_few_is_a_batch_length_error_and_caches_nothing() {
        let cache = miscounting(Miscount::OneTooFew);
        let binding = Binding::from("users/email");
        let request = [
            (KeyId::new(vec![1]), binding),
            (KeyId::new(vec![2]), binding),
        ];

        let result = cache.retrieve_keys(&request).await;
        assert!(matches!(
            result,
            Err(DelegatedError::BatchLength {
                expected: 2,
                received: 1
            })
        ));

        // The cache stored nothing, so both pairs are misses again.
        let result = cache.retrieve_keys(&request).await;
        assert!(matches!(
            result,
            Err(DelegatedError::BatchLength {
                expected: 2,
                received: 1
            })
        ));
        assert_eq!(cache.inner().inner.retrieve_calls(), 2);
        assert_eq!(cache.inner().inner.last_retrieve_batch(), pairs(&request));
    }

    #[tokio::test]
    async fn a_batch_length_error_counts_only_the_misses() {
        let cache = CachingKeyProvider::new(
            Miscounting {
                inner: CountingProvider::default(),
                miscount: Mutex::new(None),
            },
            100,
            minute(),
        );
        let binding = Binding::from("users/email");
        let (a, b, c) = (
            KeyId::new(vec![1]),
            KeyId::new(vec![2]),
            KeyId::new(vec![3]),
        );

        // Cache `a` while the provider still answers correctly.
        cache.retrieve_keys(&[(a.clone(), binding)]).await.unwrap();
        cache.inner().arm(Miscount::OneTooMany);

        // Three requests, one hit: the inner provider is asked for two keys
        // and returns three.
        let request = [
            (a.clone(), binding),
            (b.clone(), binding),
            (c.clone(), binding),
        ];
        let result = cache.retrieve_keys(&request).await;
        assert!(matches!(
            result,
            Err(DelegatedError::BatchLength {
                expected: 2,
                received: 3
            })
        ));
        let misses = [(b.clone(), binding), (c.clone(), binding)];
        assert_eq!(cache.inner().inner.last_retrieve_batch(), pairs(&misses));

        // The cache stored neither miss, so the inner provider is asked for
        // both again.
        let result = cache.retrieve_keys(&request).await;
        assert!(matches!(
            result,
            Err(DelegatedError::BatchLength {
                expected: 2,
                received: 3
            })
        ));
        assert_eq!(cache.inner().inner.retrieve_calls(), 3);
        assert_eq!(cache.inner().inner.last_retrieve_batch(), pairs(&misses));
    }

    #[test]
    fn the_inner_provider_constants_are_forwarded() {
        type Cached = CachingKeyProvider<CountingProvider, 4>;
        assert_eq!(
            <Cached as KeyProvider<4>>::RECONSTRUCTION,
            KeyReconstruction::ClientAndServer
        );
        assert_eq!(<Cached as KeyProvider<4>>::CUSTODY, KeyCustody::BackendHeld);
    }
}
