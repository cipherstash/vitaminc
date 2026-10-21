use crate::key_id::KeyId;
use crate::provider::MaybeSync;
use futures::future::TryFutureExt as _;
use futures::stream::{self, StreamExt as _, TryStreamExt as _};
use std::collections::HashMap;
use std::future::Future;
use std::num::NonZeroUsize;
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

/// The first byte of the bytes a data key binds on Google Cloud KMS, Azure
/// Managed HSM and Vault Transit. The binding follows it.
///
/// These backends also encrypt directly under the same key
/// ([`EncryptWithKey`](crate::EncryptWithKey)), and the two uses must not
/// open each other's ciphertexts. Direct encryption binds a fixed label
/// that starts with [`DIRECT_ENCRYPTION_TAG`] instead, so no binding gives
/// the same bytes (ADR 0006). The tag also makes the bytes non-empty for
/// [`Binding::EMPTY`], and the encoding stays one-to-one: two bindings give
/// the same bytes only if they are the same binding.
#[cfg(any(feature = "azure", feature = "gcp", feature = "vault"))]
pub(crate) const DATA_KEY_TAG: u8 = 0x01;

/// The first byte of the fixed label that direct encryption binds on
/// Google Cloud KMS, Azure Managed HSM and Vault Transit. See
/// [`DATA_KEY_TAG`].
#[cfg(any(feature = "azure", feature = "gcp", feature = "vault"))]
pub(crate) const DIRECT_ENCRYPTION_TAG: u8 = 0x00;

/// The bytes a data key binds under `binding`: [`DATA_KEY_TAG`], then the
/// binding bytes. Never empty, not even for [`Binding::EMPTY`].
#[cfg(any(feature = "azure", feature = "gcp", feature = "vault"))]
pub(crate) fn tagged_binding(binding: Binding<'_>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1 + binding.as_bytes().len());
    bytes.push(DATA_KEY_TAG);
    bytes.extend_from_slice(binding.as_bytes());
    bytes
}

/// Bytes a caller attaches to a data key when it is minted and must present
/// again to retrieve it. Stack Encrypt passes each leaf's rendered context
/// (its descriptor).
///
/// Every source binds. The backend binds the bytes into the data key, so a
/// retrieval under a different binding fails. ZeroKMS binds its descriptor
/// and logs it per retrieval. AWS KMS binds an `EncryptionContext`. Google
/// Cloud KMS and Azure Managed HSM bind additional authenticated data.
/// Vault Transit binds the derivation context of a derived key. A source
/// that cannot bind cannot be a data key source (ADR 0006).
///
/// What reaches the backend is not always the bare bytes. Each vendor
/// source also marks the use, so a data key never opens as a direct
/// ciphertext of [`EncryptWithKey`](crate::EncryptWithKey), and a direct
/// ciphertext never opens as a data key. AWS KMS adds the
/// `EncryptionContext` entry `"vitaminc:use": "data-key"`, and sends the
/// binding, as base64, under `"vitaminc:binding"` only when the binding is
/// not empty. Google Cloud KMS, Azure Managed HSM and Vault Transit bind the
/// byte `0x01` and then the binding. So [`Binding::EMPTY`] still binds a
/// value on every backend. ADR 0006 has the details.
///
/// `provider::AuthorityKeySource` binds
/// locally: the binding is an input to the derivation of each key. A
/// retrieval under a different binding there does not fail. It derives a
/// different key, which opens nothing, and the consumer's AEAD reports
/// that.
///
/// A newtype rather than a bare `&[u8]`, so a plaintext or a key id cannot
/// be passed where a binding belongs.
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
///
/// This is a threat-model property, not a statement about what the stored
/// identifier *is*. For that, see [`KeyCustody`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyReconstruction {
    ClientAndServer,
    ServerOnly,
}

/// What the [`KeyId`] a source hands back actually is: the data key itself
/// in wrapped form (`ClientHeld`), or a reference the backend resolves from
/// material it keeps (`BackendHeld`).
///
/// Every envelope backend is `ClientHeld`. AWS KMS returns a
/// `CiphertextBlob`, Google Cloud KMS and Vault Transit return a ciphertext,
/// and Azure Key Vault returns its wrapped value: in each case the key id
/// *is* the data key under encryption, and the backend keeps no copy of it.
/// ZeroKMS is `BackendHeld` — its key id describes a key the service rebuilds
/// from material it holds.
///
/// The difference is a **storage obligation**, which is why a source declares
/// it instead of leaving a caller to know it. A `ClientHeld` key id is the
/// only copy of that data key: lose it and the key is unrecoverable, because
/// nothing server-side remembers the key ever existed. A `BackendHeld` key id
/// can be re-presented to a backend that still holds the material.
///
/// Not to be confused with [`KeyReconstruction`], which asks whether a
/// server-side compromise plus the stored key id is enough to recover the
/// key. The two are independent, and every vendor source in this crate is
/// `ClientHeld` *and*
/// [`ServerOnly`](KeyReconstruction::ServerOnly): a wrapped key is not a
/// secret the client withholds, because the backend unwraps it on demand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCustody {
    /// The key id is the data key in wrapped form. Store it durably; it is
    /// the only copy.
    ClientHeld,
    /// The key id references a key the backend can resolve from its own
    /// material.
    BackendHeld,
}

/// Capability: re-derive/unwrap a previously generated data key.
#[allow(async_fn_in_trait)]
pub trait RetrieveDataKey<const N: usize> {
    type Error: std::error::Error + Send + Sync + 'static;

    const RECONSTRUCTION: KeyReconstruction;

    /// See [`KeyCustody`]. Declared beside `RECONSTRUCTION` because it is
    /// the other half of what a caller must know about a stored key id:
    /// `RECONSTRUCTION` says who could recover the key, `CUSTODY` says
    /// whether the caller is holding the key itself or a reference to one.
    const CUSTODY: KeyCustody;

    async fn retrieve_data_key(
        &self,
        key_id: &KeyId,
        binding: Binding<'_>,
    ) -> Result<Protected<[u8; N]>, Self::Error>;
}

/// Capability: mint a batch of data keys.
///
/// Every implementation mints one distinct key per binding. A batch never
/// shares one key across values: one key cannot carry the bindings of
/// several values (ADR 0006). To make fewer backend calls than one per
/// value, derive each key from a cached authority key (ADR 0007), which
/// still gives one key per value.
#[allow(async_fn_in_trait)]
pub trait BatchGenerateDataKey<const N: usize>: GenerateDataKey<N> {
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

/// How many backend requests [`fan_out_generate`] and [`dedup_retrieve`]
/// keep in flight at one time, unless the caller sets a different limit.
///
/// Without a limit, a batch of N values sends N requests at once. A large
/// batch can then hit the vendor's request quota or use all the
/// connections in the client's pool. Each source that fans out stores its
/// own limit, starts with this value, and lets the caller change it (for
/// example `AwsDataKeySource::with_max_in_flight`).
///
/// The type is [`NonZeroUsize`], so a limit of zero, which would never
/// send a request, cannot be set.
pub const DEFAULT_MAX_IN_FLIGHT: NonZeroUsize = match NonZeroUsize::new(32) {
    Some(limit) => limit,
    None => unreachable!(),
};

/// N round trips, one distinct key per item — preserves per-value key
/// isolation (every value access is its own auditable retrieval). Fails
/// the whole batch if any item fails (fail-fast); does not roll back keys
/// already minted server-side before the failure.
///
/// At most `max_in_flight` requests run at one time (see
/// [`DEFAULT_MAX_IN_FLIGHT`]). The keys come back in the order of
/// `bindings`.
pub async fn fan_out_generate<const N: usize, T: GenerateDataKey<N> + MaybeSync>(
    backend: &T,
    bindings: &[Binding<'_>],
    max_in_flight: NonZeroUsize,
) -> Result<Vec<GeneratedDataKey<N>>, T::Error> {
    // Each request future is made here, before the first `.await`, and is
    // not polled until `buffered` takes it. See `bounded` for why.
    let requests: Vec<_> = bindings
        .iter()
        .map(|binding| backend.generate_data_key(*binding))
        .collect();
    bounded(requests, max_in_flight).await
}

/// Dedupes by KeyId, retrieves each distinct id once, expands to input
/// order/length. Against a fan-out-generated batch the ids are always
/// distinct, so this is N round trips; it saves a round trip only when a
/// caller presents the same id more than once.
/// Dedupes on the whole `(KeyId, Binding)` pair, not on the id alone: a
/// backend answers the same id differently under different bindings — one
/// of them by refusing — so collapsing them would hand one item a key it
/// never asked for.
///
/// At most `max_in_flight` requests run at one time (see
/// [`DEFAULT_MAX_IN_FLIGHT`]). The dedup is a hash lookup per item, so a
/// large batch costs time in proportion to its length.
pub async fn dedup_retrieve<const N: usize, T: RetrieveDataKey<N> + MaybeSync>(
    backend: &T,
    keys: &[(KeyId, Binding<'_>)],
    max_in_flight: NonZeroUsize,
) -> Result<Vec<Protected<[u8; N]>>, T::Error> {
    // The position of each distinct pair in `distinct`, and for each item
    // the position of its pair. `distinct` keeps first-seen order.
    let mut position: HashMap<&(KeyId, Binding<'_>), usize> = HashMap::with_capacity(keys.len());
    let mut distinct: Vec<&(KeyId, Binding<'_>)> = Vec::new();
    let slots: Vec<usize> = keys
        .iter()
        .map(|key| {
            *position.entry(key).or_insert_with(|| {
                distinct.push(key);
                distinct.len() - 1
            })
        })
        .collect();

    let requests: Vec<_> = distinct
        .iter()
        .map(|(id, binding)| backend.retrieve_data_key(id, *binding))
        .collect();
    let retrieved = bounded(requests, max_in_flight).await?;

    // No repeats: `distinct` is the input, in order, so no key is copied.
    if retrieved.len() == slots.len() {
        return Ok(retrieved);
    }
    Ok(slots
        .into_iter()
        .map(|slot| retrieved[slot].clone())
        .collect())
}

/// Runs `requests` with at most `max_in_flight` of them in progress at one
/// time, and returns their outputs in the order of `requests`. Stops at the
/// first error, and drops the requests that are still in progress.
///
/// A request starts as soon as any slot is free, so one slow request does
/// not stop the next ones from starting. The outputs are put back in order
/// at the end.
///
/// The caller makes the futures and passes them in a `Vec`. A closure that
/// makes them inside the stream (`stream::iter(items).map(..)`) stays in
/// the caller's future across the `.await`. The compiler then cannot prove
/// that future is `Send` for every lifetime of the borrowed items, and the
/// `KeyProvider` impls need it to be `Send`.
async fn bounded<F, O, E>(requests: Vec<F>, max_in_flight: NonZeroUsize) -> Result<Vec<O>, E>
where
    F: Future<Output = Result<O, E>>,
{
    let mut outputs: Vec<(usize, O)> = stream::iter(
        requests
            .into_iter()
            .enumerate()
            .map(|(index, request)| request.map_ok(move |output| (index, output))),
    )
    .buffer_unordered(max_in_flight.get())
    .try_collect()
    .await?;
    outputs.sort_unstable_by_key(|(index, _)| *index);
    Ok(outputs.into_iter().map(|(_, output)| output).collect())
}

/// Pairs each id with [`Binding::EMPTY`], for tests whose assertion is
/// about something other than binding.
#[cfg(test)]
pub(crate) fn with_empty_binding(ids: &[KeyId]) -> Vec<(KeyId, Binding<'static>)> {
    ids.iter().map(|id| (id.clone(), Binding::EMPTY)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use vitaminc_protected::Controlled;

    #[derive(Debug, thiserror::Error)]
    #[error("refused")]
    struct Refused;

    /// A source that records each call, counts the calls in progress, and
    /// yields a few times per call so that the calls overlap. Its key
    /// material is the first byte of the key id (for `generate`, of the
    /// binding) and then the binding length, so a test can see which
    /// request each key answers.
    #[derive(Default)]
    struct Counting {
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        calls: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
        /// A call whose key id (for `generate`, binding) starts with this
        /// byte fails.
        refuse: Option<u8>,
    }

    impl Counting {
        fn refusing(byte: u8) -> Self {
            Self {
                refuse: Some(byte),
                ..Self::default()
            }
        }

        async fn call(&self, id: &[u8], binding: Binding<'_>) -> Result<[u8; 2], Refused> {
            self.calls
                .lock()
                .unwrap()
                .push((id.to_vec(), binding.as_bytes().to_vec()));
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(now, Ordering::SeqCst);
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            if self.refuse.is_some() && id.first() == self.refuse.as_ref() {
                return Err(Refused);
            }
            Ok([id[0], binding.as_bytes().len() as u8])
        }

        fn calls(&self) -> usize {
            self.calls.lock().unwrap().len()
        }

        fn max_in_flight(&self) -> usize {
            self.max_in_flight.load(Ordering::SeqCst)
        }
    }

    impl GenerateDataKey<2> for Counting {
        type Error = Refused;

        async fn generate_data_key(
            &self,
            binding: Binding<'_>,
        ) -> Result<GeneratedDataKey<2>, Refused> {
            let key = self.call(binding.as_bytes(), binding).await?;
            Ok(GeneratedDataKey {
                plaintext: Protected::new(key),
                key_id: KeyId::new(binding.as_bytes().to_vec()),
            })
        }
    }

    impl RetrieveDataKey<2> for Counting {
        type Error = Refused;
        const RECONSTRUCTION: KeyReconstruction = KeyReconstruction::ServerOnly;
        const CUSTODY: KeyCustody = KeyCustody::ClientHeld;

        async fn retrieve_data_key(
            &self,
            key_id: &KeyId,
            binding: Binding<'_>,
        ) -> Result<Protected<[u8; 2]>, Refused> {
            self.call(key_id.as_bytes(), binding)
                .await
                .map(Protected::new)
        }
    }

    fn limit(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    /// One binding per byte, so each binding is distinct and names itself.
    fn bindings(bytes: &[[u8; 1]]) -> Vec<Binding<'_>> {
        bytes.iter().map(|b| Binding::new(b)).collect()
    }

    fn ids(n: u8) -> Vec<(KeyId, Binding<'static>)> {
        (0..n)
            .map(|i| (KeyId::new(vec![i]), Binding::EMPTY))
            .collect()
    }

    #[test]
    fn the_default_limit_is_32() {
        assert_eq!(DEFAULT_MAX_IN_FLIGHT.get(), 32);
    }

    #[tokio::test]
    async fn fan_out_keeps_order_and_never_exceeds_the_limit() {
        let source = Counting::default();
        let bytes: Vec<[u8; 1]> = (0..20).map(|i| [i]).collect();
        let bindings = bindings(&bytes);

        let keys = fan_out_generate(&source, &bindings, limit(3))
            .await
            .unwrap();

        let firsts: Vec<u8> = keys
            .iter()
            .map(|k| k.plaintext.clone().risky_unwrap()[0])
            .collect();
        assert_eq!(firsts, (0..20).collect::<Vec<u8>>());
        for (key, binding) in keys.iter().zip(&bindings) {
            assert_eq!(key.key_id.as_bytes(), binding.as_bytes());
        }
        assert_eq!(source.calls(), 20);
        assert_eq!(source.max_in_flight(), 3);
    }

    #[tokio::test]
    async fn dedup_keeps_order_and_never_exceeds_the_limit() {
        let source = Counting::default();

        let retrieved = dedup_retrieve(&source, &ids(20), limit(4)).await.unwrap();

        let firsts: Vec<u8> = retrieved.into_iter().map(|k| k.risky_unwrap()[0]).collect();
        assert_eq!(firsts, (0..20).collect::<Vec<u8>>());
        assert_eq!(source.calls(), 20);
        assert_eq!(source.max_in_flight(), 4);
    }

    #[tokio::test]
    async fn dedup_makes_one_call_per_distinct_pair_and_fans_duplicates_back_out() {
        let source = Counting::default();
        let (a, b) = (KeyId::new(vec![b'a']), KeyId::new(vec![b'b']));
        let bound = Binding::from("xy");
        let keys = vec![
            (a.clone(), Binding::EMPTY),
            (b.clone(), Binding::EMPTY),
            (a.clone(), Binding::EMPTY),
            // The same id under another binding is another request.
            (a.clone(), bound),
            (b.clone(), Binding::EMPTY),
            (a.clone(), bound),
        ];

        let retrieved = dedup_retrieve(&source, &keys, limit(2)).await.unwrap();

        let got: Vec<[u8; 2]> = retrieved.into_iter().map(|k| k.risky_unwrap()).collect();
        assert_eq!(
            got,
            vec![
                [b'a', 0],
                [b'b', 0],
                [b'a', 0],
                [b'a', 2],
                [b'b', 0],
                [b'a', 2]
            ]
        );
        // One call per distinct pair, in first-seen order.
        assert_eq!(
            *source.calls.lock().unwrap(),
            vec![
                (b"a".to_vec(), Vec::new()),
                (b"b".to_vec(), Vec::new()),
                (b"a".to_vec(), b"xy".to_vec()),
            ]
        );
    }

    #[tokio::test]
    async fn an_empty_batch_makes_no_call() {
        let source = Counting::default();

        let generated = fan_out_generate(&source, &[], DEFAULT_MAX_IN_FLIGHT)
            .await
            .unwrap();
        let retrieved = dedup_retrieve(&source, &[], DEFAULT_MAX_IN_FLIGHT)
            .await
            .unwrap();

        assert!(generated.is_empty());
        assert!(retrieved.is_empty());
        assert_eq!(source.calls(), 0);
    }

    #[tokio::test]
    async fn a_slow_request_does_not_stop_later_ones_from_starting() {
        // Request 0 is slow. With a limit of 2, requests 1 to 9 must still
        // run one after another in the other slot, and the outputs must
        // still come back in order.
        let done = AtomicUsize::new(0);
        let done = &done;
        let requests: Vec<_> = (0..10usize)
            .map(|i| async move {
                if i == 0 {
                    for _ in 0..1000 {
                        tokio::task::yield_now().await;
                    }
                    return Ok::<_, Refused>((i, done.load(Ordering::SeqCst)));
                }
                tokio::task::yield_now().await;
                done.fetch_add(1, Ordering::SeqCst);
                Ok((i, 0))
            })
            .collect();

        let outputs = bounded(requests, limit(2)).await.unwrap();

        assert_eq!(
            outputs[0],
            (0, 9),
            "request 0 saw every other request finish"
        );
        let order: Vec<usize> = outputs.iter().map(|(i, _)| *i).collect();
        assert_eq!(order, (0..10).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn an_error_stops_the_batch_before_later_requests_start() {
        // Item 2 fails. With a limit of 1 the requests run one at a time,
        // so items 3 and later never start.
        let source = Counting::refusing(2);
        let bytes: Vec<[u8; 1]> = (0..10).map(|i| [i]).collect();
        let result = fan_out_generate(&source, &bindings(&bytes), limit(1)).await;
        assert!(result.is_err());
        assert_eq!(source.calls(), 3);

        let source = Counting::refusing(2);
        let result = dedup_retrieve(&source, &ids(10), limit(1)).await;
        assert!(result.is_err());
        assert_eq!(source.calls(), 3);
    }

    #[tokio::test]
    async fn dedup_of_a_large_batch_with_many_duplicates_makes_one_call_per_pair() {
        // 10_000 items over 100 distinct ids. A `Vec::contains` dedup makes
        // about 10_000 * 100 comparisons here. A hash lookup per item makes
        // 10_000.
        let source = Counting::default();
        let keys: Vec<(KeyId, Binding<'_>)> = (0..10_000u32)
            .map(|i| (KeyId::new(vec![(i % 100) as u8]), Binding::EMPTY))
            .collect();

        let retrieved = dedup_retrieve(&source, &keys, DEFAULT_MAX_IN_FLIGHT)
            .await
            .unwrap();

        assert_eq!(retrieved.len(), 10_000);
        for (i, key) in retrieved.iter().enumerate() {
            assert_eq!(key.clone().risky_unwrap()[0], (i % 100) as u8);
        }
        assert_eq!(source.calls(), 100);
        assert_eq!(source.max_in_flight(), DEFAULT_MAX_IN_FLIGHT.get());
    }
}
