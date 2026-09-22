use super::{Binding, BindingSupport, DelegatedError, IndexKeyProvider, KeyProvider};
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
}

impl<const N: usize, T> IndexKeyProvider<N> for FixedIndexKeySource<T>
where
    T: KeyProvider<N> + Sync,
{
    type Error = DelegatedError<T::Error>;

    async fn load_index_key(&self) -> Result<IndexKeyMaterial<N>, Self::Error> {
        // retrieve_keys returns exactly one entry per input, in order: a
        // single-element slice in, the one result out.
        let mut keys = self
            .inner
            .retrieve_keys(&[(self.index_key_id.clone(), Binding::EMPTY)])
            .await
            .map_err(DelegatedError::Inner)?;
        match (keys.pop(), keys.len()) {
            (Some(key), 0) => Ok(IndexKeyMaterial(key)),
            (key, rest) => Err(DelegatedError::BatchLength {
                expected: 1,
                received: rest + usize::from(key.is_some()),
            }),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyIsolation, KeyReconstruction};
    use vitaminc_protected::Controlled;

    /// Returns `count` keys per request instead of one.
    struct Misbehaving(usize);

    impl KeyProvider<4> for Misbehaving {
        type Error = std::convert::Infallible;
        const RECONSTRUCTION: KeyReconstruction = KeyReconstruction::ServerOnly;
        const ISOLATION: KeyIsolation = KeyIsolation::PerValue;
        const BINDING: BindingSupport = BindingSupport::Unbound;

        /// One key per binding, with the binding's length as the material,
        /// so a test can see that a call reached this provider.
        async fn generate_keys(
            &self,
            bindings: &[Binding<'_>],
        ) -> Result<Vec<GeneratedDataKey<4>>, Self::Error> {
            Ok(bindings
                .iter()
                .enumerate()
                .map(|(i, b)| GeneratedDataKey {
                    plaintext: Protected::new([b.as_bytes().len() as u8; 4]),
                    key_id: KeyId::new(vec![i as u8]),
                })
                .collect())
        }

        async fn retrieve_keys(
            &self,
            requests: &[(KeyId, Binding<'_>)],
        ) -> Result<Vec<Protected<[u8; 4]>>, Self::Error> {
            Ok((0..requests.len() * self.0)
                .map(|i| Protected::new([i as u8; 4]))
                .collect())
        }
    }

    #[tokio::test]
    async fn the_index_key_is_the_one_key_retrieved_under_an_empty_binding() {
        let source = FixedIndexKeySource::new(Misbehaving(1), KeyId::new(vec![1]));
        let key = source.load_index_key().await.unwrap();
        assert_eq!(key.0.risky_unwrap(), [0u8; 4]);
    }

    #[tokio::test]
    async fn data_key_calls_pass_straight_through_to_the_inner_provider() {
        let source = FixedIndexKeySource::new(Misbehaving(1), KeyId::new(vec![1]));
        let generated = source
            .generate_keys(&[Binding::from("ab"), Binding::from("cde")])
            .await
            .unwrap();
        assert_eq!(generated.len(), 2);
        assert_eq!(generated[1].plaintext.clone().risky_unwrap(), [3u8; 4]);
        assert_eq!(generated[1].key_id, KeyId::new(vec![1]));

        let retrieved = source
            .retrieve_keys(&[
                (KeyId::new(vec![7]), Binding::EMPTY),
                (KeyId::new(vec![8]), Binding::EMPTY),
            ])
            .await
            .unwrap();
        assert_eq!(retrieved.len(), 2);
        assert_eq!(retrieved[0].clone().risky_unwrap(), [0u8; 4]);
        assert_eq!(retrieved[1].clone().risky_unwrap(), [1u8; 4]);
        assert_eq!(
            <FixedIndexKeySource<Misbehaving> as KeyProvider<4>>::BINDING,
            BindingSupport::Unbound
        );
    }

    #[tokio::test]
    async fn an_inner_provider_that_breaks_the_batch_contract_is_an_error_not_a_panic() {
        for (count, received) in [(0, 0), (2, 2)] {
            let source = FixedIndexKeySource::new(Misbehaving(count), KeyId::new(vec![1]));
            let Err(err) = source.load_index_key().await else {
                panic!("{count} keys per request must not load an index key");
            };
            assert!(
                matches!(err, DelegatedError::BatchLength { expected: 1, received: r } if r == received),
                "{err}"
            );
        }
    }
}
