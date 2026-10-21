use crate::data_key::RetrieveDataKey;
use crate::key_id::KeyId;
use vitaminc_protected::Protected;

/// A deterministic key, one per backend key, used only to derive local
/// search-index terms (e.g. an HMAC-SHA256 PRF) — never used as a
/// per-value data key.
/// Distinguished from `Protected<[u8; N]>` purely for misuse-resistance:
/// nothing about the underlying bytes differs from a normal retrieved data
/// key, only how the caller is allowed to use them.
pub struct IndexKeyMaterial<const N: usize>(pub Protected<[u8; N]>);

/// Retrieve the fixed, persisted index key for this backend. `key_id` MUST
/// be the same KeyId every time this is called for a given backend key —
/// determinism comes entirely from the caller always presenting the same
/// stored identifier, not from anything the backend does. That KeyId is
/// provisioned once, out-of-band, typically via a single
/// [`GenerateDataKey::generate_data_key`](crate::GenerateDataKey::generate_data_key)
/// call whose result is persisted durably (config, secrets store, ...)
/// before this is ever called — that provisioning step is a deployment
/// concern, not part of this trait design.
///
/// **Mint the index key with [`Binding::EMPTY`](crate::Binding::EMPTY).**
/// This function retrieves it with `Binding::EMPTY`, because an index key
/// belongs to the backend key, not to a value. Every source binds, so a key
/// minted under a different binding does not come back. A vendor source
/// and `FakeKeyProvider` refuse the retrieval each time the service
/// starts. `AuthorityKeySource` does not refuse it: it derives a key that
/// is not the one it minted, with no error.
///
/// ```
/// use vitaminc_kms::{
///     load_index_key, Binding, GenerateDataKey, IndexKeyMaterial, KeyId, RetrieveDataKey,
/// };
///
/// /// Once, when the deployment is set up. Persist the returned id.
/// async fn provision<B: GenerateDataKey<32>>(backend: &B) -> Result<KeyId, B::Error> {
///     Ok(backend.generate_data_key(Binding::EMPTY).await?.key_id)
/// }
///
/// /// Each time the service starts, with the persisted id.
/// async fn start<B: RetrieveDataKey<32>>(
///     backend: &B,
///     index_key_id: &KeyId,
/// ) -> Result<IndexKeyMaterial<32>, B::Error> {
///     load_index_key(backend, index_key_id).await
/// }
/// ```
pub async fn load_index_key<const N: usize, T: RetrieveDataKey<N>>(
    backend: &T,
    key_id: &KeyId,
) -> Result<IndexKeyMaterial<N>, T::Error> {
    // `Binding::EMPTY`: an index key is one per *backend key*, not one per
    // value, so there is no context to bind it to — and the provisioning
    // `generate_data_key` call this loads the result of has none either.
    // Both sides must agree, and empty is the only value both can name
    // without the deployment carrying a shared secret string.
    backend
        .retrieve_data_key(key_id, crate::data_key::Binding::EMPTY)
        .await
        .map(IndexKeyMaterial)
}
