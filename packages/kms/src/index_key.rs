use crate::data_key::RetrieveDataKey;
use crate::key_id::KeyId;
use vitaminc_protected::Protected;

/// A deterministic per-keyset key used only to derive local search-index
/// terms (e.g. an HMAC-SHA256 PRF) — never used as a per-value data key.
/// Distinguished from `Protected<[u8; N]>` purely for misuse-resistance:
/// nothing about the underlying bytes differs from a normal retrieved data
/// key, only how the caller is allowed to use them.
pub struct IndexKeyMaterial<const N: usize>(pub Protected<[u8; N]>);

/// Retrieve the fixed, persisted index key for this backend. `key_id` MUST
/// be the same KeyId every time this is called for a given keyset —
/// determinism comes entirely from the caller always presenting the same
/// stored identifier, not from anything the backend does. That KeyId is
/// provisioned once, out-of-band, typically via a single
/// [`GenerateDataKey::generate_data_key`](crate::GenerateDataKey::generate_data_key)
/// call whose result is persisted durably (config, secrets store, ...)
/// before this is ever called — that provisioning step is a deployment
/// concern, not part of this trait design.
pub async fn load_index_key<const N: usize, T: RetrieveDataKey<N>>(
    backend: &T,
    key_id: &KeyId,
) -> Result<IndexKeyMaterial<N>, T::Error> {
    backend.retrieve_data_key(key_id).await.map(IndexKeyMaterial)
}
