//! [`AuthorityKeySource`]: one backend call per cache refresh, and one data
//! key per value derived locally (ADR 0007). The wire format is ADR 0008.

use super::{
    only, AuthorityKeyCachePolicy, Binding, DelegatedError, DerivesFromAuthorityKey,
    IndexKeyProvider, KeyProvider,
};
use crate::{GeneratedDataKey, IndexKeyMaterial, KeyCustody, KeyId, KeyReconstruction};
use hmac::digest::{FixedOutput, KeyInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::{Generatable, RandomError, SafeRand};

/// The width of an authority key, in bytes. The inner provider mints and
/// unwraps authority keys as `KeyProvider<32>`.
const AUTHORITY_KEY_LEN: usize = 32;

/// The prefix of the binding that an authority key is minted and unwrapped
/// under. The 4-byte big-endian version follows it (ADR 0008).
const AUTHORITY_BINDING_LABEL: &[u8; 29] = b"vitaminc-kms/authority-key/v1";

/// The prefix of the HKDF `info` for each data key (ADR 0008).
const DATA_KEY_INFO_LABEL: &[u8; 38] = b"vitaminc-kms/authority-key/v1/data-key";

/// The first byte of every [`KeyId`] this source hands back.
const KEY_ID_FORMAT: u8 = 0x01;

/// The width of the random salt in each [`KeyId`], in bytes.
const SALT_LEN: usize = 16;

/// `format (1) || version (4, big-endian) || salt (16)`.
const KEY_ID_LEN: usize = 1 + 4 + SALT_LEN;

/// The width of a SHA-256 output, and so of the HKDF PRK and of each
/// HKDF-Expand block.
const HASH_LEN: usize = 32;

/// HKDF-SHA256 can expand at most 255 blocks of 32 bytes.
const MAX_DATA_KEY_LEN: usize = 255 * HASH_LEN;

/// The version of one authority key. A [`KeyId`] names the version its data
/// key was derived under, so a retrieval finds the right authority key
/// after a rotation.
///
/// Versions are the deployment's own numbers. The source does not order
/// them or require them to be contiguous: [`AuthorityKeys`] says which one
/// is current.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorityKeyVersion(u32);

impl AuthorityKeyVersion {
    pub const fn new(version: u32) -> Self {
        Self(version)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for AuthorityKeyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The deployment's authority keys: each version's wrapped form, and the
/// version that mints new data keys.
///
/// This is the authority-key store. It is the deployment's configuration,
/// not a service: each entry is the [`KeyId`] that
/// [`AuthorityKeySource::provision`] returned once for that version, which
/// the deployment persists durably (configuration, a secrets store),
/// exactly as it persists the index key id of a
/// [`FixedIndexKeySource`](super::FixedIndexKeySource).
///
/// **Rotation:** provision a new version, add it, and make it current. Keep
/// every earlier version that a stored [`KeyId`] still names: a retrieval
/// under a version that is not here fails with
/// [`AuthorityKeyError::UnknownVersion`], and the data under it cannot be
/// read. Remove a version only when no stored `KeyId` names it.
///
/// Losing a version's wrapped id loses every data key derived under it.
/// The storage obligation that a client-held [`KeyId`] puts on each value
/// moves here, to one id per version.
#[derive(Debug, Clone)]
pub struct AuthorityKeys {
    current: AuthorityKeyVersion,
    wrapped: BTreeMap<AuthorityKeyVersion, KeyId>,
}

impl AuthorityKeys {
    /// `current` mints every new data key, and must be one of `versions`.
    /// Every other version is for retrieval only.
    pub fn new(
        current: AuthorityKeyVersion,
        versions: impl IntoIterator<Item = (AuthorityKeyVersion, KeyId)>,
    ) -> Result<Self, AuthorityKeysError> {
        let mut wrapped = BTreeMap::new();
        for (version, key_id) in versions {
            if wrapped.insert(version, key_id).is_some() {
                return Err(AuthorityKeysError::DuplicateVersion { version });
            }
        }
        if !wrapped.contains_key(&current) {
            return Err(AuthorityKeysError::CurrentNotHeld { version: current });
        }
        Ok(Self { current, wrapped })
    }

    /// The version that mints new data keys.
    pub fn current(&self) -> AuthorityKeyVersion {
        self.current
    }

    /// The current version and its wrapped form.
    fn current_wrapped(&self) -> (AuthorityKeyVersion, &KeyId) {
        // `new` refuses a current version it does not hold.
        (self.current, &self.wrapped[&self.current])
    }

    /// The wrapped form of `version`, if this deployment holds it.
    pub fn wrapped(&self, version: AuthorityKeyVersion) -> Option<&KeyId> {
        self.wrapped.get(&version)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorityKeysError {
    #[error("authority key version {version} is given more than once")]
    DuplicateVersion { version: AuthorityKeyVersion },
    #[error("the current authority key version {version} is not one of the versions given")]
    CurrentNotHeld { version: AuthorityKeyVersion },
}

/// The error of an [`AuthorityKeySource`].
#[derive(Debug, thiserror::Error)]
pub enum AuthorityKeyError<E: std::error::Error + 'static> {
    /// The inner provider could not unwrap an authority key. It is shared,
    /// because one fetch serves every call that waited for it.
    #[error(transparent)]
    Fetch(Arc<DelegatedError<E>>),
    /// The key id at `position` in the batch is not one this source
    /// encodes: it has the wrong length or an unknown format byte.
    #[error("the key id at batch position {position} is not an authority-key key id")]
    MalformedKeyId { position: usize },
    /// The key id at `position` names a version that [`AuthorityKeys`] does
    /// not hold.
    #[error("the key id at batch position {position} names authority key version {version}, which this source does not hold")]
    UnknownVersion {
        position: usize,
        version: AuthorityKeyVersion,
    },
    #[error(transparent)]
    Random(#[from] RandomError),
}

/// A [`KeyProvider`] that derives each data key from a cached *authority
/// key*, so that a batch costs one backend call per cache refresh and not
/// one per value (ADR 0007).
///
/// An authority key is a 32-byte data key of the inner provider, minted
/// once per version by [`provision`](Self::provision) and stored by the
/// deployment in wrapped form ([`AuthorityKeys`]). On the first call, and
/// again when the cached copy expires, the source asks the inner provider
/// to unwrap it. Each value then gets its own data key:
///
/// ```text
/// data key = HKDF-SHA256(authority key, salt, info(version, N, binding))
/// KeyId    = 0x01 || version || salt
/// ```
///
/// with a fresh 16-byte random salt per value. The exact encoding is ADR
/// 0008.
///
/// # Binding
///
/// The binding is an input to the derivation, so every value is bound. A
/// retrieval under a different binding does not fail: it derives a
/// different key, which opens nothing. There is no backend here to refuse
/// it, and the source cannot tell a wrong binding from a right one. The
/// consumer's AEAD detects it, when the derived key does not open the
/// ciphertext. This is the one source where a wrong binding is not an
/// error from the provider.
///
/// # Auditing and material in memory
///
/// This inverts the stance of [`CachingKeyProvider`](super::CachingKeyProvider),
/// and makes it the normal path, one tier up:
///
/// * **Per-value retrieval is not per-value authorization.** The backend
///   authorizes and logs one unwrap of the authority key per cache
///   refresh. It does not see the values derived from it. A deployment that
///   needs an audit record or a policy check per value must use the inner
///   provider directly, and must not use this.
/// * **Plaintext authority material stays in memory.** A cached authority
///   key can derive every data key under its version for as long as it is
///   cached. It is [`Protected`], and zeroizes when its entry leaves the
///   cache. The [`AuthorityKeyCachePolicy`] is a security control: its
///   `ttl` is the longest time for which a revoked backend key still works
///   in this process.
///
/// The cache has no background task. It drops an expired authority key,
/// and so zeroizes it, only during maintenance, which runs on later calls.
/// A deployment that needs a hard limit while the source is idle calls
/// [`purge_expired`](DerivesFromAuthorityKey::purge_expired) on a timer.
///
/// When several calls miss the cache at the same time, one of them fetches
/// the authority key and the others wait for that fetch. So a refresh under
/// load is still one backend call per version.
///
/// Every value that HKDF derives on the way to a data key is [`Protected`]
/// and zeroizes on drop: the PRK, and each HKDF-Expand block. The HMAC
/// states that take in the authority key and the PRK wipe on drop too
/// (`hmac/zeroize`). Only the hash function's own working memory is out of
/// reach, the same as for every other HMAC in this workspace.
///
/// # Constants
///
/// [`CUSTODY`](KeyProvider::CUSTODY) is
/// [`BackendHeld`](KeyCustody::BackendHeld): a [`KeyId`] is a version and a
/// salt, with no key material, and is useless without the authority key.
/// [`RECONSTRUCTION`](KeyProvider::RECONSTRUCTION) is the inner provider's:
/// a data key is recoverable exactly when its authority key is, and the
/// inner provider decides that.
///
/// # Empty batches
///
/// An empty batch returns an empty result and makes no backend call. It
/// does not fetch or refresh an authority key.
pub struct AuthorityKeySource<T> {
    inner: T,
    keys: AuthorityKeys,
    policy: AuthorityKeyCachePolicy,
    cache: moka::future::Cache<AuthorityKeyVersion, Protected<[u8; AUTHORITY_KEY_LEN]>>,
}

impl<T> AuthorityKeySource<T> {
    /// Derive data keys from the authority keys in `keys`, which `inner`
    /// unwraps, and cache each unwrapped authority key under `policy`.
    pub fn new(inner: T, keys: AuthorityKeys, policy: AuthorityKeyCachePolicy) -> Self {
        Self {
            inner,
            keys,
            policy,
            cache: moka::future::Cache::builder()
                .max_capacity(policy.max_entries)
                .time_to_live(policy.ttl)
                .build(),
        }
    }

    /// Mint the authority key for `version` with `inner`, and return its
    /// wrapped form, for the deployment to persist in its [`AuthorityKeys`].
    ///
    /// This is a one-time step per version, like provisioning the index key
    /// of a [`FixedIndexKeySource`](super::FixedIndexKeySource). Do not call
    /// it at startup: a new authority key under a version that is already
    /// in use makes every data key derived under that version unreadable.
    ///
    /// The key is minted under a fixed binding that names the version (ADR
    /// 0008), never under a caller's binding. So a value's data key cannot
    /// be an authority key, and the wrapped id of one version does not
    /// unwrap as another version.
    pub async fn provision(
        inner: &T,
        version: AuthorityKeyVersion,
    ) -> Result<KeyId, DelegatedError<T::Error>>
    where
        T: KeyProvider<AUTHORITY_KEY_LEN>,
    {
        let binding = authority_binding(version);
        let minted = inner
            .generate_keys(&[Binding::new(&binding)])
            .await
            .map_err(DelegatedError::Inner)?;
        only(minted).map(|key| key.key_id)
    }

    /// The provider that unwraps the authority keys.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// The authority keys this source derives from.
    pub fn keys(&self) -> &AuthorityKeys {
        &self.keys
    }
}

impl<T: KeyProvider<AUTHORITY_KEY_LEN> + Sync> AuthorityKeySource<T> {
    /// The plaintext authority key for `version`: from the cache, or from
    /// one unwrap by the inner provider that every concurrent miss shares.
    async fn authority_key(
        &self,
        version: AuthorityKeyVersion,
        wrapped: &KeyId,
    ) -> Result<Protected<[u8; AUTHORITY_KEY_LEN]>, AuthorityKeyError<T::Error>> {
        self.cache
            .try_get_with(version, async {
                let binding = authority_binding(version);
                let keys = self
                    .inner
                    .retrieve_keys(&[(wrapped.clone(), Binding::new(&binding))])
                    .await
                    .map_err(DelegatedError::Inner)?;
                only(keys)
            })
            .await
            .map_err(AuthorityKeyError::Fetch)
    }
}

impl<const N: usize, T: KeyProvider<AUTHORITY_KEY_LEN> + Sync> KeyProvider<N>
    for AuthorityKeySource<T>
{
    type Error = AuthorityKeyError<T::Error>;

    const RECONSTRUCTION: KeyReconstruction = T::RECONSTRUCTION;
    const CUSTODY: KeyCustody = KeyCustody::BackendHeld;

    async fn generate_keys(
        &self,
        bindings: &[Binding<'_>],
    ) -> Result<Vec<GeneratedDataKey<N>>, Self::Error> {
        if bindings.is_empty() {
            return Ok(Vec::new());
        }

        let (version, wrapped) = self.keys.current_wrapped();
        let authority_key = self.authority_key(version, wrapped).await?;

        let mut rng = SafeRand::from_entropy()?;
        bindings
            .iter()
            .map(|binding| {
                let salt = <[u8; SALT_LEN]>::random(&mut rng)?;
                Ok(GeneratedDataKey {
                    plaintext: derive_data_key(&authority_key, version, &salt, *binding),
                    key_id: encode_key_id(version, &salt),
                })
            })
            .collect()
    }

    async fn retrieve_keys(
        &self,
        keys: &[(KeyId, Binding<'_>)],
    ) -> Result<Vec<Protected<[u8; N]>>, Self::Error> {
        // Decode and resolve the whole batch before any backend call, so a
        // malformed or unknown key id costs no unwrap.
        let mut decoded = Vec::with_capacity(keys.len());
        let mut wanted: BTreeMap<AuthorityKeyVersion, &KeyId> = BTreeMap::new();
        for (position, (key_id, binding)) in keys.iter().enumerate() {
            let (version, salt) =
                decode_key_id(key_id).ok_or(AuthorityKeyError::MalformedKeyId { position })?;
            let wrapped = self
                .keys
                .wrapped(version)
                .ok_or(AuthorityKeyError::UnknownVersion { position, version })?;
            wanted.insert(version, wrapped);
            decoded.push((version, salt, *binding));
        }

        // One authority key per distinct version; none for an empty batch.
        // The versions unwrap concurrently, so a batch that spans a
        // rotation pays one round trip, not one per version.
        let authority_keys: BTreeMap<_, _> = futures::future::try_join_all(wanted.into_iter().map(
            |(version, wrapped)| async move {
                Ok::<_, AuthorityKeyError<T::Error>>((
                    version,
                    self.authority_key(version, wrapped).await?,
                ))
            },
        ))
        .await?
        .into_iter()
        .collect();

        decoded
            .iter()
            .map(|(version, salt, binding)| {
                // Every decoded version was fetched just above.
                let authority_key = &authority_keys[version];
                Ok(derive_data_key(authority_key, *version, salt, *binding))
            })
            .collect()
    }
}

impl<T> DerivesFromAuthorityKey for AuthorityKeySource<T>
where
    T: Sync,
{
    fn cache_policy(&self) -> AuthorityKeyCachePolicy {
        self.policy
    }

    async fn purge_expired(&self) {
        self.cache.run_pending_tasks().await;
    }
}

/// Pure delegation, so that the source composes with an inner provider
/// that also loads the index key, as
/// [`CachingKeyProvider`](super::CachingKeyProvider) does.
impl<const N: usize, T: IndexKeyProvider<N> + Sync> IndexKeyProvider<N> for AuthorityKeySource<T> {
    type Error = T::Error;

    async fn load_index_key(&self) -> Result<IndexKeyMaterial<N>, Self::Error> {
        self.inner.load_index_key().await
    }
}

/// `"vitaminc-kms/authority-key/v1" || u32be(version)` (ADR 0008).
fn authority_binding(version: AuthorityKeyVersion) -> [u8; AUTHORITY_BINDING_LABEL.len() + 4] {
    let mut binding = [0u8; AUTHORITY_BINDING_LABEL.len() + 4];
    binding[..AUTHORITY_BINDING_LABEL.len()].copy_from_slice(AUTHORITY_BINDING_LABEL);
    binding[AUTHORITY_BINDING_LABEL.len()..].copy_from_slice(&version.0.to_be_bytes());
    binding
}

/// `0x01 || u32be(version) || salt` (ADR 0008).
fn encode_key_id(version: AuthorityKeyVersion, salt: &[u8; SALT_LEN]) -> KeyId {
    let mut bytes = Vec::with_capacity(KEY_ID_LEN);
    bytes.push(KEY_ID_FORMAT);
    bytes.extend_from_slice(&version.0.to_be_bytes());
    bytes.extend_from_slice(salt);
    KeyId::new(bytes)
}

/// The inverse of [`encode_key_id`]: `None` for any other length or format
/// byte.
fn decode_key_id(key_id: &KeyId) -> Option<(AuthorityKeyVersion, [u8; SALT_LEN])> {
    let bytes: &[u8; KEY_ID_LEN] = key_id.as_bytes().try_into().ok()?;
    let (format, rest) = bytes.split_first()?;
    if *format != KEY_ID_FORMAT {
        return None;
    }
    let (version, salt) = rest.split_at(4);
    Some((
        AuthorityKeyVersion(u32::from_be_bytes(version.try_into().ok()?)),
        salt.try_into().ok()?,
    ))
}

/// `HKDF-SHA256(salt, authority key, info, N)`, with
/// `info = "vitaminc-kms/authority-key/v1/data-key" || u32be(version) ||
/// u16be(N) || u64be(len(binding)) || binding` (ADR 0008).
///
/// Every field but the binding has a fixed width, and the binding carries
/// its length, so the `info` is injective. `N` is in it so that a short key
/// is not a prefix of a long one under the same salt.
fn derive_data_key<const N: usize>(
    authority_key: &Protected<[u8; AUTHORITY_KEY_LEN]>,
    version: AuthorityKeyVersion,
    salt: &[u8; SALT_LEN],
    binding: Binding<'_>,
) -> Protected<[u8; N]> {
    const {
        assert!(
            N > 0 && N <= MAX_DATA_KEY_LEN,
            "HKDF-SHA256 derives data keys of 1 to 8160 bytes"
        );
    }
    let binding = binding.as_bytes();
    // `N` fits in a `u16` by the assertion above.
    let length = (N as u16).to_be_bytes();
    let binding_length = (binding.len() as u64).to_be_bytes();

    let prk = hkdf_extract(salt, authority_key.risky_ref());
    let mut data_key = Protected::new([0u8; N]);
    hkdf_expand(
        &prk,
        &[
            DATA_KEY_INFO_LABEL,
            &version.0.to_be_bytes(),
            &length,
            &binding_length,
            binding,
        ],
        data_key.risky_inner_mut(),
    );
    data_key
}

/// HKDF-Extract with SHA-256 (RFC 5869, section 2.2): `PRK = HMAC(salt,
/// IKM)`.
///
/// This and [`hkdf_expand`] stand in for the `hkdf` crate, because that
/// crate keeps the PRK and each expand block in plain arrays that it drops
/// without wiping. Here, HMAC writes each value straight into [`Protected`]
/// memory, which zeroizes on drop.
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Protected<[u8; HASH_LEN]> {
    let mut mac = new_hmac(salt);
    mac.update(ikm);
    let mut prk = Protected::new([0u8; HASH_LEN]);
    FixedOutput::finalize_into(mac, prk.risky_inner_mut().into());
    prk
}

/// HKDF-Expand with SHA-256 (RFC 5869, section 2.3): `T(i) = HMAC(PRK,
/// T(i-1) || info || i)`, and `okm` is the first `okm.len()` bytes of
/// `T(1) || T(2) || ...`. `info` is the concatenation of `info`'s parts.
///
/// The caller makes sure that `okm` is at most [`MAX_DATA_KEY_LEN`] bytes,
/// so the block counter fits in one byte.
fn hkdf_expand(prk: &Protected<[u8; HASH_LEN]>, info: &[&[u8]], okm: &mut [u8]) {
    debug_assert!(okm.len() <= MAX_DATA_KEY_LEN);
    let mut block = Protected::new([0u8; HASH_LEN]);
    for (index, chunk) in okm.chunks_mut(HASH_LEN).enumerate() {
        let mut mac = new_hmac(prk.risky_ref());
        if index > 0 {
            mac.update(block.risky_ref());
        }
        for part in info {
            mac.update(part);
        }
        // At most 255 blocks, by the length check above.
        mac.update(&[index as u8 + 1]);
        FixedOutput::finalize_into(mac, block.risky_inner_mut().into());
        chunk.copy_from_slice(&block.risky_ref()[..chunk.len()]);
    }
}

/// HMAC-SHA256 under `key`. HMAC takes a key of any length, so this cannot
/// fail.
fn new_hmac(key: &[u8]) -> Hmac<Sha256> {
    <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes a key of any length")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    #[derive(Debug, thiserror::Error)]
    #[error("the backend refused the request")]
    struct Refused;

    /// Keys remembered under `(key_id, binding)`.
    type Stored = HashMap<(KeyId, Vec<u8>), [u8; 32]>;

    /// An inner provider that counts its batch calls and binds as a real
    /// backend does: a key comes back only under the binding it was minted
    /// with.
    #[derive(Default)]
    struct Backend {
        keys: Mutex<Stored>,
        minted: AtomicUsize,
        generate_calls: AtomicUsize,
        retrieve_calls: AtomicUsize,
    }

    impl Backend {
        fn generate_calls(&self) -> usize {
            self.generate_calls.load(Ordering::SeqCst)
        }

        fn retrieve_calls(&self) -> usize {
            self.retrieve_calls.load(Ordering::SeqCst)
        }

        fn calls(&self) -> usize {
            self.generate_calls() + self.retrieve_calls()
        }
    }

    impl KeyProvider<32> for Backend {
        type Error = Refused;

        const RECONSTRUCTION: KeyReconstruction = KeyReconstruction::ClientAndServer;
        const CUSTODY: KeyCustody = KeyCustody::ClientHeld;

        async fn generate_keys(
            &self,
            bindings: &[Binding<'_>],
        ) -> Result<Vec<GeneratedDataKey<32>>, Self::Error> {
            self.generate_calls.fetch_add(1, Ordering::SeqCst);
            let mut keys = self.keys.lock().unwrap();
            Ok(bindings
                .iter()
                .map(|binding| {
                    let n = self.minted.fetch_add(1, Ordering::SeqCst) as u8;
                    let key_id = KeyId::new(vec![0xEE, n]);
                    let plaintext = [n.wrapping_add(1); 32];
                    keys.insert((key_id.clone(), binding.as_bytes().to_vec()), plaintext);
                    GeneratedDataKey {
                        plaintext: Protected::new(plaintext),
                        key_id,
                    }
                })
                .collect())
        }

        async fn retrieve_keys(
            &self,
            requests: &[(KeyId, Binding<'_>)],
        ) -> Result<Vec<Protected<[u8; 32]>>, Self::Error> {
            self.retrieve_calls.fetch_add(1, Ordering::SeqCst);
            let keys = self.keys.lock().unwrap();
            requests
                .iter()
                .map(|(id, binding)| {
                    keys.get(&(id.clone(), binding.as_bytes().to_vec()))
                        .map(|key| Protected::new(*key))
                        .ok_or(Refused)
                })
                .collect()
        }
    }

    const V1: AuthorityKeyVersion = AuthorityKeyVersion::new(1);
    const V2: AuthorityKeyVersion = AuthorityKeyVersion::new(2);

    fn policy(ttl: Duration) -> AuthorityKeyCachePolicy {
        AuthorityKeyCachePolicy {
            max_entries: 4,
            ttl,
        }
    }

    fn minute() -> Duration {
        Duration::from_secs(60)
    }

    /// A backend with version 1 provisioned, and a source over it. The
    /// provisioning call is the one generate call the backend has seen.
    async fn source(ttl: Duration) -> AuthorityKeySource<Backend> {
        let backend = Backend::default();
        let wrapped = AuthorityKeySource::provision(&backend, V1).await.unwrap();
        let keys = AuthorityKeys::new(V1, [(V1, wrapped)]).unwrap();
        AuthorityKeySource::new(backend, keys, policy(ttl))
    }

    fn bytes<const N: usize>(key: &Protected<[u8; N]>) -> [u8; N] {
        key.clone().risky_unwrap()
    }

    #[tokio::test]
    async fn generate_then_retrieve_round_trips_under_each_binding() {
        let source = source(minute()).await;
        let bindings = [
            Binding::from("users/email"),
            Binding::from("users/age"),
            Binding::EMPTY,
        ];

        let generated: Vec<GeneratedDataKey<32>> = source.generate_keys(&bindings).await.unwrap();
        let requests: Vec<(KeyId, Binding<'_>)> = generated
            .iter()
            .zip(bindings)
            .rev()
            .map(|(key, binding)| (key.key_id.clone(), binding))
            .collect();
        let retrieved: Vec<Protected<[u8; 32]>> = source.retrieve_keys(&requests).await.unwrap();

        let expected: Vec<[u8; 32]> = generated
            .iter()
            .rev()
            .map(|k| bytes(&k.plaintext))
            .collect();
        let got: Vec<[u8; 32]> = retrieved.iter().map(bytes).collect();
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn every_value_in_a_batch_gets_its_own_key_and_key_id() {
        let source = source(minute()).await;
        let binding = Binding::from("users/email");

        let keys: Vec<GeneratedDataKey<32>> = source.generate_keys(&[binding; 50]).await.unwrap();

        let mut material: Vec<[u8; 32]> = keys.iter().map(|k| bytes(&k.plaintext)).collect();
        let mut ids: Vec<Vec<u8>> = keys.iter().map(|k| k.key_id.as_bytes().to_vec()).collect();
        material.sort();
        material.dedup();
        ids.sort();
        ids.dedup();
        assert_eq!((material.len(), ids.len()), (50, 50));
    }

    #[tokio::test]
    async fn a_wrong_binding_derives_a_different_key_and_is_not_an_error() {
        let source = source(minute()).await;
        let generated: Vec<GeneratedDataKey<32>> = source
            .generate_keys(&[Binding::from("users/email")])
            .await
            .unwrap();
        let key_id = generated[0].key_id.clone();

        let retrieved: Vec<Protected<[u8; 32]>> = source
            .retrieve_keys(&[
                (key_id.clone(), Binding::from("users/email")),
                (key_id.clone(), Binding::from("users/age")),
                (key_id, Binding::EMPTY),
            ])
            .await
            .unwrap();

        let right = bytes(&generated[0].plaintext);
        assert_eq!(bytes(&retrieved[0]), right);
        assert_ne!(bytes(&retrieved[1]), right);
        assert_ne!(bytes(&retrieved[2]), right);
        assert_ne!(bytes(&retrieved[1]), bytes(&retrieved[2]));
    }

    #[tokio::test]
    async fn many_values_cost_one_backend_call_per_cache_refresh() {
        let source = source(minute()).await;
        let binding = Binding::from("users/email");

        let mut generated: Vec<GeneratedDataKey<32>> = Vec::new();
        for _ in 0..4 {
            generated.extend(source.generate_keys(&[binding; 25]).await.unwrap());
        }
        let requests: Vec<(KeyId, Binding<'_>)> = generated
            .iter()
            .map(|k| (k.key_id.clone(), binding))
            .collect();
        let retrieved: Vec<Protected<[u8; 32]>> = source.retrieve_keys(&requests).await.unwrap();

        assert_eq!(retrieved.len(), 100);
        assert_eq!(source.inner().retrieve_calls(), 1);
        assert_eq!(source.inner().generate_calls(), 1, "provisioning only");
    }

    #[tokio::test]
    async fn concurrent_misses_share_one_fetch() {
        let source = source(minute()).await;
        let batch = [Binding::from("users/email")];

        let batches = futures::future::join_all(
            (0..16).map(|_| KeyProvider::<32>::generate_keys(&source, &batch)),
        )
        .await;

        assert!(batches.iter().all(Result::is_ok));
        assert_eq!(source.inner().retrieve_calls(), 1);
    }

    #[tokio::test]
    async fn an_empty_batch_makes_no_backend_call_and_fetches_no_authority_key() {
        let source = source(minute()).await;
        let before = source.inner().calls();

        let generated: Vec<GeneratedDataKey<32>> = source.generate_keys(&[]).await.unwrap();
        let retrieved: Vec<Protected<[u8; 32]>> = source.retrieve_keys(&[]).await.unwrap();

        assert!(generated.is_empty() && retrieved.is_empty());
        assert_eq!(source.inner().calls(), before);
        source.cache.run_pending_tasks().await;
        assert_eq!(source.cache.entry_count(), 0);
    }

    #[tokio::test]
    async fn an_expired_authority_key_is_fetched_again() {
        let source = source(Duration::from_millis(50)).await;
        let binding = Binding::from("users/email");

        let first: Vec<GeneratedDataKey<32>> = source.generate_keys(&[binding]).await.unwrap();
        let _: Vec<GeneratedDataKey<32>> = source.generate_keys(&[binding]).await.unwrap();
        assert_eq!(source.inner().retrieve_calls(), 1);

        tokio::time::sleep(Duration::from_millis(200)).await;

        let retrieved: Vec<Protected<[u8; 32]>> = source
            .retrieve_keys(&[(first[0].key_id.clone(), binding)])
            .await
            .unwrap();
        assert_eq!(source.inner().retrieve_calls(), 2);
        assert_eq!(bytes(&retrieved[0]), bytes(&first[0].plaintext));
    }

    #[tokio::test]
    async fn purge_expired_drops_an_expired_authority_key_from_memory() {
        let source = source(Duration::from_millis(50)).await;
        let _: Vec<GeneratedDataKey<32>> = source
            .generate_keys(&[Binding::from("users/email")])
            .await
            .unwrap();
        source.purge_expired().await;
        assert_eq!(source.cache.entry_count(), 1);

        tokio::time::sleep(Duration::from_millis(200)).await;

        source.purge_expired().await;
        assert_eq!(source.cache.entry_count(), 0);
    }

    #[tokio::test]
    async fn after_a_rotation_old_key_ids_retrieve_and_new_keys_use_the_new_version() {
        let old = source(minute()).await;
        let binding = Binding::from("users/email");
        let before: Vec<GeneratedDataKey<32>> = old.generate_keys(&[binding]).await.unwrap();

        // The deployment provisions version 2, keeps version 1, and makes
        // version 2 current.
        let v1 = old.keys().wrapped(V1).unwrap().clone();
        let backend = old.inner;
        let v2 = AuthorityKeySource::provision(&backend, V2).await.unwrap();
        let keys = AuthorityKeys::new(V2, [(V1, v1), (V2, v2)]).unwrap();
        let rotated = AuthorityKeySource::new(backend, keys, policy(minute()));
        let calls = rotated.inner().retrieve_calls();

        let after: Vec<GeneratedDataKey<32>> = rotated.generate_keys(&[binding]).await.unwrap();
        assert_eq!(decode_key_id(&before[0].key_id).unwrap().0, V1);
        assert_eq!(decode_key_id(&after[0].key_id).unwrap().0, V2);

        let retrieved: Vec<Protected<[u8; 32]>> = rotated
            .retrieve_keys(&[
                (before[0].key_id.clone(), binding),
                (after[0].key_id.clone(), binding),
            ])
            .await
            .unwrap();
        assert_eq!(bytes(&retrieved[0]), bytes(&before[0].plaintext));
        assert_eq!(bytes(&retrieved[1]), bytes(&after[0].plaintext));
        // One unwrap for version 2 when generating, one for version 1 here.
        assert_eq!(rotated.inner().retrieve_calls(), calls + 2);
    }

    #[tokio::test]
    async fn a_version_the_deployment_does_not_hold_is_an_error() {
        let source = source(minute()).await;
        let binding = Binding::from("users/email");
        let generated: Vec<GeneratedDataKey<32>> = source.generate_keys(&[binding]).await.unwrap();
        let unknown = encode_key_id(V2, &[7; SALT_LEN]);
        let calls = source.inner().calls();

        let result: Result<Vec<Protected<[u8; 32]>>, _> = source
            .retrieve_keys(&[(generated[0].key_id.clone(), binding), (unknown, binding)])
            .await;

        assert!(
            matches!(
                result,
                Err(AuthorityKeyError::UnknownVersion { position: 1, version }) if version == V2
            ),
            "{:?}",
            result.err()
        );
        assert_eq!(source.inner().calls(), calls);
    }

    #[tokio::test]
    async fn a_malformed_key_id_is_an_error_and_costs_no_backend_call() {
        let source = source(minute()).await;
        let calls = source.inner().calls();
        let good = encode_key_id(V1, &[7; SALT_LEN]).as_bytes().to_vec();

        let mut wrong_format = good.clone();
        wrong_format[0] = 0x02;
        let malformed = [
            Vec::new(),
            vec![KEY_ID_FORMAT],
            good[..KEY_ID_LEN - 1].to_vec(),
            [good.as_slice(), &[0]].concat(),
            wrong_format,
        ];

        for bytes in malformed {
            let len = bytes.len();
            let result: Result<Vec<Protected<[u8; 32]>>, _> = source
                .retrieve_keys(&[
                    (KeyId::new(good.clone()), Binding::EMPTY),
                    (KeyId::new(bytes), Binding::EMPTY),
                ])
                .await;
            assert!(
                matches!(
                    result,
                    Err(AuthorityKeyError::MalformedKeyId { position: 1 })
                ),
                "{len} bytes: {:?}",
                result.err()
            );
        }
        assert_eq!(source.inner().calls(), calls);
    }

    #[tokio::test]
    async fn an_authority_key_the_backend_refuses_is_an_error() {
        let backend = Backend::default();
        let keys = AuthorityKeys::new(V1, [(V1, KeyId::new(vec![1, 2, 3]))]).unwrap();
        let source = AuthorityKeySource::new(backend, keys, policy(minute()));

        let result: Result<Vec<GeneratedDataKey<32>>, _> =
            source.generate_keys(&[Binding::EMPTY]).await;

        assert!(
            matches!(&result, Err(AuthorityKeyError::Fetch(err)) if matches!(**err, DelegatedError::Inner(Refused))),
            "{:?}",
            result.err()
        );
    }

    /// Returns `count` keys per request instead of one.
    struct Misbehaving(usize);

    impl KeyProvider<32> for Misbehaving {
        type Error = Infallible;
        const RECONSTRUCTION: KeyReconstruction = KeyReconstruction::ServerOnly;
        const CUSTODY: KeyCustody = KeyCustody::ClientHeld;

        async fn generate_keys(
            &self,
            _bindings: &[Binding<'_>],
        ) -> Result<Vec<GeneratedDataKey<32>>, Self::Error> {
            Ok((0..self.0)
                .map(|i| GeneratedDataKey {
                    plaintext: Protected::new([0; 32]),
                    key_id: KeyId::new(vec![i as u8]),
                })
                .collect())
        }

        async fn retrieve_keys(
            &self,
            _requests: &[(KeyId, Binding<'_>)],
        ) -> Result<Vec<Protected<[u8; 32]>>, Self::Error> {
            Ok((0..self.0).map(|_| Protected::new([0; 32])).collect())
        }
    }

    #[tokio::test]
    async fn an_inner_provider_that_breaks_the_batch_contract_is_an_error_not_a_panic() {
        for count in [0, 2] {
            let provisioned = AuthorityKeySource::provision(&Misbehaving(count), V1).await;
            assert!(
                matches!(provisioned, Err(DelegatedError::BatchLength { expected: 1, received }) if received == count),
                "{count}"
            );

            let keys = AuthorityKeys::new(V1, [(V1, KeyId::new(vec![0]))]).unwrap();
            let source = AuthorityKeySource::new(Misbehaving(count), keys, policy(minute()));
            let result: Result<Vec<GeneratedDataKey<32>>, _> =
                source.generate_keys(&[Binding::EMPTY]).await;
            assert!(
                matches!(&result, Err(AuthorityKeyError::Fetch(err)) if matches!(**err, DelegatedError::BatchLength { expected: 1, received } if received == count)),
                "{count}"
            );
        }
    }

    #[tokio::test]
    async fn the_authority_key_is_minted_and_unwrapped_under_the_version_binding() {
        let source = source(minute()).await;
        let _: Vec<GeneratedDataKey<32>> = source.generate_keys(&[Binding::EMPTY]).await.unwrap();

        let stored = source.inner().keys.lock().unwrap();
        let bindings: Vec<&Vec<u8>> = stored.keys().map(|(_, binding)| binding).collect();
        assert_eq!(
            bindings,
            [&b"vitaminc-kms/authority-key/v1\x00\x00\x00\x01".to_vec()]
        );
    }

    #[test]
    fn authority_keys_refuse_a_duplicate_version_and_a_current_version_they_do_not_hold() {
        let id = || KeyId::new(vec![1]);
        assert!(matches!(
            AuthorityKeys::new(V1, [(V1, id()), (V1, id())]),
            Err(AuthorityKeysError::DuplicateVersion { version }) if version == V1
        ));
        assert!(matches!(
            AuthorityKeys::new(V2, [(V1, id())]),
            Err(AuthorityKeysError::CurrentNotHeld { version }) if version == V2
        ));
        assert!(matches!(
            AuthorityKeys::new(V1, []),
            Err(AuthorityKeysError::CurrentNotHeld { .. })
        ));
    }

    #[test]
    fn the_constants_say_backend_held_and_forward_reconstruction() {
        type Source = AuthorityKeySource<Backend>;
        assert_eq!(
            <Source as KeyProvider<32>>::CUSTODY,
            KeyCustody::BackendHeld
        );
        assert_eq!(
            <Source as KeyProvider<16>>::RECONSTRUCTION,
            KeyReconstruction::ClientAndServer
        );
    }

    #[tokio::test]
    async fn the_cache_policy_is_the_one_the_source_was_built_with() {
        let source = source(Duration::from_secs(5)).await;
        assert_eq!(source.cache_policy(), policy(Duration::from_secs(5)));
    }

    fn hex<const N: usize>(bytes: [u8; N]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Known-answer vectors for the derivation in ADR 0008, computed with an
    /// independent HKDF-SHA256 (Python's `hmac` and `hashlib`).
    #[test]
    fn the_derivation_matches_the_known_answer_vectors() {
        let authority_key = Protected::new(std::array::from_fn::<u8, 32, _>(|i| i as u8));
        let salt: [u8; SALT_LEN] = std::array::from_fn(|i| 0xA0 + i as u8);
        let email = Binding::from("users/email");

        fn derive<const N: usize>(
            key: &Protected<[u8; 32]>,
            version: AuthorityKeyVersion,
            salt: &[u8; SALT_LEN],
            binding: Binding<'_>,
        ) -> String {
            let key = derive_data_key::<N>(key, version, salt, binding);
            hex(key.risky_unwrap())
        }

        assert_eq!(
            derive::<32>(&authority_key, V1, &salt, email),
            "07d8cd3caa4ae196ec3a44c83071db7a8ad46f8d291fa2cce78caa5060c8b248"
        );
        assert_eq!(
            derive::<32>(&authority_key, V1, &salt, Binding::EMPTY),
            "53b1023e582deafa9c737e82cabb35a8d3e300dc0f6ac74f1a1144b818877c05"
        );
        assert_eq!(
            derive::<32>(&authority_key, V2, &salt, email),
            "3ed427e20193b3c58a1c28608d4dd61281c733be531775e06a23b24a74027542"
        );
        assert_eq!(
            derive::<16>(&authority_key, V1, &salt, email),
            "081d4dac89ad5d0bb587f5b9ad5a75fd"
        );
        assert_eq!(
            derive::<64>(&authority_key, V1, &salt, email),
            "17b1325a45d3e012f50fe0a1b34350dcde2d9cd3b573d797e6e9c415f46225d5\
             d975e716e6b19eae4fbdb22998c06d01c3e50c8eddf5b4446afc58047d07d61d"
        );
    }

    #[test]
    fn the_key_id_encoding_matches_the_known_answer_vector() {
        let salt: [u8; SALT_LEN] = std::array::from_fn(|i| 0xA0 + i as u8);
        let version = AuthorityKeyVersion::new(0x0102_0304);
        let key_id = encode_key_id(version, &salt);

        assert_eq!(
            key_id.as_bytes(),
            [
                0x01, 0x01, 0x02, 0x03, 0x04, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
                0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
            ]
        );
        assert_eq!(decode_key_id(&key_id), Some((version, salt)));
    }

    #[test]
    fn the_authority_binding_matches_the_known_answer_vector() {
        assert_eq!(
            authority_binding(AuthorityKeyVersion::new(0x0102_0304)).as_slice(),
            b"vitaminc-kms/authority-key/v1\x01\x02\x03\x04"
        );
    }

    /// Against LocalStack on `localhost:4566` — see the crate README for
    /// how to bring it up.
    #[cfg(feature = "aws")]
    mod localstack {
        use super::*;
        use crate::aws::testing::{encrypt_decrypt_key, localstack_client};
        use crate::aws::AwsDataKeySource;

        #[tokio::test]
        async fn authority_keys_round_trip_through_aws_kms() {
            let client = localstack_client();
            let key_id = encrypt_decrypt_key(&client).await;
            let aws = AwsDataKeySource::<32>::new(client, key_id);

            let wrapped = AuthorityKeySource::provision(&aws, V1).await.unwrap();
            let keys = AuthorityKeys::new(V1, [(V1, wrapped)]).unwrap();
            let source = AuthorityKeySource::new(aws, keys, policy(minute()));

            let bindings = [Binding::from("users/email"), Binding::from("users/age")];
            let generated: Vec<GeneratedDataKey<32>> =
                source.generate_keys(&bindings).await.unwrap();
            let requests: Vec<(KeyId, Binding<'_>)> = generated
                .iter()
                .zip(bindings)
                .map(|(key, binding)| (key.key_id.clone(), binding))
                .collect();
            let retrieved: Vec<Protected<[u8; 32]>> =
                source.retrieve_keys(&requests).await.unwrap();

            assert_eq!(bytes(&retrieved[0]), bytes(&generated[0].plaintext));
            assert_eq!(bytes(&retrieved[1]), bytes(&generated[1].plaintext));
            assert_ne!(bytes(&retrieved[0]), bytes(&retrieved[1]));

            // The wrong binding derives a different key, and AWS sees no
            // call for it at all.
            let wrong: Vec<Protected<[u8; 32]>> = source
                .retrieve_keys(&[(generated[0].key_id.clone(), Binding::from("users/age"))])
                .await
                .unwrap();
            assert_ne!(bytes(&wrong[0]), bytes(&generated[0].plaintext));
        }

        #[tokio::test]
        async fn aws_kms_refuses_the_authority_key_under_another_version() {
            let client = localstack_client();
            let key_id = encrypt_decrypt_key(&client).await;
            let aws = AwsDataKeySource::<32>::new(client, key_id);

            // The id minted for version 1, filed under version 2: AWS refuses
            // the unwrap, because the encryption context names the version.
            let wrapped = AuthorityKeySource::provision(&aws, V1).await.unwrap();
            let keys = AuthorityKeys::new(V2, [(V2, wrapped)]).unwrap();
            let source = AuthorityKeySource::new(aws, keys, policy(minute()));

            let result: Result<Vec<GeneratedDataKey<32>>, _> =
                source.generate_keys(&[Binding::EMPTY]).await;
            assert!(matches!(result, Err(AuthorityKeyError::Fetch(_))));
        }
    }
    /// RFC 5869, appendix A, test cases 1 to 3 (SHA-256). They check the
    /// HKDF here against the standard, apart from the known answers above.
    /// Case 2 expands to 82 bytes, so it covers more than one block. Case 3
    /// has an empty salt, which HMAC treats the same as `HashLen` zeros.
    #[test]
    fn hkdf_matches_the_rfc_5869_sha256_test_vectors() {
        fn hex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        let ikm_2: Vec<u8> = (0x00..=0x4f).collect();
        let salt_2: Vec<u8> = (0x60..=0xaf).collect();
        let info_2: Vec<u8> = (0xb0..=0xff).collect();
        struct Case {
            ikm: Vec<u8>,
            salt: Vec<u8>,
            info: Vec<u8>,
            prk: &'static str,
            okm: &'static str,
        }
        let cases = [
            Case {
                ikm: vec![0x0b; 22],
                salt: hex("000102030405060708090a0b0c"),
                info: hex("f0f1f2f3f4f5f6f7f8f9"),
                prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            },
            Case {
                ikm: ikm_2,
                salt: salt_2,
                info: info_2,
                prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
            },
            Case {
                ikm: vec![0x0b; 22],
                salt: Vec::new(),
                info: Vec::new(),
                prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            },
        ];
        for Case {
            ikm,
            salt,
            info,
            prk,
            okm,
        } in cases
        {
            let derived_prk = hkdf_extract(&salt, &ikm);
            assert_eq!(derived_prk.risky_ref().to_vec(), hex(prk));
            let mut derived_okm = vec![0u8; okm.len() / 2];
            // Split `info` in two, to check that its parts are concatenated.
            let (head, tail) = info.split_at(info.len() / 2);
            hkdf_expand(&derived_prk, &[head, tail], &mut derived_okm);
            assert_eq!(derived_okm, hex(okm));
        }
    }
}
