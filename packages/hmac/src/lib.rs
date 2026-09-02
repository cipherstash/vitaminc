#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use std::{any::Any, borrow::Cow, convert::Infallible};

use hmac::{
    digest::{
        common::{Key, KeySizeUser},
        FixedOutput, KeyInit, Output, OutputSizeUser, Update,
    },
    Hmac,
};
use sha2::Sha256;
use vitaminc_protected::{Acceptable, Controlled, DefaultScope, Protected, ProtectedDigest};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use vitaminc_prf::{
    MapPrf, Prf, PrfBuildError, PrfContext, PrfEncoding, PrfError, PrfKeyInit, PrfValue,
    PrfVisitor, ReadyPrf, ResolvedPrf, ResolvedVisitor, SeqPrf,
};

type PassthroughValue = Box<dyn Any + Send + 'static>;

const SHA256_BLOCK_SIZE: usize = 64;
const SHA256_OUTPUT_SIZE: usize = 32;
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

/// Length of the key accepted by [`HmacSha256Prf::new`].
pub const KEY_LEN: usize = 32;

/// Shortest key accepted by [`HmacSha256Prf::try_from_bytes`].
pub const MIN_KEY_LEN: usize = KEY_LEN;

/// Key material offered to [`HmacSha256Prf::try_from_bytes`] was too short to
/// key the PRF safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeakKeyError {
    len: usize,
}

impl WeakKeyError {
    /// Length of the rejected key, in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the rejected key was empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl std::fmt::Display for WeakKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HMAC-SHA256 PRF key must be at least {MIN_KEY_LEN} bytes, got {}",
            self.len
        )
    }
}

impl std::error::Error for WeakKeyError {}

/// HMAC-SHA256 keyed without leaving unwiped copies of key material.
///
/// RustCrypto's `Hmac` state wipes on drop when the `hmac` and `sha2`
/// `zeroize` features are enabled, but its constructor normalizes the key
/// through temporaries that are never wiped: `get_der_key`'s padded block and
/// the ipad/opad buffer in `new_from_slice`. This type performs the same
/// RFC 2104 keying with every key-derived buffer held in a [`Zeroizing`]
/// allocation; the two digest states wipe themselves on drop via `sha2`'s
/// `zeroize` feature.
struct ZeroizingHmacSha256 {
    /// Inner hash, initialized with `key ^ ipad`.
    digest: Sha256,
    /// Outer hash, initialized with `key ^ opad`.
    opad_digest: Sha256,
}

impl KeySizeUser for ZeroizingHmacSha256 {
    type KeySize = <Hmac<Sha256> as KeySizeUser>::KeySize;
}

impl KeyInit for ZeroizingHmacSha256 {
    fn new(key: &Key<Self>) -> Self {
        Self::new_from_slice(key.as_slice()).expect("HMAC-SHA256 accepts keys of any length")
    }

    fn new_from_slice(key: &[u8]) -> Result<Self, hmac::digest::InvalidLength> {
        let mut block = Zeroizing::new([0_u8; SHA256_BLOCK_SIZE]);
        if key.len() <= SHA256_BLOCK_SIZE {
            block[..key.len()].copy_from_slice(key);
        } else {
            let mut hashed = Zeroizing::new([0_u8; SHA256_OUTPUT_SIZE]);
            let mut hasher = Sha256::default();
            Update::update(&mut hasher, key);
            FixedOutput::finalize_into(hasher, (&mut *hashed).into());
            block[..hashed.len()].copy_from_slice(hashed.as_slice());
        }

        block.iter_mut().for_each(|byte| *byte ^= IPAD);
        let mut digest = Sha256::default();
        Update::update(&mut digest, block.as_slice());

        block.iter_mut().for_each(|byte| *byte ^= IPAD ^ OPAD);
        let mut opad_digest = Sha256::default();
        Update::update(&mut opad_digest, block.as_slice());

        Ok(Self {
            digest,
            opad_digest,
        })
    }
}

impl OutputSizeUser for ZeroizingHmacSha256 {
    type OutputSize = <Hmac<Sha256> as OutputSizeUser>::OutputSize;
}

impl Update for ZeroizingHmacSha256 {
    fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.digest, data);
    }
}

impl FixedOutput for ZeroizingHmacSha256 {
    fn finalize_into(self, out: &mut Output<Self>) {
        let Self {
            digest,
            mut opad_digest,
        } = self;
        // The inner hash permits forgeries if disclosed, so it is buffered in
        // a wiped allocation.
        let mut inner = Zeroizing::new([0_u8; SHA256_OUTPUT_SIZE]);
        FixedOutput::finalize_into(digest, (&mut *inner).into());
        Update::update(&mut opad_digest, inner.as_slice());
        FixedOutput::finalize_into(opad_digest, out);
    }
}

impl ZeroizeOnDrop for ZeroizingHmacSha256 {}

/// Local HMAC-SHA256 structured PRF.
///
/// The PRF owns its key outright. Construction takes the key by value, the
/// key lives in a single [`Protected`] allocation for the life of the PRF,
/// and it is wiped when the PRF drops, unconditionally. There is no `Clone`:
/// a shared handle would make that wipe depend on whichever clone happens to
/// drop last, which no call site can see. Derivation borrows the PRF
/// (`&self`), so one instance serves any number of derivations.
///
/// Each leaf derives `HMAC-SHA256(key, PAE(encoding, context, input))`.
pub struct HmacSha256Prf {
    key: Protected<Vec<u8>>,
}

// The only field is `Protected`, which wipes on drop; there is no other copy
// of the key to leave behind. `ZeroizingHmacSha256` covers the expanded
// ipad/opad state each derivation builds from it.
impl ZeroizeOnDrop for HmacSha256Prf {}

impl HmacSha256Prf {
    /// Key the PRF with a full-strength key.
    ///
    /// The array type carries the length guarantee, so this cannot fail.
    pub fn new(key: Protected<[u8; KEY_LEN]>) -> Self {
        // `risky_ref` + drop, not `map`: `map` moves the array out through
        // `risky_unwrap`, and a bare `[u8; 32]` has no destructor to wipe it.
        // Borrowing leaves the array inside its `Protected`, which wipes it
        // when `key` drops at the end of this call.
        Self::from_vec(Protected::new(key.risky_ref().to_vec()))
    }

    /// Key the PRF with key material whose length is only known at runtime,
    /// such as a KMS response or an environment variable.
    ///
    /// # Errors
    ///
    /// Returns [`WeakKeyError`] if the key is shorter than [`MIN_KEY_LEN`].
    /// HMAC itself accepts any key length, including an empty one, which
    /// would silently produce derivations that anybody can recompute.
    pub fn try_from_bytes(key: Protected<Vec<u8>>) -> Result<Self, WeakKeyError> {
        let len = key.risky_ref().len();
        if len < MIN_KEY_LEN {
            return Err(WeakKeyError { len });
        }
        Ok(Self::from_vec(key))
    }

    fn from_vec(key: Protected<Vec<u8>>) -> Self {
        Self { key }
    }

    fn derive<T>(&self, data: &T, encoding: PrfEncoding, context: &PrfContext<'_>) -> [u8; 32]
    where
        T: Controlled + Acceptable<DefaultScope>,
        T::Inner: AsRef<[u8]>,
    {
        let mut hmac: ProtectedDigest<ZeroizingHmacSha256> =
            ProtectedDigest::new_with_key(&self.key)
                .expect("HMAC-SHA256 accepts keys of any length");

        // Stream PAE directly into the digest. Building a framed Vec here would
        // create an ordinary, unwiped copy of the protected input.
        hmac.update_public(&3_u64.to_le_bytes());
        hmac.update_public(&(encoding.as_bytes().len() as u64).to_le_bytes());
        hmac.update_public(encoding.as_bytes());
        hmac.update_public(&(context.as_bytes().len() as u64).to_le_bytes());
        hmac.update_public(context.as_bytes());
        hmac.update_public(&(data.risky_ref().as_ref().len() as u64).to_le_bytes());
        hmac.update(data);

        let mut block = [0_u8; 32];
        hmac.finalize_public_into(&mut block);
        block
    }

    fn resolved<T: Send + 'static>(
        result: Result<T, PrfError<Infallible>>,
    ) -> ReadyPrf<T, Infallible> {
        ReadyPrf::new(result)
    }
}

impl PrfKeyInit for HmacSha256Prf {
    type Key = Protected<[u8; KEY_LEN]>;
    type KeyError = WeakKeyError;

    fn new(key: Self::Key) -> Self {
        HmacSha256Prf::new(key)
    }

    fn try_from_bytes(key: Protected<Vec<u8>>) -> Result<Self, Self::KeyError> {
        HmacSha256Prf::try_from_bytes(key)
    }
}

impl Prf for HmacSha256Prf {
    type Block = [u8; 32];
    type BackendError = Infallible;
    type Passthrough = PassthroughValue;
    type SeqPrf<'a> = HmacSeqPrf<'a>;
    type MapPrf<'a> = HmacMapPrf<'a>;
    type Ok<T>
        = ReadyPrf<T, Infallible>
    where
        T: Send + 'static;

    fn prf_bytes_vec<V>(
        &self,
        data: Protected<Vec<u8>>,
        encoding: PrfEncoding,
        context: PrfContext<'static>,
        visitor: V,
    ) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        let block = self.derive(&data, encoding, &context);
        Self::resolved(visitor.visit_block(block).map_err(PrfError::Visitor))
    }

    // Overrides the Vec-copying default: fixed-size leaves stream into the
    // digest without an intermediate heap allocation.
    fn prf_bytes_array<const N: usize, V>(
        &self,
        data: Protected<[u8; N]>,
        encoding: PrfEncoding,
        context: PrfContext<'static>,
        visitor: V,
    ) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        let block = self.derive(&data, encoding, &context);
        Self::resolved(visitor.visit_block(block).map_err(PrfError::Visitor))
    }

    fn prf_seq(&self, size_hint: Option<usize>) -> Self::SeqPrf<'_> {
        HmacSeqPrf {
            backend: self,
            values: Vec::with_capacity(size_hint.unwrap_or(0)),
            error: None,
        }
    }

    fn prf_map(&self, size_hint: Option<usize>) -> Self::MapPrf<'_> {
        HmacMapPrf {
            backend: self,
            entries: Vec::with_capacity(size_hint.unwrap_or(0)),
            pending_key: None,
            error: None,
        }
    }

    fn prf_none<V>(&self, _context: PrfContext<'static>, visitor: V) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        Self::resolved(visitor.visit_absent().map_err(PrfError::Visitor))
    }

    fn passthrough<V>(&self, value: Self::Passthrough, visitor: V) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        Self::resolved(visitor.visit_passthrough(value).map_err(PrfError::Visitor))
    }

    fn passthrough_boxed<V>(
        &self,
        value: Box<dyn Any + Send + 'static>,
        visitor: V,
    ) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        self.passthrough(value, visitor)
    }

    fn failure<T>(&self, error: PrfError<Self::BackendError>) -> Self::Ok<T>
    where
        T: Send + 'static,
    {
        Self::resolved(Err(error))
    }
}

/// Sequence driver borrowing its [`HmacSha256Prf`] for one derivation.
pub struct HmacSeqPrf<'a> {
    backend: &'a HmacSha256Prf,
    values: Vec<ResolvedPrf<[u8; 32], PassthroughValue>>,
    error: Option<PrfError<Infallible>>,
}

impl SeqPrf for HmacSeqPrf<'_> {
    type Prf = HmacSha256Prf;
    type Block = [u8; 32];
    type BackendError = Infallible;
    type Passthrough = PassthroughValue;

    fn prf_next<T>(mut self, value: T, context: PrfContext<'static>) -> Self
    where
        T: PrfValue,
    {
        if self.error.is_none() {
            match value
                .prf_visit_with_context(self.backend, context, ResolvedVisitor)
                .into_result()
            {
                Ok(value) => self.values.push(value),
                Err(error) => self.error = Some(error),
            }
        }
        self
    }

    fn passthrough_next(mut self, value: Self::Passthrough) -> Self {
        if self.error.is_none() {
            self.values.push(ResolvedPrf::Passthrough(value));
        }
        self
    }

    fn passthrough_next_boxed(self, value: Box<dyn Any + Send + 'static>) -> Self {
        self.passthrough_next(value)
    }

    fn end<V>(self, visitor: V) -> <Self::Prf as Prf>::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        if let Some(error) = self.error {
            return self.backend.failure(error);
        }
        HmacSha256Prf::resolved(
            ResolvedPrf::Sequence(self.values)
                .visit(visitor)
                .map_err(PrfError::Visitor),
        )
    }
}

/// Map driver borrowing its [`HmacSha256Prf`] for one derivation.
pub struct HmacMapPrf<'a> {
    backend: &'a HmacSha256Prf,
    entries: Vec<(String, ResolvedPrf<[u8; 32], PassthroughValue>)>,
    pending_key: Option<String>,
    error: Option<PrfError<Infallible>>,
}

impl HmacMapPrf<'_> {
    fn set_build_error(&mut self, error: PrfBuildError) {
        if self.error.is_none() {
            self.error = Some(PrfError::Build(error));
        }
    }

    fn is_duplicate_key(&self, key: &str) -> bool {
        self.entries.iter().any(|(existing, _)| existing == key)
    }
}

impl MapPrf for HmacMapPrf<'_> {
    type Prf = HmacSha256Prf;
    type Block = [u8; 32];
    type BackendError = Infallible;
    type Passthrough = PassthroughValue;

    fn prf_key<K>(mut self, key: K) -> Self
    where
        K: Into<Cow<'static, str>>,
    {
        if self.pending_key.is_some() {
            self.set_build_error(PrfBuildError::KeyWithoutValue);
        } else if self.error.is_none() {
            self.pending_key = Some(key.into().into_owned());
        }
        self
    }

    fn prf_value<T>(mut self, value: T, context: PrfContext<'static>) -> Self
    where
        T: PrfValue,
    {
        let Some(key) = self.pending_key.take() else {
            self.set_build_error(PrfBuildError::ValueWithoutKey);
            return self;
        };
        if self.error.is_some() {
            return self;
        }
        if self.is_duplicate_key(&key) {
            self.set_build_error(PrfBuildError::DuplicateKey);
            return self;
        }
        let entry_context = context.for_map_entry(&key);
        match value
            .prf_visit_with_context(self.backend, entry_context, ResolvedVisitor)
            .into_result()
        {
            Ok(value) => self.entries.push((key, value)),
            Err(error) => self.error = Some(error),
        }
        self
    }

    fn passthrough_entry<K>(mut self, key: K, value: Self::Passthrough) -> Self
    where
        K: Into<Cow<'static, str>>,
    {
        if self.pending_key.is_some() {
            self.set_build_error(PrfBuildError::KeyWithoutValue);
        } else if self.error.is_none() {
            let key = key.into().into_owned();
            if self.is_duplicate_key(&key) {
                self.set_build_error(PrfBuildError::DuplicateKey);
            } else {
                self.entries.push((key, ResolvedPrf::Passthrough(value)));
            }
        }
        self
    }

    fn passthrough_entry_boxed<K>(self, key: K, value: Box<dyn Any + Send + 'static>) -> Self
    where
        K: Into<Cow<'static, str>>,
    {
        self.passthrough_entry(key, value)
    }

    fn end<V>(mut self, visitor: V) -> <Self::Prf as Prf>::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        if self.pending_key.is_some() {
            self.set_build_error(PrfBuildError::DanglingKey);
        }
        if let Some(error) = self.error {
            return self.backend.failure(error);
        }
        HmacSha256Prf::resolved(
            ResolvedPrf::Map(self.entries)
                .visit(visitor)
                .map_err(PrfError::Visitor),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::ZeroizingHmacSha256;
    use hmac::{
        digest::{FixedOutput, KeyInit, Update},
        Hmac, Mac,
    };
    use quickcheck_macros::quickcheck;
    use sha2::Sha256;
    use vitaminc_protected::ProtectedDigest;
    use zeroize::ZeroizeOnDrop;

    #[test]
    fn hmac_sha256_state_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<ProtectedDigest<ZeroizingHmacSha256>>();
        // The marker impl on ZeroizingHmacSha256 is honest only while its
        // digest states wipe themselves.
        assert_zeroize_on_drop::<Sha256>();
    }

    fn zeroizing_hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut hmac = ZeroizingHmacSha256::new_from_slice(key).unwrap();
        Update::update(&mut hmac, data);
        let mut out = [0_u8; 32];
        FixedOutput::finalize_into(hmac, (&mut out).into());
        out
    }

    #[quickcheck]
    fn matches_rustcrypto_hmac(key: Vec<u8>, data: Vec<u8>) -> bool {
        let reference = {
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
            Mac::update(&mut mac, &data);
            mac.finalize().into_bytes()
        };
        zeroizing_hmac(&key, &data).as_slice() == reference.as_slice()
    }

    #[test]
    fn matches_rustcrypto_hmac_at_key_normalization_boundaries() {
        // Exercises both branches of key normalization deterministically:
        // block-sized-or-smaller keys are padded, larger keys are hashed.
        for key_len in [0, 1, 63, 64, 65, 131] {
            let key = vec![0xaa_u8; key_len];
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
            Mac::update(&mut mac, b"boundary");
            assert_eq!(
                zeroizing_hmac(&key, b"boundary").as_slice(),
                mac.finalize().into_bytes().as_slice(),
                "key length {key_len}"
            );
        }
    }
}
