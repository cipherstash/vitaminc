use std::{
    any::Any,
    borrow::Cow,
    convert::Infallible,
    future::{ready, IntoFuture, Ready},
    sync::Arc,
};

use sha2::{Digest, Sha256};
use vitaminc_protected::{Controlled, Protected};

use crate::visitor::ResolvedVisitor;
use crate::{
    traits::apply_visitor, MapPrf, Prf, PrfBuildError, PrfContext, PrfEncoding, PrfError, PrfValue,
    PrfVisitor, ResolvedPrf, SeqPrf,
};

type PassthroughValue = Box<dyn Any + Send + 'static>;
const SHA256_BLOCK_SIZE: usize = 64;
const HMAC_IPAD: u8 = 0x36;
const HMAC_OPAD: u8 = 0x5c;

/// An immediately available, awaitable PRF result.
#[must_use = "PRF output does nothing until it is awaited or inspected"]
pub struct ReadyPrf<T, E> {
    result: Result<T, PrfError<E>>,
}

impl<T, E> ReadyPrf<T, E> {
    pub fn new(result: Result<T, PrfError<E>>) -> Self {
        Self { result }
    }

    pub fn into_result(self) -> Result<T, PrfError<E>> {
        self.result
    }
}

impl<T, E> IntoFuture for ReadyPrf<T, E> {
    type Output = Result<T, PrfError<E>>;
    type IntoFuture = Ready<Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        ready(self.result)
    }
}

/// Local HMAC-SHA256 structured PRF.
///
/// The key remains in a [`Protected`] allocation shared by nested drivers.
/// Each leaf derives `HMAC-SHA256(key, PAE(encoding, context, input))`.
#[derive(Clone)]
pub struct HmacSha256Prf {
    key: Arc<Protected<Vec<u8>>>,
}

impl HmacSha256Prf {
    pub fn new(key: Protected<Vec<u8>>) -> Self {
        Self { key: Arc::new(key) }
    }

    pub fn from_key_array<const N: usize>(key: Protected<[u8; N]>) -> Self {
        Self::new(Protected::new(key.risky_ref().to_vec()))
    }

    fn derive(
        &self,
        data: &Protected<Vec<u8>>,
        encoding: PrfEncoding,
        context: &PrfContext<'_>,
    ) -> [u8; 32] {
        let mut key_block = Protected::new([0_u8; SHA256_BLOCK_SIZE]);
        if self.key.risky_ref().len() <= SHA256_BLOCK_SIZE {
            key_block.risky_inner_mut()[..self.key.risky_ref().len()]
                .copy_from_slice(self.key.risky_ref());
        } else {
            let mut hasher = Sha256::new();
            hasher.update(self.key.risky_ref());
            let mut hashed_key = Protected::new([0_u8; 32]);
            hasher.finalize_into(hashed_key.risky_inner_mut().into());
            key_block.risky_inner_mut()[..hashed_key.risky_ref().len()]
                .copy_from_slice(hashed_key.risky_ref());
        }

        for byte in key_block.risky_inner_mut() {
            *byte ^= HMAC_IPAD;
        }

        let mut inner = Sha256::new();
        inner.update(key_block.risky_ref());

        // Stream PAE directly into the digest. Building a framed Vec here would
        // create an ordinary, unwiped copy of the protected input.
        let pieces = [encoding.as_bytes(), context.as_bytes(), data.risky_ref()];
        inner.update((pieces.len() as u64).to_le_bytes());
        for piece in pieces {
            inner.update((piece.len() as u64).to_le_bytes());
            inner.update(piece);
        }
        let mut inner_hash = Protected::new([0_u8; 32]);
        inner.finalize_into(inner_hash.risky_inner_mut().into());

        for byte in key_block.risky_inner_mut() {
            *byte ^= HMAC_IPAD ^ HMAC_OPAD;
        }

        let mut outer = Sha256::new();
        outer.update(key_block.risky_ref());
        outer.update(inner_hash.risky_ref());
        let mut block = [0_u8; 32];
        outer.finalize_into((&mut block).into());
        block
    }

    fn resolved<T: Send + 'static>(
        result: Result<T, PrfError<Infallible>>,
    ) -> ReadyPrf<T, Infallible> {
        ReadyPrf::new(result)
    }
}

impl Prf for HmacSha256Prf {
    type Block = [u8; 32];
    type BackendError = Infallible;
    type Passthrough = PassthroughValue;
    type SeqPrf = HmacSeqPrf;
    type MapPrf = HmacMapPrf;
    type Ok<T>
        = ReadyPrf<T, Infallible>
    where
        T: Send + 'static;

    fn prf_bytes_vec<V>(
        self,
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

    fn prf_seq(self, size_hint: Option<usize>) -> Self::SeqPrf {
        HmacSeqPrf {
            backend: self,
            values: Vec::with_capacity(size_hint.unwrap_or(0)),
            error: None,
        }
    }

    fn prf_map(self, size_hint: Option<usize>) -> Self::MapPrf {
        HmacMapPrf {
            backend: self,
            entries: Vec::with_capacity(size_hint.unwrap_or(0)),
            pending_key: None,
            error: None,
        }
    }

    fn prf_none<V>(self, _context: PrfContext<'static>, visitor: V) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        Self::resolved(visitor.visit_absent().map_err(PrfError::Visitor))
    }

    fn passthrough<V>(self, value: Self::Passthrough, visitor: V) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        Self::resolved(visitor.visit_passthrough(value).map_err(PrfError::Visitor))
    }

    fn passthrough_boxed<V>(
        self,
        value: Box<dyn Any + Send + 'static>,
        visitor: V,
    ) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        self.passthrough(value, visitor)
    }

    fn failure<T>(self, error: PrfError<Self::BackendError>) -> Self::Ok<T>
    where
        T: Send + 'static,
    {
        Self::resolved(Err(error))
    }
}

pub struct HmacSeqPrf {
    backend: HmacSha256Prf,
    values: Vec<ResolvedPrf<[u8; 32], PassthroughValue>>,
    error: Option<PrfError<Infallible>>,
}

impl SeqPrf for HmacSeqPrf {
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
                .prf_visit_with_context(self.backend.clone(), context, ResolvedVisitor)
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
            apply_visitor(ResolvedPrf::Sequence(self.values), visitor).map_err(PrfError::Visitor),
        )
    }
}

pub struct HmacMapPrf {
    backend: HmacSha256Prf,
    entries: Vec<(String, ResolvedPrf<[u8; 32], PassthroughValue>)>,
    pending_key: Option<String>,
    error: Option<PrfError<Infallible>>,
}

impl HmacMapPrf {
    fn set_build_error(&mut self, error: PrfBuildError) {
        if self.error.is_none() {
            self.error = Some(PrfError::Build(error));
        }
    }
}

impl MapPrf for HmacMapPrf {
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
        let entry_context = context.for_map_entry(&key);
        match value
            .prf_visit_with_context(self.backend.clone(), entry_context, ResolvedVisitor)
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
            self.entries
                .push((key.into().into_owned(), ResolvedPrf::Passthrough(value)));
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
            apply_visitor(ResolvedPrf::Map(self.entries), visitor).map_err(PrfError::Visitor),
        )
    }
}

#[cfg(test)]
mod tests {
    use sha2::Sha256;
    use zeroize::ZeroizeOnDrop;

    #[test]
    fn sha256_state_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Sha256>();
    }
}
