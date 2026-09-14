//! Deterministic, non-cryptographic backend proving the trait contract
//! stands alone. Blocks are SipHash mixes of the framed input, which is
//! enough for the unit tests' equality and separation assertions but has
//! no security properties.

use std::{
    any::Any,
    borrow::Cow,
    collections::hash_map::DefaultHasher,
    convert::Infallible,
    hash::{Hash, Hasher},
};

use vitaminc_protected::{Controlled, Protected};

use crate::{
    visitor::ResolvedVisitor, Context, MapPrf, Prf, PrfBuildError, PrfEncoding, PrfError, PrfValue,
    PrfVisitor, ReadyPrf, ResolvedPrf, SeqPrf,
};

type PassthroughValue = Box<dyn Any + Send + 'static>;

#[derive(Clone, Default)]
pub(crate) struct MockPrf;

impl MockPrf {
    fn derive(data: &[u8], encoding: PrfEncoding, context: &Context<'_>) -> [u8; 32] {
        let mut block = [0_u8; 32];
        for (index, chunk) in block.chunks_mut(8).enumerate() {
            let mut hasher = DefaultHasher::new();
            (index as u64).hash(&mut hasher);
            encoding.as_bytes().hash(&mut hasher);
            context.as_bytes().hash(&mut hasher);
            data.hash(&mut hasher);
            chunk.copy_from_slice(&hasher.finish().to_le_bytes());
        }
        block
    }

    fn resolved<T: Send + 'static>(
        result: Result<T, PrfError<Infallible>>,
    ) -> ReadyPrf<T, Infallible> {
        ReadyPrf::new(result)
    }
}

impl Prf for MockPrf {
    type Block = [u8; 32];
    type BackendError = Infallible;
    type Passthrough = PassthroughValue;
    type SeqPrf<'a> = MockSeqPrf<'a>;
    type MapPrf<'a> = MockMapPrf<'a>;
    type Ok<T>
        = ReadyPrf<T, Infallible>
    where
        T: Send + 'static;

    fn prf_bytes_vec<V>(
        &self,
        data: Protected<Vec<u8>>,
        encoding: PrfEncoding,
        context: Context<'static>,
        visitor: V,
    ) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        let block = Self::derive(data.risky_ref(), encoding, &context);
        Self::resolved(visitor.visit_block(block).map_err(PrfError::Visitor))
    }

    fn prf_bytes_array<const N: usize, V>(
        &self,
        data: Protected<[u8; N]>,
        encoding: PrfEncoding,
        context: Context<'static>,
        visitor: V,
    ) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        let block = Self::derive(data.risky_ref(), encoding, &context);
        Self::resolved(visitor.visit_block(block).map_err(PrfError::Visitor))
    }

    fn prf_seq(&self, size_hint: Option<usize>) -> Self::SeqPrf<'_> {
        MockSeqPrf {
            backend: self,
            values: Vec::with_capacity(size_hint.unwrap_or(0)),
            error: None,
        }
    }

    fn prf_map(&self, size_hint: Option<usize>) -> Self::MapPrf<'_> {
        MockMapPrf {
            backend: self,
            entries: Vec::with_capacity(size_hint.unwrap_or(0)),
            pending_key: None,
            error: None,
        }
    }

    fn prf_none<V>(&self, _context: Context<'static>, visitor: V) -> Self::Ok<V::Value>
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

pub(crate) struct MockSeqPrf<'a> {
    backend: &'a MockPrf,
    values: Vec<ResolvedPrf<[u8; 32], PassthroughValue>>,
    error: Option<PrfError<Infallible>>,
}

impl SeqPrf for MockSeqPrf<'_> {
    type Prf = MockPrf;
    type Block = [u8; 32];
    type BackendError = Infallible;
    type Passthrough = PassthroughValue;

    fn prf_next<T>(mut self, value: T, context: Context<'static>) -> Self
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
        MockPrf::resolved(
            ResolvedPrf::Sequence(self.values)
                .visit(visitor)
                .map_err(PrfError::Visitor),
        )
    }
}

pub(crate) struct MockMapPrf<'a> {
    backend: &'a MockPrf,
    entries: Vec<(String, ResolvedPrf<[u8; 32], PassthroughValue>)>,
    pending_key: Option<String>,
    error: Option<PrfError<Infallible>>,
}

impl MockMapPrf<'_> {
    fn set_build_error(&mut self, error: PrfBuildError) {
        if self.error.is_none() {
            self.error = Some(PrfError::Build(error));
        }
    }

    fn is_duplicate_key(&self, key: &str) -> bool {
        self.entries.iter().any(|(existing, _)| existing == key)
    }
}

impl MapPrf for MockMapPrf<'_> {
    type Prf = MockPrf;
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

    fn prf_value<T>(mut self, value: T, context: Context<'static>) -> Self
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
        MockPrf::resolved(
            ResolvedPrf::Map(self.entries)
                .visit(visitor)
                .map_err(PrfError::Visitor),
        )
    }
}
