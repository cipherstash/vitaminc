use std::{any::Any, borrow::Cow, future::IntoFuture};

use vitaminc_protected::{Controlled, Protected};

use crate::BlockVisitor;
use crate::{IntoPrfContext, PrfContext, PrfError, PrfVisitor, PrfVisitorError, ResolvedPrf};

/// A type that can describe its structure to a [`Prf`] backend.
///
/// The caller supplies a visitor because PRF output is policy-neutral: the
/// same resolved block can become an equality term, Bloom positions, or an
/// application-specific record.
pub trait PrfValue {
    /// Derive one raw backend block with no context.
    fn prf<P>(self, prf: P) -> P::Ok<P::Block>
    where
        Self: Sized,
        P: Prf,
    {
        self.prf_visit(prf, BlockVisitor)
    }

    /// Derive a structured result with no context and interpret it with
    /// `visitor`.
    fn prf_visit<P, V>(self, prf: P, visitor: V) -> P::Ok<V::Value>
    where
        Self: Sized,
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
    {
        self.prf_visit_with_context(prf, PrfContext::empty(), visitor)
    }

    /// Derive one raw backend block under `context`.
    fn prf_with_context<'a, P, C>(self, prf: P, context: C) -> P::Ok<P::Block>
    where
        Self: Sized,
        P: Prf,
        C: IntoPrfContext<'a>,
    {
        self.prf_visit_with_context(prf, context, BlockVisitor)
    }

    /// Derive a structured result under `context` and interpret it with
    /// `visitor`. Implementations provide this method; the other entry points
    /// are conveniences built on it.
    fn prf_visit_with_context<'a, P, V, C>(self, prf: P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>;
}

/// Backend for structured pseudorandom derivation.
pub trait Prf: Sized {
    type Block: Send + 'static;
    type BackendError: std::error::Error + Send + Sync + 'static;
    type Passthrough: Send + 'static;
    type SeqPrf: SeqPrf<
        Prf = Self,
        Block = Self::Block,
        BackendError = Self::BackendError,
        Passthrough = Self::Passthrough,
    >;
    type MapPrf: MapPrf<
        Prf = Self,
        Block = Self::Block,
        BackendError = Self::BackendError,
        Passthrough = Self::Passthrough,
    >;

    type Ok<T>: IntoFuture<Output = Result<T, PrfError<Self::BackendError>>>
    where
        T: Send + 'static;

    fn prf_bytes_vec<V>(
        self,
        data: Protected<Vec<u8>>,
        context: PrfContext<'static>,
        visitor: V,
    ) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>;

    fn prf_bytes_array<const N: usize, V>(
        self,
        data: Protected<[u8; N]>,
        context: PrfContext<'static>,
        visitor: V,
    ) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        self.prf_bytes_vec(Protected::new(data.risky_ref().to_vec()), context, visitor)
    }

    fn prf_seq(self, size_hint: Option<usize>) -> Self::SeqPrf;
    fn prf_map(self, size_hint: Option<usize>) -> Self::MapPrf;

    fn prf_some<T, V>(
        self,
        value: T,
        context: PrfContext<'static>,
        visitor: V,
    ) -> Self::Ok<V::Value>
    where
        T: PrfValue,
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        value.prf_visit_with_context(self, context, visitor)
    }

    fn prf_none<V>(self, context: PrfContext<'static>, visitor: V) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>;

    /// Explicit, non-secret output channel. The value is not processed by the
    /// PRF and must never contain secret material.
    fn passthrough<V>(self, value: Self::Passthrough, visitor: V) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>;

    /// Type-erased passthrough for generic [`PrfValue`] implementations.
    fn passthrough_boxed<V>(
        self,
        value: Box<dyn Any + Send + 'static>,
        visitor: V,
    ) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>;

    /// Construct an already-failed deferred output. This lets structural
    /// drivers preserve the uniform awaitable return type.
    fn failure<T>(self, error: PrfError<Self::BackendError>) -> Self::Ok<T>
    where
        T: Send + 'static;
}

pub trait SeqPrf: Sized {
    type Prf: Prf<
        Block = Self::Block,
        BackendError = Self::BackendError,
        Passthrough = Self::Passthrough,
        SeqPrf = Self,
    >;
    type Block: Send + 'static;
    type BackendError: std::error::Error + Send + Sync + 'static;
    type Passthrough: Send + 'static;

    /// Sequence positions deliberately do not refine `context`. Equal values
    /// in one equality-search domain therefore derive equal terms.
    fn prf_next<T>(self, value: T, context: PrfContext<'static>) -> Self
    where
        T: PrfValue;

    fn passthrough_next(self, value: Self::Passthrough) -> Self;
    fn passthrough_next_boxed(self, value: Box<dyn Any + Send + 'static>) -> Self;

    fn end<V>(self, visitor: V) -> <Self::Prf as Prf>::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>;
}

pub trait MapPrf: Sized {
    type Prf: Prf<
        Block = Self::Block,
        BackendError = Self::BackendError,
        Passthrough = Self::Passthrough,
        MapPrf = Self,
    >;
    type Block: Send + 'static;
    type BackendError: std::error::Error + Send + Sync + 'static;
    type Passthrough: Send + 'static;

    fn prf_key<K>(self, key: K) -> Self
    where
        K: Into<Cow<'static, str>>;

    /// Implementations automatically refine the supplied context with the
    /// pending map key using `vitaminc/prf/map-entry/v1`.
    fn prf_value<T>(self, value: T, context: PrfContext<'static>) -> Self
    where
        T: PrfValue;

    fn prf_entry<K, T>(self, key: K, value: T, context: PrfContext<'static>) -> Self
    where
        K: Into<Cow<'static, str>>,
        T: PrfValue,
    {
        self.prf_key(key).prf_value(value, context)
    }

    fn passthrough_entry<K>(self, key: K, value: Self::Passthrough) -> Self
    where
        K: Into<Cow<'static, str>>;

    fn passthrough_entry_boxed<K>(self, key: K, value: Box<dyn Any + Send + 'static>) -> Self
    where
        K: Into<Cow<'static, str>>;

    fn end<V>(self, visitor: V) -> <Self::Prf as Prf>::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>;
}

/// Helper for backend implementations to apply a visitor to a resolved node.
pub(crate) fn apply_visitor<Block, Passthrough, V>(
    node: ResolvedPrf<Block, Passthrough>,
    visitor: V,
) -> Result<V::Value, PrfVisitorError>
where
    V: PrfVisitor<Block, Passthrough>,
{
    node.visit(visitor)
}
