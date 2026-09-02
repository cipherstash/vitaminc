use std::{any::Any, borrow::Cow, future::IntoFuture};

use vitaminc_protected::{Controlled, Protected};

use crate::BlockVisitor;
use crate::{IntoPrfContext, PrfContext, PrfEncoding, PrfError, PrfVisitor};

/// A type that can describe its structure to a [`Prf`] backend.
///
/// The caller supplies a visitor because PRF output is policy-neutral: the
/// same resolved block can become an equality term, Bloom positions, or an
/// application-specific record.
///
/// Every entry point borrows the backend. A derivation is a pure function of
/// the key and the input, so nothing is consumed; one backend instance serves
/// any number of derivations without being cloned.
pub trait PrfValue {
    /// Derive one raw backend block with no context.
    fn prf<P>(self, prf: &P) -> P::Ok<P::Block>
    where
        Self: Sized,
        P: Prf,
    {
        self.prf_visit(prf, BlockVisitor)
    }

    /// Derive a structured result with no context and interpret it with
    /// `visitor`.
    fn prf_visit<P, V>(self, prf: &P, visitor: V) -> P::Ok<V::Value>
    where
        Self: Sized,
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
    {
        self.prf_visit_with_context(prf, PrfContext::empty(), visitor)
    }

    /// Derive one raw backend block under `context`.
    fn prf_with_context<'a, P, C>(self, prf: &P, context: C) -> P::Ok<P::Block>
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
    fn prf_visit_with_context<'a, P, V, C>(
        self,
        prf: &P,
        context: C,
        visitor: V,
    ) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>;
}

/// Construction of a [`Prf`] backend from key material.
///
/// This is the one place the key changes hands. Both constructors take the
/// key **by value**, so the material moves into the backend rather than being
/// copied at the boundary, and the backend owns it for the rest of its life:
/// when the backend drops, the key is wiped. Backends must not hand out
/// shared handles to the key (for example behind an `Arc`), because that
/// turns "wiped when this backend drops" into "wiped when the last
/// outstanding handle drops", which no call site can see.
///
/// The shape mirrors RustCrypto's `KeyInit`, with the deliberate difference
/// that the key is owned rather than borrowed and copied in.
pub trait PrfKeyInit: Sized {
    /// Fixed-size key type whose length is guaranteed by construction, so
    /// [`new`](PrfKeyInit::new) cannot fail. Always a controlled type; a
    /// bare array cannot key a backend.
    type Key: Controlled;

    /// Reason [`try_from_bytes`](PrfKeyInit::try_from_bytes) can reject key
    /// material, typically because it is too short.
    type KeyError: std::error::Error + Send + Sync + 'static;

    /// Key the backend with a full-strength key of the statically known
    /// length.
    fn new(key: Self::Key) -> Self;

    /// Key the backend with material whose length is only known at runtime,
    /// such as a KMS response or an environment variable.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError`](PrfKeyInit::KeyError) if the material is not
    /// acceptable as a key.
    fn try_from_bytes(key: Protected<Vec<u8>>) -> Result<Self, Self::KeyError>;
}

/// Backend for structured pseudorandom derivation.
///
/// Every method borrows the backend. The structural drivers returned by
/// [`prf_seq`](Prf::prf_seq) and [`prf_map`](Prf::prf_map) borrow it for the
/// length of one derivation, which is why they carry a lifetime. Results do
/// not: [`Ok`](Prf::Ok) has no lifetime parameter, so no borrow of the backend
/// can escape into an awaitable output.
pub trait Prf: Sized {
    type Block: Send + 'static;
    type BackendError: std::error::Error + Send + Sync + 'static;
    type Passthrough: Send + 'static;

    /// Driver for sequence-shaped values, borrowing the backend for one
    /// derivation.
    type SeqPrf<'a>: SeqPrf<
        Prf = Self,
        Block = Self::Block,
        BackendError = Self::BackendError,
        Passthrough = Self::Passthrough,
    >
    where
        Self: 'a;

    /// Driver for map-shaped values, borrowing the backend for one
    /// derivation.
    type MapPrf<'a>: MapPrf<
        Prf = Self,
        Block = Self::Block,
        BackendError = Self::BackendError,
        Passthrough = Self::Passthrough,
    >
    where
        Self: 'a;

    /// Awaitable output. It carries no lifetime, so it must own everything it
    /// needs to resolve; a deferred backend that resolves later must hold its
    /// own key material rather than borrow this backend's.
    type Ok<T>: IntoFuture<Output = Result<T, PrfError<Self::BackendError>>>
    where
        T: Send + 'static;

    /// Derive a protected byte vector in an explicit semantic `encoding`
    /// domain. Backends must bind the encoding, context, and input with
    /// prefix-free framing.
    fn prf_bytes_vec<V>(
        &self,
        data: Protected<Vec<u8>>,
        encoding: PrfEncoding,
        context: PrfContext<'static>,
        visitor: V,
    ) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>;

    /// Fixed-array counterpart to [`prf_bytes_vec`](Prf::prf_bytes_vec).
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
        self.prf_bytes_vec(
            Protected::new(data.risky_ref().to_vec()),
            encoding,
            context,
            visitor,
        )
    }

    fn prf_seq(&self, size_hint: Option<usize>) -> Self::SeqPrf<'_>;
    fn prf_map(&self, size_hint: Option<usize>) -> Self::MapPrf<'_>;

    fn prf_some<T, V>(
        &self,
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

    fn prf_none<V>(&self, context: PrfContext<'static>, visitor: V) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>;

    /// Explicit, non-secret output channel. The value is not processed by the
    /// PRF and must never contain secret material.
    fn passthrough<V>(&self, value: Self::Passthrough, visitor: V) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>;

    /// Type-erased passthrough for generic [`PrfValue`] implementations.
    fn passthrough_boxed<V>(
        &self,
        value: Box<dyn Any + Send + 'static>,
        visitor: V,
    ) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>;

    /// Construct an already-failed deferred output. This lets structural
    /// drivers preserve the uniform awaitable return type.
    fn failure<T>(&self, error: PrfError<Self::BackendError>) -> Self::Ok<T>
    where
        T: Send + 'static;
}

/// Sequence driver. A driver is owned by one caller for the length of one
/// derivation, so its builder methods consume and return `Self`; it borrows
/// the backend it was created from.
pub trait SeqPrf: Sized {
    type Prf: Prf<
        Block = Self::Block,
        BackendError = Self::BackendError,
        Passthrough = Self::Passthrough,
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

/// Map driver. See [`SeqPrf`] for the ownership convention.
pub trait MapPrf: Sized {
    type Prf: Prf<
        Block = Self::Block,
        BackendError = Self::BackendError,
        Passthrough = Self::Passthrough,
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
