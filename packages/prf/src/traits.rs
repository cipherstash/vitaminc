use std::{any::Any, borrow::Cow, future::IntoFuture};

use vitaminc_protected::{Controlled, Protected};

use crate::BlockVisitor;
use crate::{Context, IntoPrfContext, PrfEncoding, PrfError, PrfVisitor};

/// A type that can describe its structure to a [`Prf`] backend.
///
/// The caller supplies a visitor because PRF output is policy-neutral: the
/// same resolved block can become an equality term, Bloom positions, or an
/// application-specific record.
///
/// Every entry point borrows the backend. A derivation is a pure function of
/// the key and the input; one backend instance serves any number of derivations
/// without being cloned. The input value and visitor are consumed.
///
/// Failures are reported through the backend's awaitable [`Prf::Ok`], including
/// local construction errors, backend failures, and visitor shape mismatches.
/// `prf` and `prf_with_context` use [`BlockVisitor`], so a sequence, map, absent
/// value, or passthrough needs a different visitor to succeed.
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
        self.prf_visit_with_context(prf, Context::empty(), visitor)
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
///
/// [`Prf`] is a supertrait, so `P: PrfKeyInit` alone says "a PRF I can
/// build from a key"; generic code does not need to spell out `P: Prf` as
/// well.
pub trait PrfKeyInit: Prf {
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
///
/// # Implementer contract
///
/// For a fixed key, encoding, context, and leaf bytes, derivation must be
/// deterministic. Container drivers preserve insertion order and report local
/// structural failures through their final output. They must not deliver a
/// successful partial result after a child fails. Visitors run on resolved
/// nodes and their failures become [`PrfError::Visitor`].
///
/// Execution may be eager (as in [`crate::ReadyPrf`]) or deferred. Dropping an
/// output does not undo eager work or necessarily cancel remote work. A deferred
/// backend must document when work begins, cleanup, and retry behavior; this
/// trait provides no transaction or exactly-once guarantee.
pub trait Prf: Sized {
    /// Owned pseudorandom output for one leaf, independent of the input lifetime.
    type Block: Send + 'static;
    /// Backend execution failure, carried by [`PrfError::Backend`].
    type BackendError: std::error::Error + Send + Sync + 'static;
    /// Owned representation of explicit non-secret passthrough values.
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
    /// The owned plaintext must remain protected or be wiped after processing,
    /// including on error. Resolve the block through `visitor`; report backend
    /// and visitor failures through [`PrfError`] in the returned awaitable.
    fn prf_bytes_vec<V>(
        &self,
        data: Protected<Vec<u8>>,
        encoding: PrfEncoding,
        context: Context<'static>,
        visitor: V,
    ) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>;

    /// Fixed-array counterpart to [`prf_bytes_vec`](Prf::prf_bytes_vec).
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
        self.prf_bytes_vec(
            Protected::new(data.risky_ref().to_vec()),
            encoding,
            context,
            visitor,
        )
    }

    /// Start a sequence in insertion order. `size_hint` is an allocation hint,
    /// not a required count; `None` means the length is unknown.
    fn prf_seq(&self, size_hint: Option<usize>) -> Self::SeqPrf<'_>;
    /// Start a map with distinct string keys, preserving insertion order.
    /// `size_hint` is an allocation hint, not a required count.
    fn prf_map(&self, size_hint: Option<usize>) -> Self::MapPrf<'_>;

    /// Derive a present optional value. The default forwards it with the same
    /// context and visitor, so `Some(value)` shares `value`'s derivation.
    fn prf_some<T, V>(&self, value: T, context: Context<'static>, visitor: V) -> Self::Ok<V::Value>
    where
        T: PrfValue,
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        value.prf_visit_with_context(self, context, visitor)
    }

    /// Resolve an absent value through [`PrfVisitor::visit_absent`]. Absence
    /// is structural, not a pseudorandom block; [`BlockVisitor`] refuses it.
    fn prf_none<V>(&self, context: Context<'static>, visitor: V) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>;

    /// Explicit, non-secret output channel. The value is not processed by the
    /// PRF and must never contain secret material.
    fn passthrough<V>(&self, value: Self::Passthrough, visitor: V) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>;

    /// Type-erased passthrough for generic [`PrfValue`] implementations.
    /// The value must be non-secret. If the backend cannot represent its type,
    /// report [`crate::PrfBuildError::InvalidPassthrough`] through the output.
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
/// Errors are retained by the driver and surfaced by [`end`](Self::end).
/// Dropping a driver abandons its result; it need not undo eager backend work.
pub trait SeqPrf: Sized {
    /// Backend that owns the key and supplies this driver's output type.
    type Prf: Prf<
        Block = Self::Block,
        BackendError = Self::BackendError,
        Passthrough = Self::Passthrough,
    >;
    /// Owned pseudorandom output for one leaf, independent of the input lifetime.
    type Block: Send + 'static;
    /// Backend execution failure, carried by [`PrfError::Backend`].
    type BackendError: std::error::Error + Send + Sync + 'static;
    /// Owned representation of explicit non-secret passthrough values.
    type Passthrough: Send + 'static;

    /// Sequence positions deliberately do not refine `context`. Equal values
    /// in one equality-search domain therefore derive equal terms.
    fn prf_next<T>(self, value: T, context: Context<'static>) -> Self
    where
        T: PrfValue;

    /// Append a non-secret child without cryptographic processing.
    fn passthrough_next(self, value: Self::Passthrough) -> Self;
    /// Append a type-erased non-secret child. An unsupported type is retained
    /// as a build error and reported by [`end`](Self::end).
    fn passthrough_next_boxed(self, value: Box<dyn Any + Send + 'static>) -> Self;

    /// Finish the sequence and pass its resolved children to `visitor` in order.
    /// The awaitable reports a retained child/build error, a backend failure,
    /// or the visitor's error; no successful partial result is returned.
    fn end<V>(self, visitor: V) -> <Self::Prf as Prf>::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>;
}

/// Map driver. See [`SeqPrf`] for the ownership convention.
///
/// Keys travel in the clear and must be unique. Pair each [`prf_key`](Self::prf_key)
/// with one [`prf_value`](Self::prf_value), or use [`prf_entry`](Self::prf_entry).
/// Drivers retain the first error and surface it from [`end`](Self::end);
/// later calls must not turn a failed build into a successful partial result.
pub trait MapPrf: Sized {
    /// Backend that owns the key and supplies this driver's output type.
    type Prf: Prf<
        Block = Self::Block,
        BackendError = Self::BackendError,
        Passthrough = Self::Passthrough,
    >;
    /// Owned pseudorandom output for one leaf, independent of the input lifetime.
    type Block: Send + 'static;
    /// Backend execution failure, carried by [`PrfError::Backend`].
    type BackendError: std::error::Error + Send + Sync + 'static;
    /// Owned representation of explicit non-secret passthrough values.
    type Passthrough: Send + 'static;

    /// Set the key for the next value. A preceding key without a value records
    /// [`crate::PrfBuildError::KeyWithoutValue`].
    fn prf_key<K>(self, key: K) -> Self
    where
        K: Into<Cow<'static, str>>;

    /// Implementations automatically refine the supplied context with the
    /// pending map key through `Context::for_map_entry`.
    /// Record [`crate::PrfBuildError::ValueWithoutKey`] if no key is pending,
    /// or [`crate::PrfBuildError::DuplicateKey`] if the key was already used.
    fn prf_value<T>(self, value: T, context: Context<'static>) -> Self
    where
        T: PrfValue;

    /// Add a key and derived value together, with the same validation and
    /// context refinement as calling `prf_key` followed by `prf_value`.
    fn prf_entry<K, T>(self, key: K, value: T, context: Context<'static>) -> Self
    where
        K: Into<Cow<'static, str>>,
        T: PrfValue,
    {
        self.prf_key(key).prf_value(value, context)
    }

    /// Append a non-secret entry without PRF processing. A pending unpaired
    /// key or duplicate entry key records a build error for [`end`](Self::end).
    fn passthrough_entry<K>(self, key: K, value: Self::Passthrough) -> Self
    where
        K: Into<Cow<'static, str>>;

    /// Type-erased counterpart of [`passthrough_entry`](Self::passthrough_entry).
    /// Also records a build error if the backend cannot represent the value.
    fn passthrough_entry_boxed<K>(self, key: K, value: Box<dyn Any + Send + 'static>) -> Self
    where
        K: Into<Cow<'static, str>>;

    /// Finish the map and visit resolved entries in insertion order.
    /// A pending key records [`crate::PrfBuildError::DanglingKey`]. The awaitable
    /// reports retained build/child errors, backend failures, or visitor failures.
    fn end<V>(self, visitor: V) -> <Self::Prf as Prf>::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>;
}
