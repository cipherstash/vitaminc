//! The sealed order plaintext, the trait a scheme implements to encrypt
//! it, and the column a caller encrypts through.
//!
//! A caller opens a column on a scheme, with the type the column declares
//! and the context its terms compare within, and encrypts values:
//! `scheme.column(OrderTarget::I32, ("orders", "total")).encrypt(42u8)`.
//! It never sees the encoding. A scheme implements one method over the
//! sealed [`OrderPlaintext`] and the salt the column derives, and never
//! sees bytes that skipped the encoding (the only way to make a plaintext
//! is [`order`]) or a salt it could derive differently from another
//! scheme.

use core::cmp::Ordering;
use core::fmt;

use vitaminc_aead::plaintext::{self, SourceError};
use vitaminc_aead::{Encrypt, Logical, MapSink, Physical, SeqSink, Sink};
use vitaminc_context::{Context, IntoContext};
use vitaminc_normalize::NormalizeError;
use vitaminc_protected::{Controlled, OpaqueDebug, Protected};

use crate::{order, OrderTarget};

/// The label every salt this crate derives leads with.
const SALT_LABEL: &[u8] = b"vitaminc/ore/v1";

/// One scalar's order term before encryption: bytes whose order is the
/// value's order, encoded as the target they were made for.
///
/// Only [`order`] builds one, so a scheme can rely on the bytes being the
/// encoding of their target. A caller never needs one:
/// [`OrderColumn::encrypt`] takes the value itself. `Debug` shows the
/// domain and width and masks the bytes.
#[derive(OpaqueDebug)]
pub struct OrderPlaintext {
    #[non_sensitive]
    target: OrderTarget,
    bytes: Protected<Vec<u8>>,
}

impl OrderPlaintext {
    pub(crate) fn new(target: OrderTarget, bytes: Protected<Vec<u8>>) -> Self {
        debug_assert!(
            target.width().is_none_or(|w| w == bytes.risky_ref().len()),
            "{target:?} encodes to its width"
        );
        Self { target, bytes }
    }

    /// The target the bytes were encoded as.
    pub fn target(&self) -> OrderTarget {
        self.target
    }

    /// The frozen domain label, one of the [`domain`](crate::domain)
    /// constants: the target's.
    pub fn domain(&self) -> &'static str {
        self.target.domain()
    }

    /// The width every term of this target has, or `None` for text and
    /// bytes, whose terms vary in length. A fixed-width scheme reads this
    /// rather than counting bytes, so it refuses a target rather than a
    /// value.
    pub fn width(&self) -> Option<usize> {
        self.target.width()
    }

    /// The term's bytes, protected. A scheme reads them with
    /// [`risky_ref`](Controlled::risky_ref) and nothing else should.
    pub fn bytes(&self) -> &Protected<Vec<u8>> {
        &self.bytes
    }
}

/// Why a scheme produced no term. Never includes plaintext.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OrderError<E> {
    /// The scalar has no order term as the column's target: no order for
    /// its kind, another kind than the target, outside the target, not
    /// valid for its logical type, or text with a code point unassigned
    /// in Unicode 16.
    #[error("no order term: {0}")]
    Term(#[from] NormalizeError),
    /// The value is a sequence, a map or a passthrough, which has no
    /// single term. Walk it with [`order_terms`](crate::order_terms).
    #[error("a container has no single order term; walk it for one per scalar")]
    NotScalar,
    /// The value could not be read: its source failed before any term
    /// was made.
    #[error("the value could not be read: {0}")]
    Source(SourceError),
    /// The scheme does not take terms of this domain: a fixed-width scheme
    /// given text, or a width above its limit.
    #[error("{scheme} has no order term for {domain}")]
    Unsupported {
        /// The scheme's [`NAME`](OrderScheme::NAME).
        scheme: &'static str,
        /// The term's domain label.
        domain: &'static str,
    },
    /// The scheme's own failure.
    #[error("the order scheme failed: {0}")]
    Backend(E),
}

impl<E> OrderError<E> {
    /// The refusal of `plaintext`'s domain by scheme `S`.
    pub fn unsupported<S: OrderScheme + ?Sized>(plaintext: &OrderPlaintext) -> Self {
        Self::Unsupported {
            scheme: S::NAME,
            domain: plaintext.domain(),
        }
    }
}

/// An order scheme: encrypts one sealed plaintext so that the terms still
/// compare.
///
/// A scheme implements [`encrypt_plaintext`](OrderScheme::encrypt_plaintext)
/// and nothing else. A caller does not call it: it opens a column with
/// [`OrderEncrypt::column`], which every scheme has, and encrypts values
/// there. The column derives the salt the scheme binds, so no scheme can
/// leave a part of it out.
///
/// Terms compare only between terms of the same scheme, key, target and
/// context: a column. The scheme keeps its own comparison (CLLW ORE and
/// block ORE do not compare byte by byte) in [`compare`](Self::compare),
/// and its own stored bytes through `AsRef<[u8]>`. A term is not `Ord`:
/// that would promise an order between any two terms, and no term carries
/// which column it came from, so two terms of different columns would
/// compare as noise and break every sort and tree that trusted the
/// promise.
///
/// Implemented by the scheme crates behind a `vitaminc` feature, and by a
/// mock in this crate's tests. An implementation reads the plaintext's
/// [`bytes`](OrderPlaintext::bytes), binds `salt`, and refuses a target it
/// cannot take with [`OrderError::unsupported`]; it never pads or
/// truncates.
pub trait OrderScheme {
    /// The scheme's name, bound into every term's salt and named in its
    /// refusals: `"cllw-ore"`, `"cllw-ope"`, `"block-ore"`.
    const NAME: &'static str;

    /// What one term encrypts to.
    type Term: AsRef<[u8]>;

    /// The scheme's own failure. [`Infallible`](core::convert::Infallible)
    /// for a scheme that cannot fail once keyed.
    type Error: core::error::Error + Send + Sync + 'static;

    /// Encrypt a sealed plaintext, binding `salt`: `PAE("vitaminc/ore/v1",
    /// NAME, domain, context)`, which the column derives. A CLLW scheme
    /// passes it as its salt; a scheme without one, block ORE, derives its
    /// keys under it.
    ///
    /// # Errors
    ///
    /// [`OrderError::Unsupported`] if the scheme does not take this
    /// target, [`OrderError::Backend`] if it failed.
    fn encrypt_plaintext(
        &self,
        plaintext: &OrderPlaintext,
        salt: &Context<'_>,
    ) -> Result<Self::Term, OrderError<Self::Error>>;

    /// The order of two terms of one column, as the order of the values
    /// they encrypt. Needs no key: that is what makes the scheme an order
    /// scheme.
    ///
    /// Over the terms of one column this is a total order, so a caller may
    /// sort with it. `None` says the two cannot be compared: one is not a
    /// term of this scheme, or the two were not made to compare (block
    /// ORE under different padding). A scheme returns `None` wherever it
    /// can tell, and never falls back to comparing bytes it cannot order.
    /// It cannot tell everything: two well-formed terms of different
    /// columns may compare as noise, so a caller keeps a column's terms
    /// together, as [`OrderColumn::compare`] says.
    fn compare(a: &Self::Term, b: &Self::Term) -> Option<Ordering>;
}

/// What a caller does with any [`OrderScheme`]: open a column. Implemented
/// for every scheme and for nothing else, so a scheme cannot change how a
/// column binds its terms.
pub trait OrderEncrypt: OrderScheme {
    /// A column of `target` values, whose terms compare only with each
    /// other: under `context` (a table and column, a tenant, whatever they
    /// must compare within), this scheme and its key.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::cmp::Ordering;
    /// use vitaminc_ore::{Int, OrderEncrypt, OrderTarget, Physical, Raw};
    /// # use vitaminc_ore::{Context, OrderError, OrderPlaintext, OrderScheme};
    /// # /// Keeps the bytes as they are, for the example. Any scheme will do.
    /// # struct Clear;
    /// # impl OrderScheme for Clear {
    /// #     const NAME: &'static str = "clear";
    /// #     type Term = Vec<u8>;
    /// #     type Error = core::convert::Infallible;
    /// #     fn encrypt_plaintext(&self, p: &OrderPlaintext, _: &Context<'_>) -> Result<Vec<u8>, OrderError<Self::Error>> {
    /// #         use vitaminc_protected::Controlled;
    /// #         Ok(p.bytes().risky_ref().clone())
    /// #     }
    /// #     fn compare(a: &Vec<u8>, b: &Vec<u8>) -> Option<Ordering> {
    /// #         Some(a.cmp(b))
    /// #     }
    /// # }
    /// # let scheme = Clear;
    ///
    /// let total = scheme.column(OrderTarget::I32, ("orders", "total"));
    /// // Whatever width a value arrives at, it is encoded as the column's,
    /// // and the column compares its terms.
    /// let (a, b) = (total.encrypt(41i8)?, total.encrypt(42i64)?);
    /// assert_eq!(total.compare(&a, &b), Some(Ordering::Less));
    ///
    /// // A typed scalar goes in as `Raw`, into a column of its type.
    /// let placed = scheme.column(OrderTarget::Date, ("orders", "placed"));
    /// let day = placed.encrypt(Raw(Some(vitaminc_ore::Logical::Date), Physical::Int(Int::I32(19_000))))?;
    /// # Ok::<(), OrderError<core::convert::Infallible>>(())
    /// ```
    fn column<'a, C: IntoContext<'a>>(
        &self,
        target: OrderTarget,
        context: C,
    ) -> OrderColumn<'_, Self> {
        let context = context.into_context().encode();
        OrderColumn {
            scheme: self,
            target,
            salt: salt(Self::NAME, target, &context),
        }
    }
}

impl<S: OrderScheme + ?Sized> OrderEncrypt for S {}

/// `PAE("vitaminc/ore/v1", scheme, domain, context)`. Leading with this
/// crate's own label keeps it apart from any context another crate
/// derives from the same parts.
fn salt(scheme: &str, target: OrderTarget, context: &Context<'_>) -> Context<'static> {
    Context::pae(&[
        SALT_LABEL,
        scheme.as_bytes(),
        target.domain().as_bytes(),
        context.as_bytes(),
    ])
}

/// One column of an order index on a scheme: its target and the salt its
/// terms are bound under, fixed when it is opened so every term of it
/// agrees. From [`OrderEncrypt::column`]. `Debug` shows the target and
/// masks the scheme, whose key it holds, and the salt.
#[derive(OpaqueDebug)]
pub struct OrderColumn<'s, S: OrderScheme + ?Sized> {
    scheme: &'s S,
    #[non_sensitive]
    target: OrderTarget,
    salt: Context<'static>,
}

impl<S: OrderScheme + ?Sized> OrderColumn<'_, S> {
    /// The type every value of this column is encoded as.
    pub fn target(&self) -> OrderTarget {
        self.target
    }

    /// The salt every term of this column is bound under. Not secret.
    pub fn salt(&self) -> &Context<'static> {
        &self.salt
    }

    /// Encrypt one scalar as this column's target: an integer of any width
    /// it fits, a float, a string, bytes, or a typed value such as a date.
    ///
    /// A scalar with no term is refused rather than skipped: a caller who
    /// asks for one term and gets none should hear about it.
    ///
    /// # Errors
    ///
    /// [`OrderError::Term`] if the scalar has no term as the column's
    /// target, [`OrderError::NotScalar`] if the value is a container,
    /// [`OrderError::Source`] if the value could not be read, else as
    /// [`OrderScheme::encrypt_plaintext`].
    pub fn encrypt<V: Encrypt>(&self, value: V) -> Result<S::Term, OrderError<S::Error>> {
        let plaintext = value.visit(Scalar(self.target))?;
        self.scheme.encrypt_plaintext(&plaintext, &self.salt)
    }

    /// Encrypt a plaintext [`order_terms`](crate::order_terms) collected
    /// from a whole value.
    ///
    /// # Errors
    ///
    /// [`OrderError::Term`] with [`NormalizeError::Mismatch`] if it was
    /// encoded as another target than this column's, else as
    /// [`OrderScheme::encrypt_plaintext`].
    pub fn encrypt_term(
        &self,
        plaintext: &OrderPlaintext,
    ) -> Result<S::Term, OrderError<S::Error>> {
        if plaintext.target() != self.target {
            return Err(OrderError::Term(NormalizeError::Mismatch));
        }
        self.scheme.encrypt_plaintext(plaintext, &self.salt)
    }

    /// The order of two of this column's terms, as the order of the values
    /// they encrypt: [`OrderScheme::compare`]. A total order over the
    /// column's terms, so they sort by it.
    ///
    /// Both terms must be this column's. A term records nothing of its
    /// column, so the scheme cannot always tell two columns' terms apart,
    /// and may order them as noise. `None` where it can tell: a term not
    /// of this scheme, or two terms not made to compare.
    pub fn compare(&self, a: &S::Term, b: &S::Term) -> Option<Ordering> {
        S::compare(a, b)
    }
}

/// A scheme keyed from secret bytes, as
/// [`PrfKeyInit`](https://docs.rs/vitaminc-prf) keys a PRF, so an index
/// layer can construct any scheme the same way.
pub trait OrderKeyInit: OrderScheme + Sized {
    /// The scheme's full-strength key, a protected array.
    type Key: Controlled;
    /// Why key material of a length only known at runtime was refused.
    type KeyError: core::error::Error + Send + Sync + 'static;

    /// Key the scheme with a full-strength key. Cannot fail: the type
    /// carries the length.
    fn new(key: Self::Key) -> Self;

    /// Key the scheme with material whose length is only known at runtime,
    /// such as a KMS response.
    ///
    /// # Errors
    ///
    /// [`KeyError`](OrderKeyInit::KeyError) if the material is unfit, a
    /// short key say. Accepting it would produce terms anyone can order.
    fn try_from_bytes(key: Protected<Vec<u8>>) -> Result<Self, Self::KeyError>;
}

/// The sink one scalar is walked into: it encodes the scalar as its
/// target with [`order`] and refuses a container.
#[derive(Clone, Copy)]
struct Scalar(OrderTarget);

/// How one scalar fails to become a plaintext.
#[derive(Debug, thiserror::Error)]
enum ScalarError {
    #[error(transparent)]
    Term(NormalizeError),
    #[error("not a scalar")]
    NotScalar,
    #[error(transparent)]
    Source(SourceError),
}

impl plaintext::Error for ScalarError {
    fn source(error: SourceError) -> Self {
        Self::Source(error)
    }
}

impl<E> From<ScalarError> for OrderError<E> {
    fn from(error: ScalarError) -> Self {
        match error {
            ScalarError::Term(e) => Self::Term(e),
            ScalarError::NotScalar => Self::NotScalar,
            ScalarError::Source(e) => Self::Source(e),
        }
    }
}

impl Sink for Scalar {
    type Ok = OrderPlaintext;
    type Error = ScalarError;
    type Seq = Never;
    type Map = Never;

    fn scalar(
        self,
        ty: Option<Logical>,
        value: Physical<'_>,
    ) -> Result<OrderPlaintext, ScalarError> {
        order(self.0, ty, value).map_err(ScalarError::Term)
    }

    fn seq(self, _: Option<usize>) -> Result<Never, ScalarError> {
        Err(ScalarError::NotScalar)
    }

    fn map(self, _: Option<usize>) -> Result<Never, ScalarError> {
        Err(ScalarError::NotScalar)
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<OrderPlaintext, ScalarError> {
        Err(ScalarError::NotScalar)
    }
}

/// The container sink [`Scalar`] never hands out. Uninhabited, so it
/// cannot be built.
enum Never {}

impl SeqSink for Never {
    type Ok = OrderPlaintext;
    type Error = ScalarError;
    type Element<'s>
        = Scalar
    where
        Self: 's;

    fn element(&mut self) -> Result<Scalar, ScalarError> {
        match *self {}
    }

    fn end(self) -> Result<OrderPlaintext, ScalarError> {
        match self {}
    }
}

impl MapSink for Never {
    type Ok = OrderPlaintext;
    type Error = ScalarError;
    type Entry<'s>
        = Scalar
    where
        Self: 's;

    fn entry(&mut self, _: &str) -> Result<Scalar, ScalarError> {
        match *self {}
    }

    fn end(self) -> Result<OrderPlaintext, ScalarError> {
        match self {}
    }
}

impl fmt::Display for OrderPlaintext {
    /// The domain only: never the bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.domain())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain;
    use vitaminc_aead::Int;

    #[test]
    fn every_target_has_the_width_its_encoding_has() {
        for target in OrderTarget::ALL {
            let variable = matches!(target, OrderTarget::Text | OrderTarget::Bytes);
            assert_eq!(target.width().is_none(), variable, "{target:?}");
        }
        let p = order(OrderTarget::I32, None, Physical::Int(Int::I8(1))).expect("term");
        assert_eq!(p.width(), Some(4));
        assert_eq!(p.bytes().risky_ref().len(), 4);
        assert_eq!(p.target(), OrderTarget::I32);
        assert_eq!(
            order(OrderTarget::Text, None, Physical::Text("a"))
                .expect("term")
                .width(),
            None
        );
    }

    #[test]
    fn the_salt_binds_label_scheme_domain_and_context() {
        let context = ("tenant", 1u64).into_context().encode();
        let salted = salt("mock", OrderTarget::I8, &context);
        assert_eq!(
            salted,
            Context::pae(&[
                b"vitaminc/ore/v1",
                b"mock",
                domain::INT8.as_bytes(),
                context.as_bytes()
            ])
        );
        assert_ne!(salted, salt("other", OrderTarget::I8, &context));
        assert_ne!(salted, salt("mock", OrderTarget::U8, &context));
        assert_ne!(
            salted,
            salt(
                "mock",
                OrderTarget::I8,
                &("tenant", 2u64).into_context().encode()
            )
        );
    }

    #[test]
    fn debug_and_display_show_the_domain_and_mask_the_bytes() {
        let p = order(OrderTarget::Text, None, Physical::Text("secret")).expect("term");
        let shown = format!("{p:?}");
        assert!(shown.contains("Text") && shown.contains("***"), "{shown}");
        assert!(!shown.contains("secret"), "{shown}");
        assert_eq!(p.to_string(), domain::TEXT);
    }

    #[test]
    fn errors_say_what_failed_without_plaintext() {
        type E = OrderError<&'static str>;
        assert_eq!(
            E::Term(NormalizeError::NoDomain).to_string(),
            "no order term: no domain for this kind of value"
        );
        assert_eq!(
            E::Term(NormalizeError::Mismatch).to_string(),
            "no order term: the value is not of the kind the index declares"
        );
        assert_eq!(
            E::Term(NormalizeError::OutOfRange).to_string(),
            "no order term: the value does not fit the type the index declares"
        );
        assert_eq!(
            E::NotScalar.to_string(),
            "a container has no single order term; walk it for one per scalar"
        );
        assert_eq!(
            E::Source(SourceError::msg("getter threw")).to_string(),
            "the value could not be read: getter threw"
        );
        assert_eq!(
            E::Unsupported {
                scheme: "block-ore",
                domain: domain::TEXT
            }
            .to_string(),
            "block-ore has no order term for vitaminc/ore/value/text-folded/unicode-16/v1"
        );
        assert_eq!(
            E::Backend("down").to_string(),
            "the order scheme failed: down"
        );
        let from: E = NormalizeError::Invalid.into();
        assert!(matches!(from, E::Term(NormalizeError::Invalid)));
    }

    #[test]
    fn the_scalar_sink_encodes_one_scalar_as_its_target_and_refuses_a_container() {
        let p = 7i16.visit(Scalar(OrderTarget::I64)).expect("scalar");
        assert_eq!(p.domain(), domain::INT64);
        assert!(matches!(
            vec![1u16, 2].visit(Scalar(OrderTarget::U16)),
            Err(ScalarError::NotScalar)
        ));
        assert!(matches!(
            std::collections::BTreeMap::from([("k", 1u16)]).visit(Scalar(OrderTarget::U16)),
            Err(ScalarError::NotScalar)
        ));
        assert!(matches!(
            true.visit(Scalar(OrderTarget::U8)),
            Err(ScalarError::Term(NormalizeError::NoDomain))
        ));
    }
}
