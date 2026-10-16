//! The sealed order plaintext, and the trait a scheme implements to
//! encrypt it.
//!
//! A caller encrypts a value: `scheme.encrypt(42i32)`, or any other scalar
//! of the data model, and never sees the encoding. A scheme implements
//! one method over the sealed [`OrderPlaintext`], and never sees bytes
//! that skipped the encoding: the only way to make one is
//! [`order`](crate::order), which is why raw bytes handed to a scheme
//! cannot sort wrong. The plaintext carries its domain and, for a
//! fixed-width kind, its width, so a scheme can refuse a kind by name,
//! and it derives the salt every scheme binds, so two schemes never
//! disagree about what a term is bound to.

use core::fmt;

use vitaminc_aead::plaintext::{self, SourceError};
use vitaminc_aead::{Encrypt, Logical, MapSink, Physical, SeqSink, Sink};
use vitaminc_context::{Context, IntoContext};
use vitaminc_normalize::NormalizeError;
use vitaminc_protected::{Controlled, OpaqueDebug, Protected};

use crate::{domain, order};

/// The label every salt this crate derives leads with.
const SALT_LABEL: &[u8] = b"vitaminc/ore/v1";

/// One scalar's order term before encryption: bytes whose order is the
/// value's order, with the frozen domain label they belong to.
///
/// Only [`order`] builds one, so a scheme can rely on the bytes being the
/// encoding of their domain. A caller never needs one:
/// [`OrderScheme::encrypt`] takes the value itself. `Debug` shows the
/// domain and width and masks the bytes.
#[derive(OpaqueDebug)]
pub struct OrderPlaintext {
    #[non_sensitive]
    domain: &'static str,
    #[non_sensitive]
    width: Option<usize>,
    bytes: Protected<Vec<u8>>,
}

impl OrderPlaintext {
    pub(crate) fn new(domain: &'static str, bytes: Protected<Vec<u8>>) -> Self {
        let width = width_of(domain);
        debug_assert!(
            width.is_none_or(|w| w == bytes.risky_ref().len()),
            "{domain} encodes to its width"
        );
        Self {
            domain,
            width,
            bytes,
        }
    }

    /// The frozen domain label, one of the [`domain`] constants.
    pub fn domain(&self) -> &'static str {
        self.domain
    }

    /// The width every term of this domain has, or `None` for text and
    /// bytes, whose terms vary in length. A fixed-width scheme reads this
    /// rather than counting bytes, so it refuses a kind rather than a
    /// value.
    pub fn width(&self) -> Option<usize> {
        self.width
    }

    /// The term's bytes, protected. A scheme reads them with
    /// [`risky_ref`](Controlled::risky_ref) and nothing else should.
    pub fn bytes(&self) -> &Protected<Vec<u8>> {
        &self.bytes
    }

    /// The salt a scheme binds this term under: `PAE("vitaminc/ore/v1",
    /// scheme, domain, context)`. Leading with this crate's own label keeps
    /// it apart from any context another crate derives from the same
    /// parts. A CLLW scheme passes it as its salt; a scheme without a salt
    /// derives its keys under it.
    pub fn salt(&self, scheme: &str, context: &Context<'_>) -> Context<'static> {
        Context::pae(&[
            SALT_LABEL,
            scheme.as_bytes(),
            self.domain.as_bytes(),
            context.as_bytes(),
        ])
    }
}

/// The width of every term of a domain, or `None` for a variable-length
/// domain.
fn width_of(domain: &str) -> Option<usize> {
    match domain {
        domain::INT8 | domain::UINT8 => Some(1),
        domain::INT16 | domain::UINT16 => Some(2),
        domain::INT32 | domain::UINT32 | domain::FLOAT32 | domain::DATE => Some(4),
        domain::INT64 | domain::UINT64 | domain::FLOAT64 => Some(8),
        domain::TIMESTAMP => Some(12),
        domain::DECIMAL => Some(14),
        domain::INT128 | domain::UINT128 | domain::UUID => Some(16),
        _ => None,
    }
}

/// Why a scheme produced no term. Never includes plaintext.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OrderError<E> {
    /// The scalar has no order term: no order domain for its kind, not
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

/// An order scheme: encrypts one scalar so that the terms still compare.
///
/// A caller uses [`encrypt`](OrderScheme::encrypt) or
/// [`encrypt_with_context`](OrderScheme::encrypt_with_context) with any
/// scalar of the data model: an integer, a float, a string, bytes, or a
/// typed value such as a date. The value's kind decides the term's
/// domain, as it does everywhere else in the stack. A scheme implements
/// [`encrypt_plaintext`](OrderScheme::encrypt_plaintext) over the sealed
/// [`OrderPlaintext`] those methods build, and nothing else.
///
/// Terms compare only between terms of the same scheme, key, domain and
/// context: a column. The scheme keeps its own comparison (CLLW ORE and
/// block ORE do not compare byte by byte) through its term's `Ord`, and
/// its own stored bytes through `AsRef<[u8]>`.
///
/// Implemented by the scheme crates behind a `vitaminc` feature, and by a
/// mock in this crate's tests. An implementation reads the plaintext's
/// [`bytes`](OrderPlaintext::bytes), binds [`salt`](OrderScheme::salt),
/// and refuses a domain it cannot take with
/// [`OrderError::unsupported`]; it never pads or truncates.
pub trait OrderScheme {
    /// The scheme's name, bound into every term's salt and named in its
    /// refusals: `"cllw-ore"`, `"cllw-ope"`, `"block-ore"`.
    const NAME: &'static str;

    /// What one term encrypts to.
    type Term: Ord + AsRef<[u8]>;

    /// The scheme's own failure. [`Infallible`](core::convert::Infallible)
    /// for a scheme that cannot fail once keyed.
    type Error: core::error::Error + Send + Sync + 'static;

    /// Encrypt a sealed plaintext under `context`, binding its domain.
    /// What a scheme implements; a caller uses
    /// [`encrypt`](OrderScheme::encrypt).
    ///
    /// # Errors
    ///
    /// [`OrderError::Unsupported`] if the scheme does not take this
    /// domain, [`OrderError::Backend`] if it failed.
    fn encrypt_plaintext(
        &self,
        plaintext: &OrderPlaintext,
        context: &Context<'_>,
    ) -> Result<Self::Term, OrderError<Self::Error>>;

    /// Encrypt one scalar under the empty context.
    ///
    /// # Examples
    ///
    /// ```
    /// use vitaminc_ore::{Int, Logical, OrderError, NormalizeError, OrderScheme, Physical, Raw};
    /// # use vitaminc_ore::{Context, OrderPlaintext};
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
    /// # }
    /// # let scheme = Clear;
    ///
    /// // Any scalar of the data model; its kind decides the domain.
    /// assert!(scheme.encrypt(41u32)? < scheme.encrypt(42u32)?);
    /// let name = scheme.encrypt("Ada")?;
    ///
    /// // A typed scalar goes in as `Raw`.
    /// let day = Raw(Some(Logical::Date), Physical::Int(Int::I32(19_000)));
    /// let date = scheme.encrypt(day)?;
    ///
    /// // A scalar with no order term is refused, not skipped.
    /// assert!(matches!(
    ///     scheme.encrypt(true),
    ///     Err(OrderError::Term(NormalizeError::NoDomain))
    /// ));
    /// # Ok::<(), OrderError<core::convert::Infallible>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// As [`encrypt_with_context`](OrderScheme::encrypt_with_context).
    fn encrypt<V: Encrypt>(&self, value: V) -> Result<Self::Term, OrderError<Self::Error>> {
        self.encrypt_with_context(value, ())
    }

    /// Encrypt one scalar under `context`: a column, a tenant, whatever
    /// the term must compare within. The value is encoded by
    /// [`order`] and handed to
    /// [`encrypt_plaintext`](OrderScheme::encrypt_plaintext).
    ///
    /// A scalar with no order term is refused rather than skipped: a
    /// caller who asks for one term and gets none should hear about it.
    ///
    /// # Examples
    ///
    /// ```
    /// use vitaminc_ore::OrderScheme;
    /// # use vitaminc_ore::{Context, OrderError, OrderPlaintext};
    /// # struct Clear;
    /// # impl OrderScheme for Clear {
    /// #     const NAME: &'static str = "clear";
    /// #     type Term = Vec<u8>;
    /// #     type Error = core::convert::Infallible;
    /// #     fn encrypt_plaintext(&self, p: &OrderPlaintext, c: &Context<'_>) -> Result<Vec<u8>, OrderError<Self::Error>> {
    /// #         use vitaminc_protected::Controlled;
    /// #         let mut t = self.salt(p, c).as_bytes().to_vec();
    /// #         t.extend_from_slice(p.bytes().risky_ref());
    /// #         Ok(t)
    /// #     }
    /// # }
    /// # let scheme = Clear;
    ///
    /// // A column: the term compares only with terms under the same context.
    /// let quantity = scheme.encrypt_with_context(42u32, ("orders", "quantity"))?;
    /// let other = scheme.encrypt_with_context(42u32, ("orders", "total"))?;
    /// assert_ne!(quantity, other);
    /// # Ok::<(), OrderError<core::convert::Infallible>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`OrderError::Term`] if the scalar has no order term,
    /// [`OrderError::NotScalar`] if the value is a container,
    /// [`OrderError::Source`] if the value could not be read, else as
    /// [`encrypt_plaintext`](OrderScheme::encrypt_plaintext).
    fn encrypt_with_context<'a, V, C>(
        &self,
        value: V,
        context: C,
    ) -> Result<Self::Term, OrderError<Self::Error>>
    where
        V: Encrypt,
        C: IntoContext<'a>,
    {
        let plaintext = value.visit(Scalar)?;
        self.encrypt_plaintext(&plaintext, &context.into_context().encode())
    }

    /// The salt this scheme binds `plaintext` under: the plaintext's
    /// [`salt`](OrderPlaintext::salt) with this scheme's name.
    fn salt(&self, plaintext: &OrderPlaintext, context: &Context<'_>) -> Context<'static> {
        plaintext.salt(Self::NAME, context)
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

/// The sink one scalar is walked into: it encodes the scalar with
/// [`order`] and refuses a container.
struct Scalar;

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
        order(ty, value).map_err(ScalarError::Term)
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
        f.write_str(self.domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_aead::Int;

    #[test]
    fn every_domain_has_the_width_its_encoding_has() {
        for d in domain::ALL {
            let fixed = width_of(d);
            let variable = matches!(*d, domain::TEXT | domain::BYTES);
            assert_eq!(fixed.is_none(), variable, "{d}");
        }
        let p = order(None, Physical::Int(Int::I32(1))).expect("term");
        assert_eq!(p.width(), Some(4));
        assert_eq!(p.bytes().risky_ref().len(), 4);
        assert_eq!(
            order(None, Physical::Text("a")).expect("term").width(),
            None
        );
    }

    #[test]
    fn the_salt_binds_label_scheme_domain_and_context() {
        let p = order(None, Physical::Int(Int::I8(1))).expect("term");
        let context = ("tenant", 1u64).into_context().encode();
        let salt = p.salt("mock", &context);
        assert_eq!(
            salt,
            Context::pae(&[
                b"vitaminc/ore/v1",
                b"mock",
                domain::INT8.as_bytes(),
                context.as_bytes()
            ])
        );
        assert_ne!(salt, p.salt("other", &context));
        assert_ne!(
            salt,
            p.salt("mock", &("tenant", 2u64).into_context().encode())
        );
        let q = order(None, Physical::Int(Int::U8(0x81))).expect("term");
        assert_eq!(p.bytes().risky_ref(), q.bytes().risky_ref());
        assert_ne!(salt, q.salt("mock", &context));
    }

    #[test]
    fn debug_and_display_show_the_domain_and_mask_the_bytes() {
        let p = order(None, Physical::Text("secret")).expect("term");
        let shown = format!("{p:?}");
        assert!(
            shown.contains(domain::TEXT) && shown.contains("***"),
            "{shown}"
        );
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
    fn the_scalar_sink_encodes_one_scalar_and_refuses_a_container() {
        let p = 7i16.visit(Scalar).expect("scalar");
        assert_eq!(p.domain(), domain::INT16);
        assert!(matches!(
            vec![1u16, 2].visit(Scalar),
            Err(ScalarError::NotScalar)
        ));
        assert!(matches!(
            std::collections::BTreeMap::from([("k", 1u16)]).visit(Scalar),
            Err(ScalarError::NotScalar)
        ));
        assert!(matches!(
            true.visit(Scalar),
            Err(ScalarError::Term(NormalizeError::NoDomain))
        ));
    }
}
