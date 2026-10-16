//! The sealed order plaintext, and the trait a scheme implements to
//! encrypt it.
//!
//! A scheme never sees bytes that skipped the encoding: the only way to
//! make an [`OrderPlaintext`] is [`order`](crate::order), which is why
//! raw bytes handed to a scheme cannot sort wrong. The plaintext carries
//! its domain and, for a fixed-width kind, its width, so a scheme can
//! refuse a kind by name, and it derives the salt every scheme binds, so
//! two schemes never disagree about what a term is bound to.

use core::fmt;

use vitaminc_aead::{Logical, Physical};
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
/// encoding of their domain. `Debug` shows the domain and width and
/// masks the bytes.
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
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OrderError<E> {
    /// The scalar has no order term: no order domain for its kind, not
    /// valid for its logical type, or text with a code point unassigned
    /// in Unicode 16. From [`order_term`], which encodes on the way in.
    #[error("no order term: {0}")]
    Term(#[from] NormalizeError),
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

/// An order scheme: encrypts one [`OrderPlaintext`] under a context so
/// that the terms still compare.
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

    /// Encrypt `plaintext` under `context`, binding its domain.
    ///
    /// # Errors
    ///
    /// [`OrderError::Unsupported`] if the scheme does not take this
    /// domain, [`OrderError::Backend`] if it failed.
    fn encrypt(
        &self,
        plaintext: &OrderPlaintext,
        context: &Context<'_>,
    ) -> Result<Self::Term, OrderError<Self::Error>>;

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

/// One order term for one scalar, encrypted: [`order`] then
/// [`OrderScheme::encrypt`], for a caller that holds a scalar and its type
/// (a query parameter, say) rather than a value to walk. It refuses a
/// scalar with no term rather than returning nothing: a caller who asks
/// for one term and gets none should hear about it.
///
/// # Errors
///
/// [`OrderError::Term`] if the scalar has no order term, else as
/// [`OrderScheme::encrypt`].
pub fn order_term<'a, S, C>(
    scheme: &S,
    ty: Option<Logical>,
    value: Physical<'_>,
    context: C,
) -> Result<S::Term, OrderError<S::Error>>
where
    S: OrderScheme,
    C: IntoContext<'a>,
{
    let plaintext = order(ty, value)?;
    scheme.encrypt(&plaintext, &context.into_context().encode())
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
        assert_eq!(from, E::Term(NormalizeError::Invalid));
    }
}
