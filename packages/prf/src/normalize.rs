//! Equality terms for the plaintext data model.
//!
//! Normalization happens once, in the index sink of `vitaminc-normalize`,
//! and the PRF only sees the result: a frozen domain label and protected
//! bytes. [`Normalized`] is a `PrfValue` directly. [`EqualityTerm`] is the
//! one-scalar convenience that normalizes on the way in, for a caller that
//! has a physical value and its logical type in hand rather than a walk.

use vitaminc_aead::{Logical, Physical};
use vitaminc_normalize::{normalize, NormalizeError, Normalized};
use vitaminc_protected::OpaqueDebug;

use crate::{IntoPrfContext, Prf, PrfEncoding, PrfError, PrfValue, PrfVisitor};

/// Derive under the term's own domain, over its normalized bytes.
///
/// The fields of a `Normalized` are public, so its domain is caller input
/// here: an empty one, which no frozen domain is, fails with
/// [`NormalizeError::NoDomain`] rather than reaching the encoding's
/// non-empty assertion.
impl PrfValue for Normalized {
    fn prf_visit_with_context<'a, P, V, C>(self, prf: &P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        if self.domain.is_empty() {
            return no_domain(prf);
        }
        prf.prf_bytes_vec(
            self.bytes,
            PrfEncoding::new(self.domain),
            context.into_prf_context().into_owned(),
            visitor,
        )
    }
}

/// As for the owned term; the bytes are copied inside `Protected`.
impl PrfValue for &Normalized {
    fn prf_visit_with_context<'a, P, V, C>(self, prf: &P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        if self.domain.is_empty() {
            return no_domain(prf);
        }
        prf.prf_bytes_vec(
            self.bytes.clone(),
            PrfEncoding::new(self.domain),
            context.into_prf_context().into_owned(),
            visitor,
        )
    }
}

/// The refusal for a term with an empty domain.
fn no_domain<P: Prf, T: Send + 'static>(prf: &P) -> P::Ok<T> {
    prf.failure(PrfError::Normalize(NormalizeError::NoDomain))
}

/// One scalar to derive an equality term for: a physical value and the
/// logical type it represents, normalized on the way in.
///
/// This is the one place the PRF crate normalizes. The ADR has the index
/// sink do that over a whole document, and the PRF only see the result;
/// `EqualityTerm` is for the other shape of caller, one that holds a
/// single scalar and its type (a query parameter, say) rather than a
/// value to walk, and is the direct replacement for deriving from a
/// `&Value`. It refuses what [`normalize`] refuses: a scalar with no
/// equality domain (a null, a boolean, a logical type outside the opt-in
/// table), text with a code point unassigned in Unicode 16, or a value
/// that is not valid for its logical type fails with
/// [`PrfError::Normalize`] before anything is derived. That differs from
/// the document sink, which skips a null or a boolean, because a caller
/// who asks for one term and gets none should hear about it.
///
/// The types it takes, [`Logical`] and [`Physical`], are
/// `vitaminc_aead`'s.
///
/// ```
/// use vitaminc_prf::{EqualityTerm, PrfValue};
/// use vitaminc_aead::{Int, Logical, Physical};
/// # use vitaminc_prf::Prf;
/// # fn derive<P: Prf>(prf: &P) -> P::Ok<P::Block> {
/// // A date, under the date domain rather than the integer one.
/// EqualityTerm::new(Some(Logical::Date), Physical::Int(Int::I32(19_000))).prf(prf)
/// # }
/// ```
///
/// `Debug` shows the logical type and masks the value.
#[derive(Clone, Copy, OpaqueDebug)]
pub struct EqualityTerm<'a> {
    #[non_sensitive]
    logical: Option<Logical>,
    value: Physical<'a>,
}

impl<'a> EqualityTerm<'a> {
    /// A term for `value`, read as `logical` if that is `Some`.
    pub fn new(logical: Option<Logical>, value: Physical<'a>) -> Self {
        Self { logical, value }
    }
}

impl PrfValue for EqualityTerm<'_> {
    fn prf_visit_with_context<'a, P, V, C>(self, prf: &P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        match normalize(self.logical, self.value) {
            Ok(normalized) => normalized.prf_visit_with_context(prf, context, visitor),
            Err(error) => prf.failure(PrfError::Normalize(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_backend::MockPrf, Context, NormalizeError};
    use vitaminc_aead::Int;
    use vitaminc_normalize::domain;

    #[test]
    fn a_normalized_term_derives_under_its_own_domain() {
        let backend = MockPrf;
        let term = normalize(None, Physical::Int(Int::I8(7))).expect("int");
        let by_ref = (&term).prf(&backend).into_result().expect("derives");
        // The borrowed term derives under the same context as the owned one
        // and the scalar it came from, and a different context differs.
        let under = |ctx: u64| {
            (&term)
                .prf_with_context(&backend, ("tenant", ctx))
                .into_result()
                .expect("derives")
        };
        assert_eq!(
            under(1),
            EqualityTerm::new(None, Physical::Int(Int::I8(7)))
                .prf_with_context(&backend, ("tenant", 1u64))
                .into_result()
                .expect("derives")
        );
        assert_ne!(under(1), under(2));
        assert_ne!(under(1), by_ref);
        let owned = term.prf(&backend).into_result().expect("derives");
        assert_eq!(by_ref, owned);
        // The domain is the term's, not a built-in encoding's.
        let mut bytes = vec![1u8];
        bytes.extend_from_slice(&7u128.to_be_bytes());
        let expected = backend.prf_bytes_vec(
            vitaminc_protected::Protected::new(bytes),
            PrfEncoding::new(domain::INTEGER),
            Context::empty().into_owned(),
            crate::BlockVisitor,
        );
        assert_eq!(owned, expected.into_result().expect("derives"));
        assert_ne!(owned, 7i8.prf(&backend).into_result().expect("derives"));
    }

    #[test]
    fn equality_normalizes_on_the_way_in() {
        let backend = MockPrf;
        let composed = EqualityTerm::new(None, Physical::Text("e\u{301}"));
        let precomposed = EqualityTerm::new(None, Physical::Text("é"));
        assert_eq!(
            composed.prf(&backend).into_result().expect("derives"),
            precomposed.prf(&backend).into_result().expect("derives")
        );
        assert_ne!(
            composed
                .prf_with_context(&backend, ("tenant", 1u64))
                .into_result()
                .expect("derives"),
            composed
                .prf_with_context(&backend, ("tenant", 2u64))
                .into_result()
                .expect("derives")
        );
        assert_eq!(
            EqualityTerm::new(None, Physical::Int(Int::I8(34)))
                .prf(&backend)
                .into_result()
                .expect("derives"),
            EqualityTerm::new(None, Physical::Int(Int::U64(34)))
                .prf(&backend)
                .into_result()
                .expect("derives")
        );
    }

    #[test]
    fn a_normalization_failure_is_a_normalize_error() {
        let backend = MockPrf;
        assert!(matches!(
            EqualityTerm::new(None, Physical::Bool(false))
                .prf(&backend)
                .into_result(),
            Err(PrfError::Normalize(NormalizeError::NoDomain))
        ));
        assert!(matches!(
            EqualityTerm::new(None, Physical::Text("\u{378}"))
                .prf(&backend)
                .into_result(),
            Err(PrfError::Normalize(NormalizeError::UnassignedCodePoint))
        ));
        assert!(matches!(
            EqualityTerm::new(Some(Logical::Uuid), Physical::Bytes(&[0; 15]))
                .prf(&backend)
                .into_result(),
            Err(PrfError::Normalize(NormalizeError::Invalid))
        ));
        let error: PrfError<core::convert::Infallible> = NormalizeError::NoDomain.into();
        assert_eq!(
            error.to_string(),
            "cannot derive an equality term: no domain for this kind of value"
        );
    }

    /// A `Normalized` built by hand with an empty domain is refused like
    /// any term with no domain, owned or borrowed, instead of panicking.
    #[test]
    fn an_empty_domain_is_refused_not_a_panic() {
        let backend = MockPrf;
        let empty = || Normalized {
            domain: "",
            bytes: vitaminc_protected::Protected::new(vec![1]),
        };
        assert!(matches!(
            (&empty()).prf(&backend).into_result(),
            Err(PrfError::Normalize(NormalizeError::NoDomain))
        ));
        assert!(matches!(
            empty().prf(&backend).into_result(),
            Err(PrfError::Normalize(NormalizeError::NoDomain))
        ));
    }

    #[test]
    fn debug_shows_the_logical_type_and_masks_the_value() {
        let term = EqualityTerm::new(Some(Logical::Date), Physical::Text("secret"));
        let shown = format!("{term:?}");
        assert!(shown.contains("Date") && shown.contains("***"), "{shown}");
        assert!(!shown.contains("secret"), "{shown}");
    }
}
