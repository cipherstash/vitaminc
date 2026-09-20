//! The PRF's domain-separation context, as a view of a context.
//!
//! The bytes a PRF derives under for a context are the context's canonical
//! encoding, owned by [`vitaminc_context`]. This module adds nothing to that
//! encoding: [`IntoPrfContext`] is a blanket over [`IntoContext`], so a
//! context type implements `IntoContext` once and gets `IntoPrfContext` (and
//! the AEAD crate's `IntoAad`) for free, with byte-identical results on both
//! sides.

pub use vitaminc_context::{Context, ContextPiece, IntoContext};

/// The context a PRF derives under. Kept as a name for the transition; it
/// is [`Context`].
#[deprecated(
    since = "0.5.0",
    note = "renamed to `Context`, re-exported here from `vitaminc_context`"
)]
pub type PrfContext<'a> = Context<'a>;

/// Types that can be used as the domain-separation context of a PRF
/// derivation.
///
/// This is the PRF's view of a context. It is implemented for every type
/// that implements [`IntoContext`], and only through that blanket, so the
/// bytes a PRF derives under are always the context's canonical encoding
/// and always equal to what an AEAD authenticates for the same value. There
/// is nothing to implement here: give a type of your own an `IntoContext`
/// impl and it is an `IntoPrfContext`.
///
/// ```rust
/// use vitaminc_prf::{ContextPiece, IntoContext, IntoPrfContext};
///
/// struct TenantId(u64);
///
/// impl<'a> IntoContext<'a> for TenantId {
///     fn into_context(self) -> ContextPiece<'a> {
///         ("tenant", self.0).into_context()
///     }
/// }
///
/// assert_eq!(
///     TenantId(7).into_prf_context(),
///     ("tenant", 7u64).into_prf_context(),
/// );
/// ```
pub trait IntoPrfContext<'a>: IntoContext<'a> {
    /// The bytes the PRF derives under: the canonical encoding of
    /// [`into_context`](IntoContext::into_context).
    fn into_prf_context(self) -> Context<'a>;
}

impl<'a, T> IntoPrfContext<'a> for T
where
    T: IntoContext<'a>,
{
    fn into_prf_context(self) -> Context<'a> {
        self.into_context().encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_context_is_its_own_prf_context() {
        let ctx = ("users/email", 7u64).into_prf_context();
        assert_eq!(
            ctx.clone().into_prf_context(),
            ctx,
            "an encoded context re-encodes to itself"
        );
    }

    #[test]
    fn the_empty_context_is_the_unit_context() {
        assert_eq!(Context::empty(), ().into_prf_context());
    }
}
