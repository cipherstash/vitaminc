//! Keying an order scheme from a PRF.

use core::fmt;
use core::marker::PhantomData;

use vitaminc_prf::{PrfVisitor, PrfVisitorError};
use vitaminc_protected::Protected;
use zeroize::Zeroize;

use crate::OrderKeyInit;

/// A [`PrfVisitor`] that keys the order scheme `S` from the block a PRF
/// derives, and returns the keyed scheme.
///
/// The visitor holds no plaintext, so the PRF call, and a backend that
/// derives the block later, never hold the value being ordered. Open a space
/// on the scheme it returns and encrypt there, by reference, once the key has
/// arrived:
///
/// ```text
/// let scheme: ClwwOre = context.prf_visit_with_context(&prf, domain, SchemeVisitor::new())
///     .await?;
/// let term = scheme.target(OrderTarget::Text).encrypt_checked(&value)?;
/// ```
///
/// `S` is any scheme keyed with a protected copy of the block
/// ([`OrderKeyInit<Key = Protected<B>>`](OrderKeyInit)). The block is moved
/// into that copy and its own place is wiped, so the only copy of the key is
/// the scheme's, which wipes it when the scheme is dropped.
pub struct SchemeVisitor<S>(PhantomData<fn() -> S>);

impl<S> SchemeVisitor<S> {
    /// A visitor that keys an `S`.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<S> Default for SchemeVisitor<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> fmt::Debug for SchemeVisitor<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SchemeVisitor")
    }
}

impl<S, B, P> PrfVisitor<B, P> for SchemeVisitor<S>
where
    S: OrderKeyInit<Key = Protected<B>> + Send + 'static,
    B: Zeroize + Default + Send + 'static,
{
    type Value = S;

    fn visit_block(self, mut block: B) -> Result<S, PrfVisitorError> {
        let key = Protected::new(core::mem::take(&mut block));
        block.zeroize();
        Ok(S::new(key))
    }
}
