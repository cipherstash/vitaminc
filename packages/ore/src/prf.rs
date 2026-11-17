//! Keying an order scheme from a PRF.

use core::fmt;
use core::marker::PhantomData;

use vitaminc_prf::{MapAccess, PrfVisitor, PrfVisitorError, ResolvedPrf, SeqAccess};
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
/// `S` is any scheme keyed with a protected array of the block's length
/// ([`OrderKeyInit<Key = Protected<[u8; N]>>`](OrderKeyInit)), as every
/// scheme in `clww-ore` and `ore-rs` is. The block is copied into that
/// protected key and the visitor's own copy is wiped. Any other shape is
/// refused with [`PrfVisitorError::UnexpectedShape`], and the visitor wipes
/// every block in a refused sequence or map, at any depth, before it
/// returns. Copies the PRF backend made before it called the visitor are
/// the backend's to wipe.
///
/// Derive order keys under a context of their own, one that no stored or
/// queried term is derived under. A key and a term from the same PRF key
/// and context would be the same bytes.
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

impl<S, const N: usize, P> PrfVisitor<[u8; N], P> for SchemeVisitor<S>
where
    S: OrderKeyInit<Key = Protected<[u8; N]>> + Send + 'static,
{
    type Value = S;

    fn visit_block(self, mut block: [u8; N]) -> Result<S, PrfVisitorError> {
        let key = Protected::new(block);
        block.zeroize();
        Ok(S::new(key))
    }

    fn visit_seq(self, seq: SeqAccess<[u8; N], P>) -> Result<S, PrfVisitorError> {
        seq.for_each(|mut node| wipe(&mut node));
        Err(PrfVisitorError::UnexpectedShape)
    }

    fn visit_map(self, map: MapAccess<[u8; N], P>) -> Result<S, PrfVisitorError> {
        map.for_each(|(_, mut node)| wipe(&mut node));
        Err(PrfVisitorError::UnexpectedShape)
    }
}

/// Wipe every block in a refused node, at any depth. Nested blocks are
/// wiped where they are, in their container's buffer, not moved out first.
/// Passthrough values are not secret and drop as they are.
fn wipe<const N: usize, P>(node: &mut ResolvedPrf<[u8; N], P>) {
    match node {
        ResolvedPrf::Block(block) => block.zeroize(),
        ResolvedPrf::Sequence(nodes) => nodes.iter_mut().for_each(wipe),
        ResolvedPrf::Map(entries) => entries.iter_mut().for_each(|(_, node)| wipe(node)),
        ResolvedPrf::Absent | ResolvedPrf::Passthrough(_) => {}
    }
}
