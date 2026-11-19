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
/// ```
/// use vitaminc_hmac::HmacSha256Prf;
/// use vitaminc_ore::{OrderEncrypt, OrderTarget, SchemeVisitor};
/// use vitaminc_prf::{PrfKeyInit, PrfValue};
/// use vitaminc_protected::Protected;
/// # use vitaminc_ore::{Context, OrderKeyInit, OrderPlaintext, OrderScheme};
/// # /// Keeps its key and the bytes, for the example. Any scheme keyed
/// # /// with a 32-byte array will do.
/// # struct ClwwOre(Protected<[u8; 32]>);
/// # impl OrderScheme for ClwwOre {
/// #     const NAME: &'static str = "example";
/// #     type Term = Vec<u8>;
/// #     type Error = core::convert::Infallible;
/// #     type Space = ();
/// #     fn open(&self, _: OrderTarget, _: &Context<'_>) -> Result<(), Self::Error> {
/// #         Ok(())
/// #     }
/// #     fn encrypt_plaintext(&self, _: &(), p: &OrderPlaintext) -> Result<Vec<u8>, Self::Error> {
/// #         use vitaminc_protected::Controlled;
/// #         let mut term = self.0.risky_ref().to_vec();
/// #         term.extend_from_slice(p.bytes().risky_ref());
/// #         Ok(term)
/// #     }
/// #     fn compare(a: &Vec<u8>, b: &Vec<u8>) -> Option<core::cmp::Ordering> {
/// #         Some(a.cmp(b))
/// #     }
/// # }
/// # impl OrderKeyInit for ClwwOre {
/// #     type Key = Protected<[u8; 32]>;
/// #     type KeyError = core::convert::Infallible;
/// #     fn new(key: Self::Key) -> Self {
/// #         Self(key)
/// #     }
/// #     fn try_from_bytes(_: Protected<Vec<u8>>) -> Result<Self, Self::KeyError> {
/// #         unimplemented!("not used by the example")
/// #     }
/// # }
/// # vitaminc_ore::supports_every_target!(ClwwOre);
/// # let prf = HmacSha256Prf::new(Protected::new([7u8; 32]));
/// # let context: &[u8] = b"users/surname";
/// # let domain = "order";
/// let value = String::from("Lovelace");
///
/// // A real backend may derive the block later; `.await` the result there.
/// let scheme: ClwwOre = context
///     .prf_visit_with_context(&prf, domain, SchemeVisitor::new())
///     .into_result()?;
/// let term = scheme.target(OrderTarget::Text).encrypt_checked(&value)?;
/// # let _ = term;
/// # Ok::<(), Box<dyn std::error::Error>>(())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every block in the node, at any depth, in order.
    fn blocks(node: &ResolvedPrf<[u8; 4], ()>) -> Vec<[u8; 4]> {
        match node {
            ResolvedPrf::Block(block) => vec![*block],
            ResolvedPrf::Sequence(nodes) => nodes.iter().flat_map(blocks).collect(),
            ResolvedPrf::Map(entries) => {
                entries.iter().flat_map(|(_, node)| blocks(node)).collect()
            }
            ResolvedPrf::Absent | ResolvedPrf::Passthrough(_) => vec![],
        }
    }

    /// A refused node's blocks are wiped where they are, nested ones
    /// included, and its other nodes are left as they were.
    #[test]
    fn wipe_zeroes_every_block_at_any_depth() {
        let mut node = ResolvedPrf::Sequence(vec![
            ResolvedPrf::Block([1; 4]),
            ResolvedPrf::Sequence(vec![ResolvedPrf::Block([2; 4]), ResolvedPrf::Absent]),
            ResolvedPrf::Map(vec![
                (String::from("a"), ResolvedPrf::Block([3; 4])),
                (
                    String::from("b"),
                    ResolvedPrf::Map(vec![(String::from("c"), ResolvedPrf::Block([4; 4]))]),
                ),
                (String::from("d"), ResolvedPrf::Passthrough(())),
            ]),
        ]);
        assert_eq!(blocks(&node).len(), 4, "the tree holds four blocks");

        wipe(&mut node);

        assert_eq!(blocks(&node), vec![[0; 4]; 4], "a block was left unwiped");
        let ResolvedPrf::Sequence(nodes) = &node else {
            panic!("wipe changed the node's shape")
        };
        assert!(
            matches!(&nodes[1], ResolvedPrf::Sequence(inner) if matches!(inner[1], ResolvedPrf::Absent)),
            "wipe changed an absent node"
        );
    }
}
