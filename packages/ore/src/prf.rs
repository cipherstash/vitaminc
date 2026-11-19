//! Keying an order scheme from a PRF.

use core::fmt;
use core::marker::PhantomData;

use vitaminc_prf::{MapAccess, PrfVisitor, PrfVisitorError, ResolvedPrf, SeqAccess};
use vitaminc_protected::Protected;
use zeroize::Zeroize;

use crate::OrderKeyInit;

/// A [`PrfVisitor`] that keys the order scheme `S` with the block a PRF
/// derives, and returns the keyed scheme.
///
/// The visitor contains no plaintext. So the value you want to order is
/// never passed to the PRF call. A backend that derives the block later
/// never keeps a copy of the value either. When the visitor returns the
/// scheme, open a space on it and encrypt the value there by reference:
///
/// ```
/// use vitaminc_hmac::HmacSha256Prf;
/// use vitaminc_ore::{OrderEncrypt, OrderTarget, SchemeVisitor};
/// use vitaminc_prf::{PrfKeyInit, PrfValue};
/// use vitaminc_protected::Protected;
/// # use vitaminc_ore::{Context, OrderKeyInit, OrderPlaintext, OrderScheme};
/// # /// A stand-in scheme for the example. The scheme's term is its key,
/// # /// followed by the plaintext bytes. Any scheme keyed with a 32-byte
/// # /// array works.
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
/// // A backend that derives the block later returns a future. With that
/// // backend, use `.await` in place of `into_result`.
/// let scheme: ClwwOre = context
///     .prf_visit_with_context(&prf, domain, SchemeVisitor::new())
///     .into_result()?;
/// let term = scheme.target(OrderTarget::Text).encrypt_checked(&value)?;
/// # let _ = term;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// `S` can be any scheme whose key is a protected array of the block's
/// length ([`OrderKeyInit<Key = Protected<[u8; N]>>`](OrderKeyInit)).
/// Every scheme in `clww-ore` and `ore-rs` has a key of that type.
///
/// # Refused shapes
///
/// Only a single block keys a scheme. The visitor returns
/// [`PrfVisitorError::UnexpectedShape`] for every other shape: a sequence,
/// a map, an absent value, or a passthrough value.
///
/// # What the visitor wipes
///
/// The visitor copies the block into the scheme's protected key, then
/// wipes its own copy. When the visitor refuses a sequence or map, it wipes
/// every block in it, at any depth, before it returns. The visitor cannot
/// wipe copies that the PRF backend made before calling it. The backend is
/// responsible for those copies.
///
/// # Use a separate context for order keys
///
/// Derive order keys under a context that you use only for keys. Do not
/// derive any stored or queried term under that context. With the same PRF
/// key and context, a key and a term would be the same bytes.
pub struct SchemeVisitor<S>(PhantomData<fn() -> S>);

impl<S> SchemeVisitor<S> {
    /// Creates a visitor that keys an `S`.
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

/// Wipes every block in a refused node, at any depth.
///
/// Each nested block is wiped in place, in its container's buffer. Moving a
/// block out first would leave its bytes in the buffer, unwiped. Passthrough
/// values are not secret, so they are dropped without a wipe.
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

    /// `wipe` zeroes every block in place, nested blocks included.
    /// `wipe` leaves the other nodes as they were.
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
