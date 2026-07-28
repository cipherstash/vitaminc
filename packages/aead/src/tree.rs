//! A reusable recursive ciphertext tree, a structural encrypt codec, and the
//! generic [`Decipher`] machinery that drives it.
//!
//! Most ciphers that produce a structured ciphertext (a single sealed value, a
//! sequence, a map, …) share the *same* structural traversal — only the per-leaf
//! sealing/opening differs. This module factors that traversal out:
//!
//! - [`CipherTree<L>`] is the recursive container, generic over the per-leaf
//!   payload `L`.
//! - [`TreeCipher`] implements [`Cipher`]. It does **not** seal anything: it
//!   walks the plaintext structure and collects each byte leaf — together with
//!   the AAD bound at that position — into a [`CipherTree<PendingLeaf>`]. Sealing
//!   is a separate, cipher-specific step.
//! - [`TreeDecipher<O>`] implements [`Decipher`] for any [`LeafOpener`] `O`; it
//!   drives the [`DecipherVisitor`] walk and calls [`LeafOpener::open`] at each
//!   leaf.
//!
//! ## Why sealing is a separate step (encrypt side)
//!
//! Splitting *structure* from *sealing* is what lets one codec serve both an
//! eager, single-key cipher and a batching one:
//!
//! - `vitaminc_encrypt::Aes256Cipher` runs [`TreeCipher`] to build the pending
//!   tree, then seals it leaf-by-leaf under fresh random nonces (see its
//!   `seal_tree`).
//! - A ZeroKMS-backed cipher can build the same pending tree, call
//!   [`CipherTree::leaf_count`] to size a single batched data-key request, then
//!   [`CipherTree::try_map_leaves`] to seal every leaf with the fetched keys.
//!
//! Both reuse [`TreeCipher`] verbatim; only the seal step differs. The earlier
//! `LeafSealer` design called a seal hook eagerly at each leaf, which a batching
//! cipher could not satisfy without buffering plaintext behind a no-op `seal`
//! and a second pass anyway — so the buffering is made explicit here instead.
//!
//! The trade-off of deferring the seal is that the whole plaintext structure is
//! resident (inside [`Protected`], so still zeroized on drop) as a
//! [`CipherTree<PendingLeaf>`] before sealing, rather than each leaf being sealed
//! the instant it is visited. For the small structured values this is used for,
//! that transient residency is negligible.
//!
//! ## Leaf ordering contract
//!
//! [`CipherTree::leaf_count`], [`CipherTree::for_each_leaf`], and
//! [`CipherTree::try_map_leaves`] all visit keyed leaves in the **same**
//! depth-first, left-to-right order. A batching cipher relies on this: it
//! collects per-leaf material with `for_each_leaf` (or sizes a request with
//! `leaf_count`), fetches keys in that order, then re-seals positionally with
//! `try_map_leaves`. The alignment is pinned by a test (`leaf_order_is_stable`).
//!
//! ## Coherence
//!
//! [`TreeDecipher`]'s generic impl is on the concrete local type, **not** a
//! blanket `impl<C> Decipher for &C`. A conditional blanket would conflict
//! (E0119) with any direct `Decipher` impl, and that trait is a public extension
//! point meant to be implemented directly. Concrete ciphers wrap themselves in a
//! [`LeafOpener`] instead.

use std::any::Any;

use vitaminc_protected::Protected;

use crate::{
    Cipher, Decipher, DecipherVisitor, Decrypt, Encrypt, IntoAad, MapAccess, MapCipher, SeqAccess,
    SeqCipher, Unspecified,
};

/// A recursive ciphertext container whose shape mirrors the encrypted plaintext.
///
/// Generic over the per-leaf payload `L` (e.g. a [`PendingLeaf`] awaiting a data
/// key, or a sealed `LocalCipherText`).
#[derive(Debug)]
pub enum CipherTree<L> {
    /// A single sealed value.
    Single(L),
    /// A sequence of ciphertexts (from a `Vec`-shaped plaintext).
    Sequence(Vec<CipherTree<L>>),
    /// A map of (cleartext key, ciphertext value) pairs. Keys are not encrypted.
    Map(Vec<(String, CipherTree<L>)>),
    /// The authenticated absent marker produced by [`Cipher::encrypt_none`].
    None(L),
    /// A typed value passed through unencrypted via [`Cipher::passthrough`].
    ///
    /// The value is type-erased into a boxed [`Any`]; the decrypt side recovers
    /// it with a runtime downcast (see [`Decipher::decrypt_passthrough`]). This
    /// representation is **not** serializable or inspectable: a cipher that needs
    /// to transmit the tree over a wire (e.g. for batch transport) will need a
    /// typed/serializable passthrough variant instead. Passthrough is for
    /// non-sensitive in-process data only — see [`Cipher::passthrough`].
    Passthrough(Box<dyn Any + Send + 'static>),
}

impl<L> CipherTree<L> {
    /// Number of keyed leaves ([`Single`](Self::Single) + [`None`](Self::None));
    /// passthrough nodes carry no leaf payload.
    pub fn leaf_count(&self) -> usize {
        match self {
            CipherTree::Single(_) | CipherTree::None(_) => 1,
            CipherTree::Sequence(items) => items.iter().map(Self::leaf_count).sum(),
            CipherTree::Map(entries) => entries.iter().map(|(_, v)| v.leaf_count()).sum(),
            CipherTree::Passthrough(_) => 0,
        }
    }

    /// Visit every keyed leaf in depth-first, left-to-right order. This is the
    /// canonical leaf order — [`try_map_leaves`](Self::try_map_leaves) consumes
    /// leaves in the same order, so collectors and sealers line up (see the
    /// module-level "Leaf ordering contract").
    pub fn for_each_leaf<'s>(&'s self, f: &mut impl FnMut(&'s L)) {
        match self {
            CipherTree::Single(leaf) | CipherTree::None(leaf) => f(leaf),
            CipherTree::Sequence(items) => items.iter().for_each(|i| i.for_each_leaf(f)),
            CipherTree::Map(entries) => entries.iter().for_each(|(_, v)| v.for_each_leaf(f)),
            CipherTree::Passthrough(_) => {}
        }
    }

    /// Fallibly transform every keyed leaf, preserving structure (and passthrough
    /// nodes). Leaves are visited in [`for_each_leaf`](Self::for_each_leaf) order,
    /// so a closure that draws from an ordered key source stays aligned. The
    /// first `Err` short-circuits.
    pub fn try_map_leaves<M, E>(
        self,
        f: &mut impl FnMut(L) -> Result<M, E>,
    ) -> Result<CipherTree<M>, E> {
        Ok(match self {
            CipherTree::Single(leaf) => CipherTree::Single(f(leaf)?),
            CipherTree::None(leaf) => CipherTree::None(f(leaf)?),
            CipherTree::Sequence(items) => CipherTree::Sequence(
                items
                    .into_iter()
                    .map(|item| item.try_map_leaves(f))
                    .collect::<Result<Vec<_>, E>>()?,
            ),
            CipherTree::Map(entries) => CipherTree::Map(
                entries
                    .into_iter()
                    .map(|(k, v)| v.try_map_leaves(f).map(|v| (k, v)))
                    .collect::<Result<Vec<_>, E>>()?,
            ),
            CipherTree::Passthrough(value) => CipherTree::Passthrough(value),
        })
    }
}

/// A byte leaf collected by [`TreeCipher`], awaiting sealing.
///
/// Carries the plaintext (kept inside [`Protected`] so the zeroize-on-drop
/// guarantee survives until the leaf is sealed or dropped) and the AAD bytes
/// bound at this position in the structure. A cipher's seal step consumes a
/// `PendingLeaf` and produces its own sealed leaf type.
pub struct PendingLeaf {
    /// The plaintext bytes to seal. For an [`encrypt_none`](Cipher::encrypt_none)
    /// marker this is the empty vector (sealed so its tag still binds the AAD).
    pub plaintext: Protected<Vec<u8>>,
    /// The fully-encoded AAD bytes the leaf must be authenticated against.
    pub aad: Vec<u8>,
}

impl PendingLeaf {
    fn new<'a, A: IntoAad<'a>>(plaintext: Protected<Vec<u8>>, aad: A) -> Self {
        Self {
            plaintext,
            aad: aad.into_aad().as_bytes().to_vec(),
        }
    }
}

// =============================================================================
// Encrypt side — a structural codec that collects, but does not seal.
// =============================================================================

/// A [`Cipher`] that walks a plaintext structure into a [`CipherTree<PendingLeaf>`]
/// **without sealing**. Run this to get the tree shape and per-leaf plaintext+AAD,
/// then seal the leaves with a cipher-specific step (see the module docs).
pub struct TreeCipher;

impl Cipher for TreeCipher {
    type Ok = CipherTree<PendingLeaf>;
    type Error = Unspecified;
    type SeqCipher = TreeSeq;
    type MapCipher = TreeMap;

    fn encrypt_bytes_vec<'a, A>(
        self,
        data: Protected<Vec<u8>>,
        aad: A,
    ) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        Ok(CipherTree::Single(PendingLeaf::new(data, aad)))
    }

    fn encrypt_seq(self, size_hint: Option<usize>) -> Self::SeqCipher {
        TreeSeq {
            items: Vec::with_capacity(size_hint.unwrap_or(0)),
        }
    }

    fn encrypt_map(self) -> Self::MapCipher {
        TreeMap {
            entries: Vec::new(),
            current_key: None,
        }
    }

    fn encrypt_none<'a, A>(self, aad: A) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        // The marker seals an empty plaintext so its tag still binds the AAD.
        Ok(CipherTree::None(PendingLeaf::new(
            Protected::new(Vec::new()),
            aad,
        )))
    }

    fn passthrough<T>(self, value: T) -> Result<Self::Ok, Self::Error>
    where
        T: Any + Send + 'static,
    {
        Ok(CipherTree::Passthrough(Box::new(value)))
    }
}

/// [`SeqCipher`] for [`TreeCipher`]: accumulates a pending [`CipherTree`] per element.
pub struct TreeSeq {
    items: Vec<CipherTree<PendingLeaf>>,
}

impl SeqCipher for TreeSeq {
    type Ok = CipherTree<PendingLeaf>;
    type Error = Unspecified;

    fn encrypt_next<'a, T, A>(mut self, data: T, aad: A) -> Result<Self, Self::Error>
    where
        T: Encrypt,
        A: IntoAad<'a>,
    {
        // Recurse with a fresh structural codec — the element is collected, not sealed.
        self.items.push(data.encrypt_with_aad(TreeCipher, aad)?);
        Ok(self)
    }

    fn passthrough_next<T>(mut self, value: T) -> Result<Self, Self::Error>
    where
        T: Any + Send + 'static,
    {
        self.items.push(CipherTree::Passthrough(Box::new(value)));
        Ok(self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(CipherTree::Sequence(self.items))
    }
}

/// [`MapCipher`] for [`TreeCipher`]: keys are stored in the clear; values become
/// sub-trees. Enforces the key→value call contract like a hand-written impl.
pub struct TreeMap {
    entries: Vec<(String, CipherTree<PendingLeaf>)>,
    current_key: Option<&'static str>,
}

impl MapCipher for TreeMap {
    type Ok = CipherTree<PendingLeaf>;
    type Error = Unspecified;

    fn encrypt_key(mut self, key: &'static str) -> Result<Self, Self::Error> {
        // Two keys with no intervening value is a contract violation.
        if self.current_key.is_some() {
            return Err(Unspecified);
        }
        self.current_key = Some(key);
        Ok(self)
    }

    fn encrypt_value<'a, T, A>(mut self, value: T, aad: A) -> Result<Self, Self::Error>
    where
        T: Encrypt,
        A: IntoAad<'a>,
    {
        let key = self.current_key.take().ok_or(Unspecified)?;
        let value = value.encrypt_with_aad(TreeCipher, aad)?;
        self.entries.push((key.to_string(), value));
        Ok(self)
    }

    fn passthrough_entry<T>(mut self, key: &'static str, value: T) -> Result<Self, Self::Error>
    where
        T: Any + Send + 'static,
    {
        if self.current_key.is_some() {
            return Err(Unspecified);
        }
        self.entries
            .push((key.to_string(), CipherTree::Passthrough(Box::new(value))));
        Ok(self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        if self.current_key.is_some() {
            return Err(Unspecified);
        }
        Ok(CipherTree::Map(self.entries))
    }
}

// =============================================================================
// Decrypt side
// =============================================================================

/// Opens one leaf back to plaintext. The single per-cipher operation on the
/// decrypt side.
///
/// `Copy` because openers are stateless lookups — each leaf self-identifies the
/// key it needs (e.g. via a stored nonce, or an iv+tag a batching cipher resolves
/// against a pre-fetched key map), so the same opener can be threaded through
/// every leaf of the structure without ownership churn.
pub trait LeafOpener: Copy {
    /// The per-leaf payload this opener consumes (a cipher's sealed leaf type).
    type Leaf;

    /// Open `leaf`, authenticating against `aad`, returning the plaintext bytes.
    fn open(self, leaf: Self::Leaf, aad: &[u8]) -> Result<Protected<Vec<u8>>, Unspecified>;
}

/// A [`Decipher`] over a [`CipherTree`] that delegates each leaf to a
/// [`LeafOpener`]. Synchronous: `Ok<T> = Result<T, Unspecified>`.
pub struct TreeDecipher<O: LeafOpener> {
    tree: CipherTree<O::Leaf>,
    opener: O,
}

impl<O: LeafOpener> TreeDecipher<O> {
    /// Build a decipher that opens `tree`'s leaves with `opener`.
    pub fn new(opener: O, tree: CipherTree<O::Leaf>) -> Self {
        Self { tree, opener }
    }
}

impl<'c, O: LeafOpener> Decipher<'c> for TreeDecipher<O> {
    type Ok<T>
        = Result<T, Unspecified>
    where
        T: Send + 'c;

    fn map_ok<T, U, F>(ok: Self::Ok<T>, f: F) -> Self::Ok<U>
    where
        T: Send + 'c,
        U: Send + 'c,
        F: FnOnce(T) -> U,
    {
        ok.map(f)
    }

    fn decrypt_bytes<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        match self.tree {
            CipherTree::Single(leaf) => {
                let aad = aad.into_aad();
                visitor.visit_bytes_vec(self.opener.open(leaf, aad.as_bytes())?)
            }
            _ => Err(Unspecified),
        }
    }

    fn decrypt_seq<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        match self.tree {
            CipherTree::Sequence(items) => visitor.visit_seq(TreeSeqAccess {
                items: items.into_iter(),
                opener: self.opener,
                aad: aad.into_aad(),
            }),
            _ => Err(Unspecified),
        }
    }

    fn decrypt_map<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        match self.tree {
            CipherTree::Map(entries) => visitor.visit_map(TreeMapAccess {
                entries: entries.into_iter(),
                opener: self.opener,
                aad: aad.into_aad(),
            }),
            _ => Err(Unspecified),
        }
    }

    fn decrypt_passthrough<T>(self) -> Self::Ok<T>
    where
        T: Any + Send + 'static,
    {
        match self.tree {
            CipherTree::Passthrough(boxed) => {
                boxed.downcast::<T>().map(|b| *b).map_err(|_| Unspecified)
            }
            _ => Err(Unspecified),
        }
    }

    fn decrypt_option<'a, T, A>(self, aad: A) -> Self::Ok<Option<T>>
    where
        T: Decrypt<'c> + 'c,
        A: IntoAad<'a>,
    {
        match self.tree {
            CipherTree::None(leaf) => {
                // Authenticate the absent marker (verifies the tag) and discard.
                let aad = aad.into_aad();
                self.opener.open(leaf, aad.as_bytes())?;
                Ok(None)
            }
            CipherTree::Passthrough(_) => Err(Unspecified),
            // Any other shape is the `Some` payload — recurse into `T`.
            other => T::decrypt_with_aad(TreeDecipher::new(self.opener, other), aad).map(Some),
        }
    }
}

/// [`SeqAccess`] for [`TreeDecipher`]. Re-applies the sequence AAD to every
/// element by borrowing the stored bytes (no per-element allocation).
pub struct TreeSeqAccess<'a, O: LeafOpener> {
    items: std::vec::IntoIter<CipherTree<O::Leaf>>,
    opener: O,
    aad: crate::Aad<'a>,
}

impl<'c, 'a, O: LeafOpener> SeqAccess<'c> for TreeSeqAccess<'a, O> {
    type Error = Unspecified;

    fn next_element<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<T>, Self::Error> {
        match self.items.next() {
            Some(tree) => {
                T::decrypt_with_aad(TreeDecipher::new(self.opener, tree), self.aad.as_bytes())
                    .map(Some)
            }
            None => Ok(None),
        }
    }
}

/// [`MapAccess`] for [`TreeDecipher`]. Keys are returned in the clear; each value
/// is decrypted under the stored AAD.
pub struct TreeMapAccess<'a, O: LeafOpener> {
    entries: std::vec::IntoIter<(String, CipherTree<O::Leaf>)>,
    opener: O,
    aad: crate::Aad<'a>,
}

impl<'c, 'a, O: LeafOpener> MapAccess<'c> for TreeMapAccess<'a, O> {
    type Error = Unspecified;

    fn next_entry<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<(String, T)>, Self::Error> {
        match self.entries.next() {
            Some((key, tree)) => {
                let value =
                    T::decrypt_with_aad(TreeDecipher::new(self.opener, tree), self.aad.as_bytes())?;
                Ok(Some((key, value)))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the module's "Leaf ordering contract": `for_each_leaf`,
    /// `try_map_leaves`, and `leaf_count` must agree on which leaves exist and in
    /// what order. A batching cipher collects per-leaf material in `for_each_leaf`
    /// order and re-seals positionally with `try_map_leaves`; if the two ever
    /// diverged, leaf *i* would be sealed under the key fetched for leaf *j*. This
    /// test would catch that before it became a silent key/leaf misalignment.
    #[test]
    fn leaf_order_is_stable() {
        // A mixed tree: a map containing a passthrough (no leaf), a single, and a
        // nested sequence — exercises every variant of the traversal.
        let tree: CipherTree<u32> = CipherTree::Map(vec![
            ("pt".to_string(), CipherTree::Passthrough(Box::new(0u8))),
            ("a".to_string(), CipherTree::Single(1)),
            (
                "seq".to_string(),
                CipherTree::Sequence(vec![
                    CipherTree::Single(2),
                    CipherTree::None(3),
                    CipherTree::Single(4),
                ]),
            ),
        ]);

        // Passthrough carries no leaf, so 4 keyed leaves: 1, 2, 3, 4.
        assert_eq!(tree.leaf_count(), 4);

        let mut visited = Vec::new();
        tree.for_each_leaf(&mut |leaf: &u32| visited.push(*leaf));
        assert_eq!(visited, vec![1, 2, 3, 4]);

        // try_map_leaves consumes leaves in the *same* order: tag each with its
        // visit index and confirm the structure-preserving result lines up.
        let mut idx = 0u32;
        let mapped: CipherTree<(u32, u32)> = tree
            .try_map_leaves(&mut |leaf| {
                let pos = idx;
                idx += 1;
                Ok::<_, ()>((leaf, pos))
            })
            .expect("infallible");

        let mut pairs = Vec::new();
        mapped.for_each_leaf(&mut |(leaf, pos): &(u32, u32)| pairs.push((*leaf, *pos)));
        // (leaf value, position) — positions follow the same 0..4 leaf order.
        assert_eq!(pairs, vec![(1, 0), (2, 1), (3, 2), (4, 3)]);
    }
}
