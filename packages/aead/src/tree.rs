//! A reusable recursive ciphertext tree and the generic [`Cipher`]/[`Decipher`]
//! machinery that drives it.
//!
//! Most ciphers that produce a structured ciphertext (a single sealed value, a
//! sequence, a map, …) share the *same* structural traversal — only the per-leaf
//! sealing/opening differs. This module factors that traversal out:
//!
//! - [`CipherTree<L>`] is the recursive container, generic over the per-leaf
//!   payload `L`.
//! - [`TreeCipher<S>`] implements [`Cipher`] for any [`LeafSealer`] `S`; it
//!   handles the sequence/map/option/passthrough structure and calls
//!   [`LeafSealer::seal`] at each byte leaf.
//! - [`TreeDecipher<O>`] implements [`Decipher`] for any [`LeafOpener`] `O`; it
//!   drives the [`DecipherVisitor`] walk and calls [`LeafOpener::open`] at each
//!   leaf.
//!
//! A concrete cipher therefore only has to define its leaf type and the two
//! leaf operations. `vitaminc_encrypt::Aes256Cipher` seals each leaf eagerly
//! under a random nonce; a ZeroKMS-backed cipher can stash plaintext leaves and
//! batch-seal them afterwards — both reuse everything here.
//!
//! ## Coherence
//!
//! The generic impls are on the concrete local types [`TreeCipher`] /
//! [`TreeDecipher`], **not** a blanket `impl<C> Cipher for &C`. A conditional
//! blanket would conflict (E0119) with any direct `Cipher`/`Decipher` impl,
//! and those traits are public extension points meant to be implemented
//! directly. Concrete ciphers wrap themselves in a [`LeafSealer`]/[`LeafOpener`]
//! instead.

use std::any::Any;

use vitaminc_protected::Protected;

use crate::{
    Cipher, Decipher, DecipherVisitor, Decrypt, Encrypt, IntoAad, MapAccess, MapCipher, SeqAccess,
    SeqCipher, Unspecified,
};

/// A recursive ciphertext container whose shape mirrors the encrypted plaintext.
///
/// Generic over the per-leaf payload `L` (e.g. a sealed `LocalCipherText`, or a
/// pending plaintext awaiting a data key).
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
    /// keys in the same order, so collectors and sealers line up.
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
            CipherTree::Sequence(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(item.try_map_leaves(f)?);
                }
                CipherTree::Sequence(out)
            }
            CipherTree::Map(entries) => {
                let mut out = Vec::with_capacity(entries.len());
                for (k, v) in entries {
                    out.push((k, v.try_map_leaves(f)?));
                }
                CipherTree::Map(out)
            }
            CipherTree::Passthrough(value) => CipherTree::Passthrough(value),
        })
    }
}

/// Seals one plaintext leaf. The single per-cipher operation on the encrypt side.
///
/// Implementors are typically a `Copy` wrapper around a borrowed cipher (so the
/// sealer can be threaded through nested structures without ownership churn).
pub trait LeafSealer: Copy {
    /// The sealed (or pending) per-leaf payload this sealer produces.
    type Leaf;

    /// Seal `plaintext` bound to `aad`, producing the leaf payload.
    fn seal(self, plaintext: Protected<Vec<u8>>, aad: &[u8]) -> Result<Self::Leaf, Unspecified>;
}

/// Opens one leaf back to plaintext. The single per-cipher operation on the
/// decrypt side. `Copy` for the same threading reason as [`LeafSealer`].
pub trait LeafOpener: Copy {
    /// The per-leaf payload this opener consumes (matches a [`LeafSealer::Leaf`]).
    type Leaf;

    /// Open `leaf`, authenticating against `aad`, returning the plaintext bytes.
    fn open(self, leaf: Self::Leaf, aad: &[u8]) -> Result<Protected<Vec<u8>>, Unspecified>;
}

// =============================================================================
// Encrypt side
// =============================================================================

/// A [`Cipher`] that builds a [`CipherTree`] by delegating each leaf to a
/// [`LeafSealer`]. Wrap a cipher's sealer in this to get the full structural
/// drive for free.
pub struct TreeCipher<S>(pub S);

impl<S: LeafSealer> Cipher for TreeCipher<S> {
    type Ok = CipherTree<S::Leaf>;
    type Error = Unspecified;
    type SeqCipher = TreeSeq<S>;
    type MapCipher = TreeMap<S>;

    fn encrypt_bytes_vec<'a, A>(
        self,
        data: Protected<Vec<u8>>,
        aad: A,
    ) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        let aad = aad.into_aad();
        Ok(CipherTree::Single(self.0.seal(data, aad.as_bytes())?))
    }

    fn encrypt_seq(self, size_hint: Option<usize>) -> Self::SeqCipher {
        TreeSeq {
            sealer: self.0,
            items: Vec::with_capacity(size_hint.unwrap_or(0)),
        }
    }

    fn encrypt_map(self) -> Self::MapCipher {
        TreeMap {
            sealer: self.0,
            entries: Vec::new(),
            current_key: None,
        }
    }

    fn encrypt_none<'a, A>(self, aad: A) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        // Seal an empty plaintext so the leaf's tag binds the AAD.
        let aad = aad.into_aad();
        Ok(CipherTree::None(
            self.0.seal(Protected::new(Vec::new()), aad.as_bytes())?,
        ))
    }

    fn passthrough<T>(self, value: T) -> Result<Self::Ok, Self::Error>
    where
        T: Any + Send + 'static,
    {
        Ok(CipherTree::Passthrough(Box::new(value)))
    }
}

/// [`SeqCipher`] for [`TreeCipher`]: accumulates a [`CipherTree`] per element.
pub struct TreeSeq<S: LeafSealer> {
    sealer: S,
    items: Vec<CipherTree<S::Leaf>>,
}

impl<S: LeafSealer> SeqCipher for TreeSeq<S> {
    type Ok = CipherTree<S::Leaf>;
    type Error = Unspecified;

    fn encrypt_next<'a, T, A>(mut self, data: T, aad: A) -> Result<Self, Self::Error>
    where
        T: Encrypt,
        A: IntoAad<'a>,
    {
        // Recurse with a fresh `TreeCipher` over the (Copy) sealer.
        self.items
            .push(data.encrypt_with_aad(TreeCipher(self.sealer), aad)?);
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
pub struct TreeMap<S: LeafSealer> {
    sealer: S,
    entries: Vec<(String, CipherTree<S::Leaf>)>,
    current_key: Option<&'static str>,
}

impl<S: LeafSealer> MapCipher for TreeMap<S> {
    type Ok = CipherTree<S::Leaf>;
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
        let value = value.encrypt_with_aad(TreeCipher(self.sealer), aad)?;
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
            other => T::decrypt_with_aad(
                TreeDecipher {
                    tree: other,
                    opener: self.opener,
                },
                aad,
            )
            .map(Some),
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
            Some(tree) => T::decrypt_with_aad(
                TreeDecipher {
                    tree,
                    opener: self.opener,
                },
                self.aad.as_bytes(),
            )
            .map(Some),
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
                let value = T::decrypt_with_aad(
                    TreeDecipher {
                        tree,
                        opener: self.opener,
                    },
                    self.aad.as_bytes(),
                )?;
                Ok(Some((key, value)))
            }
            None => Ok(None),
        }
    }
}
