//! Encryption as a sink, over a bytes-only backend.
//!
//! The layers:
//!
//! - [`EncryptSink`]: scalars to tagged leaf bytes, and the container
//!   rules (element and entry AAD, empty markers, at least one sealed node,
//!   no duplicate keys). This is the rest of today's `Cipher` plus
//!   `impl Encrypt for Value`, in one place. It never calls a backend: it
//!   produces a tree of [`Pending`] leaves, each with its plaintext and the
//!   AAD its position derives.
//! - [`Backend`] and [`AsyncBackend`]: seal and open one leaf, or every
//!   leaf of one document at once. Bytes only, no types. This is the part
//!   of today's `Cipher` that genuinely belongs to the AEAD.
//! - [`seal_all`] and [`seal_all_async`]: the leaf traversal. Split the
//!   planned tree into its shape and its leaves, seal the leaves, put them
//!   back.
//!
//! So the walk is synchronous whatever the backend is. A native binding
//! can walk a live host object that can't be awaited in the middle, and a
//! remote key provider can seal every leaf of a document in one round
//! trip.
//!
//! The ciphertext tree reuses vitaminc's `CipherText` enum, with a
//! passthrough payload that is a frame, not a `Value` or a `Box<dyn Any>`.

use std::collections::HashSet;
use std::future::Future;
use std::marker::PhantomData;

use futures::future::try_join_all;
use vitaminc_aead::{Cipher, CipherText, Context, Decipher, DecipherVisitor, IntoAad, LocalCipherText, Unspecified};
use vitaminc_encrypt::{Aes256Cipher, AesCipherText};
use vitaminc_protected::{Controlled, Protected};

use crate::frame_writer::{to_frame, FrameWriteError};
use crate::kinds::{Logical, Physical};
use crate::model::{Error, MapSink, Plaintext, SeqSink, Sink, SourceError};
use crate::scalar::{self, Form, ScalarError};

/// A leaf the walk has planned but nobody has sealed: its tagged plaintext
/// and the AAD derived for its place in the tree.
pub struct Pending {
    pub plaintext: Protected<Vec<u8>>,
    pub aad: Context<'static>,
}

/// Seal and open one leaf, synchronously. The backend binds the wire
/// version into the AAD itself (`for_leaf`), as `seal_leaf` does today.
pub trait Backend {
    type Leaf;
    type Error;

    fn seal(&self, plaintext: Protected<Vec<u8>>, aad: &Context<'_>) -> Result<Self::Leaf, Self::Error>;
    fn open(&self, leaf: Self::Leaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Self::Error>;
}

/// Seal and open leaves through something that has to be awaited: a
/// remote key provider, a KMS, a cloud HSM.
///
/// `seal_many` and `open_many` take every leaf of one document in walk
/// order. The defaults seal each leaf concurrently; a provider with a batch
/// API overrides them to make one round trip per document.
pub trait AsyncBackend: Sync {
    type Leaf: Send;
    type Error: Send;

    fn seal(&self, plaintext: Protected<Vec<u8>>, aad: Context<'static>) -> impl Future<Output = Result<Self::Leaf, Self::Error>> + Send;

    fn open(&self, leaf: Self::Leaf, aad: Context<'static>) -> impl Future<Output = Result<Protected<Vec<u8>>, Self::Error>> + Send;

    /// Every leaf of one document, in walk order. Must return one sealed
    /// leaf per pending leaf, in the same order.
    fn seal_many(&self, leaves: Vec<Pending>) -> impl Future<Output = Result<Vec<Self::Leaf>, Self::Error>> + Send {
        async move { try_join_all(leaves.into_iter().map(|p| self.seal(p.plaintext, p.aad))).await }
    }

    /// Every sealed leaf of one document with the AAD its position derives,
    /// in walk order. Must return one plaintext per leaf, in the same order.
    fn open_many(
        &self,
        leaves: Vec<(Self::Leaf, Context<'static>)>,
    ) -> impl Future<Output = Result<Vec<Protected<Vec<u8>>>, Self::Error>> + Send {
        async move { try_join_all(leaves.into_iter().map(|(leaf, aad)| self.open(leaf, aad))).await }
    }
}

/// SPIKE: AES via today's public API, so the ciphertext is byte-compatible
/// with today's and the tests can prove it. A real backend would implement
/// `seal`/`open` directly on the key and nonce generator: about 30 lines.
impl Backend for Aes256Cipher {
    type Leaf = LocalCipherText;
    type Error = Unspecified;

    fn seal(&self, plaintext: Protected<Vec<u8>>, aad: &Context<'_>) -> Result<LocalCipherText, Unspecified> {
        match self.encrypt_bytes_vec(plaintext, Context::from_encoded(aad.as_bytes()))? {
            AesCipherText::Single(leaf) => Ok(leaf),
            _ => Err(Unspecified),
        }
    }

    fn open(&self, leaf: LocalCipherText, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Unspecified> {
        struct Raw;
        impl DecipherVisitor<'_> for Raw {
            type Value = Protected<Vec<u8>>;
            fn visit_bytes_vec(self, data: Protected<Vec<u8>>) -> Result<Self::Value, Unspecified> {
                Ok(data)
            }
        }
        self.decipher(AesCipherText::Single(leaf))
            .decrypt_bytes(Raw, Context::from_encoded(aad.as_bytes()))
    }
}

/// A passthrough subtree: one transport value frame, in the clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassthroughFrame(pub Vec<u8>);

pub type Node<L> = CipherText<L, PassthroughFrame>;

#[derive(Debug)]
pub enum EncryptError<E> {
    Backend(E),
    Source(SourceError),
    /// Duplicate key, a container with nothing sealed in it, a value
    /// that isn't valid for its logical type, or a backend that returned
    /// the wrong number of leaves.
    Shape(&'static str),
}

impl<E> Error for EncryptError<E> {
    fn source(error: SourceError) -> Self {
        Self::Source(error)
    }
}

impl<E> From<FrameWriteError> for EncryptError<E> {
    fn from(error: FrameWriteError) -> Self {
        match error {
            FrameWriteError::Source(e) => Self::Source(e),
            _ => Self::Shape("passthrough subtree can't be framed"),
        }
    }
}

/// Walk a source into a tree of pending leaves. No backend involved: this
/// is the whole of the data-model work, and it's synchronous.
pub fn plan<'a, P, E, A>(p: P, aad: A) -> Result<Node<Pending>, EncryptError<E>>
where
    P: Plaintext,
    A: IntoAad<'a>,
{
    p.visit(EncryptSink::root(aad))
}

/// Encrypt any source with tagged leaves.
pub fn encrypt<'a, P, B, A>(p: P, backend: &B, aad: A) -> Result<Node<B::Leaf>, EncryptError<B::Error>>
where
    P: Plaintext,
    B: Backend,
    A: IntoAad<'a>,
{
    seal_all(backend, plan(p, aad)?)
}

/// Encrypt any source through an async backend. The walk happens before
/// the first await.
pub async fn encrypt_async<'a, P, B, A>(p: P, backend: &B, aad: A) -> Result<Node<B::Leaf>, EncryptError<B::Error>>
where
    P: Plaintext,
    B: AsyncBackend,
    A: IntoAad<'a>,
{
    seal_all_async(backend, plan(p, aad)?).await
}

/// Seal every pending leaf, one at a time.
pub fn seal_all<B: Backend>(backend: &B, node: Node<Pending>) -> Result<Node<B::Leaf>, EncryptError<B::Error>> {
    let mut pending = Vec::new();
    let shape = split(node, &mut pending);
    let leaves = pending
        .into_iter()
        .map(|p| backend.seal(p.plaintext, &p.aad))
        .collect::<Result<Vec<_>, _>>()
        .map_err(EncryptError::Backend)?;
    Ok(fill(shape, leaves)?)
}

/// Seal every pending leaf in one `seal_many` call.
pub async fn seal_all_async<B: AsyncBackend>(backend: &B, node: Node<Pending>) -> Result<Node<B::Leaf>, EncryptError<B::Error>> {
    let mut pending = Vec::new();
    let shape = split(node, &mut pending);
    let leaves = backend.seal_many(pending).await.map_err(EncryptError::Backend)?;
    Ok(fill(shape, leaves)?)
}

/// A tree's shape with its leaves taken out, in walk order.
pub(crate) fn split<L>(node: Node<L>, leaves: &mut Vec<L>) -> Node<()> {
    match node {
        CipherText::Single(leaf) => {
            leaves.push(leaf);
            CipherText::Single(())
        }
        CipherText::Sequence(items) => CipherText::Sequence(items.into_iter().map(|n| split(n, leaves)).collect()),
        CipherText::EmptySequence(leaf) => {
            leaves.push(leaf);
            CipherText::EmptySequence(())
        }
        CipherText::Map(entries) => {
            CipherText::Map(entries.into_iter().map(|(k, n)| (k, split(n, leaves))).collect())
        }
        CipherText::EmptyMap(leaf) => {
            leaves.push(leaf);
            CipherText::EmptyMap(())
        }
        CipherText::None(leaf) => {
            leaves.push(leaf);
            CipherText::None(())
        }
        CipherText::Passthrough(p) => CipherText::Passthrough(p),
    }
}

/// Put leaves back into a shape, in walk order. Refuses a count mismatch,
/// which can only be a backend bug.
pub(crate) fn fill<L>(shape: Node<()>, leaves: Vec<L>) -> Result<Node<L>, LeafCount> {
    let mut leaves = leaves.into_iter();
    let node = fill_from(shape, &mut leaves).ok_or(LeafCount::TooFew)?;
    if leaves.next().is_some() {
        return Err(LeafCount::TooMany);
    }
    Ok(node)
}

/// A backend returned a different number of leaves than it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeafCount {
    TooFew,
    TooMany,
}

impl<E> From<LeafCount> for EncryptError<E> {
    fn from(count: LeafCount) -> Self {
        EncryptError::Shape(match count {
            LeafCount::TooFew => "backend returned too few leaves",
            LeafCount::TooMany => "backend returned too many leaves",
        })
    }
}

fn fill_from<L>(shape: Node<()>, leaves: &mut impl Iterator<Item = L>) -> Option<Node<L>> {
    Some(match shape {
        CipherText::Single(()) => CipherText::Single(leaves.next()?),
        CipherText::Sequence(items) => {
            CipherText::Sequence(items.into_iter().map(|n| fill_from(n, leaves)).collect::<Option<_>>()?)
        }
        CipherText::EmptySequence(()) => CipherText::EmptySequence(leaves.next()?),
        CipherText::Map(entries) => CipherText::Map(
            entries
                .into_iter()
                .map(|(k, n)| fill_from(n, leaves).map(|n| (k, n)))
                .collect::<Option<_>>()?,
        ),
        CipherText::EmptyMap(()) => CipherText::EmptyMap(leaves.next()?),
        CipherText::None(()) => CipherText::None(leaves.next()?),
        CipherText::Passthrough(p) => CipherText::Passthrough(p),
    })
}

/// Where a finished node goes: back to the caller, or into a parent.
pub trait Slot {
    type Ok;
    fn put(self, node: Node<Pending>) -> Self::Ok;
}

pub struct Root;

impl Slot for Root {
    type Ok = Node<Pending>;
    fn put(self, node: Node<Pending>) -> Node<Pending> {
        node
    }
}

pub struct Push<'s>(&'s mut Vec<Node<Pending>>);

impl Slot for Push<'_> {
    type Ok = ();
    fn put(self, node: Node<Pending>) {
        self.0.push(node);
    }
}

pub struct Entry<'s>(&'s mut Vec<(String, Node<Pending>)>, String);

impl Slot for Entry<'_> {
    type Ok = ();
    fn put(self, node: Node<Pending>) {
        self.0.push((self.1, node));
    }
}

/// The encrypting sink. `E` is the backend's error type, so that this sink
/// can be teed with others before any backend is involved; the sink itself
/// never produces `EncryptError::Backend`.
pub struct EncryptSink<E, O> {
    aad: Context<'static>,
    out: O,
    _error: PhantomData<E>,
}

impl<E> EncryptSink<E, Root> {
    pub fn root<'a>(aad: impl IntoAad<'a>) -> Self {
        Self {
            aad: aad.into_aad().into_owned(),
            out: Root,
            _error: PhantomData,
        }
    }
}

impl<E, O: Slot> EncryptSink<E, O> {
    /// Plan one scalar as one leaf: its tag, then its payload.
    fn leaf(self, ty: Option<Logical>, v: Physical<'_>) -> Result<O::Ok, EncryptError<E>> {
        let mut plaintext = Protected::new(Vec::new());
        scalar::write(ty, v, plaintext.risky_inner_mut(), Form::Leaf).map_err(|e| match e {
            ScalarError::Invalid => EncryptError::Shape("value isn't valid for its logical type"),
            ScalarError::TooLong => EncryptError::Shape("too long"),
        })?;
        Ok(self.out.put(CipherText::Single(Pending { plaintext, aad: self.aad })))
    }
}

fn marker(aad: Context<'static>) -> Pending {
    Pending {
        plaintext: Protected::new(Vec::new()),
        aad,
    }
}

impl<E, O: Slot> Sink for EncryptSink<E, O> {
    type Ok = O::Ok;
    type Error = EncryptError<E>;
    type Seq = EncryptSeq<E, O>;
    type Map = EncryptMap<E, O>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<O::Ok, Self::Error> {
        self.leaf(ty, v)
    }

    fn seq(self, len: Option<usize>) -> Result<Self::Seq, Self::Error> {
        Ok(EncryptSeq {
            element_aad: self.aad.for_sequence_element(),
            aad: self.aad,
            items: Vec::with_capacity(len.unwrap_or(0).min(1024)),
            out: self.out,
            _error: PhantomData,
        })
    }

    fn map(self, _len: Option<usize>) -> Result<Self::Map, Self::Error> {
        Ok(EncryptMap {
            aad: self.aad,
            entries: Vec::new(),
            seen: HashSet::new(),
            out: self.out,
            _error: PhantomData,
        })
    }

    /// Passthrough is non-sensitive by design: it's framed, not sealed.
    fn passthrough<P: Plaintext>(self, value: P) -> Result<O::Ok, Self::Error> {
        let frame = to_frame(value)?;
        Ok(self
            .out
            .put(CipherText::Passthrough(PassthroughFrame(frame.risky_ref().to_vec()))))
    }
}

fn sealed_any<L>(nodes: impl IntoIterator<Item = impl std::borrow::Borrow<Node<L>>>) -> bool {
    nodes
        .into_iter()
        .any(|n| !matches!(n.borrow(), CipherText::Passthrough(_)))
}

pub struct EncryptSeq<E, O> {
    aad: Context<'static>,
    element_aad: Context<'static>,
    items: Vec<Node<Pending>>,
    out: O,
    _error: PhantomData<E>,
}

impl<E, O: Slot> SeqSink for EncryptSeq<E, O> {
    type Ok = O::Ok;
    type Error = EncryptError<E>;
    type Element<'s>
        = EncryptSink<E, Push<'s>>
    where
        Self: 's;

    fn element(&mut self) -> Result<Self::Element<'_>, Self::Error> {
        Ok(EncryptSink {
            aad: self.element_aad.clone(),
            out: Push(&mut self.items),
            _error: PhantomData,
        })
    }

    fn end(self) -> Result<O::Ok, Self::Error> {
        let node = if self.items.is_empty() {
            CipherText::EmptySequence(marker(self.aad.for_empty_sequence()))
        } else if !sealed_any(&self.items) {
            // Passthrough authenticates nothing: an all-passthrough
            // sequence would decrypt under any AAD.
            return Err(EncryptError::Shape("sequence has nothing sealed"));
        } else {
            CipherText::Sequence(self.items)
        };
        Ok(self.out.put(node))
    }
}

pub struct EncryptMap<E, O> {
    aad: Context<'static>,
    entries: Vec<(String, Node<Pending>)>,
    seen: HashSet<String>,
    out: O,
    _error: PhantomData<E>,
}

impl<E, O: Slot> MapSink for EncryptMap<E, O> {
    type Ok = O::Ok;
    type Error = EncryptError<E>;
    type Entry<'s>
        = EncryptSink<E, Entry<'s>>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, Self::Error> {
        if !self.seen.insert(key.to_owned()) {
            return Err(EncryptError::Shape("duplicate key"));
        }
        Ok(EncryptSink {
            aad: self.aad.for_map_entry(key),
            out: Entry(&mut self.entries, key.to_owned()),
            _error: PhantomData,
        })
    }

    fn end(self) -> Result<O::Ok, Self::Error> {
        let node = if self.entries.is_empty() {
            CipherText::EmptyMap(marker(self.aad.for_empty_map()))
        } else if !sealed_any(self.entries.iter().map(|(_, n)| n)) {
            return Err(EncryptError::Shape("map has nothing sealed"));
        } else {
            CipherText::Map(self.entries)
        };
        Ok(self.out.put(node))
    }
}
