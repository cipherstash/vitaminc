//! Decrypt into any sink. Replaces `Decipher`, `DecipherVisitor`,
//! `SeqAccess`, `MapAccess` and `Decrypt for Value` on the dynamic path.
//!
//! Two steps, mirroring encryption:
//!
//! 1. [`open_all`] / [`open_all_async`]: derive each leaf's AAD from its
//!    position, open every leaf (one `open_many` call for an async
//!    backend), and put the plaintexts back into the tree.
//! 2. [`walk`]: feed the opened tree to the sink, scalar by scalar,
//!    physical plus logical. Go passes a `FrameWriter`, Node a JS builder,
//!    a typed Rust caller a [`Decode`](crate::typed::Decode) sink.
//!
//! The rules (empty markers, nothing-sealed containers, duplicate keys) are
//! today's, moved here from `AesDecipher`.

use std::collections::HashSet;

use vitaminc_aead::{CipherText, Context, IntoAad};
use vitaminc_protected::{Controlled, Protected};

use crate::encrypt::{fill, AsyncBackend, Backend, Node};
use crate::frame::Frame;
use crate::kinds::Physical;
use crate::model::{Error, MapSink, SeqSink, Sink, SourceError};
use crate::scalar;

/// A leaf after opening: its tagged plaintext.
pub type Opened = Protected<Vec<u8>>;

#[derive(Debug)]
pub enum DecryptError<E> {
    /// Wrong key, wrong AAD, or tampered ciphertext.
    Auth,
    /// The tree or a leaf's plaintext isn't well formed, or the backend
    /// returned the wrong number of leaves.
    Malformed,
    /// The sink refused what it was given (a typed sink got the wrong kind).
    Sink(E),
}

impl<E> From<E> for DecryptError<E> {
    fn from(e: E) -> Self {
        Self::Sink(e)
    }
}

pub fn decrypt_into<'a, B, S, A>(backend: &B, node: Node<B::Leaf>, aad: A, sink: S) -> Result<S::Ok, DecryptError<S::Error>>
where
    B: Backend,
    S: Sink,
    A: IntoAad<'a>,
{
    walk(open_all(backend, node, aad)?, sink)
}

/// Decrypt through an async backend. Every leaf is opened before the sink
/// sees anything, so the sink itself is never awaited.
pub async fn decrypt_into_async<'a, B, S, A>(backend: &B, node: Node<B::Leaf>, aad: A, sink: S) -> Result<S::Ok, DecryptError<S::Error>>
where
    B: AsyncBackend,
    S: Sink,
    A: IntoAad<'a>,
{
    walk(open_all_async(backend, node, aad).await?, sink)
}

/// Open every leaf, one at a time.
pub fn open_all<'a, B, E, A>(backend: &B, node: Node<B::Leaf>, aad: A) -> Result<Node<Opened>, DecryptError<E>>
where
    B: Backend,
    A: IntoAad<'a>,
{
    let mut sealed = Vec::new();
    let shape = split_with_aad(node, &aad.into_aad(), &mut sealed);
    let opened = sealed
        .into_iter()
        .map(|(leaf, aad)| backend.open(leaf, &aad))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| DecryptError::Auth)?;
    fill(shape, opened).map_err(|_| DecryptError::Malformed)
}

/// Open every leaf in one `open_many` call.
pub async fn open_all_async<'a, B, E, A>(backend: &B, node: Node<B::Leaf>, aad: A) -> Result<Node<Opened>, DecryptError<E>>
where
    B: AsyncBackend,
    A: IntoAad<'a>,
{
    let mut sealed = Vec::new();
    let shape = split_with_aad(node, &aad.into_aad(), &mut sealed);
    let opened = backend.open_many(sealed).await.map_err(|_| DecryptError::Auth)?;
    fill(shape, opened).map_err(|_| DecryptError::Malformed)
}

/// A tree's shape with its leaves taken out, each paired with the AAD its
/// position derives. The derivations are the ones `EncryptSink` used.
fn split_with_aad<L>(node: Node<L>, aad: &Context<'_>, leaves: &mut Vec<(L, Context<'static>)>) -> Node<()> {
    match node {
        CipherText::Single(leaf) => {
            leaves.push((leaf, aad.clone().into_owned()));
            CipherText::Single(())
        }
        CipherText::Sequence(items) => {
            let element_aad = aad.for_sequence_element();
            CipherText::Sequence(items.into_iter().map(|n| split_with_aad(n, &element_aad, leaves)).collect())
        }
        CipherText::EmptySequence(leaf) => {
            leaves.push((leaf, aad.for_empty_sequence()));
            CipherText::EmptySequence(())
        }
        CipherText::Map(entries) => CipherText::Map(
            entries
                .into_iter()
                .map(|(k, n)| {
                    let shape = split_with_aad(n, &aad.for_map_entry(&k), leaves);
                    (k, shape)
                })
                .collect(),
        ),
        CipherText::EmptyMap(leaf) => {
            leaves.push((leaf, aad.for_empty_map()));
            CipherText::EmptyMap(())
        }
        CipherText::None(leaf) => {
            leaves.push((leaf, aad.for_none()));
            CipherText::None(())
        }
        CipherText::Passthrough(p) => CipherText::Passthrough(p),
    }
}

fn sealed_any<L>(nodes: &[&Node<L>]) -> bool {
    nodes.iter().any(|n| !matches!(n, CipherText::Passthrough(_)))
}

/// Feed an opened tree to a sink.
pub fn walk<S: Sink>(node: Node<Opened>, sink: S) -> Result<S::Ok, DecryptError<S::Error>> {
    let empty_marker = |plaintext: Opened| match plaintext.risky_ref().is_empty() {
        true => Ok(()),
        false => Err(DecryptError::Auth),
    };
    match node {
        CipherText::Single(plaintext) => {
            let (ty, v) = scalar::read_leaf(plaintext.risky_ref()).map_err(|_| DecryptError::Malformed)?;
            Ok(sink.scalar(ty, v)?)
            // `plaintext` drops and wipes here.
        }
        CipherText::Sequence(items) => {
            if !sealed_any(&items.iter().collect::<Vec<_>>()) {
                return Err(DecryptError::Malformed);
            }
            let mut seq = sink.seq(Some(items.len()))?;
            for item in items {
                walk(item, seq.element()?)?;
            }
            Ok(seq.end()?)
        }
        CipherText::EmptySequence(plaintext) => {
            empty_marker(plaintext)?;
            Ok(sink.seq(Some(0))?.end()?)
        }
        CipherText::Map(entries) => {
            let mut seen = HashSet::new();
            if !entries.iter().all(|(k, _)| seen.insert(k.clone()))
                || !sealed_any(&entries.iter().map(|(_, v)| v).collect::<Vec<_>>())
            {
                return Err(DecryptError::Malformed);
            }
            let mut map = sink.map(Some(entries.len()))?;
            for (key, value) in entries {
                walk(value, map.entry(&key)?)?;
            }
            Ok(map.end()?)
        }
        CipherText::EmptyMap(plaintext) => {
            empty_marker(plaintext)?;
            Ok(sink.map(Some(0))?.end()?)
        }
        // Only static Rust `Option::None` makes this today. The data model
        // has no separate "absent", so it reads as null.
        CipherText::None(plaintext) => {
            empty_marker(plaintext)?;
            Ok(sink.scalar(None, Physical::Null)?)
        }
        CipherText::Passthrough(frame) => {
            let frame = Frame::parse(&frame.0).map_err(|_| DecryptError::Malformed)?;
            Ok(sink.passthrough(frame)?)
        }
    }
}

/// Lets a `?` on a sink error inside `walk` also accept source errors.
impl<E: Error> Error for DecryptError<E> {
    fn source(error: SourceError) -> Self {
        Self::Sink(E::source(error))
    }
}
