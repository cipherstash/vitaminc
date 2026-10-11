//! Decrypt into any sink. Replaces `Decipher`, `DecipherVisitor`,
//! `SeqAccess`, `MapAccess` and `Decrypt for Value` on the dynamic path.
//!
//! The ciphertext tree is walked and each opened leaf is fed to the sink as
//! a scalar, physical plus logical. Go passes a `FrameWriter`, Node a JS builder, a typed
//! Rust caller a [`Decode`](crate::typed::Decode) sink. The rules (empty
//! markers, nothing-sealed containers, duplicate keys) are today's, moved
//! here from `AesDecipher`.

use std::collections::HashSet;

use vitaminc_aead::{CipherText, Context, IntoAad};
use vitaminc_protected::Controlled;

use crate::encrypt::{Backend, Node};
use crate::frame::Frame;
use crate::kinds::Physical;
use crate::model::{Error, MapSink, SeqSink, Sink, SourceError};
use crate::scalar;

#[derive(Debug)]
pub enum DecryptError<E> {
    /// Wrong key, wrong AAD, or tampered ciphertext.
    Auth,
    /// The tree or a leaf's plaintext isn't well formed.
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
    walk(backend, node, &aad.into_aad(), sink)
}

fn sealed_any<L>(nodes: &[&Node<L>]) -> bool {
    nodes.iter().any(|n| !matches!(n, CipherText::Passthrough(_)))
}

fn walk<B: Backend, S: Sink>(backend: &B, node: Node<B::Leaf>, aad: &Context<'_>, sink: S) -> Result<S::Ok, DecryptError<S::Error>> {
    let open = |leaf, aad: &Context<'_>| backend.open(leaf, aad).map_err(|_| DecryptError::Auth);
    let empty_marker = |leaf, aad: Context<'static>| match open(leaf, &aad)?.risky_ref().is_empty() {
        true => Ok(()),
        false => Err(DecryptError::Auth),
    };
    match node {
        CipherText::Single(leaf) => {
            let plaintext = open(leaf, aad)?;
            let (ty, v) = scalar::read_leaf(plaintext.risky_ref()).map_err(|_| DecryptError::Malformed)?;
            Ok(sink.scalar(ty, v)?)
            // `plaintext` drops and wipes here.
        }
        CipherText::Sequence(items) => {
            if !sealed_any(&items.iter().collect::<Vec<_>>()) {
                return Err(DecryptError::Malformed);
            }
            let element_aad = aad.for_sequence_element();
            let mut seq = sink.seq(Some(items.len()))?;
            for item in items {
                walk(backend, item, &element_aad, seq.element()?)?;
            }
            Ok(seq.end()?)
        }
        CipherText::EmptySequence(leaf) => {
            empty_marker(leaf, aad.for_empty_sequence())?;
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
                walk(backend, value, &aad.for_map_entry(&key), map.entry(&key)?)?;
            }
            Ok(map.end()?)
        }
        CipherText::EmptyMap(leaf) => {
            empty_marker(leaf, aad.for_empty_map())?;
            Ok(sink.map(Some(0))?.end()?)
        }
        // Only static Rust `Option::None` makes this today. The data model
        // has no separate "absent", so it reads as null.
        CipherText::None(leaf) => {
            empty_marker(leaf, aad.for_none())?;
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
