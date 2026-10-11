//! Encryption as a sink, over a bytes-only backend.
//!
//! The layers:
//!
//! - [`Backend`]: seal and open one leaf. Bytes only, no types. This is
//!   the part of today's `Cipher` that genuinely belongs to the AEAD.
//! - [`EncryptSink`]: scalars to tagged leaf bytes, and the container
//!   rules (element and entry AAD, empty markers, at least one sealed node,
//!   no duplicate keys). This is the rest of today's `Cipher` plus
//!   `impl Encrypt for Value`, in one place.
//!
//! The ciphertext tree reuses vitaminc's `CipherText` enum, with a
//! passthrough payload that is a frame, not a `Value` or a `Box<dyn Any>`.

use std::collections::HashSet;

use vitaminc_aead::{Cipher, CipherText, Context, Decipher, DecipherVisitor, IntoAad, LocalCipherText, Unspecified};
use vitaminc_encrypt::{Aes256Cipher, AesCipherText};
use vitaminc_protected::{Controlled, Protected};

use crate::frame_writer::{to_frame, FrameWriteError};
use crate::kinds::{Logical, Physical};
use crate::model::{Error, MapSink, Plaintext, SeqSink, Sink, SourceError};
use crate::scalar::{self, Form, ScalarError};

/// Seal and open one leaf. The backend binds the wire version into the AAD
/// itself (`for_leaf`), as `seal_leaf` does today.
pub trait Backend {
    type Leaf;
    type Error;

    fn seal(&self, plaintext: Protected<Vec<u8>>, aad: &Context<'_>) -> Result<Self::Leaf, Self::Error>;
    fn open(&self, leaf: Self::Leaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Self::Error>;
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
    /// Duplicate key, a container with nothing sealed in it, or a value
    /// that isn't valid for its logical type.
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

/// Encrypt any source with tagged leaves.
pub fn encrypt<'a, P, B, A>(p: P, backend: &B, aad: A) -> Result<Node<B::Leaf>, EncryptError<B::Error>>
where
    P: Plaintext,
    B: Backend,
    A: IntoAad<'a>,
{
    p.visit(EncryptSink::root(backend, aad))
}

/// Where a finished node goes: back to the caller, or into a parent.
pub trait Slot<L> {
    type Ok;
    fn put(self, node: Node<L>) -> Self::Ok;
}

pub struct Root;

impl<L> Slot<L> for Root {
    type Ok = Node<L>;
    fn put(self, node: Node<L>) -> Node<L> {
        node
    }
}

pub struct Push<'s, L>(&'s mut Vec<Node<L>>);

impl<L> Slot<L> for Push<'_, L> {
    type Ok = ();
    fn put(self, node: Node<L>) {
        self.0.push(node);
    }
}

pub struct Entry<'s, L>(&'s mut Vec<(String, Node<L>)>, String);

impl<L> Slot<L> for Entry<'_, L> {
    type Ok = ();
    fn put(self, node: Node<L>) {
        self.0.push((self.1, node));
    }
}

pub struct EncryptSink<'b, B, O> {
    backend: &'b B,
    aad: Context<'static>,
    out: O,
}

impl<'b, B: Backend> EncryptSink<'b, B, Root> {
    pub fn root<'a>(backend: &'b B, aad: impl IntoAad<'a>) -> Self {
        Self {
            backend,
            aad: aad.into_aad().into_owned(),
            out: Root,
        }
    }
}

impl<B: Backend, O: Slot<B::Leaf>> EncryptSink<'_, B, O> {
    /// Seal one scalar as one leaf: its tag, then its payload.
    fn leaf(self, ty: Option<Logical>, v: Physical<'_>) -> Result<O::Ok, EncryptError<B::Error>> {
        let mut plaintext = Protected::new(Vec::new());
        scalar::write(ty, v, plaintext.risky_inner_mut(), Form::Leaf).map_err(|e| match e {
            ScalarError::Invalid => EncryptError::Shape("value isn't valid for its logical type"),
            ScalarError::TooLong => EncryptError::Shape("too long"),
        })?;
        let leaf = self.backend.seal(plaintext, &self.aad).map_err(EncryptError::Backend)?;
        Ok(self.out.put(CipherText::Single(leaf)))
    }

    fn marker(backend: &B, aad: Context<'static>) -> Result<B::Leaf, EncryptError<B::Error>> {
        backend.seal(Protected::new(Vec::new()), &aad).map_err(EncryptError::Backend)
    }
}

impl<'b, B: Backend, O: Slot<B::Leaf>> Sink for EncryptSink<'b, B, O> {
    type Ok = O::Ok;
    type Error = EncryptError<B::Error>;
    type Seq = EncryptSeq<'b, B, O>;
    type Map = EncryptMap<'b, B, O>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<O::Ok, Self::Error> {
        self.leaf(ty, v)
    }

    fn seq(self, len: Option<usize>) -> Result<Self::Seq, Self::Error> {
        Ok(EncryptSeq {
            backend: self.backend,
            element_aad: self.aad.for_sequence_element(),
            aad: self.aad,
            items: Vec::with_capacity(len.unwrap_or(0).min(1024)),
            out: self.out,
        })
    }

    fn map(self, _len: Option<usize>) -> Result<Self::Map, Self::Error> {
        Ok(EncryptMap {
            backend: self.backend,
            aad: self.aad,
            entries: Vec::new(),
            seen: HashSet::new(),
            out: self.out,
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

pub struct EncryptSeq<'b, B: Backend, O> {
    backend: &'b B,
    aad: Context<'static>,
    element_aad: Context<'static>,
    items: Vec<Node<B::Leaf>>,
    out: O,
}

impl<'b, B: Backend, O: Slot<B::Leaf>> SeqSink for EncryptSeq<'b, B, O> {
    type Ok = O::Ok;
    type Error = EncryptError<B::Error>;
    type Element<'s>
        = EncryptSink<'b, B, Push<'s, B::Leaf>>
    where
        Self: 's;

    fn element(&mut self) -> Result<Self::Element<'_>, Self::Error> {
        Ok(EncryptSink {
            backend: self.backend,
            aad: self.element_aad.clone(),
            out: Push(&mut self.items),
        })
    }

    fn end(self) -> Result<O::Ok, Self::Error> {
        let node = if self.items.is_empty() {
            let leaf = EncryptSink::<B, O>::marker(self.backend, self.aad.for_empty_sequence())?;
            CipherText::EmptySequence(leaf)
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

pub struct EncryptMap<'b, B: Backend, O> {
    backend: &'b B,
    aad: Context<'static>,
    entries: Vec<(String, Node<B::Leaf>)>,
    seen: HashSet<String>,
    out: O,
}

impl<'b, B: Backend, O: Slot<B::Leaf>> MapSink for EncryptMap<'b, B, O> {
    type Ok = O::Ok;
    type Error = EncryptError<B::Error>;
    type Entry<'s>
        = EncryptSink<'b, B, Entry<'s, B::Leaf>>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, Self::Error> {
        if !self.seen.insert(key.to_owned()) {
            return Err(EncryptError::Shape("duplicate key"));
        }
        Ok(EncryptSink {
            backend: self.backend,
            aad: self.aad.for_map_entry(key),
            out: Entry(&mut self.entries, key.to_owned()),
        })
    }

    fn end(self) -> Result<O::Ok, Self::Error> {
        let node = if self.entries.is_empty() {
            let leaf = EncryptSink::<B, O>::marker(self.backend, self.aad.for_empty_map())?;
            CipherText::EmptyMap(leaf)
        } else if !sealed_any(self.entries.iter().map(|(_, n)| n)) {
            return Err(EncryptError::Shape("map has nothing sealed"));
        } else {
            CipherText::Map(self.entries)
        };
        Ok(self.out.put(node))
    }
}
