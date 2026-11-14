//! **SPIKE.** A sealed record: a struct encrypted into a struct.
//!
//! [`encrypt`](crate::encrypt) turns any source into one type-erased tree,
//! [`Node`]. That tree is what a host (JavaScript, Go, a dynamic plan)
//! needs, but it costs a Rust caller who knows the record's type: every
//! passthrough field is copied into a [`PassthroughFrame`] of bytes, because
//! one tree type has to hold a passthrough of any type.
//!
//! `#[derive(Seal)]` generates the typed counterpart of a struct instead.
//! For a struct `User`, it generates:
//!
//! - `SealedUser<L>`: each sealed field is a [`Node<L>`], and each
//!   passthrough field keeps its own type. [`Seal::seal`] **moves** the
//!   passthrough fields across, so nothing is copied.
//! - `SealedUserRef<'r, L>`: the same, with each passthrough field a
//!   `&'r T` borrowed from the record. [`Seal::seal_ref`] copies nothing
//!   either.
//!
//! Every sealed field is planned by the same [`EncryptSink`] as
//! [`encrypt`](crate::encrypt), under the same context
//! ([`Context::for_map_entry`](crate::Context::for_map_entry) of the
//! field's key), and the whole record is sealed in one batch. So a sealed
//! field is byte-for-byte the entry the dynamic tree would hold, and
//! `into_node` turns a sealed record into that tree, framing the
//! passthrough fields only then.
//!
//! This module is the runtime support the derive calls. It is public only
//! so the generated code can reach it.

use core::convert::Infallible;
use core::future::Future;

use vitaminc_protected::Controlled;

use crate::encrypt_sink::{EncryptMap, EncryptSink};
use crate::frame::PassthroughFrame;
use crate::plaintext::{Encrypt, EncryptRef, MapSink, Sink};
use crate::seal::{
    open_all, open_all_async, seal_all, seal_all_async, AsyncCipher, Cipher, LeafCount, Node,
    Opened, Pending,
};
use crate::shape::{self, Root};
use crate::typed::{DecodeError, Decrypt};
use crate::walk::{opening, walk, DecryptError};
use crate::{CipherText, EncryptError, IntoAad};

/// A struct that seals into its typed counterpart. Derive it with
/// `#[derive(Seal)]`; see the [module documentation](self).
pub trait Seal: Sized {
    /// The sealed record, owning its passthrough fields.
    type Sealed<L>;
    /// The sealed record, borrowing its passthrough fields from `Self`.
    type SealedRef<'r, L>
    where
        Self: 'r;

    /// Seal the record, moving its passthrough fields into the result.
    ///
    /// # Errors
    ///
    /// As [`encrypt`](crate::encrypt).
    fn seal<'a, C: Cipher>(
        self,
        cipher: &C,
        aad: impl IntoAad<'a>,
    ) -> Result<Self::Sealed<C::Leaf>, EncryptError<C::Error>>;

    /// Seal a borrowed record. The result borrows its passthrough fields.
    ///
    /// # Errors
    ///
    /// As [`encrypt`](crate::encrypt).
    fn seal_ref<'r, 'a, C: Cipher>(
        &'r self,
        cipher: &C,
        aad: impl IntoAad<'a>,
    ) -> Result<Self::SealedRef<'r, C::Leaf>, EncryptError<C::Error>>;

    /// [`seal`](Seal::seal) through an async cipher, in one `seal_many`
    /// call. The record is planned before this returns, so the future holds
    /// the planned leaves and the passthrough fields, not the plaintext.
    fn seal_async<'a, C: AsyncCipher>(
        self,
        cipher: &C,
        aad: impl IntoAad<'a>,
    ) -> impl Future<Output = Result<Self::Sealed<C::Leaf>, EncryptError<C::Error>>>;
}

/// The sealed fields of one record, planned as the entries of one map.
pub struct RecordPlan<E> {
    map: EncryptMap<E, Root>,
}

impl<E> RecordPlan<E> {
    /// Start a plan for `sealed` sealed fields under `aad`.
    ///
    /// # Errors
    ///
    /// None in practice: a map at the root is never refused.
    pub fn new<'a>(aad: impl IntoAad<'a>, sealed: usize) -> Result<Self, EncryptError<E>> {
        Ok(Self {
            map: EncryptSink::root(aad).map(Some(sealed))?,
        })
    }

    /// Plan one sealed field under its key.
    ///
    /// # Errors
    ///
    /// As [`plan`](crate::plan).
    pub fn field<P: Encrypt>(&mut self, key: &str, value: P) -> Result<(), EncryptError<E>> {
        value.visit(self.map.entry(key)?)
    }

    /// The planned map.
    ///
    /// # Errors
    ///
    /// As [`plan`](crate::plan).
    pub fn finish(self) -> Result<Node<Pending>, EncryptError<E>> {
        self.map.end()
    }
}

/// The sealed fields, in the order they were planned.
pub struct SealedFields<L>(std::vec::IntoIter<(String, Node<L>)>);

impl<L> SealedFields<L> {
    fn new(node: Node<L>) -> Self {
        Self(match node {
            CipherText::Map(entries) => entries.into_iter(),
            _ => Vec::new().into_iter(),
        })
    }

    /// The next sealed field.
    ///
    /// # Errors
    ///
    /// [`EncryptError::Count`] if the record has no more: a cipher bug,
    /// since sealing keeps the plan's shape.
    pub fn next_field<E>(&mut self) -> Result<Node<L>, EncryptError<E>> {
        self.0
            .next()
            .map(|(_, node)| node)
            .ok_or(EncryptError::Count(LeafCount::TooFew))
    }
}

/// Seal a planned record.
///
/// # Errors
///
/// As [`encrypt`](crate::encrypt).
pub fn seal_record<C: Cipher>(
    cipher: &C,
    plan: Node<Pending>,
) -> Result<SealedFields<C::Leaf>, EncryptError<C::Error>> {
    Ok(SealedFields::new(seal_all(cipher, plan)?))
}

/// Seal a planned record through an async cipher, in one `seal_many` call.
///
/// # Errors
///
/// As [`encrypt_async`](crate::encrypt_async).
pub async fn seal_record_async<C: AsyncCipher>(
    cipher: &C,
    plan: Node<Pending>,
) -> Result<SealedFields<C::Leaf>, EncryptError<C::Error>> {
    Ok(SealedFields::new(seal_all_async(cipher, plan).await?))
}

/// The opened fields of one record, in order.
pub struct OpenedFields(std::vec::IntoIter<(String, Node<Opened>)>);

impl OpenedFields {
    fn new(node: Node<Opened>) -> Self {
        Self(match node {
            CipherText::Map(entries) => entries.into_iter(),
            _ => Vec::new().into_iter(),
        })
    }

    /// Decode the next field as `T`.
    ///
    /// # Errors
    ///
    /// As [`decrypt`](crate::decrypt).
    pub fn field<T: Decrypt, C>(&mut self) -> Result<T, DecryptError<DecodeError, C>> {
        let (_, node) = self.0.next().ok_or(DecryptError::Malformed)?;
        walk(node, T::sink()).map_err(DecryptError::with_cipher)
    }
}

/// Open the sealed fields of a record, each under its key, in one batch.
///
/// # Errors
///
/// As [`decrypt`](crate::decrypt).
pub fn open_record<'a, C: Cipher>(
    cipher: &C,
    fields: Vec<(String, Node<C::Leaf>)>,
    aad: impl IntoAad<'a>,
) -> Result<OpenedFields, DecryptError<DecodeError, C::Error>> {
    let opened = open_all(cipher, CipherText::Map(fields), &aad.into_aad()).map_err(opening)?;
    Ok(OpenedFields::new(opened))
}

/// [`open_record`] through an async cipher, in one `open_many` call.
///
/// # Errors
///
/// As [`decrypt_async`](crate::decrypt_async).
pub async fn open_record_async<'a, C: AsyncCipher>(
    cipher: &C,
    fields: Vec<(String, Node<C::Leaf>)>,
    aad: impl IntoAad<'a>,
) -> Result<OpenedFields, DecryptError<DecodeError, C::Error>> {
    let aad = aad.into_aad().into_owned();
    let opened = open_all_async(cipher, CipherText::Map(fields), &aad)
        .await
        .map_err(opening)?;
    Ok(OpenedFields::new(opened))
}

/// Frame a passthrough field for the dynamic tree, as the encrypting sink
/// frames a passthrough entry of a map at the root.
///
/// # Errors
///
/// As [`plan`](crate::plan) for a passthrough: a value too deep or too
/// long for a frame.
pub fn frame_field<P: ?Sized + EncryptRef>(
    value: &P,
) -> Result<PassthroughFrame, EncryptError<Infallible>> {
    let frame = shape::frame_passthrough(value.lend(), 1, &Root, EncryptError::Shape)?;
    Ok(PassthroughFrame(frame.risky_unwrap()))
}
