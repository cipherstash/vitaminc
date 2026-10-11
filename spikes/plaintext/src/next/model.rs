//! The data model with the API open: push-style containers and an error
//! channel for sources.
//!
//! Compared with the stage-1 model (`crate::model`):
//!
//! - **Containers are push-style.** `SeqSink::element` returns a sink for the
//!   next element, rather than taking the element as a value. The source
//!   drives the whole walk, so any number of sinks can share one walk
//!   (see [`Tee`](super::tee::Tee)).
//! - **Sources can fail.** Every sink error implements [`Error`], so a
//!   source can stop the walk with [`Error::source`]. That's what lets a
//!   native binding walk a live host object (a JS getter can throw) without
//!   a snapshot first. It's serde's `ser::Error::custom` pattern.
//! - **Lengths are optional,** for host iterables that don't know their size.
//!
//! There is no `Encrypt` trait. Encryption is a sink, driven by
//! [`encrypt`](super::encrypt::encrypt).

use std::fmt;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;

pub trait Plaintext {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error>;
}

/// Every sink's error type. A source reports its own failure through
/// `source`, without knowing which sink it's feeding.
pub trait Error: Sized {
    fn source(error: SourceError) -> Self;
}

/// A failure reading the source: a getter threw, a string had an unpaired
/// surrogate, a BigInt was out of range.
#[derive(Debug)]
pub struct SourceError(pub Box<dyn std::error::Error + Send + Sync>);

impl SourceError {
    pub fn msg(msg: impl Into<String>) -> Self {
        Self(msg.into().into())
    }
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

pub trait Sink: Sized {
    type Ok;
    type Error: Error;
    type Seq: SeqSink<Ok = Self::Ok, Error = Self::Error>;
    type Map: MapSink<Ok = Self::Ok, Error = Self::Error>;

    fn null(self) -> Result<Self::Ok, Self::Error>;
    fn undefined(self) -> Result<Self::Ok, Self::Error>;
    fn bool(self, v: bool) -> Result<Self::Ok, Self::Error>;

    fn i8(self, v: i8) -> Result<Self::Ok, Self::Error>;
    fn i16(self, v: i16) -> Result<Self::Ok, Self::Error>;
    fn i32(self, v: i32) -> Result<Self::Ok, Self::Error>;
    fn i64(self, v: i64) -> Result<Self::Ok, Self::Error>;
    fn i128(self, v: i128) -> Result<Self::Ok, Self::Error>;
    fn u8(self, v: u8) -> Result<Self::Ok, Self::Error>;
    fn u16(self, v: u16) -> Result<Self::Ok, Self::Error>;
    fn u32(self, v: u32) -> Result<Self::Ok, Self::Error>;
    fn u64(self, v: u64) -> Result<Self::Ok, Self::Error>;
    fn u128(self, v: u128) -> Result<Self::Ok, Self::Error>;
    fn f32(self, v: f32) -> Result<Self::Ok, Self::Error>;
    fn f64(self, v: f64) -> Result<Self::Ok, Self::Error>;

    fn date(self, v: NaiveDate) -> Result<Self::Ok, Self::Error>;
    fn timestamp(self, v: DateTime<Utc>) -> Result<Self::Ok, Self::Error>;
    fn decimal(self, v: Decimal) -> Result<Self::Ok, Self::Error>;

    fn str(self, v: &str) -> Result<Self::Ok, Self::Error>;
    fn bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error>;

    fn seq(self, len: Option<usize>) -> Result<Self::Seq, Self::Error>;
    fn map(self, len: Option<usize>) -> Result<Self::Map, Self::Error>;

    /// A subtree that travels in the clear. It's walked like anything else;
    /// the sink decides what "in the clear" means for it.
    fn passthrough<P: Plaintext>(self, value: P) -> Result<Self::Ok, Self::Error>;
}

pub trait SeqSink: Sized {
    type Ok;
    type Error: Error;
    /// A sink for one element. Its `Ok` is ignored: it writes into `self`.
    type Element<'s>: Sink<Error = Self::Error>
    where
        Self: 's;

    fn element(&mut self) -> Result<Self::Element<'_>, Self::Error>;
    fn end(self) -> Result<Self::Ok, Self::Error>;
}

pub trait MapSink: Sized {
    type Ok;
    type Error: Error;
    type Entry<'s>: Sink<Error = Self::Error>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, Self::Error>;
    fn end(self) -> Result<Self::Ok, Self::Error>;
}

/// Walk each item into its own element sink. The loop every container
/// source writes.
pub fn visit_seq<S, I>(sink: S, len: Option<usize>, items: I) -> Result<S::Ok, S::Error>
where
    S: Sink,
    I: IntoIterator,
    I::Item: Plaintext,
{
    let mut seq = sink.seq(len)?;
    for item in items {
        item.visit(seq.element()?)?;
    }
    seq.end()
}

pub fn visit_map<'k, S, I, P>(sink: S, len: Option<usize>, entries: I) -> Result<S::Ok, S::Error>
where
    S: Sink,
    I: IntoIterator<Item = (&'k str, P)>,
    P: Plaintext,
{
    let mut map = sink.map(len)?;
    for (key, value) in entries {
        value.visit(map.entry(key)?)?;
    }
    map.end()
}
