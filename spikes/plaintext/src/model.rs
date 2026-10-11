//! The data model: what a plaintext source can say about itself.
//!
//! This is the serde split applied to vitaminc. [`Plaintext`] plays the part
//! of `serde::Serialize`: a type describes itself once, in terms of typed
//! scalars and containers. [`Sink`] plays the part of `serde::Serializer`:
//! something that consumes that description. Encryption, transport framing,
//! equality terms and building a `Value` are all sinks.
//!
//! The difference from vitaminc's `Cipher` data model is that scalars stay
//! typed. `Cipher::encrypt_bytes_array` only ever sees bytes, so `u32` and
//! `i32` look the same to it. Index terms need to know which one they got,
//! so the type has to survive to the sink.

use std::convert::Infallible;
use std::marker::PhantomData;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;

/// A value that can describe itself to any [`Sink`].
///
/// Implemented once per source: Rust primitives, `Value`, a borrowed
/// transport [`Frame`](crate::Frame), and so on.
///
/// `visit` is infallible on the source side. A source that can fail part
/// way through (a live JS object whose getter throws) can't report that
/// through `S::Error`, because the encrypt sink's error type is the cipher's.
/// Such sources validate or snapshot first. See the README.
pub trait Plaintext {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error>;
}

/// Consumes one value described through the data model.
///
/// Every method is required, so adding a kind here is a compile error in
/// every sink until it decides what to do. That is the exhaustiveness
/// property `#[non_exhaustive]` on `Value` takes away.
pub trait Sink: Sized {
    type Ok;
    type Error;
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

    /// Start a sequence of exactly `len` elements.
    fn seq(self, len: usize) -> Result<Self::Seq, Self::Error>;
    /// Start a map of exactly `len` entries.
    fn map(self, len: usize) -> Result<Self::Map, Self::Error>;

    /// A subtree that travels in the clear (see `Value::Passthrough`).
    fn passthrough<P: Plaintext>(self, value: P) -> Result<Self::Ok, Self::Error>;
}

/// Elements are passed as values, and the sink decides when to walk them.
///
/// This is forced by vitaminc's `SeqCipher::encrypt_next<T: Encrypt>`, which
/// takes the element as a value and walks it itself. By-value chaining
/// mirrors the `SeqCipher` idiom.
pub trait SeqSink: Sized {
    type Ok;
    type Error;

    fn element<P: Plaintext>(self, value: P) -> Result<Self, Self::Error>;
    fn end(self) -> Result<Self::Ok, Self::Error>;
}

pub trait MapSink: Sized {
    type Ok;
    type Error;

    fn entry<P: Plaintext>(self, key: &str, value: P) -> Result<Self, Self::Error>;
    fn end(self) -> Result<Self::Ok, Self::Error>;
}

/// Container sinks for a sink that refuses containers, after serde's
/// `ser::Impossible`. It can't be constructed.
pub struct Impossible<Ok, E> {
    never: Infallible,
    _types: PhantomData<(Ok, E)>,
}

impl<Ok, E> SeqSink for Impossible<Ok, E> {
    type Ok = Ok;
    type Error = E;

    fn element<P: Plaintext>(self, _value: P) -> Result<Self, E> {
        match self.never {}
    }

    fn end(self) -> Result<Ok, E> {
        match self.never {}
    }
}

impl<Ok, E> MapSink for Impossible<Ok, E> {
    type Ok = Ok;
    type Error = E;

    fn entry<P: Plaintext>(self, _key: &str, _value: P) -> Result<Self, E> {
        match self.never {}
    }

    fn end(self) -> Result<Ok, E> {
        match self.never {}
    }
}
