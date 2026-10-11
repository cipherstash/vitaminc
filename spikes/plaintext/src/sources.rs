//! Rust types as sources. Go's frame is in [`crate::frame`], the Node
//! walker in `hosts::js`.

use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;

use crate::kinds::{self, Float, Int, Logical, Physical, TimeUnit};
use crate::model::{visit_map, visit_seq, Error, Plaintext, SeqSink, Sink, SourceError};

macro_rules! int {
    ($($ty:ty),* $(,)?) => {
        $(
            impl Plaintext for $ty {
                fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                    sink.scalar(None, Physical::Int(self.into()))
                }
            }
        )*
    };
}

int!(i8, i16, i32, i64, i128, u8, u16, u32, u64, u128);

impl Plaintext for bool {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Bool(self))
    }
}

impl Plaintext for f32 {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Float(Float::F32(self)))
    }
}

impl Plaintext for f64 {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Float(Float::F64(self)))
    }
}

impl Plaintext for &str {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Text(self))
    }
}

impl Plaintext for &String {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Text(self))
    }
}

/// A byte string. `Vec<u8>` and `&[u8]` would clash with the sequence impls.
#[derive(Clone, Copy, Debug)]
pub struct Bytes<'a>(pub &'a [u8]);

impl Plaintext for Bytes<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Bytes(self.0))
    }
}

// The chrono and rust_decimal types are logical types over an int. Each
// source says which, and the int it stands for.

impl Plaintext for NaiveDate {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(Some(Logical::Date), Physical::Int(Int::I32(kinds::date_days(self))))
    }
}

impl Plaintext for DateTime<Utc> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let nanos = kinds::timestamp_nanos(self)
            .ok_or_else(|| S::Error::source(SourceError::msg("a leap second has no count of nanoseconds")))?;
        sink.scalar(Some(Logical::Timestamp(TimeUnit::Nanos)), Physical::Int(Int::I128(nanos)))
    }
}

impl Plaintext for Decimal {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let (scale, mantissa) = kinds::decimal_parts(self);
        sink.scalar(Some(Logical::Decimal { scale }), Physical::Int(Int::I128(mantissa)))
    }
}

/// A uuid: a logical type today's tag table doesn't have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uuid(pub [u8; 16]);

impl Plaintext for &Uuid {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(Some(Logical::Uuid), Physical::Bytes(&self.0))
    }
}

/// Any scalar, as given. For tests and for poking around.
#[derive(Clone, Copy, Debug)]
pub struct Raw<'a>(pub Option<Logical>, pub Physical<'a>);

impl Plaintext for Raw<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(self.0, self.1)
    }
}

impl<T: Plaintext> Plaintext for Option<T> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        match self {
            Some(v) => v.visit(sink),
            None => sink.scalar(None, Physical::Null),
        }
    }
}

impl<T: Plaintext> Plaintext for Vec<T> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let len = Some(self.len());
        visit_seq(sink, len, self)
    }
}

impl<'a, T> Plaintext for &'a Vec<T>
where
    &'a T: Plaintext,
{
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        visit_seq(sink, Some(self.len()), self.iter())
    }
}

impl<'a, V> Plaintext for &'a BTreeMap<String, V>
where
    &'a V: Plaintext,
{
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        visit_map(sink, Some(self.len()), self.iter().map(|(k, v)| (k.as_str(), v)))
    }
}

/// A source that fails part way through, to exercise the error channel.
pub struct Failing<P>(pub P);

impl<P: Plaintext> Plaintext for Failing<P> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut seq = sink.seq(None)?;
        self.0.visit(seq.element()?)?;
        Err(S::Error::source(SourceError::msg("getter threw")))
    }
}
