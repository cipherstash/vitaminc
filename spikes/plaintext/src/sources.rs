//! Rust types as sources. Go's frame is in [`crate::frame`], the Node
//! walker in `hosts::js`.

use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;

use crate::model::{visit_map, visit_seq, Error, Plaintext, SeqSink, Sink, SourceError};

macro_rules! scalar {
    ($($ty:ty => $method:ident),* $(,)?) => {
        $(
            impl Plaintext for $ty {
                fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                    sink.$method(self)
                }
            }
        )*
    };
}

scalar! {
    bool => bool,
    i8 => i8, i16 => i16, i32 => i32, i64 => i64, i128 => i128,
    u8 => u8, u16 => u16, u32 => u32, u64 => u64, u128 => u128,
    f32 => f32, f64 => f64,
    NaiveDate => date, DateTime<Utc> => timestamp, Decimal => decimal,
}

impl Plaintext for &str {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.str(self)
    }
}

impl Plaintext for &String {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.str(self)
    }
}

/// A byte string. `Vec<u8>` and `&[u8]` would clash with the sequence impls.
#[derive(Clone, Copy, Debug)]
pub struct Bytes<'a>(pub &'a [u8]);

impl Plaintext for Bytes<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.bytes(self.0)
    }
}

impl<T: Plaintext> Plaintext for Option<T> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        match self {
            Some(v) => v.visit(sink),
            None => sink.null(),
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
