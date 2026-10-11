//! Rust types as sources. The width comes from the static type, as Go's does.

use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;

use crate::model::{MapSink, Plaintext, SeqSink, Sink};

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

/// Byte strings need a wrapper: `Vec<u8>` is already a sequence of `u8`.
pub struct Bytes<'a>(pub &'a [u8]);

impl Plaintext for Bytes<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.bytes(self.0)
    }
}

/// `None` is a tagged null, as a dynamic host would send it. Rust's static
/// `Option` impl uses `encrypt_none` instead; see the README.
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
        let len = self.len();
        self.into_iter()
            .try_fold(sink.seq(len)?, SeqSink::element)?
            .end()
    }
}

impl<'a, T> Plaintext for &'a Vec<T>
where
    &'a T: Plaintext,
{
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        self.iter()
            .try_fold(sink.seq(self.len())?, SeqSink::element)?
            .end()
    }
}

impl<V: Plaintext> Plaintext for BTreeMap<String, V> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let len = self.len();
        self.into_iter()
            .try_fold(sink.map(len)?, |map, (k, v)| map.entry(&k, v))?
            .end()
    }
}
