//! Sources: Rust types, and Go's frame. No `Value`.

use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use vitaminc_aead_value::{tags, transport};

use super::model::{visit_map, visit_seq, Error, MapSink, Plaintext, SeqSink, Sink, SourceError};
use crate::scalar;
use crate::sources::frame::{Cursor, Frame, VALIDATED};

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

pub use crate::sources::rust::Bytes;

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

/// Go's frame, walked in place, now driving push-style containers.
impl Plaintext for Frame<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut c = Cursor::new(self.as_bytes());
        match c.byte().expect(VALIDATED) {
            transport::ARRAY => {
                let count = c.count().expect(VALIDATED);
                let mut seq = sink.seq(Some(count))?;
                for _ in 0..count {
                    c.node(0).expect(VALIDATED).visit(seq.element()?)?;
                }
                seq.end()
            }
            transport::OBJECT => {
                let count = c.count().expect(VALIDATED);
                let mut map = sink.map(Some(count))?;
                for _ in 0..count {
                    let len = c.count().expect(VALIDATED);
                    let key = std::str::from_utf8(c.take(len).expect(VALIDATED)).expect(VALIDATED);
                    c.node(0).expect(VALIDATED).visit(map.entry(key)?)?;
                }
                map.end()
            }
            transport::PASSTHROUGH => sink.passthrough(c.node(0).expect(VALIDATED)),
            tag @ (tags::STRING | tags::BYTES) => {
                let len = c.count().expect(VALIDATED);
                leaf(tag, c.take(len).expect(VALIDATED), sink)
            }
            tag => {
                let len = scalar::fixed_len(tag).expect(VALIDATED);
                leaf(tag, c.take(len).expect(VALIDATED), sink)
            }
        }
    }
}

/// Feed one scalar, given as `tag` and its payload, to a sink. Shared by the
/// frame source and by decryption, whose leaf plaintext is `tag ++ payload`.
/// Returns `None` for an invalid scalar.
pub(crate) fn leaf<S: Sink>(tag: u8, p: &[u8], sink: S) -> Result<S::Ok, S::Error> {
    try_leaf(tag, p, sink).unwrap_or_else(|| Err(S::Error::source(SourceError::msg("invalid scalar"))))
}

pub(crate) fn try_leaf<S: Sink>(tag: u8, p: &[u8], sink: S) -> Option<Result<S::Ok, S::Error>> {
    if !scalar::valid(tag, p) {
        return None;
    }
    macro_rules! le {
        ($ty:ty) => {
            <$ty>::from_le_bytes(p.try_into().ok()?)
        };
    }
    Some(match tag {
        tags::NULL => sink.null(),
        tags::UNDEFINED => sink.undefined(),
        tags::BOOL_FALSE => sink.bool(false),
        tags::BOOL_TRUE => sink.bool(true),
        tags::INT8 => sink.i8(le!(i8)),
        tags::INT16 => sink.i16(le!(i16)),
        tags::INT32 => sink.i32(le!(i32)),
        tags::INT64 => sink.i64(le!(i64)),
        tags::INT128 => sink.i128(le!(i128)),
        tags::UINT8 => sink.u8(le!(u8)),
        tags::UINT16 => sink.u16(le!(u16)),
        tags::UINT32 => sink.u32(le!(u32)),
        tags::UINT64 => sink.u64(le!(u64)),
        tags::UINT128 => sink.u128(le!(u128)),
        tags::FLOAT32 => sink.f32(f32::from_bits(le!(u32))),
        tags::FLOAT64 => sink.f64(f64::from_bits(le!(u64))),
        tags::DATE => sink.date(scalar::date(p)?),
        tags::TIMESTAMP => sink.timestamp(scalar::timestamp(p)?),
        tags::DECIMAL => sink.decimal(scalar::decimal(p)?),
        tags::STRING => sink.str(std::str::from_utf8(p).ok()?),
        tags::BYTES => sink.bytes(p),
        _ => return None,
    })
}
