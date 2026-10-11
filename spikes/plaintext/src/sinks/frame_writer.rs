//! Writing a transport frame is a sink too. With this, any source can feed
//! the Go side, and `Value` to bytes is no longer special code.

use std::collections::HashSet;

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use rust_decimal::Decimal;
use vitaminc_aead_value::{tags, transport};
use vitaminc_protected::{Controlled, Protected};

use crate::model::{MapSink, Plaintext, SeqSink, Sink};
use crate::scalar;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameWriteError {
    TooDeep,
    TooLong,
    /// A source sent more or fewer children than it announced.
    CountMismatch,
    DuplicateKey,
}

/// Write `p` as one transport value node.
pub fn to_frame<P: Plaintext>(p: P) -> Result<Protected<Vec<u8>>, FrameWriteError> {
    let mut out = Protected::new(Vec::new());
    p.visit(FrameWriter {
        out: out.risky_inner_mut(),
        depth: 0,
    })?;
    Ok(out)
}

pub struct FrameWriter<'o> {
    out: &'o mut Vec<u8>,
    depth: usize,
}

impl<'o> FrameWriter<'o> {
    /// Same depth rule as the transport decoder: no node below `MAX_DEPTH`.
    fn node(self, tag: u8) -> Result<Self, FrameWriteError> {
        if self.depth > transport::MAX_DEPTH {
            return Err(FrameWriteError::TooDeep);
        }
        self.out.push(tag);
        Ok(self)
    }

    fn fixed(self, tag: u8, payload: &[u8]) -> Result<(), FrameWriteError> {
        self.node(tag)?.out.extend_from_slice(payload);
        Ok(())
    }

    fn variable(self, tag: u8, payload: &[u8]) -> Result<(), FrameWriteError> {
        let out = self.node(tag)?.out;
        write_len(out, payload.len())?;
        out.extend_from_slice(payload);
        Ok(())
    }
}

fn write_len(out: &mut Vec<u8>, len: usize) -> Result<(), FrameWriteError> {
    let len = u32::try_from(len).map_err(|_| FrameWriteError::TooLong)?;
    out.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

macro_rules! le {
    ($($method:ident($ty:ty) => $tag:ident),* $(,)?) => {
        $(
            fn $method(self, v: $ty) -> Result<(), FrameWriteError> {
                self.fixed(tags::$tag, &v.to_le_bytes())
            }
        )*
    };
}

impl<'o> Sink for FrameWriter<'o> {
    type Ok = ();
    type Error = FrameWriteError;
    type Seq = FrameSeq<'o>;
    type Map = FrameMap<'o>;

    fn null(self) -> Result<(), FrameWriteError> {
        self.fixed(tags::NULL, &[])
    }

    fn undefined(self) -> Result<(), FrameWriteError> {
        self.fixed(tags::UNDEFINED, &[])
    }

    fn bool(self, v: bool) -> Result<(), FrameWriteError> {
        self.fixed(if v { tags::BOOL_TRUE } else { tags::BOOL_FALSE }, &[])
    }

    le! {
        i8(i8) => INT8, i16(i16) => INT16, i32(i32) => INT32, i64(i64) => INT64, i128(i128) => INT128,
        u8(u8) => UINT8, u16(u16) => UINT16, u32(u32) => UINT32, u64(u64) => UINT64, u128(u128) => UINT128,
    }

    fn f32(self, v: f32) -> Result<(), FrameWriteError> {
        self.fixed(tags::FLOAT32, &v.to_bits().to_le_bytes())
    }

    fn f64(self, v: f64) -> Result<(), FrameWriteError> {
        self.fixed(tags::FLOAT64, &v.to_bits().to_le_bytes())
    }

    fn date(self, v: NaiveDate) -> Result<(), FrameWriteError> {
        self.fixed(tags::DATE, &v.num_days_from_ce().to_le_bytes())
    }

    fn timestamp(self, v: DateTime<Utc>) -> Result<(), FrameWriteError> {
        self.fixed(tags::TIMESTAMP, &scalar::timestamp_bytes(v))
    }

    fn decimal(self, v: Decimal) -> Result<(), FrameWriteError> {
        self.fixed(tags::DECIMAL, &v.serialize())
    }

    fn str(self, v: &str) -> Result<(), FrameWriteError> {
        self.variable(tags::STRING, v.as_bytes())
    }

    fn bytes(self, v: &[u8]) -> Result<(), FrameWriteError> {
        self.variable(tags::BYTES, v)
    }

    fn seq(self, len: usize) -> Result<FrameSeq<'o>, FrameWriteError> {
        let depth = self.depth;
        let out = self.node(transport::ARRAY)?.out;
        write_len(out, len)?;
        Ok(FrameSeq {
            out,
            depth,
            remaining: len,
        })
    }

    fn map(self, len: usize) -> Result<FrameMap<'o>, FrameWriteError> {
        let depth = self.depth;
        let out = self.node(transport::OBJECT)?.out;
        write_len(out, len)?;
        Ok(FrameMap {
            out,
            depth,
            remaining: len,
            seen: HashSet::new(),
        })
    }

    fn passthrough<P: Plaintext>(self, value: P) -> Result<(), FrameWriteError> {
        let depth = self.depth;
        let out = self.node(transport::PASSTHROUGH)?.out;
        value.visit(FrameWriter {
            out,
            depth: depth + 1,
        })
    }
}

pub struct FrameSeq<'o> {
    out: &'o mut Vec<u8>,
    depth: usize,
    remaining: usize,
}

impl SeqSink for FrameSeq<'_> {
    type Ok = ();
    type Error = FrameWriteError;

    fn element<P: Plaintext>(mut self, value: P) -> Result<Self, FrameWriteError> {
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or(FrameWriteError::CountMismatch)?;
        value.visit(FrameWriter {
            out: &mut *self.out,
            depth: self.depth + 1,
        })?;
        Ok(self)
    }

    fn end(self) -> Result<(), FrameWriteError> {
        match self.remaining {
            0 => Ok(()),
            _ => Err(FrameWriteError::CountMismatch),
        }
    }
}

pub struct FrameMap<'o> {
    out: &'o mut Vec<u8>,
    depth: usize,
    remaining: usize,
    seen: HashSet<String>,
}

impl MapSink for FrameMap<'_> {
    type Ok = ();
    type Error = FrameWriteError;

    fn entry<P: Plaintext>(mut self, key: &str, value: P) -> Result<Self, FrameWriteError> {
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or(FrameWriteError::CountMismatch)?;
        // The decoder refuses duplicate keys, so the writer must too.
        if !self.seen.insert(key.to_owned()) {
            return Err(FrameWriteError::DuplicateKey);
        }
        write_len(self.out, key.len())?;
        self.out.extend_from_slice(key.as_bytes());
        value.visit(FrameWriter {
            out: &mut *self.out,
            depth: self.depth + 1,
        })?;
        Ok(self)
    }

    fn end(self) -> Result<(), FrameWriteError> {
        match self.remaining {
            0 => Ok(()),
            _ => Err(FrameWriteError::CountMismatch),
        }
    }
}
