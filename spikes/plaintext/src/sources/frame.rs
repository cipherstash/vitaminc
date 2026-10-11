//! A borrowed transport frame as a source. This is Go's value as Rust sees it.
//!
//! Go can't implement a Rust trait, and the value has to cross the wasm
//! boundary as bytes anyway. So the "foreign type" on the Rust side is the
//! frame vcffi wrote. `Frame` walks those bytes in place. No `Value` tree is
//! built, and no scalar ever leaves the buffer except to go straight to a
//! sink.
//!
//! [`Frame::parse`] validates the whole frame up front. That is what lets
//! `visit` be infallible (see [`Plaintext`] for why it has to be).

use std::collections::HashSet;

use vitaminc_aead_value::{tags, transport};

use crate::model::{MapSink, Plaintext, SeqSink, Sink};
use crate::scalar;

/// Exactly one validated value node.
#[derive(Clone, Copy, Debug)]
pub struct Frame<'a> {
    bytes: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameError;

impl<'a> Frame<'a> {
    /// Validate `bytes` as one transport value node. Accepts and rejects
    /// exactly what `transport::decode_value` does (tested on the shared
    /// corpus and on mutated inputs).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, FrameError> {
        let mut cursor = Cursor { buf: bytes, pos: 0 };
        skip(&mut cursor, 0)?;
        if cursor.pos != bytes.len() {
            return Err(FrameError);
        }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

pub(crate) struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn finished(&self) -> bool {
        self.pos == self.buf.len()
    }

    pub(crate) fn byte(&mut self) -> Result<u8, FrameError> {
        let b = *self.buf.get(self.pos).ok_or(FrameError)?;
        self.pos += 1;
        Ok(b)
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], FrameError> {
        let end = self.pos.checked_add(n).ok_or(FrameError)?;
        let s = self.buf.get(self.pos..end).ok_or(FrameError)?;
        self.pos = end;
        Ok(s)
    }

    pub(crate) fn count(&mut self) -> Result<usize, FrameError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes(b.try_into().map_err(|_| FrameError)?) as usize)
    }

    /// The next whole value node, as its own frame.
    pub(crate) fn node(&mut self, depth: usize) -> Result<Frame<'a>, FrameError> {
        let start = self.pos;
        skip(self, depth)?;
        Ok(Frame {
            bytes: &self.buf[start..self.pos],
        })
    }
}

/// Step over one value node, validating it. Mirrors `decode_value_inner`.
fn skip(c: &mut Cursor<'_>, depth: usize) -> Result<(), FrameError> {
    if depth > transport::MAX_DEPTH {
        return Err(FrameError);
    }
    match c.byte()? {
        transport::ARRAY => {
            for _ in 0..c.count()? {
                skip(c, depth + 1)?;
            }
        }
        transport::OBJECT => {
            let count = c.count()?;
            let mut seen = HashSet::new();
            for _ in 0..count {
                let len = c.count()?;
                let key = std::str::from_utf8(c.take(len)?).map_err(|_| FrameError)?;
                if !seen.insert(key) {
                    return Err(FrameError);
                }
                skip(c, depth + 1)?;
            }
        }
        transport::PASSTHROUGH => skip(c, depth + 1)?,
        tag => {
            let len = match tag {
                tags::STRING | tags::BYTES => c.count()?,
                _ => scalar::fixed_len(tag).ok_or(FrameError)?,
            };
            if !scalar::valid(tag, c.take(len)?) {
                return Err(FrameError);
            }
        }
    }
    Ok(())
}

// Everything below runs on a frame `parse` accepted, so a read can't fail.
pub(crate) const VALIDATED: &str = "frame was validated by Frame::parse";

impl Plaintext for Frame<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut c = Cursor {
            buf: self.bytes,
            pos: 0,
        };
        let tag = c.byte().expect(VALIDATED);
        match tag {
            transport::ARRAY => {
                let count = c.count().expect(VALIDATED);
                let mut seq = sink.seq(count)?;
                for _ in 0..count {
                    seq = seq.element(c.node(0).expect(VALIDATED))?;
                }
                seq.end()
            }
            transport::OBJECT => {
                let count = c.count().expect(VALIDATED);
                let mut map = sink.map(count)?;
                for _ in 0..count {
                    let len = c.count().expect(VALIDATED);
                    let key = std::str::from_utf8(c.take(len).expect(VALIDATED)).expect(VALIDATED);
                    map = map.entry(key, c.node(0).expect(VALIDATED))?;
                }
                map.end()
            }
            transport::PASSTHROUGH => sink.passthrough(c.node(0).expect(VALIDATED)),
            tags::STRING => {
                let len = c.count().expect(VALIDATED);
                sink.str(std::str::from_utf8(c.take(len).expect(VALIDATED)).expect(VALIDATED))
            }
            tags::BYTES => {
                let len = c.count().expect(VALIDATED);
                sink.bytes(c.take(len).expect(VALIDATED))
            }
            tag => {
                let len = scalar::fixed_len(tag).expect(VALIDATED);
                visit_fixed(tag, c.take(len).expect(VALIDATED), sink)
            }
        }
    }
}

fn visit_fixed<S: Sink>(tag: u8, p: &[u8], sink: S) -> Result<S::Ok, S::Error> {
    macro_rules! le {
        ($ty:ty) => {
            <$ty>::from_le_bytes(p.try_into().expect(VALIDATED))
        };
    }
    match tag {
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
        // Raw bit patterns, so signalling NaNs survive.
        tags::FLOAT32 => sink.f32(f32::from_bits(le!(u32))),
        tags::FLOAT64 => sink.f64(f64::from_bits(le!(u64))),
        tags::DATE => sink.date(scalar::date(p).expect(VALIDATED)),
        tags::TIMESTAMP => sink.timestamp(scalar::timestamp(p).expect(VALIDATED)),
        tags::DECIMAL => sink.decimal(scalar::decimal(p).expect(VALIDATED)),
        _ => unreachable!("{VALIDATED}"),
    }
}
