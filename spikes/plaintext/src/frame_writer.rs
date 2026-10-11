//! Transport frames from any source, push-style. Unknown lengths are
//! patched in at `end`.

use std::collections::HashSet;

use vitaminc_aead_value::transport;
use vitaminc_protected::{Controlled, Protected};

use crate::kinds::{Logical, Physical};
use crate::model::{Error, MapSink, Plaintext, SeqSink, Sink, SourceError};
use crate::scalar::{self, Form, ScalarError};

#[derive(Debug)]
pub enum FrameWriteError {
    TooDeep,
    TooLong,
    /// A value that isn't valid for its logical type.
    Invalid,
    CountMismatch,
    DuplicateKey,
    Source(SourceError),
}

impl Error for FrameWriteError {
    fn source(error: SourceError) -> Self {
        Self::Source(error)
    }
}

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
    /// Write one value node onto the end of `out`.
    pub fn new(out: &'o mut Vec<u8>) -> Self {
        Self { out, depth: 0 }
    }
}

impl<'o> FrameWriter<'o> {
    fn node(self, tag: u8) -> Result<&'o mut Vec<u8>, FrameWriteError> {
        if self.depth > transport::MAX_DEPTH {
            return Err(FrameWriteError::TooDeep);
        }
        self.out.push(tag);
        Ok(self.out)
    }

    fn container(self, tag: u8) -> Result<Count<'o>, FrameWriteError> {
        let depth = self.depth;
        let out = self.node(tag)?;
        let at = out.len();
        out.extend_from_slice(&[0; 4]);
        Ok(Count {
            out,
            depth,
            at,
            n: 0,
        })
    }
}

fn write_len(out: &mut Vec<u8>, len: usize) -> Result<(), FrameWriteError> {
    let len = u32::try_from(len).map_err(|_| FrameWriteError::TooLong)?;
    out.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

/// A container whose count is written once the children are known.
struct Count<'o> {
    out: &'o mut Vec<u8>,
    depth: usize,
    at: usize,
    n: usize,
}

impl<'o> Count<'o> {
    fn child(&mut self) -> FrameWriter<'_> {
        self.n += 1;
        FrameWriter {
            out: &mut *self.out,
            depth: self.depth + 1,
        }
    }

    fn end(self, expected: Option<usize>) -> Result<(), FrameWriteError> {
        if expected.is_some_and(|e| e != self.n) {
            return Err(FrameWriteError::CountMismatch);
        }
        let n = u32::try_from(self.n).map_err(|_| FrameWriteError::TooLong)?;
        self.out[self.at..self.at + 4].copy_from_slice(&n.to_le_bytes());
        Ok(())
    }
}

impl<'o> Sink for FrameWriter<'o> {
    type Ok = ();
    type Error = FrameWriteError;
    type Seq = FrameSeq<'o>;
    type Map = FrameMap<'o>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<(), FrameWriteError> {
        if self.depth > transport::MAX_DEPTH {
            return Err(FrameWriteError::TooDeep);
        }
        scalar::write(ty, v, self.out, Form::Frame).map_err(|e| match e {
            ScalarError::Invalid => FrameWriteError::Invalid,
            ScalarError::TooLong => FrameWriteError::TooLong,
        })
    }

    fn seq(self, len: Option<usize>) -> Result<FrameSeq<'o>, FrameWriteError> {
        Ok(FrameSeq {
            count: self.container(transport::ARRAY)?,
            expected: len,
        })
    }

    fn map(self, len: Option<usize>) -> Result<FrameMap<'o>, FrameWriteError> {
        Ok(FrameMap {
            count: self.container(transport::OBJECT)?,
            expected: len,
            seen: HashSet::new(),
        })
    }

    fn passthrough<P: Plaintext>(self, value: P) -> Result<(), FrameWriteError> {
        let depth = self.depth;
        let out = self.node(transport::PASSTHROUGH)?;
        value.visit(FrameWriter {
            out,
            depth: depth + 1,
        })
    }
}

pub struct FrameSeq<'o> {
    count: Count<'o>,
    expected: Option<usize>,
}

impl SeqSink for FrameSeq<'_> {
    type Ok = ();
    type Error = FrameWriteError;
    type Element<'s>
        = FrameWriter<'s>
    where
        Self: 's;

    fn element(&mut self) -> Result<FrameWriter<'_>, FrameWriteError> {
        Ok(self.count.child())
    }

    fn end(self) -> Result<(), FrameWriteError> {
        self.count.end(self.expected)
    }
}

pub struct FrameMap<'o> {
    count: Count<'o>,
    expected: Option<usize>,
    seen: HashSet<String>,
}

impl MapSink for FrameMap<'_> {
    type Ok = ();
    type Error = FrameWriteError;
    type Entry<'s>
        = FrameWriter<'s>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<FrameWriter<'_>, FrameWriteError> {
        if !self.seen.insert(key.to_owned()) {
            return Err(FrameWriteError::DuplicateKey);
        }
        write_len(self.count.out, key.len())?;
        self.count.out.extend_from_slice(key.as_bytes());
        Ok(self.count.child())
    }

    fn end(self) -> Result<(), FrameWriteError> {
        self.count.end(self.expected)
    }
}
